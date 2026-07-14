// Copyright 2026 The p9 Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p9

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/hugelgupf/p9/linux"
	"github.com/hugelgupf/socketpair"
	"github.com/u-root/uio/ulog/ulogtest"
)

// This file regression-tests the additive AttachUname client API:
//   - legacy Attach(name) must emit an empty UserName and the supplied AttachName;
//   - AttachUname(uname, name) must emit both exact fields on the wire;
//   - a successful attach returns a usable attached file (non-nil File, nil error);
//   - an attach denied by the server surfaces as an error and the client
//     reclaims the allocated fid (subsequent attaches still succeed).
//
// Because the p9.Attacher interface does not surface uname, these tests tee the
// server-side connection and decode the emitted tattach directly — the same
// standard 9P field the Hyprstream /9p plane authorizes mount tickets from.

// rejectAttacher models the authorized-plane denial: Attach fails with EACCES
// before any fid is established, mirroring the empty-uname / bad-ticket path.
type rejectAttacher struct{}

func (rejectAttacher) Attach() (File, error) { return nil, linux.EACCES }

// stubFile implements p9.File with ENOSYS for every method that the attach
// path does not exercise, so the server can establish the root fid. The attach
// handler only calls GetAttr (must report a valid Mode) and Close.
type stubFile struct{}

func (stubFile) Walk([]string) ([]QID, File, error) { return nil, nil, linux.ENOSYS }
func (stubFile) WalkGetAttr([]string) ([]QID, File, AttrMask, Attr, error) {
	return nil, nil, AttrMask{}, Attr{}, linux.ENOSYS
}
func (stubFile) StatFS() (FSStat, error) { return FSStat{}, linux.ENOSYS }
func (stubFile) GetAttr(AttrMask) (QID, AttrMask, Attr, error) {
	return QID{}, AttrMask{Mode: true}, Attr{Mode: ModeDirectory | 0755}, nil
}
func (stubFile) SetAttr(SetAttrMask, SetAttr) error        { return linux.ENOSYS }
func (stubFile) Close() error                              { return nil }
func (stubFile) Open(OpenFlags) (QID, uint32, error)       { return QID{}, 0, linux.ENOSYS }
func (stubFile) ReadAt([]byte, int64) (int, error)         { return 0, linux.ENOSYS }
func (stubFile) WriteAt([]byte, int64) (int, error)        { return 0, linux.ENOSYS }
func (stubFile) SetXattr(string, []byte, XattrFlags) error { return linux.ENOSYS }
func (stubFile) GetXattr(string) ([]byte, error)           { return nil, linux.ENOSYS }
func (stubFile) ListXattrs() ([]string, error)             { return nil, linux.ENOSYS }
func (stubFile) RemoveXattr(string) error                  { return linux.ENOSYS }
func (stubFile) FSync() error                              { return linux.ENOSYS }
func (stubFile) Lock(int, LockType, LockFlags, uint64, uint64, string) (LockStatus, error) {
	return LockStatusError, linux.ENOSYS
}
func (stubFile) Create(string, OpenFlags, FileMode, UID, GID) (File, QID, uint32, error) {
	return nil, QID{}, 0, linux.ENOSYS
}
func (stubFile) Mkdir(string, FileMode, UID, GID) (QID, error) { return QID{}, linux.ENOSYS }
func (stubFile) Symlink(string, string, UID, GID) (QID, error) { return QID{}, linux.ENOSYS }
func (stubFile) Link(File, string) error                       { return linux.ENOSYS }
func (stubFile) Mknod(string, FileMode, uint32, uint32, UID, GID) (QID, error) {
	return QID{}, linux.ENOSYS
}
func (stubFile) Rename(File, string) error               { return linux.ENOSYS }
func (stubFile) RenameAt(string, File, string) error     { return linux.ENOSYS }
func (stubFile) UnlinkAt(string, uint32) error           { return linux.ENOSYS }
func (stubFile) Readdir(uint64, uint32) (Dirents, error) { return nil, linux.ENOSYS }
func (stubFile) Readlink() (string, error)               { return "", linux.ENOSYS }
func (stubFile) Renamed(File, string)                    {}

type okAttacher struct{}

func (okAttacher) Attach() (File, error) { return stubFile{}, nil }

// teeConn copies every byte the server reads into rec so the test can decode
// the tattach the client actually emitted, regardless of the server response.
type teeConn struct {
	net.Conn
	rec *bytes.Buffer
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.rec.Write(p[:n])
	}
	return n, err
}

type teeListener struct {
	net.Listener
	rec *bytes.Buffer
}

func (l *teeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &teeConn{Conn: c, rec: l.rec}, nil
}

// serveTee starts an in-process server over a socketpair and returns a
// connected client plus the buffer of server-side bytes.
func serveTee(t *testing.T, attacher Attacher) (*Client, *bytes.Buffer) {
	t.Helper()
	l := socketpair.Listen()
	tl := &teeListener{Listener: l, rec: &bytes.Buffer{}}
	s := NewServer(attacher, WithServerLogger(ulogtest.Logger{TB: t}))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = s.Serve(tl)
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})

	conn, err := l.Dial()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c, err := NewClient(conn,
		WithMessageSize(1024*1024),
		WithClientLogger(ulogtest.Logger{TB: t}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, tl.rec
}

// decodeTattach scans the recorded 9P stream for the first tattach frame and
// returns its decoded fields.
func decodeTattach(t *testing.T, rec *bytes.Buffer) tattach {
	t.Helper()
	data := rec.Bytes()
	for len(data) >= int(headerLength) {
		size := binary.LittleEndian.Uint32(data[:4])
		if size < headerLength || int(size) > len(data) {
			t.Fatalf("malformed 9P frame: size=%d buf=%d", size, len(data))
		}
		if msgType(data[4]) == msgTattach {
			var att tattach
			att.decode(&buffer{data: data[headerLength:size]})
			return att
		}
		data = data[size:]
	}
	t.Fatalf("no tattach frame found in %d bytes", rec.Len())
	return tattach{}
}

// TestAttachEmitsEmptyUserName ensures the legacy Attach(name) path preserves
// upstream behavior: the standard UserName is empty and AttachName is the
// caller-supplied export selector.
func TestAttachEmitsEmptyUserName(t *testing.T) {
	c, rec := serveTee(t, rejectAttacher{})
	const aname = "exports/aname-x"
	if _, err := c.Attach(aname); err == nil {
		t.Fatalf("Attach: expected server denial, got nil error")
	}
	att := decodeTattach(t, rec)
	if att.Auth.UserName != "" {
		t.Errorf("Attach UserName = %q, want empty (backwards-compatible)", att.Auth.UserName)
	}
	if att.Auth.AttachName != aname {
		t.Errorf("Attach AttachName = %q, want %q", att.Auth.AttachName, aname)
	}
}

// TestAttachUnameEmitsExactFields ensures AttachUname populates the standard
// Tattach.UserName from the caller-supplied uname, alongside AttachName.
func TestAttachUnameEmitsExactFields(t *testing.T) {
	c, rec := serveTee(t, rejectAttacher{})
	const (
		// Fake test ticket — never a real credential.
		uname = "test-ticket"
		aname = "exports/aname-y"
	)
	if _, err := c.AttachUname(uname, aname); err == nil {
		t.Fatalf("AttachUname: expected server denial, got nil error")
	}
	att := decodeTattach(t, rec)
	if att.Auth.UserName != uname {
		t.Errorf("AttachUname UserName = %q, want %q", att.Auth.UserName, uname)
	}
	if att.Auth.AttachName != aname {
		t.Errorf("AttachUname AttachName = %q, want %q", att.Auth.AttachName, aname)
	}
}

// TestAttachUnameReturnsUsableFile ensures a server-accepted attach yields a
// non-nil File with no error — i.e. the rattach round-trip establishes a usable
// attached fid.
func TestAttachUnameReturnsUsableFile(t *testing.T) {
	c, _ := serveTee(t, okAttacher{})
	f, err := c.AttachUname("", "")
	if err != nil {
		t.Fatalf("AttachUname on accepting server: %v", err)
	}
	if f == nil {
		t.Fatalf("AttachUname returned nil file")
	}
}

// TestAttachUnameReclaimsFidOnDenial ensures the fid allocated for a denied
// attach is returned to the pool: repeated denied attaches must surface the
// server denial rather than exhausting fids.
func TestAttachUnameReclaimsFidOnDenial(t *testing.T) {
	c, _ := serveTee(t, rejectAttacher{})
	for i := 0; i < 16; i++ {
		if _, err := c.AttachUname("test-ticket", "x"); err == nil {
			t.Fatalf("denied attach %d: expected error", i)
		}
	}
	// All allocated fids must have been reclaimed; the error surfaced must be
	// the server denial, not fid-pool exhaustion.
	if _, err := c.AttachUname("test-ticket", "x"); err != nil && errors.Is(err, ErrOutOfFIDs) {
		t.Fatalf("fid leaked after denied attaches: %v", err)
	}
}
