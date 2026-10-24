package winfs

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// record builds one FILE_ID_BOTH_DIR_INFO record, padded to 8 bytes.
func record(name string, size, alloc int64, attrs, ea uint32, id uint64, ft int64, last bool) []byte {
	n := utf16.Encode([]rune(name))
	length := (offName + 2*len(n) + 7) &^ 7
	b := make([]byte, length)
	le := binary.LittleEndian
	if !last {
		le.PutUint32(b[offNext:], uint32(length))
	}
	le.PutUint64(b[offLastWrite:], uint64(ft))
	le.PutUint64(b[offEndOfFile:], uint64(size))
	le.PutUint64(b[offAllocation:], uint64(alloc))
	le.PutUint32(b[offAttributes:], attrs)
	le.PutUint32(b[offNameLength:], uint32(2*len(n)))
	le.PutUint32(b[offEaSize:], ea)
	le.PutUint64(b[offFileID:], id)
	for i, c := range n {
		le.PutUint16(b[offName+2*i:], c)
	}
	return b
}

func TestAppendEntries(t *testing.T) {
	// 2026-01-02 03:04:05 UTC as a FILETIME.
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ft := when.UnixNano()/100 + 116444736000000000
	var buf []byte
	buf = append(buf, record(".", 0, 0, fsx.AttrDirectory, 0, 1, ft, false)...)
	buf = append(buf, record("..", 0, 0, fsx.AttrDirectory, 0, 2, ft, false)...)
	buf = append(buf, record("file.bin", 5000, 8192, 0x20, 0, 77, ft, false)...)
	buf = append(buf, record("link", 0, 0, fsx.AttrDirectory|fsx.AttrReparsePoint, fsx.TagMountPoint, 78, ft, true)...)
	buf = append(buf, make([]byte, 64)...) // stale bytes after the last record

	got, err := appendEntries(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries; want 2 (no . or ..)", len(got))
	}
	f, l := got[0], got[1]
	if f.Name != "file.bin" || f.Size != 5000 || f.Allocated != 8192 || f.FileID != 77 || !f.Modified.Equal(when) || f.ReparseTag != 0 {
		t.Errorf("file = %+v", f)
	}
	if l.Name != "link" || !l.IsReparse() || l.ReparseTag != fsx.TagMountPoint {
		t.Errorf("link = %+v", l)
	}
}

func TestAppendEntriesRejectsMalformed(t *testing.T) {
	good := record("a", 1, 1, 0, 0, 1, 0, true)
	cases := map[string][]byte{
		"too short":     good[:offName-1],
		"name past end": good[:offName+1],
		"odd name length": func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[offNameLength:], 3)
			return b
		}(),
		"next too small": func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[offNext:], 8)
			return b
		}(),
	}
	for name, buf := range cases {
		if _, err := appendEntries(nil, buf); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestLongPath(t *testing.T) {
	if got := longPath(`C:\x`); got != `\\?\C:\x` {
		t.Errorf("longPath = %q", got)
	}
	if got := longPath(`\\?\C:\x`); got != `\\?\C:\x` {
		t.Errorf("longPath kept prefix = %q", got)
	}
}
