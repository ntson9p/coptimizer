// Package winfs reads the real Windows file system for the scanner. It only
// ever reads: folders are opened for listing, files are never opened.
package winfs

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// Lister lists folders with GetFileInformationByHandleEx, which returns the
// names, sizes, attributes and file IDs of a whole batch of entries per call
// without opening any of them.
type Lister struct{}

var buffers = sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}

// List implements fsx.Lister. dir must be an absolute path.
func (Lister) List(dir string) ([]fsx.Entry, error) {
	name, err := windows.UTF16PtrFromString(longPath(dir))
	if err != nil {
		return nil, &fs.PathError{Op: "list", Path: dir, Err: err}
	}
	// Backup semantics is what lets CreateFile open folders; it also lets an
	// Administrator with SeBackupPrivilege list folders their ACL hides.
	h, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "list", Path: dir, Err: err}
	}
	defer windows.CloseHandle(h)
	bp := buffers.Get().(*[]byte)
	defer buffers.Put(bp)
	buf := *bp
	var entries []fsx.Entry
	for {
		err := windows.GetFileInformationByHandleEx(h, windows.FileIdBothDirectoryInfo, &buf[0], uint32(len(buf)))
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return entries, nil
		}
		if err != nil {
			return entries, &fs.PathError{Op: "list", Path: dir, Err: err}
		}
		if entries, err = appendEntries(entries, buf); err != nil {
			return entries, &fs.PathError{Op: "list", Path: dir, Err: err}
		}
	}
}

// longPath returns the `\\?\` form of an absolute path: it reaches past 260
// characters and keeps names exactly as stored (no trimming of trailing dots
// or spaces).
func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	return `\\?\` + p
}

// Byte offsets in a FILE_ID_BOTH_DIR_INFO record.
const (
	offNext       = 0
	offLastWrite  = 24
	offEndOfFile  = 40
	offAllocation = 48
	offAttributes = 56
	offNameLength = 60
	offEaSize     = 64 // holds the reparse tag for reparse points
	offFileID     = 96
	offName       = 104
)

var errMalformed = errors.New("malformed directory information")

// appendEntries decodes the FILE_ID_BOTH_DIR_INFO records in buf.
func appendEntries(entries []fsx.Entry, buf []byte) ([]fsx.Entry, error) {
	le := binary.LittleEndian
	for off := 0; ; {
		if off+offName > len(buf) {
			return entries, errMalformed
		}
		rec := buf[off:]
		nameLen := int(le.Uint32(rec[offNameLength:]))
		if nameLen%2 != 0 || offName+nameLen > len(rec) {
			return entries, errMalformed
		}
		if name := decodeName(rec[offName : offName+nameLen]); name != "." && name != ".." {
			attrs := le.Uint32(rec[offAttributes:])
			e := fsx.Entry{
				Name:      name,
				Size:      int64(le.Uint64(rec[offEndOfFile:])),
				Allocated: int64(le.Uint64(rec[offAllocation:])),
				Attrs:     attrs,
				FileID:    le.Uint64(rec[offFileID:]),
				Modified:  fileTime(int64(le.Uint64(rec[offLastWrite:]))),
			}
			if attrs&fsx.AttrReparsePoint != 0 {
				e.ReparseTag = le.Uint32(rec[offEaSize:])
			}
			entries = append(entries, e)
		}
		next := int(le.Uint32(rec[offNext:]))
		if next == 0 {
			return entries, nil
		}
		if next < offName {
			return entries, errMalformed
		}
		off += next
	}
}

func decodeName(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// fileTime converts a FILETIME (100 ns steps since 1601) to a time.
func fileTime(ft int64) time.Time {
	if ft <= 0 {
		return time.Time{}
	}
	const unixEpoch = 116444736000000000 // 1970-01-01 in FILETIME units
	return time.Unix(0, (ft-unixEpoch)*100)
}
