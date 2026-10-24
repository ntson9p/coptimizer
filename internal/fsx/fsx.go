// Package fsx is the read-only view of a file system that the scanner works
// with, so that tests and demo mode can swap the real Windows file system for
// an in-memory one.
package fsx

import "time"

// Windows file attribute bits (FILE_ATTRIBUTE_*) that the app looks at.
const (
	AttrReadOnly           = 0x00000001
	AttrHidden             = 0x00000002
	AttrSystem             = 0x00000004
	AttrDirectory          = 0x00000010
	AttrReparsePoint       = 0x00000400
	AttrOffline            = 0x00001000
	AttrRecallOnOpen       = 0x00040000
	AttrRecallOnDataAccess = 0x00400000
)

// TagMountPoint is the reparse tag of junctions and volume mount points.
const TagMountPoint = 0xA0000003

// Entry is one item of a folder listing.
type Entry struct {
	Name       string
	Size       int64  // logical size in bytes
	Allocated  int64  // bytes the file takes on disk
	Attrs      uint32 // FILE_ATTRIBUTE_* bits
	ReparseTag uint32 // set when Attrs has AttrReparsePoint
	FileID     uint64 // identifies the file on its volume; 0 if unknown
	Modified   time.Time
}

// IsDir reports whether the entry is a folder (or a link to one).
func (e Entry) IsDir() bool { return e.Attrs&AttrDirectory != 0 }

// IsReparse reports whether the entry is a junction, symbolic link, mount
// point or other reparse point.
func (e Entry) IsReparse() bool { return e.Attrs&AttrReparsePoint != 0 }

// IsCloudOnly reports whether the file's content lives elsewhere, like an
// online-only OneDrive file. Opening such a file would download it.
func (e Entry) IsCloudOnly() bool {
	return e.Attrs&(AttrOffline|AttrRecallOnOpen|AttrRecallOnDataAccess) != 0
}

// Lister lists the entries of a folder, without "." and "..". Errors for
// folders that can't be read satisfy errors.Is(err, fs.ErrPermission).
type Lister interface {
	List(dir string) ([]Entry, error)
}
