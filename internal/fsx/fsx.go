// Package fsx is the view of a file system that the scanner and the deleter
// work with, so that tests and demo mode can swap the real Windows file system
// for an in-memory one.
package fsx

import (
	"errors"
	"time"
)

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
	Created    time.Time // zero if unknown
}

// Changed is the later of the entry's creation and last change. A file copied
// or unpacked keeps its old modification time, so its age counts from
// whichever happened last.
func (e Entry) Changed() time.Time {
	if e.Created.After(e.Modified) {
		return e.Created
	}
	return e.Modified
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

var (
	// ErrInUse is wrapped by errors for files another program holds open in
	// a way that stops them being deleted.
	ErrInUse = errors.New("in use by another program")
	// ErrLink is wrapped by errors for paths that are, or pass through, a
	// junction or link.
	ErrLink = errors.New("a junction or link")
	// ErrNotLocal is wrapped by errors for paths that aren't on a local
	// fixed drive.
	ErrNotLocal = errors.New("not on a local fixed drive")
)

// Cleaner opens folders for the deleter.
type Cleaner interface {
	// Open opens the folder at path, which must be an absolute, normalized
	// path, for cleaning. It fails unless path is a plain folder on a local
	// fixed drive, reached without passing through any junction or link.
	Open(path string) (Tree, error)
}

// Tree is an open folder. Every name is relative to it ("" is the folder
// itself), and no operation ever leaves it: a name that passes through a
// junction or link is refused.
type Tree interface {
	// Path is the folder's absolute path, as Windows itself resolved it.
	Path() string
	// List lists the folder rel, like Lister.List.
	List(rel string) ([]Entry, error)
	// Remove deletes the file or empty folder rel. A link is removed itself,
	// never its target. Read-only files are deleted too. Errors for files in
	// use wrap ErrInUse.
	Remove(rel string) error
	Close() error
}
