// Package memfs is an in-memory fsx.Lister for tests and demo mode. Paths are
// absolute Windows paths such as `C:\Users\demo`; names compare without
// regard to case, like on NTFS.
package memfs

import (
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// clusterSize is what files are rounded up to on disk.
const clusterSize = 4096

// FS is a tree of folders and files that exists only in memory.
type FS struct {
	mu     sync.RWMutex
	drives map[string]*folder // "C:" → root folder
	nextID uint64
	delay  time.Duration
	lists  map[string]int // upper-case path → how often it was listed
}

type folder struct {
	entries []fsx.Entry
	sub     map[string]*folder // upper-case name → folder
	denied  bool
}

// New returns an empty file system.
func New() *FS {
	return &FS{drives: make(map[string]*folder), lists: make(map[string]int)}
}

// SetDelay makes every List call take d, to imitate a real disk.
func (f *FS) SetDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
}

// AddFile adds a file, creating any missing folders. Its size on disk is
// size rounded up to whole 4 KiB clusters.
func (f *FS) AddFile(path string, size int64, modified time.Time) {
	f.Add(path, fsx.Entry{Size: size, Allocated: roundUp(size), Modified: modified})
}

// Add adds an entry with the given details at path, creating any missing
// folders. The entry's name is taken from path; a missing FileID is assigned.
func (f *FS) Add(path string, e fsx.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dir, name := f.parent(path)
	e.Name = name
	if e.FileID == 0 {
		f.nextID++
		e.FileID = f.nextID
	}
	dir.entries = append(dir.entries, e)
	if e.IsDir() && !e.IsReparse() {
		dir.sub[strings.ToUpper(name)] = &folder{sub: make(map[string]*folder)}
	}
}

// AddDir adds an empty folder, creating any missing parents.
func (f *FS) AddDir(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.folder(path, true)
}

// AddJunction adds a junction: a folder entry that links elsewhere and must
// never be followed.
func (f *FS) AddJunction(path string) {
	f.Add(path, fsx.Entry{Attrs: fsx.AttrDirectory | fsx.AttrReparsePoint, ReparseTag: fsx.TagMountPoint})
}

// AddHardLink adds a second name at path for the file at target.
func (f *FS) AddHardLink(path, target string) {
	f.mu.Lock()
	dir, name := f.parent(target)
	var e fsx.Entry
	found := false
	for _, x := range dir.entries {
		if strings.EqualFold(x.Name, name) {
			e, found = x, true
		}
	}
	f.mu.Unlock()
	if !found {
		panic("memfs: no file at " + target)
	}
	f.Add(path, e)
}

// Deny makes listing the folder at path fail with "access denied".
func (f *FS) Deny(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.folder(path, true).denied = true
}

// Listed reports how many times the folder at path has been listed.
func (f *FS) Listed(path string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.lists[strings.ToUpper(strings.TrimRight(path, `\`))]
}

// List implements fsx.Lister.
func (f *FS) List(dir string) ([]fsx.Entry, error) {
	f.mu.Lock()
	f.lists[strings.ToUpper(strings.TrimRight(dir, `\`))]++
	delay := f.delay
	d := f.folder(dir, false)
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	switch {
	case d == nil:
		return nil, &fs.PathError{Op: "list", Path: dir, Err: fs.ErrNotExist}
	case d.denied:
		return nil, &fs.PathError{Op: "list", Path: dir, Err: fs.ErrPermission}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]fsx.Entry(nil), d.entries...), nil
}

// parent returns the folder that holds path, creating it if needed, and the
// last name in path.
func (f *FS) parent(path string) (*folder, string) {
	segs := split(path)
	if len(segs) < 2 {
		panic(fmt.Sprintf("memfs: %q has no parent folder", path))
	}
	return f.folder(strings.Join(segs[:len(segs)-1], `\`), true), segs[len(segs)-1]
}

// folder finds the folder at path; with create it adds missing folders.
func (f *FS) folder(path string, create bool) *folder {
	segs := split(path)
	drive := strings.ToUpper(segs[0])
	d := f.drives[drive]
	if d == nil {
		if !create {
			return nil
		}
		d = &folder{sub: make(map[string]*folder)}
		f.drives[drive] = d
	}
	for _, name := range segs[1:] {
		next := d.sub[strings.ToUpper(name)]
		if next == nil {
			if !create {
				return nil
			}
			f.nextID++
			d.entries = append(d.entries, fsx.Entry{Name: name, Attrs: fsx.AttrDirectory, FileID: f.nextID})
			next = &folder{sub: make(map[string]*folder)}
			d.sub[strings.ToUpper(name)] = next
		}
		d = next
	}
	return d
}

func split(path string) []string {
	segs := strings.Split(strings.Trim(path, `\`), `\`)
	if len(segs[0]) != 2 || segs[0][1] != ':' {
		panic(fmt.Sprintf("memfs: %q is not an absolute path", path))
	}
	return segs
}

func roundUp(size int64) int64 {
	return (size + clusterSize - 1) / clusterSize * clusterSize
}
