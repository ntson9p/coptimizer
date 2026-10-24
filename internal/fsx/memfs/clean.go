package memfs

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// errNotEmpty is what removing a folder that still has entries gives.
var errNotEmpty = errors.New("the folder is not empty")

// Lock makes removing the file or folder at path fail as if another program
// had it open.
func (f *FS) Lock(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked[key(path)] = true
}

// DenyDelete makes removing the file or folder at path fail for lack of
// permission.
func (f *FS) DenyDelete(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noDelete[key(path)] = true
}

// Freed returns how many bytes on disk have been removed from drive ("C:").
func (f *FS) Freed(drive string) int64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.freed[strings.ToUpper(strings.TrimRight(drive, `\`))]
}

// Exists reports whether there is a file or folder at path.
func (f *FS) Exists(path string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	segs := split(path)
	if len(segs) == 1 {
		return f.drives[strings.ToUpper(segs[0])] != nil
	}
	dir := f.folder(strings.Join(segs[:len(segs)-1], `\`), false)
	if dir == nil {
		return false
	}
	_, i := dir.find(segs[len(segs)-1])
	return i >= 0
}

// Open implements fsx.Cleaner. Like the real one it refuses a path that is,
// or passes through, a junction.
func (f *FS) Open(path string) (fsx.Tree, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	segs := split(path)
	drive := strings.ToUpper(segs[0])
	d := f.drives[drive]
	if d == nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	stored := drive
	for _, name := range segs[1:] {
		e, i := d.find(name)
		switch {
		case i < 0:
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		case e.IsReparse():
			return nil, &fs.PathError{Op: "open", Path: path, Err: fsx.ErrLink}
		case !e.IsDir():
			return nil, &fs.PathError{Op: "open", Path: path, Err: errors.New("not a folder")}
		}
		stored += `\` + e.Name
		d = d.sub[strings.ToUpper(e.Name)]
	}
	if len(segs) == 1 {
		stored += `\`
	}
	return &tree{fs: f, path: stored}, nil
}

// tree is an open folder of an FS.
type tree struct {
	fs   *FS
	path string // with the names as stored
}

func (t *tree) Path() string { return t.path }
func (t *tree) Close() error { return nil }

func (t *tree) List(rel string) ([]fsx.Entry, error) {
	return t.fs.List(joinRel(t.path, rel))
}

// Remove deletes the file or empty folder rel, refusing to pass through a
// junction on the way.
func (t *tree) Remove(rel string) error {
	f := t.fs
	full := joinRel(t.path, rel)
	f.mu.Lock()
	defer f.mu.Unlock()
	segs := split(full)
	d := f.drives[strings.ToUpper(segs[0])]
	if d == nil || len(segs) == 1 {
		return &fs.PathError{Op: "remove", Path: full, Err: fs.ErrNotExist}
	}
	for _, name := range segs[1 : len(segs)-1] {
		e, i := d.find(name)
		switch {
		case i < 0 || !e.IsDir():
			return &fs.PathError{Op: "remove", Path: full, Err: fs.ErrNotExist}
		case e.IsReparse():
			return &fs.PathError{Op: "remove", Path: full, Err: fsx.ErrLink}
		}
		d = d.sub[strings.ToUpper(e.Name)]
	}
	e, i := d.find(segs[len(segs)-1])
	switch {
	case i < 0:
		return &fs.PathError{Op: "remove", Path: full, Err: fs.ErrNotExist}
	case f.locked[key(full)]:
		return &fs.PathError{Op: "remove", Path: full, Err: fsx.ErrInUse}
	case f.noDelete[key(full)]:
		return &fs.PathError{Op: "remove", Path: full, Err: fs.ErrPermission}
	case e.IsDir() && !e.IsReparse():
		if sub := d.sub[strings.ToUpper(e.Name)]; sub != nil && len(sub.entries) > 0 {
			return &fs.PathError{Op: "remove", Path: full, Err: errNotEmpty}
		}
		delete(d.sub, strings.ToUpper(e.Name))
	default:
		f.freed[strings.ToUpper(segs[0])] += e.Allocated
	}
	d.entries = append(d.entries[:i], d.entries[i+1:]...)
	return nil
}

// find returns the entry called name, or -1.
func (d *folder) find(name string) (fsx.Entry, int) {
	for i, e := range d.entries {
		if strings.EqualFold(e.Name, name) {
			return e, i
		}
	}
	return fsx.Entry{}, -1
}

func key(path string) string { return strings.ToUpper(strings.TrimRight(path, `\`)) }

func joinRel(dir, rel string) string {
	switch {
	case rel == "":
		return dir
	case strings.HasSuffix(dir, `\`):
		return dir + rel
	}
	return dir + `\` + rel
}
