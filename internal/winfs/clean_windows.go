package winfs

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/safety"
)

// Cleaner opens folders of the real file system for the deleter
// (fsx.Cleaner).
//
// Each folder is opened as an os.Root: every later operation names a path
// relative to that folder's handle, and Go refuses any path that leaves it,
// including through a junction or symbolic link (their targets are absolute
// paths, which os.Root treats as escapes). So even a folder swapped for a
// junction after it was checked can't lead the deleter elsewhere.
//
// Deleting needs no special privilege: COptimizer never enables
// SeRestorePrivilege or SeTakeOwnershipPrivilege, so Windows still checks each
// file's permissions.
type Cleaner struct{}

// Open implements fsx.Cleaner.
func (Cleaner) Open(path string) (fsx.Tree, error) {
	n, err := safety.Normalize(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	if windows.GetDriveType(windows.StringToUTF16Ptr(n[:3])) != windows.DRIVE_FIXED {
		return nil, &fs.PathError{Op: "open", Path: n, Err: fsx.ErrNotLocal}
	}
	root, err := os.OpenRoot(n)
	if err != nil {
		return nil, err
	}
	// Ask Windows where the folder it opened really is. A junction or link
	// on the way, a short (8.3) name or a SUBST drive all give another path.
	final, err := rootPath(root)
	if err != nil {
		root.Close()
		return nil, &fs.PathError{Op: "open", Path: n, Err: err}
	}
	if !strings.EqualFold(final, n) {
		root.Close()
		return nil, &fs.PathError{Op: "open", Path: n, Err: fsx.ErrLink}
	}
	return &tree{root: root, path: final}, nil
}

// rootPath returns the real, normalized path of the folder root has open.
func rootPath(root *os.Root) (string, error) {
	f, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return finalPath(windows.Handle(f.Fd()))
}

// finalPath returns the path of the open file or folder h, normalized.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return safety.Normalize(windows.UTF16ToString(buf[:n]))
		}
		buf = make([]uint16, n)
	}
}

// tree is a folder opened by Cleaner.
type tree struct {
	root *os.Root
	path string
}

func (t *tree) Path() string { return t.path }
func (t *tree) Close() error { return t.root.Close() }

// List lists the folder rel through the root's handle, so it can't be led
// out of the root either.
func (t *tree) List(rel string) ([]fsx.Entry, error) {
	name := rel
	if name == "" {
		name = "."
	}
	f, err := t.root.Open(name)
	if err != nil {
		return nil, classify(err)
	}
	defer f.Close()
	return listHandle(windows.Handle(f.Fd()), join(t.path, rel))
}

// Remove deletes the file or empty folder rel. os.Root opens it without
// following a link (so a link is removed, not its target), deletes read-only
// files too, and lets the deletion fail if another program has the file open
// without allowing that.
func (t *tree) Remove(rel string) error {
	if rel == "" {
		return errors.New("winfs: the open folder itself can't be removed through its own tree")
	}
	safety.GuardDelete(join(t.path, rel))
	return classify(t.root.Remove(rel))
}

// classify wraps errors the deleter tells apart.
func classify(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION), errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return errors.Join(fsx.ErrInUse, err)
	case strings.Contains(err.Error(), "path escapes from parent"):
		// os.Root's error for a path that leaves the root, which is what a
		// junction on the way does. Go doesn't export it.
		return errors.Join(fsx.ErrLink, err)
	}
	return err
}

func join(dir, name string) string {
	switch {
	case name == "":
		return dir
	case strings.HasSuffix(dir, `\`):
		return dir + name
	}
	return dir + `\` + name
}
