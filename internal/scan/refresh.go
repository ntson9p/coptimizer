package scan

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// Refresh measures again, after a cleanup, the folders and single files at
// paths, and returns a copy of res with their new contents and every total
// above them updated. res itself doesn't change, so readers of it are never
// disturbed. Paths the scan never saw are ignored.
//
// A folder is first looked up in its parent's listing, as a scan would meet
// it: one that is gone is removed, and one that has become a junction or link
// is kept as a link and never measured through. A single file is only checked
// for whether it is gone.
//
// Each folder is measured on its own, so a file hard-linked from outside it
// counts in full there. That suits caches and temporary folders; folders full
// of shared files, like WinSxS, need a new scan of the whole drive. The
// totals by file type, of hard links and of online-only files stay as they
// were.
func Refresh(ctx context.Context, l fsx.Lister, res *Result, paths []string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err // shutting down: don't copy the whole tree for nothing
	}
	out := res.clone()
	for _, p := range paths {
		if n := out.Find(p); n != nil {
			if err := refreshFolder(ctx, l, out, n, len(res.Largest)); err != nil {
				return nil, err
			}
			continue
		}
		refreshFile(l, out, p)
	}
	slices.SortFunc(out.Largest, func(a, b File) int {
		switch {
		case a.Allocated > b.Allocated:
			return -1
		case a.Allocated < b.Allocated:
			return 1
		}
		return strings.Compare(a.Path, b.Path)
	})
	if len(out.Largest) > len(res.Largest) {
		out.Largest = out.Largest[:len(res.Largest)]
	}
	out.Size, out.Allocated, out.Files, out.Folders = 0, 0, 0, 0
	for _, root := range out.Roots {
		total(root)
		out.Size += root.Size
		out.Allocated += root.Allocated
		out.Files += root.Files
		out.Folders += root.Folders
	}
	return out, nil
}

// refreshFolder measures the folder n of out again.
func refreshFolder(ctx context.Context, l fsx.Lister, out *Result, n *Node, topFiles int) error {
	if n.Link {
		return nil
	}
	path := n.Path()
	out.Largest = slices.DeleteFunc(out.Largest, func(f File) bool { return within(f.Path, path) })
	if n.Parent != nil {
		e, found, err := lookup(l, n.Parent.Path(), n.Name)
		switch {
		case err != nil:
			// The parent can't be listed: measure the folder itself.
		case !found || !e.IsDir():
			n.Parent.Children = slices.DeleteFunc(n.Parent.Children, func(c *Node) bool { return c == n })
			return nil
		case e.IsReparse():
			// Kept as a scan meets a link: listed, never followed.
			n.Link, n.Denied, n.Children = true, false, nil
			n.OwnSize, n.OwnAllocated, n.OwnFiles, n.ownNewest = 0, 0, 0, time.Time{}
			return nil
		}
	}
	fresh, err := Run(ctx, l, Options{Roots: []string{path}, TopFiles: max(topFiles, 1)})
	if err != nil {
		return err
	}
	root := fresh.Roots[0]
	n.Children = root.Children
	for _, c := range n.Children {
		c.Parent = n
	}
	n.OwnSize, n.OwnAllocated, n.OwnFiles, n.ownNewest = root.OwnSize, root.OwnAllocated, root.OwnFiles, root.ownNewest
	n.Denied = root.Denied
	out.Largest = append(out.Largest, fresh.Largest...)
	return nil
}

// refreshFile checks whether the single file at path, one of the scan's
// largest files, is gone; if so it leaves the list, and its size leaves its
// folder.
func refreshFile(l fsx.Lister, out *Result, path string) {
	i := slices.IndexFunc(out.Largest, func(f File) bool { return strings.EqualFold(f.Path, path) })
	cut := strings.LastIndexByte(path, '\\')
	if i < 0 || cut < 0 {
		return
	}
	dirPath := path[:cut]
	if cut == 2 {
		dirPath = path[:3] // a file at a drive root
	}
	dir := out.Find(dirPath)
	if dir == nil {
		return
	}
	if _, found, err := lookup(l, dirPath, path[cut+1:]); err != nil || found {
		return // still there, or it can't be told
	}
	f := out.Largest[i]
	out.Largest = slices.Delete(out.Largest, i, i+1)
	dir.OwnSize -= f.Size
	dir.OwnAllocated -= f.Allocated
	dir.OwnFiles--
}

// lookup finds the entry called name in the folder dir.
func lookup(l fsx.Lister, dir, name string) (fsx.Entry, bool, error) {
	entries, err := l.List(dir)
	if err != nil {
		return fsx.Entry{}, false, err
	}
	for _, e := range entries {
		if strings.EqualFold(e.Name, name) {
			return e, true, nil
		}
	}
	return fsx.Entry{}, false, nil
}

// clone copies the result deeply enough that Refresh can change the copy.
func (r *Result) clone() *Result {
	c := *r
	c.Roots = make([]*Node, len(r.Roots))
	for i, n := range r.Roots {
		c.Roots[i] = cloneNode(n, nil)
	}
	c.Largest = slices.Clone(r.Largest)
	c.Types = slices.Clone(r.Types)
	c.Denied = slices.Clone(r.Denied)
	return &c
}

func cloneNode(n, parent *Node) *Node {
	c := *n
	c.Parent = parent
	c.Children = make([]*Node, len(n.Children))
	for i, ch := range n.Children {
		c.Children[i] = cloneNode(ch, &c)
	}
	return &c
}

// within reports whether file lies inside the folder dir.
func within(file, dir string) bool {
	prefix := strings.TrimSuffix(dir, `\`) + `\`
	return len(file) > len(prefix) && strings.EqualFold(file[:len(prefix)], prefix)
}
