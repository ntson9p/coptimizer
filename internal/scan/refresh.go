package scan

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// Refresh measures the folders at paths again, after a cleanup, and returns a
// copy of res with their new contents and every total above them updated. res
// itself doesn't change, so readers of it are never disturbed. Folders that
// are gone are removed from the copy; paths the scan never saw are ignored.
//
// Each folder is measured on its own, so a file hard-linked from outside it
// counts in full there. That suits caches and temporary folders; folders full
// of shared files, like WinSxS, need a new scan of the whole drive. The
// totals by file type stay as they were.
func Refresh(ctx context.Context, l fsx.Lister, res *Result, paths []string) (*Result, error) {
	out := res.clone()
	for _, p := range paths {
		n := out.Find(p)
		if n == nil || n.Link {
			continue
		}
		path := n.Path()
		out.Largest = slices.DeleteFunc(out.Largest, func(f File) bool { return within(f.Path, path) })
		if _, err := l.List(path); errors.Is(err, fs.ErrNotExist) && n.Parent != nil {
			n.Parent.Children = slices.DeleteFunc(n.Parent.Children, func(c *Node) bool { return c == n })
			continue
		}
		fresh, err := Run(ctx, l, Options{Roots: []string{path}, TopFiles: max(len(res.Largest), 1)})
		if err != nil {
			return nil, err
		}
		root := fresh.Roots[0]
		n.Children = root.Children
		for _, c := range n.Children {
			c.Parent = n
		}
		n.OwnSize, n.OwnAllocated, n.OwnFiles, n.ownNewest = root.OwnSize, root.OwnAllocated, root.OwnFiles, root.ownNewest
		n.Denied = root.Denied
		out.Largest = append(out.Largest, fresh.Largest...)
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
