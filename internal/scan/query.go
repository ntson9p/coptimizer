package scan

import "strings"

// Path returns the full path of n.
func (n *Node) Path() string {
	if n.Parent == nil {
		return n.Name
	}
	return join(n.Parent.Path(), n.Name)
}

// Find returns the folder at path, or nil if the scan has no such folder.
// Names match exactly first, then ignoring ASCII case.
func (r *Result) Find(path string) *Node {
	for _, root := range r.Roots {
		rest, ok := cutPrefixFold(path, root.Name)
		if !ok {
			continue
		}
		n := root
		for _, name := range strings.Split(strings.Trim(rest, `\`), `\`) {
			if name == "" {
				continue
			}
			if n = n.child(name); n == nil {
				return nil
			}
		}
		return n
	}
	return nil
}

// LargestUnder returns up to limit of the largest files kept by the scan that
// lie inside the folder at path.
func (r *Result) LargestUnder(path string, limit int) []File {
	prefix := strings.TrimSuffix(path, `\`) + `\`
	var out []File
	for _, f := range r.Largest {
		if len(out) == limit {
			break
		}
		if len(f.Path) > len(prefix) && strings.EqualFold(f.Path[:len(prefix)], prefix) {
			out = append(out, f)
		}
	}
	return out
}

func (n *Node) child(name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

// cutPrefixFold is strings.CutPrefix ignoring case, where prefix must end at a
// path separator boundary.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	rest := s[len(prefix):]
	if rest != "" && !strings.HasSuffix(prefix, `\`) && rest[0] != '\\' {
		return "", false
	}
	return rest, true
}
