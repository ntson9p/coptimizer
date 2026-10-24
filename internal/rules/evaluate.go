package rules

import (
	"slices"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/scan"
)

// evaluation is the state of one Evaluate call: which locations are already
// claimed by a finding.
type evaluation struct {
	res         *scan.Result
	env         Env
	opts        Options
	profiles    []*scan.Node
	claimed     map[*scan.Node]bool
	inside      map[*scan.Node]int64 // bytes claimed below a folder
	files       map[string]bool      // claimed files, upper-case paths
	growthSince time.Time
}

// notProfiles are folders in C:\Users that aren't anyone's profile.
var notProfiles = []string{"Default", "Default User", "Public", "All Users"}

func newEvaluation(res *scan.Result, env Env, opts Options) *evaluation {
	ev := &evaluation{
		res: res, env: env, opts: opts,
		claimed: make(map[*scan.Node]bool),
		inside:  make(map[*scan.Node]int64),
		files:   make(map[string]bool),
	}
	if users := ev.find(env.Users); users != nil {
		for _, c := range users.Children {
			if !c.Link && !slices.ContainsFunc(notProfiles, func(s string) bool { return strings.EqualFold(s, c.Name) }) {
				ev.profiles = append(ev.profiles, c)
			}
		}
	}
	return ev
}

// find returns the scanned folder at path, or nil.
func (ev *evaluation) find(path string) *scan.Node {
	if path == "" {
		return nil
	}
	return ev.res.Find(path)
}

// pattern is one expanded pattern of a rule.
type pattern struct {
	rule  *Rule
	segs  []string
	file  bool
	order int
}

// patterns expands every rule's patterns, most specific first: deeper
// patterns, then those with fewer wildcards, then catalog order.
func (ev *evaluation) patterns() []pattern {
	var out []pattern
	for i := range catalog {
		r := &catalog[i]
		for _, list := range []struct {
			pats []string
			file bool
		}{{r.Folders, false}, {r.Files, true}} {
			for _, p := range list.pats {
				for _, e := range ev.expand(p) {
					out = append(out, pattern{rule: r, segs: splitPath(e), file: list.file, order: i})
				}
			}
		}
	}
	slices.SortStableFunc(out, func(a, b pattern) int {
		if d := len(b.segs) - len(a.segs); d != 0 {
			return d
		}
		if d := wildcards(a.segs) - wildcards(b.segs); d != 0 {
			return d
		}
		return a.order - b.order
	})
	return out
}

func wildcards(segs []string) int {
	n := 0
	for _, s := range segs {
		if strings.ContainsAny(s, "*?") {
			n++
		}
	}
	return n
}

// expand fills in the variables of p. A per-user pattern expands once per
// profile; a pattern whose variable is unknown expands to nothing.
func (ev *evaluation) expand(p string) []string {
	sys := strings.NewReplacer(
		"{SystemDrive}", ev.env.SystemDrive,
		"{Windows}", ev.env.Windows,
		"{ProgramData}", ev.env.ProgramData,
		"{ProgramFiles}", ev.env.ProgramFiles,
		"{ProgramFilesX86}", ev.env.ProgramFilesX86,
		"{Users}", ev.env.Users,
	)
	variable := p[:strings.IndexByte(p, '}')+1]
	switch variable {
	case "{Profile}", "{LocalAppData}", "{AppData}":
		var out []string
		for _, prof := range ev.profiles {
			home := prof.Path()
			out = append(out, strings.NewReplacer(
				"{Profile}", home,
				"{LocalAppData}", home+`\AppData\Local`,
				"{AppData}", home+`\AppData\Roaming`,
			).Replace(p))
		}
		return out
	}
	e := sys.Replace(p)
	if strings.HasPrefix(e, `\`) || strings.Contains(e, "{") {
		return nil // the variable was empty or unknown
	}
	return []string{e}
}

// apply claims what pattern p matches and returns the items.
func (ev *evaluation) apply(p pattern) []Item {
	var items []Item
	if p.file {
		for _, f := range ev.res.Largest {
			if matchSegs(p.segs, splitPath(f.Path)) {
				if it, ok := ev.claimFile(f, p.rule.ItemMin); ok {
					items = append(items, it)
				}
			}
		}
		return items
	}
	for _, n := range ev.matchFolders(p.segs) {
		if it, ok := ev.claimFolder(n, p.rule.ItemMin, p.rule.Unreadable); ok {
			items = append(items, it)
		}
	}
	return items
}

// matchFolders returns the scanned folders that match segs.
func (ev *evaluation) matchFolders(segs []string) []*scan.Node {
	var out []*scan.Node
	for _, root := range ev.res.Roots {
		rs := splitPath(root.Name)
		if len(segs) < len(rs) || !matchSegs(segs[:len(rs)], rs) {
			continue
		}
		cur := []*scan.Node{root}
		for _, seg := range segs[len(rs):] {
			var next []*scan.Node
			for _, n := range cur {
				for _, c := range n.Children {
					if !c.Link && matchName(seg, c.Name) {
						next = append(next, c)
					}
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return out
}

// claimFolder claims n for a finding, unless it is already claimed or is
// inside a claimed folder. What deeper findings claimed inside n doesn't count
// again.
func (ev *evaluation) claimFolder(n *scan.Node, itemMin int64, unreadableOK bool) (Item, bool) {
	if ev.isClaimed(n) {
		return Item{}, false
	}
	bytes := n.Allocated - ev.inside[n]
	unreadable := n.Denied && n.Allocated == 0
	if !(unreadable && unreadableOK) && (bytes <= 0 || bytes < itemMin) {
		return Item{}, false
	}
	ev.claimed[n] = true
	for a := n.Parent; a != nil; a = a.Parent {
		ev.inside[a] += bytes
	}
	return Item{Path: n.Path(), Kind: "folder", Bytes: bytes, Files: n.Files, Newest: n.Newest, Unreadable: unreadable}, true
}

// claimFile claims one of the scan's largest files.
func (ev *evaluation) claimFile(f scan.File, itemMin int64) (Item, bool) {
	key := strings.ToUpper(f.Path)
	if ev.files[key] || f.Allocated <= 0 || f.Allocated < itemMin {
		return Item{}, false
	}
	dir := ev.res.Find(f.Path[:strings.LastIndexByte(f.Path, '\\')+1])
	if dir != nil && ev.isClaimed(dir) {
		return Item{}, false
	}
	ev.files[key] = true
	for a := dir; a != nil; a = a.Parent {
		ev.inside[a] += f.Allocated
	}
	return Item{Path: f.Path, Kind: "file", Bytes: f.Allocated, Newest: f.Modified}, true
}

func (ev *evaluation) isClaimed(n *scan.Node) bool {
	for a := n; a != nil; a = a.Parent {
		if ev.claimed[a] {
			return true
		}
	}
	return false
}

// unexplained is the part of n that no finding claimed.
func (ev *evaluation) unexplained(n *scan.Node) int64 {
	if ev.isClaimed(n) {
		return 0
	}
	return n.Allocated - ev.inside[n]
}

// isFileClaimed reports whether f was claimed, itself or through its folder.
func (ev *evaluation) isFileClaimed(f scan.File) bool {
	if ev.files[strings.ToUpper(f.Path)] {
		return true
	}
	dir := ev.res.Find(f.Path[:strings.LastIndexByte(f.Path, '\\')+1])
	return dir != nil && ev.isClaimed(dir)
}

// underAny reports whether path is one of dirs or inside one, ignoring case.
func underAny(path string, dirs ...string) bool {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if len(path) >= len(d) && strings.EqualFold(path[:len(d)], d) &&
			(len(path) == len(d) || path[len(d)] == '\\' || strings.HasSuffix(d, `\`)) {
			return true
		}
	}
	return false
}

// splitPath splits `C:\a\b` into "C:", "a", "b".
func splitPath(p string) []string {
	return strings.Split(strings.Trim(p, `\`), `\`)
}

func matchSegs(pat, segs []string) bool {
	if len(pat) != len(segs) {
		return false
	}
	for i := range pat {
		if !matchName(pat[i], segs[i]) {
			return false
		}
	}
	return true
}

// matchName matches a name against a pattern segment, ignoring case. The
// segment may contain * (any run of characters) and ? (one character).
func matchName(pat, name string) bool {
	if !strings.ContainsAny(pat, "*?") {
		return strings.EqualFold(pat, name)
	}
	return glob([]rune(strings.ToLower(pat)), []rune(strings.ToLower(name)))
}

func glob(p, s []rune) bool {
	star, mark := -1, 0
	i, j := 0, 0
	for j < len(s) {
		switch {
		case i < len(p) && (p[i] == '?' || p[i] == s[j]):
			i++
			j++
		case i < len(p) && p[i] == '*':
			star, mark = i, j
			i++
		case star >= 0:
			i = star + 1
			mark++
			j = mark
		default:
			return false
		}
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	return i == len(p)
}
