package rules

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/scan"
)

// Detectors for findings that patterns can't express.

// nodeModules finds node_modules folders in projects: anywhere except AppData,
// the Recycle Bin and the system folders. It runs before the patterns, so a
// project's node_modules counts here rather than inside "Documents".
func nodeModules(ev *evaluation, r Rule) []Item {
	skip := make(map[*scan.Node]bool)
	for _, p := range []string{ev.env.Windows, ev.env.ProgramFiles, ev.env.ProgramFilesX86, ev.env.ProgramData} {
		if n := ev.find(p); n != nil {
			skip[n] = true
		}
	}
	var items []Item
	var walk func(n *scan.Node)
	walk = func(n *scan.Node) {
		for _, c := range n.Children {
			switch {
			case c.Link || skip[c] || strings.EqualFold(c.Name, "AppData") || strings.EqualFold(c.Name, "$Recycle.Bin"):
			case strings.EqualFold(c.Name, "node_modules"):
				if it, ok := ev.claimFolder(c, r.ItemMin, false); ok {
					items = append(items, it)
				}
			default:
				walk(c)
			}
		}
	}
	for _, root := range ev.res.Roots {
		walk(root)
	}
	return items
}

// otherAccounts reports the profiles of other users: what is left of them
// after the per-user rules took their caches.
func otherAccounts(ev *evaluation, r Rule) []Item {
	if ev.env.CurrentProfile == "" {
		return nil
	}
	var items []Item
	for _, p := range ev.profiles {
		if strings.EqualFold(p.Path(), ev.env.CurrentProfile) {
			continue
		}
		if it, ok := ev.claimFolder(p, r.ItemMin, false); ok {
			items = append(items, it)
		}
	}
	return items
}

// bigLogs reports huge log and trace files that no other finding covers.
func bigLogs(ev *evaluation, r Rule) []Item {
	var items []Item
	for _, f := range ev.res.Largest {
		if ext := strings.ToLower(filepath.Ext(f.Path)); ext != ".log" && ext != ".etl" {
			continue
		}
		if it, ok := ev.claimFile(f, r.ItemMin); ok {
			items = append(items, it)
		}
	}
	return items
}

// bigFiles reports big files that no other finding covers, outside the
// folders of Windows and installed programs.
func bigFiles(ev *evaluation, r Rule) []Item {
	var items []Item
	for _, f := range ev.res.Largest {
		if underAny(f.Path, ev.env.Windows, ev.env.ProgramFiles, ev.env.ProgramFilesX86, ev.env.ProgramData) {
			continue
		}
		if it, ok := ev.claimFile(f, r.ItemMin); ok {
			items = append(items, it)
		}
	}
	return items
}

// unrecognized reports the folders that hold at least opts.Unrecognized bytes
// no finding explains, as deep in the tree as possible. General folders like a
// profile or AppData are never reported themselves, only folders inside them.
func unrecognized(ev *evaluation, r Rule) []Item {
	min := ev.opts.Unrecognized
	containers := ev.containers()
	var items []Item
	// visit returns how many unexplained bytes it reported at or below n.
	var visit func(n *scan.Node) int64
	visit = func(n *scan.Node) int64 {
		var below int64
		for _, c := range n.Children {
			if !c.Link && ev.unexplained(c) >= min {
				below += visit(c)
			}
		}
		rest := ev.unexplained(n) - below
		if containers[n] || rest < min {
			return below
		}
		items = append(items, Item{Path: n.Path(), Kind: "folder", Bytes: rest, Files: n.Files, Newest: n.Newest, Hint: cacheHint(n.Name)})
		return below + rest
	}
	for _, root := range ev.res.Roots {
		if ev.unexplained(root) >= min {
			visit(root)
		}
	}
	return items
}

// containers are general folders that only hold other things: drive roots,
// C:\Users, each profile and its AppData folders, ProgramData, Program Files.
func (ev *evaluation) containers() map[*scan.Node]bool {
	m := make(map[*scan.Node]bool)
	add := func(p string) {
		if n := ev.find(p); n != nil {
			m[n] = true
		}
	}
	for _, r := range ev.res.Roots {
		m[r] = true
	}
	for _, p := range []string{ev.env.Users, ev.env.ProgramData, ev.env.ProgramFiles, ev.env.ProgramFilesX86, ev.env.Windows} {
		add(p)
	}
	add(ev.env.Users + `\Public`)
	add(ev.env.ProgramData + `\Microsoft`)
	for _, prof := range ev.profiles {
		m[prof] = true
		home := prof.Path()
		for _, sub := range []string{`AppData`, `AppData\Local`, `AppData\Roaming`, `AppData\LocalLow`,
			`AppData\Local\Packages`, `AppData\Local\Programs`, `AppData\Local\Microsoft`, `AppData\Roaming\Microsoft`} {
			add(home + `\` + sub)
		}
	}
	return m
}

// cacheHint flags folder names that suggest regenerable data.
func cacheHint(name string) string {
	n := strings.ToLower(name)
	for _, w := range []string{"cache", "temp", "tmp", "log", "crash", "dump", "shader"} {
		if strings.Contains(n, w) {
			return "cache"
		}
	}
	return ""
}

// growth compares the scan with earlier snapshots of the same drives and
// reports the folders that grew by at least opts.Growth bytes, as deep in the
// tree as possible. Each item's Bytes is the growth; Current is its size now.
func growth(ev *evaluation, r Rule) []Item {
	min := ev.opts.Growth
	var items []Item
	for _, s := range ev.opts.Previous {
		var root *scan.Node
		for _, n := range ev.res.Roots {
			if strings.EqualFold(n.Name, s.Root) {
				root = n
			}
		}
		if root == nil {
			continue
		}
		if ev.growthSince.IsZero() || s.Time.Before(ev.growthSince) {
			ev.growthSince = s.Time
		}
		// visit returns how much growth it reported at or below n.
		var visit func(n *scan.Node, path string) int64
		visit = func(n *scan.Node, path string) int64 {
			grew := n.Allocated - s.Folders[path]
			if grew < min {
				return 0
			}
			var below int64
			for _, c := range n.Children {
				if !c.Link {
					below += visit(c, join(path, c.Name))
				}
			}
			if rest := grew - below; rest >= min {
				items = append(items, Item{Path: path, Kind: "folder", Bytes: rest, Current: n.Allocated, Files: n.Files, Newest: n.Newest})
				return grew
			}
			return below
		}
		visit(root, root.Name)
	}
	return items
}

// Snapshot is the folder sizes of one scanned drive, kept to compare later
// scans with.
type Snapshot struct {
	Root     string           `json:"root"`
	Time     time.Time        `json:"time"`
	Elevated bool             `json:"elevated"` // taken with Administrator rights, which see more folders
	Folders  map[string]int64 `json:"folders"`  // path → bytes on disk, for folders of SnapshotMin or more
}

// SnapshotMin is the smallest folder a snapshot keeps.
const SnapshotMin = 50 * mb

// TakeSnapshot records the folders under root that hold SnapshotMin or more.
func TakeSnapshot(root *scan.Node, t time.Time, elevated bool) Snapshot {
	s := Snapshot{Root: root.Name, Time: t, Elevated: elevated, Folders: make(map[string]int64)}
	var walk func(n *scan.Node, path string)
	walk = func(n *scan.Node, path string) {
		if n.Allocated < SnapshotMin {
			return
		}
		s.Folders[path] = n.Allocated
		for _, c := range n.Children {
			if !c.Link {
				walk(c, join(path, c.Name))
			}
		}
	}
	walk(root, root.Name)
	return s
}

func join(dir, name string) string {
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}
