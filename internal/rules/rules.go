// Package rules turns a scan into findings: the known space hogs of
// docs/space-hogs.md found in it, big folders no rule explains, and folders
// that grew since an earlier scan. It only looks at the scan result and never
// reads the disk itself.
//
// Every location counts for at most one finding: the most specific pattern
// claims it first, and a broader pattern that covers it later only counts
// what is left. So findings never overlap and their sizes add up.
package rules

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/scan"
)

// Risk says what cleaning a finding costs. See docs/space-hogs.md.
type Risk string

const (
	Safe     Risk = "safe"     // regenerable: caches, temporary files, logs
	Moderate Risk = "moderate" // cleaning removes an ability or a way back
	Manual   Risk = "manual"   // personal data, or a choice only the user can make
	Info     Risk = "info"     // explains where space goes; nothing to reclaim
)

// Category groups findings as docs/space-hogs.md does.
type Category string

const (
	System   Category = "system"
	Updates  Category = "updates"
	Drivers  Category = "drivers"
	Virtual  Category = "virtual"
	Dev      Category = "dev"
	AI       Category = "ai"
	Browsers Category = "browsers"
	Apps     Category = "apps"
	Media    Category = "media"
	Games    Category = "games"
	Personal Category = "personal"
	Other    Category = "other"
)

// Rule describes one kind of space hog. Its texts live in
// web/i18n/rules.en.json under rule.<ID>.
type Rule struct {
	ID       string
	Category Category
	Risk     Risk
	// Folders and Files are patterns like `{LocalAppData}\npm-cache`: a
	// variable, then names that may contain * and ?. Files are looked up among
	// the scan's largest files.
	Folders, Files []string
	Min            int64 // report the finding only from this total size on
	ItemMin        int64 // list a single location only from this size on
	Unreadable     bool  // report the folder even when it couldn't be read

	// Action, if set, is how COptimizer can reclaim the space itself.
	Action *Action

	detect  func(ev *evaluation, r Rule) []Item // detectors beyond patterns
	stage   stage
	noTotal bool // the finding overlaps others, so it stays out of the totals
}

// ActionKind says how COptimizer carries out an action.
type ActionKind string

const (
	// Delete deletes the contents of the finding's folders, and its single
	// files, with the deleter (internal/clean).
	Delete ActionKind = "delete"
	// EmptyRecycleBin empties the user's Recycle Bin through Windows.
	EmptyRecycleBin ActionKind = "recycle-bin"
	// ComponentCleanup runs DISM /StartComponentCleanup, which removes
	// components that updates replaced.
	ComponentCleanup ActionKind = "component-cleanup"
	// DeliveryOptimization asks the Delivery Optimization service to delete
	// the update files it keeps to share with other PCs.
	DeliveryOptimization ActionKind = "delivery-optimization"
)

// Action is a way COptimizer can reclaim a finding's space itself. Its texts
// are action.<Kind>.* in web/i18n/en.json, plus an optional note for the rule,
// rule.<ID>.action, in web/i18n/rules.en.json.
type Action struct {
	Kind ActionKind `json:"kind"`
	// For Delete: Folders, if set, limits the finding's folders that are
	// cleaned to those matching these patterns (the rule's other folders need
	// their own tool). Include limits the files to those whose names match;
	// MinAge leaves what changed more recently; RemoveRoot removes each
	// folder itself too, for leftovers rather than caches.
	Folders    []string      `json:"-"`
	Include    []string      `json:"-"`
	MinAge     time.Duration `json:"-"`
	RemoveRoot bool          `json:"-"`
	// NeedsClosed are the programs (process names) that must not be running.
	NeedsClosed []string `json:"needsClosed,omitempty"`
	// Long actions take minutes and can't be stopped safely once started.
	Long bool `json:"long,omitempty"`
}

// Covers reports whether the action cleans the finding's location at path:
// every location, unless the action names its own folders.
func (a *Action) Covers(env Env, path string) bool {
	if a.Folders == nil {
		return true
	}
	segs := splitPath(path)
	for _, pat := range a.Folders {
		if matchSegs(splitPath(expandFor(env, pat, path)), segs) {
			return true
		}
	}
	return false
}

// expandFor fills in a pattern's variables for the location path, with the
// per-user ones taken from the profile path lies in.
func expandFor(env Env, pat, path string) string {
	home := "<none>" // no real name contains "<", so this matches nothing
	if env.Users != "" && len(path) > len(env.Users) && underAny(path, env.Users) {
		name, _, _ := strings.Cut(path[len(env.Users)+1:], `\`)
		home = env.Users + `\` + name
	}
	return strings.NewReplacer(
		"{SystemDrive}", env.SystemDrive, "{Windows}", env.Windows, "{ProgramData}", env.ProgramData,
		"{ProgramFiles}", env.ProgramFiles, "{ProgramFilesX86}", env.ProgramFilesX86, "{Users}", env.Users,
		"{Profile}", home, "{LocalAppData}", home+`\AppData\Local`, "{AppData}", home+`\AppData\Roaming`,
	).Replace(pat)
}

// stage orders the detectors: specific ones before the patterns, catch-alls
// after them.
type stage int

const (
	early stage = iota
	patterns
	late
	last
)

// Env is where Windows keeps things on this computer.
type Env struct {
	SystemDrive     string // `C:`
	Windows         string // `C:\Windows`
	ProgramData     string
	ProgramFiles    string
	ProgramFilesX86 string
	Users           string // `C:\Users`
	CurrentProfile  string // the profile of the user running the app; may be empty
}

// DefaultEnv is a standard installation on C:, with user's profile as the
// current one (if user isn't empty).
func DefaultEnv(user string) Env {
	e := Env{
		SystemDrive:     `C:`,
		Windows:         `C:\Windows`,
		ProgramData:     `C:\ProgramData`,
		ProgramFiles:    `C:\Program Files`,
		ProgramFilesX86: `C:\Program Files (x86)`,
		Users:           `C:\Users`,
	}
	if user != "" {
		e.CurrentProfile = e.Users + `\` + user
	}
	return e
}

// SystemEnv reads the folders from this computer's environment variables.
func SystemEnv() Env {
	e := DefaultEnv("")
	set := func(dst *string, name string) {
		if v := os.Getenv(name); v != "" {
			*dst = filepath.Clean(v)
		}
	}
	if v := os.Getenv("SystemDrive"); v != "" {
		e.SystemDrive = v // not Clean: it turns `D:` into `D:.`
	}
	set(&e.Windows, "SystemRoot")
	set(&e.ProgramData, "ProgramData")
	set(&e.ProgramFiles, "ProgramFiles")
	set(&e.ProgramFilesX86, "ProgramFiles(x86)")
	if public := os.Getenv("PUBLIC"); public != "" {
		e.Users = filepath.Dir(filepath.Clean(public))
	}
	set(&e.CurrentProfile, "USERPROFILE")
	e.SystemDrive = strings.TrimRight(e.SystemDrive, `\`)
	return e
}

// Item is one location of a finding.
type Item struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"` // "folder" or "file"
	Bytes      int64     `json:"bytes"`
	Files      int64     `json:"files,omitempty"`
	Newest     time.Time `json:"newest,omitzero"`
	Unreadable bool      `json:"unreadable,omitempty"` // couldn't be read, so its size is unknown
	Hint       string    `json:"hint,omitempty"`       // "cache" for unexplained folders named like one
	Current    int64     `json:"current,omitempty"`    // growth findings: the folder's size now (Bytes is the growth)
}

// Finding is a rule that matched, with where and how much.
type Finding struct {
	ID        string   `json:"id"`
	Category  Category `json:"category"`
	Risk      Risk     `json:"risk"`
	Bytes     int64    `json:"bytes"`
	Items     []Item   `json:"items"`
	MoreItems int      `json:"moreItems,omitempty"` // locations left out of Items
	Action    *Action  `json:"action,omitempty"`    // what COptimizer can do about it
}

// Report is everything Evaluate found.
type Report struct {
	Findings    []Finding      `json:"findings"` // largest first
	Totals      map[Risk]int64 `json:"totals"`
	GrowthSince time.Time      `json:"growthSince,omitzero"` // when the scan compared with was taken

	all     map[string][]Item // every location of every finding, Items or not
	claimed map[string]bool   // findings whose locations count for no other finding
}

// Find returns the finding with the given ID.
func (r Report) Find(id string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// Locations returns every location of the finding id, largest first,
// including those left out of its Items.
func (r Report) Locations(id string) []Item { return r.all[id] }

// ClaimedInside returns the locations of other findings that lie inside
// folder: a cleanup of folder must leave them to their own finding. Findings
// that only overlap others, like growth, don't count.
func (r Report) ClaimedInside(id, folder string) []string {
	var out []string
	for other, items := range r.all {
		if other == id || !r.claimed[other] {
			continue
		}
		for _, it := range items {
			if len(it.Path) > len(folder) && underAny(it.Path, folder) {
				out = append(out, it.Path)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Options tunes Evaluate.
type Options struct {
	Previous     []Snapshot // earlier scans of the same drives, for growth
	Unrecognized int64      // size from which an unexplained folder is reported; 0 means 1 GiB
	Growth       int64      // growth from which a folder is reported; 0 means 512 MiB
}

const (
	mb = int64(1) << 20
	gb = int64(1) << 30

	maxItems = 50
)

// Evaluate finds the space hogs in res.
func Evaluate(res *scan.Result, env Env, opts Options) Report {
	if opts.Unrecognized <= 0 {
		opts.Unrecognized = gb
	}
	if opts.Growth <= 0 {
		opts.Growth = 512 * mb
	}
	ev := newEvaluation(res, env, opts)
	found := make(map[string][]Item)
	for _, st := range []stage{early, patterns, late, last} {
		if st == patterns {
			for _, p := range ev.patterns() {
				found[p.rule.ID] = append(found[p.rule.ID], ev.apply(p)...)
			}
			continue
		}
		for _, r := range catalog {
			if r.detect != nil && r.stage == st {
				found[r.ID] = append(found[r.ID], r.detect(ev, r)...)
			}
		}
	}

	rep := Report{Totals: map[Risk]int64{Safe: 0, Moderate: 0, Manual: 0, Info: 0},
		all: make(map[string][]Item), claimed: make(map[string]bool)}
	for _, r := range catalog {
		items := found[r.ID]
		var total int64
		unreadable := false
		for _, it := range items {
			total += it.Bytes
			unreadable = unreadable || it.Unreadable
		}
		slices.SortStableFunc(items, func(a, b Item) int { return cmpBytes(a.Bytes, b.Bytes, a.Path, b.Path) })
		if len(items) > 0 {
			// Kept even when too small to report: a cleanup of a broader
			// folder must still leave these locations alone.
			rep.all[r.ID], rep.claimed[r.ID] = items, !r.noTotal
		}
		if len(items) == 0 || (total < r.Min && !(r.Unreadable && unreadable)) {
			continue
		}
		f := Finding{ID: r.ID, Category: r.Category, Risk: r.Risk, Bytes: total, Items: items, Action: r.Action}
		if len(items) > maxItems {
			f.Items, f.MoreItems = items[:maxItems], len(items)-maxItems
		}
		rep.Findings = append(rep.Findings, f)
		if !r.noTotal {
			rep.Totals[r.Risk] += total
		}
	}
	slices.SortStableFunc(rep.Findings, func(a, b Finding) int { return cmpBytes(a.Bytes, b.Bytes, a.ID, b.ID) })
	rep.GrowthSince = ev.growthSince
	return rep
}

// cmpBytes orders larger sizes first, then by name.
func cmpBytes(a, b int64, an, bn string) int {
	switch {
	case a > b:
		return -1
	case a < b:
		return 1
	}
	return strings.Compare(an, bn)
}

// Rules returns the catalog, for tests and documentation.
func Rules() []Rule { return slices.Clone(catalog) }
