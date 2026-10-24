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

	detect  func(ev *evaluation, r Rule) []Item // detectors beyond patterns
	stage   stage
	noTotal bool // the finding overlaps others, so it stays out of the totals
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
}

// Report is everything Evaluate found.
type Report struct {
	Findings    []Finding      `json:"findings"` // largest first
	Totals      map[Risk]int64 `json:"totals"`
	GrowthSince time.Time      `json:"growthSince,omitzero"` // when the scan compared with was taken
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

	rep := Report{Totals: map[Risk]int64{Safe: 0, Moderate: 0, Manual: 0, Info: 0}}
	for _, r := range catalog {
		items := found[r.ID]
		var total int64
		unreadable := false
		for _, it := range items {
			total += it.Bytes
			unreadable = unreadable || it.Unreadable
		}
		if len(items) == 0 || (total < r.Min && !(r.Unreadable && unreadable)) {
			continue
		}
		slices.SortStableFunc(items, func(a, b Item) int { return cmpBytes(a.Bytes, b.Bytes, a.Path, b.Path) })
		f := Finding{ID: r.ID, Category: r.Category, Risk: r.Risk, Bytes: total, Items: items}
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
