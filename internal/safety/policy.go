package safety

import (
	"errors"
	"fmt"
	"strings"
)

// Policy is the deny list of docs/plan.md, section 5.2: what COptimizer never
// deletes, whatever a rule asks for. The deleter checks it for every folder it
// cleans and every file it deletes, so a mistake in a rule can't reach
// Windows, installed programs or personal files.
//
// It has three kinds of entries:
//
//   - trees: nothing at or below them may be deleted (Windows, Program Files,
//     Documents…),
//   - exceptions: folders inside a tree that may be cleaned after all
//     (C:\Windows\Temp…). An exception only counts against a shallower tree,
//     so a personal folder that happens to lie inside an exception stays
//     protected,
//   - exact folders: general folders that may not be deleted or emptied
//     themselves, though some folders inside them may (C:\Users, a profile,
//     AppData\Local…).
//
// Drive roots are always refused. Adding an exception is a security-relevant
// change: review it as one.
type Policy struct {
	trees, allow, exact []pathPattern
}

// pathPattern is a path whose names may be "*" (any one name) or end in "*"
// (any name starting with the rest).
type pathPattern struct {
	segs []string
	why  string
}

// Places tells the policy where Windows keeps things on this computer.
type Places struct {
	SystemDrive     string // `C:`
	Windows         string // `C:\Windows`
	ProgramData     string
	ProgramFiles    string
	ProgramFilesX86 string
	Users           string // `C:\Users`
	// KnownFolders are the user's Desktop, Documents, Downloads… wherever
	// they have been moved. Paths that aren't local drive paths are ignored:
	// nothing on them can be deleted anyway.
	KnownFolders []string
}

// personalFolders are the folders of a profile that hold the user's own
// files.
var personalFolders = []string{
	"Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music", "Favorites", "Contacts",
	"Links", "Saved Games", "Searches", "3D Objects", "OneDrive*",
}

// NewPolicy builds the deny list for a computer. It fails if a place is
// missing or isn't a local drive path: without them nothing is protected.
func NewPolicy(pl Places) (*Policy, error) {
	drive := pl.SystemDrive
	if !strings.HasSuffix(drive, `\`) {
		drive += `\`
	}
	places := map[string]*string{
		"the system drive": &drive, "Windows": &pl.Windows, "ProgramData": &pl.ProgramData,
		"Program Files": &pl.ProgramFiles, "Program Files (x86)": &pl.ProgramFilesX86, "Users": &pl.Users,
	}
	for name, p := range places {
		n, err := Normalize(*p)
		if err != nil {
			return nil, fmt.Errorf("policy: %s: %w", name, err)
		}
		*p = n
	}
	win, pd, pf, pf86, users := pl.Windows, pl.ProgramData, pl.ProgramFiles, pl.ProgramFilesX86, pl.Users
	p := &Policy{}
	tree := func(why, base string, names ...string) { p.trees = append(p.trees, pattern(why, base, names...)) }
	allow := func(base string, names ...string) { p.allow = append(p.allow, pattern("", base, names...)) }
	exact := func(why, base string, names ...string) { p.exact = append(p.exact, pattern(why, base, names...)) }

	tree("it belongs to Windows", win)
	tree("it belongs to an installed program", pf)
	tree("it belongs to an installed program", pf86)
	tree("programs need it to be repaired and uninstalled", pd, "Package Cache")
	tree("it holds the restore points", drive, "System Volume Information")
	tree("the Recycle Bin is emptied only through Windows", drive, "$Recycle.Bin")
	tree("it belongs to the recovery environment", drive, "Recovery")
	tree("it belongs to the recovery environment", drive, "$WinREAgent")
	tree("the previous Windows installation is removed only through Windows", drive, "Windows.old*")
	tree("an upgrade may still need it", drive, "$Windows.~BT")
	tree("an upgrade may still need it", drive, "$Windows.~WS")
	tree("it holds files shared by every account", users, "Public")
	tree("new accounts are created from it", users, "Default")
	tree("new accounts are created from it", users, "Default User")
	tree("it is a link to ProgramData", users, "All Users")
	for _, name := range personalFolders {
		tree("it holds personal files", users, "*", name)
	}
	for _, kf := range pl.KnownFolders {
		if n, err := Normalize(kf); err == nil {
			tree("it holds personal files", n)
		}
	}

	// The only folders inside the trees above that may be cleaned. Each is
	// used by an action in the rule catalog.
	allow(win, "Temp")
	allow(win, "SystemTemp")
	allow(win, "Logs", "CBS")
	allow(win, "Logs", "DISM")
	allow(win, "Minidump")
	allow(win, "LiveKernelReports")
	allow(win, "MEMORY.DMP")
	for _, steam := range []string{pf86, pf} {
		allow(steam, "Steam", "steamapps", "shadercache")
		allow(steam, "Steam", "steamapps", "temp")
	}
	allow(pf86, "Steam", "dumps")
	allow(pf86, "Epic Games", "Launcher", "VaultCache")

	exact("it holds every account", users)
	exact("it is an account's profile", users, "*")
	for _, sub := range [][]string{{"AppData"}, {"AppData", "Local"}, {"AppData", "LocalLow"}, {"AppData", "Roaming"},
		{"AppData", "Local", "Microsoft"}, {"AppData", "Roaming", "Microsoft"}, {"AppData", "Local", "Packages"},
		{"AppData", "Local", "Programs"}} {
		exact("it holds the settings and data of many programs", users, append([]string{"*"}, sub...)...)
	}
	exact("it holds the data of many programs", pd)
	exact("it holds the data of many programs", pd, "Microsoft")
	exact("it holds the data of many programs", pd, "Microsoft", "Windows")
	return p, nil
}

// pattern makes a pathPattern from a normalized base path and further names.
func pattern(why, base string, names ...string) pathPattern {
	return pathPattern{segs: append(segments(base), names...), why: why}
}

// ErrRefused is wrapped by every error Check returns.
var ErrRefused = errors.New("refused by the safety policy")

// Check returns nil if the file or folder at path may be deleted (or, for a
// folder, emptied), or an error wrapping ErrRefused that says why not.
func (p *Policy) Check(path string) error {
	n, err := Normalize(path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRefused, err)
	}
	segs := segments(n)
	if len(segs) == 1 {
		return refused(n, "it is a drive root")
	}
	// Protected folders compare ignoring case in every script, so that a
	// spelling Windows treats as the same folder is caught. Exceptions
	// compare ignoring ASCII case only: when in doubt, refuse.
	for _, e := range p.exact {
		if len(e.segs) == len(segs) && e.matchPrefix(segs, strings.EqualFold) {
			return refused(n, e.why)
		}
	}
	for _, t := range p.trees {
		if len(segs) < len(t.segs) || !t.matchPrefix(segs, strings.EqualFold) {
			continue
		}
		excepted := false
		for _, a := range p.allow {
			if len(a.segs) > len(t.segs) && len(segs) >= len(a.segs) && a.matchPrefix(segs, equalFoldASCII) {
				excepted = true
				break
			}
		}
		if !excepted {
			return refused(n, t.why)
		}
	}
	return nil
}

// matchPrefix reports whether the first names of segs match the pattern.
// The caller checks that segs is long enough.
func (pp pathPattern) matchPrefix(segs []string, equal func(a, b string) bool) bool {
	for i, pat := range pp.segs {
		switch {
		case pat == "*":
		case strings.HasSuffix(pat, "*"):
			prefix := strings.TrimSuffix(pat, "*")
			if len(segs[i]) < len(prefix) || !equal(segs[i][:len(prefix)], prefix) {
				return false
			}
		case !equal(pat, segs[i]):
			return false
		}
	}
	return true
}

func refused(path, why string) error {
	return fmt.Errorf("%w: %s: %s", ErrRefused, path, why)
}
