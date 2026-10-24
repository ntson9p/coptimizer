// Package clean deletes what a cleanup action approved: the contents of cache
// and temporary folders, and single files such as memory dumps. It is the only
// code in COptimizer that deletes the user's files, so it is careful:
//
//   - every folder and every file is checked against the safety policy;
//   - it works through fsx.Tree, which never leaves the folder it opened and
//     never follows junctions or links;
//   - links, online-only files, excluded locations, files that don't match
//     Include, and anything changed more recently than MinAge are left alone;
//   - files in use, or that it may not delete, are skipped and reported, never
//     forced;
//   - a dry run makes the same decisions without deleting anything, so a
//     preview shows what the real run will do.
package clean

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/safety"
)

// Spec is what a cleanup may delete.
type Spec struct {
	Folders []string // folders whose contents may be deleted
	Files   []string // single files that may be deleted
	// Exclude lists files and folders inside Folders to leave alone, such as
	// locations another finding covers.
	Exclude []string
	// Include, if set, limits the files to those whose names match one of
	// these patterns (with * and ?).
	Include    []string
	MinAge     time.Duration // leave what was created or changed more recently
	RemoveRoot bool          // also remove each folder in Folders once it is empty
}

// Options say how to run.
type Options struct {
	DryRun bool           // decide everything, delete nothing
	Policy *safety.Policy // required
	Now    time.Time      // the time MinAge counts back from
	// Progress, if set, is called about four times a second, and once at
	// the end.
	Progress func(Progress)
}

// Progress is a snapshot of a running cleanup.
type Progress struct {
	Files   int64  `json:"files"` // deleted so far (in a dry run: that would be)
	Bytes   int64  `json:"bytes"`
	Skipped int64  `json:"skipped"`
	Current string `json:"current"`
}

// States of a Location.
const (
	Done    = "done"    // looked through; see the counts
	Missing = "missing" // isn't there (any more): nothing to do
	Refused = "refused" // the safety policy or a check refused it; see Reason
)

// Reasons for skipping or refusing.
const (
	ReasonPolicy = "policy" // the deny list protects it
	ReasonLink   = "link"   // a junction or link, or reached through one
	ReasonInUse  = "in-use" // another program has it open
	ReasonDenied = "denied" // Windows doesn't allow it (permissions)
	ReasonError  = "error"  // anything else; see Detail
)

// Location is what happened at one folder or file of a Spec.
type Location struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"` // "folder" or "file"
	State   string `json:"state"`
	Reason  string `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Files   int64  `json:"files"`   // deleted (in a dry run: that would be)
	Bytes   int64  `json:"bytes"`   // their size on disk
	Folders int64  `json:"folders"` // folders removed, the root included
	// Kept counts what was left alone on purpose: too new, excluded, not
	// matching Include, links and online-only files.
	Kept      int64 `json:"kept"`
	KeptBytes int64 `json:"keptBytes"`
	// Skipped counts files that couldn't be deleted: in use, no permission.
	Skipped      int64     `json:"skipped"`
	SkippedBytes int64     `json:"skippedBytes"`
	Samples      []string  `json:"samples,omitempty"`  // some of the files deleted
	Problems     []Problem `json:"problems,omitempty"` // the first files skipped, and why
}

// Problem is a file or folder that couldn't be deleted or read.
type Problem struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// Result is what a cleanup did.
type Result struct {
	Locations             []Location
	Files, Bytes, Folders int64
	Kept, KeptBytes       int64
	Skipped, SkippedBytes int64
	Refused               int // locations refused
	DryRun                bool
	Started, Finished     time.Time
}

const (
	maxSamples  = 5
	maxProblems = 10
)

// Run cleans what spec allows. It stops early, returning what it did so far
// and ctx's error, when ctx is cancelled.
func Run(ctx context.Context, c fsx.Cleaner, spec Spec, opts Options) (Result, error) {
	if opts.Policy == nil {
		return Result{}, errors.New("clean: no safety policy")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	r := &run{ctx: ctx, c: c, spec: spec, opts: opts, exclude: make(map[string]bool)}
	for _, p := range spec.Exclude {
		if n, err := safety.Normalize(p); err == nil {
			r.exclude[strings.ToUpper(n)] = true
		}
	}
	r.res.DryRun = opts.DryRun
	r.res.Started = time.Now()
	for _, p := range spec.Folders {
		if ctx.Err() != nil {
			break
		}
		r.res.Locations = append(r.res.Locations, r.folder(p))
	}
	for _, p := range spec.Files {
		if ctx.Err() != nil {
			break
		}
		r.res.Locations = append(r.res.Locations, r.file(p))
	}
	r.res.Finished = time.Now()
	for _, l := range r.res.Locations {
		r.res.Files += l.Files
		r.res.Bytes += l.Bytes
		r.res.Folders += l.Folders
		r.res.Kept += l.Kept
		r.res.KeptBytes += l.KeptBytes
		r.res.Skipped += l.Skipped
		r.res.SkippedBytes += l.SkippedBytes
		if l.State == Refused {
			r.res.Refused++
		}
	}
	if opts.Progress != nil {
		opts.Progress(r.progress(""))
	}
	return r.res, ctx.Err()
}

type run struct {
	ctx     context.Context
	c       fsx.Cleaner
	spec    Spec
	opts    Options
	exclude map[string]bool // upper-case normalized paths
	res     Result

	files, bytes, skipped int64 // running totals, for progress
	lastReport            time.Time
}

// folder cleans the contents of one folder of the spec.
func (r *run) folder(path string) Location {
	loc := Location{Path: path, Kind: "folder", State: Done}
	n, ok := r.check(&loc, path)
	if !ok {
		return loc
	}
	loc.Path = n
	tree, ok := r.open(&loc, n)
	if !ok {
		return loc
	}
	empty := r.walk(tree, "", tree.Path(), &loc)
	// Close first: an open folder can't be removed.
	tree.Close()
	if r.spec.RemoveRoot && empty && r.ctx.Err() == nil {
		r.removeRoot(n, &loc)
	}
	return loc
}

// file deletes one single file of the spec.
func (r *run) file(path string) Location {
	loc := Location{Path: path, Kind: "file", State: Done}
	n, ok := r.check(&loc, path)
	if !ok {
		return loc
	}
	loc.Path = n
	dir, name := filepath.Split(n)
	tree, ok := r.open(&loc, strings.TrimSuffix(dir, `\`)+rootSuffix(dir))
	if !ok {
		return loc
	}
	defer tree.Close()
	entries, err := tree.List("")
	if err != nil {
		refuse(&loc, reason(err), err.Error())
		return loc
	}
	for _, e := range entries {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		if e.IsDir() {
			refuse(&loc, ReasonError, "a folder, not a file")
		} else {
			r.entry(tree, &loc, e, e.Name, join(tree.Path(), e.Name))
		}
		return loc
	}
	loc.State = Missing
	return loc
}

// rootSuffix keeps the separator of a drive root: `C:\`.
func rootSuffix(dir string) string {
	if len(dir) == 3 && dir[1] == ':' {
		return `\`
	}
	return ""
}

// check normalizes a location of the spec and asks the policy about it.
func (r *run) check(loc *Location, path string) (string, bool) {
	n, err := safety.Normalize(path)
	if err != nil {
		refuse(loc, ReasonPolicy, err.Error())
		return "", false
	}
	if err := r.opts.Policy.Check(n); err != nil {
		refuse(loc, ReasonPolicy, err.Error())
		return "", false
	}
	return n, true
}

// open opens a folder, making sure Windows resolves it to the same place:
// a junction on the way, or a short (8.3) name, gives another path.
func (r *run) open(loc *Location, n string) (fsx.Tree, bool) {
	tree, err := r.c.Open(n)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		loc.State = Missing
		return nil, false
	case err != nil:
		refuse(loc, reason(err), err.Error())
		return nil, false
	}
	if !strings.EqualFold(tree.Path(), n) {
		tree.Close()
		refuse(loc, ReasonLink, fmt.Sprintf("%s leads to %s", n, tree.Path()))
		return nil, false
	}
	return tree, true
}

// walk cleans the folder rel of tree (at abs), deepest first. It reports
// whether the folder ended up empty, or would in a dry run.
func (r *run) walk(tree fsx.Tree, rel, abs string, loc *Location) bool {
	entries, err := tree.List(rel)
	if err != nil {
		r.problem(loc, abs, reason(err), err.Error())
		return false
	}
	empty := true
	for _, e := range entries {
		if r.ctx.Err() != nil {
			return false
		}
		if !r.entry(tree, loc, e, join(rel, e.Name), join(abs, e.Name)) {
			empty = false
		}
	}
	return empty
}

// entry handles one file or folder and reports whether it is gone (or would
// be, in a dry run).
func (r *run) entry(tree fsx.Tree, loc *Location, e fsx.Entry, rel, abs string) bool {
	switch {
	case r.exclude[strings.ToUpper(abs)], e.IsReparse(), e.IsCloudOnly(), r.opts.Policy.Check(abs) != nil:
		r.keep(loc, e)
		return false
	case e.IsDir():
		if !r.walk(tree, rel, abs, loc) || !r.oldEnough(e) {
			return false
		}
		if !r.opts.DryRun {
			if err := tree.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return false // something new appeared in it, or it is in use
			}
		}
		loc.Folders++
		return true
	case !r.included(e.Name) || !r.oldEnough(e):
		r.keep(loc, e)
		return false
	}
	r.report(abs)
	if !r.opts.DryRun {
		if err := tree.Remove(rel); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return true // already gone
			}
			loc.Skipped++
			loc.SkippedBytes += e.Allocated
			r.skipped++
			r.problem(loc, abs, reason(err), err.Error())
			return false
		}
	}
	loc.Files++
	loc.Bytes += e.Allocated
	r.files++
	r.bytes += e.Allocated
	if len(loc.Samples) < maxSamples {
		loc.Samples = append(loc.Samples, abs)
	}
	return true
}

// removeRoot removes a cleaned folder of the spec itself, through its parent.
func (r *run) removeRoot(n string, loc *Location) {
	dir, name := filepath.Split(n)
	if name == "" {
		return
	}
	if r.opts.DryRun {
		loc.Folders++
		return
	}
	parent, err := r.c.Open(strings.TrimSuffix(dir, `\`) + rootSuffix(dir))
	if err != nil {
		r.problem(loc, n, reason(err), err.Error())
		return
	}
	defer parent.Close()
	if !strings.EqualFold(join(parent.Path(), name), n) {
		r.problem(loc, n, ReasonLink, "its parent folder resolves elsewhere")
		return
	}
	if err := parent.Remove(name); err == nil {
		loc.Folders++
	} else if !errors.Is(err, fs.ErrNotExist) {
		r.problem(loc, n, reason(err), err.Error())
	}
}

func (r *run) keep(loc *Location, e fsx.Entry) {
	loc.Kept++
	if !e.IsDir() {
		loc.KeptBytes += e.Allocated
	}
}

func (r *run) oldEnough(e fsx.Entry) bool {
	return r.spec.MinAge <= 0 || r.opts.Now.Sub(e.Changed()) >= r.spec.MinAge
}

func (r *run) included(name string) bool {
	if len(r.spec.Include) == 0 {
		return true
	}
	for _, p := range r.spec.Include {
		if ok, err := filepath.Match(strings.ToLower(p), strings.ToLower(name)); err == nil && ok {
			return true
		}
	}
	return false
}

func (r *run) problem(loc *Location, path, reason, detail string) {
	if len(loc.Problems) < maxProblems {
		loc.Problems = append(loc.Problems, Problem{Path: path, Reason: reason, Detail: detail})
	}
}

// report calls the progress function, at most four times a second.
func (r *run) report(current string) {
	if r.opts.Progress == nil {
		return
	}
	if now := time.Now(); now.Sub(r.lastReport) >= 250*time.Millisecond {
		r.lastReport = now
		r.opts.Progress(r.progress(current))
	}
}

func (r *run) progress(current string) Progress {
	return Progress{Files: r.files, Bytes: r.bytes, Skipped: r.skipped, Current: current}
}

func refuse(loc *Location, reason, detail string) {
	loc.State, loc.Reason, loc.Detail = Refused, reason, detail
}

// reason sorts an error into one of the Reason codes.
func reason(err error) string {
	switch {
	case errors.Is(err, fsx.ErrInUse):
		return ReasonInUse
	case errors.Is(err, fsx.ErrLink):
		return ReasonLink
	case errors.Is(err, fs.ErrPermission):
		return ReasonDenied
	case errors.Is(err, safety.ErrRefused), errors.Is(err, fsx.ErrNotLocal):
		return ReasonPolicy
	}
	return ReasonError
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}
