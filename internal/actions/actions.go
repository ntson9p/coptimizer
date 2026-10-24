// Package actions carries out what the rule catalog says COptimizer can do
// about a finding. Prepare works out a plan without changing anything (a
// Delete action is tried as a dry run); Run carries the plan out.
//
// The page never names what to delete: a plan is built here from the
// finding's locations, and only the signed-in user's own profile and Windows'
// own folders are cleaned, never another account's files. The tools run are
// Windows' own, from System32.
package actions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/clean"
	"github.com/ntson9p/coptimizer/internal/execx"
	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

// Deps are what plans and runs need.
type Deps struct {
	Cleaner    fsx.Cleaner
	Policy     *safety.Policy
	Programs   sysinfo.Programs
	RecycleBin sysinfo.RecycleBinReader
	Mutator    sysinfo.Mutator // nil: the Recycle Bin can't be emptied
	Runner     execx.Runner    // runs Windows' own tools only
	Elevated   bool
	Env        rules.Env // its CurrentProfile is "your" profile
	Now        func() time.Time
}

// Reasons a location of a finding is left out of a plan.
const (
	LeftOtherAccount = "other-account" // in another account's profile
	LeftNeedsAdmin   = "needs-admin"   // only with Administrator rights
	LeftOwnTool      = "own-tool"      // this action doesn't cover it; its own tool does
)

// Reasons a plan can't run.
const (
	BlockedAdmin    = "needs-admin"    // run COptimizer with Administrator rights
	BlockedPrograms = "close-programs" // close Running first
	BlockedNothing  = "nothing"        // nothing to clean right now
)

// Left is a location of the finding that a plan leaves alone.
type Left struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Reason string `json:"reason"`
}

// Plan is what an action would do now, worked out without changing anything.
type Plan struct {
	Rule        string           `json:"ruleId"`
	Kind        rules.ActionKind `json:"kind"`
	Drive       string           `json:"drive"`             // whose free space the run measures
	Bytes       int64            `json:"bytes"`             // the estimate
	Files       int64            `json:"files"`             // files it would delete
	Items       int64            `json:"items,omitempty"`   // Recycle Bin: items in it
	Unknown     bool             `json:"unknown,omitempty"` // the tool decides: no estimate
	Locations   []clean.Location `json:"locations,omitempty"`
	Left        []Left           `json:"left,omitempty"`
	Command     string           `json:"command,omitempty"` // tool actions: the exact command line
	NeedsClosed []string         `json:"needsClosed,omitempty"`
	Running     []string         `json:"running,omitempty"` // of NeedsClosed, those running now
	NeedsAdmin  bool             `json:"needsAdmin,omitempty"`
	Elevated    bool             `json:"elevated"`
	Long        bool             `json:"long,omitempty"`
	MinAgeHours int              `json:"minAgeHours,omitempty"`
	Blocked     string           `json:"blocked,omitempty"` // why it can't run now

	spec clean.Spec // Delete: what the run may delete
	cmd  *execx.Cmd // tool actions
	scan []string   // folders to measure again afterwards
}

// Rescan returns the folders whose size the run changes, to measure again
// afterwards.
func (p *Plan) Rescan() []string { return slices.Clone(p.scan) }

// ErrNoAction is returned for a finding COptimizer can't act on.
var ErrNoAction = errors.New("actions: the finding has no action")

// Prepare works out what the action of finding f would do now. It changes
// nothing.
func Prepare(ctx context.Context, d Deps, rep rules.Report, f rules.Finding) (*Plan, error) {
	a := f.Action
	if a == nil {
		return nil, ErrNoAction
	}
	p := &Plan{Rule: f.ID, Kind: a.Kind, Drive: d.Env.SystemDrive + `\`, Elevated: d.Elevated, Long: a.Long,
		NeedsClosed: a.NeedsClosed, MinAgeHours: int(a.MinAge / time.Hour)}
	var err error
	switch a.Kind {
	case rules.Delete:
		err = prepareDelete(ctx, d, rep, f, p)
	case rules.EmptyRecycleBin:
		p.Bytes, p.Items, err = d.RecycleBin.RecycleBin(p.Drive)
		p.scan = []string{p.Drive + `$Recycle.Bin`}
	case rules.ComponentCleanup:
		// Nothing to measure again afterwards: WinSxS is mostly hard links
		// shared with System32, which measuring it alone would count twice.
		// Only a new scan of the drive shows its new size.
		p.NeedsAdmin, p.Unknown = true, true
		p.cmd = componentCleanup(d.Env)
	case rules.DeliveryOptimization:
		p.NeedsAdmin, p.Bytes = true, f.Bytes
		p.cmd = deliveryOptimization(d.Env)
		for _, it := range rep.Locations(f.ID) {
			p.scan = append(p.scan, it.Path)
		}
	default:
		return nil, fmt.Errorf("actions: unknown action %q", a.Kind)
	}
	if err != nil {
		return nil, err
	}
	if p.cmd != nil {
		p.Command = commandLine(*p.cmd)
	}
	if p.Running, err = running(d, a.NeedsClosed); err != nil {
		return nil, err
	}
	p.Blocked = blocked(d, p)
	return p, nil
}

func prepareDelete(ctx context.Context, d Deps, rep rules.Report, f rules.Finding, p *Plan) error {
	a := f.Action
	spec := clean.Spec{Include: a.Include, MinAge: a.MinAge, RemoveRoot: a.RemoveRoot}
	for _, it := range rep.Locations(f.ID) {
		if why := leftReason(d, a, it.Path); why != "" {
			p.Left = append(p.Left, Left{Path: it.Path, Bytes: it.Bytes, Reason: why})
			continue
		}
		if it.Kind == "file" {
			spec.Files = append(spec.Files, it.Path)
			p.scan = append(p.scan, parent(it.Path))
			continue
		}
		spec.Folders = append(spec.Folders, it.Path)
		// What another finding covers inside this folder is left to it.
		spec.Exclude = append(spec.Exclude, rep.ClaimedInside(f.ID, it.Path)...)
		p.scan = append(p.scan, it.Path)
	}
	res, err := clean.Run(ctx, d.Cleaner, spec, clean.Options{DryRun: true, Policy: d.Policy, Now: d.Now()})
	if err != nil {
		return err
	}
	p.spec, p.Locations, p.Bytes, p.Files = spec, res.Locations, res.Bytes, res.Files
	return nil
}

// leftReason says why the action leaves the finding's location at path alone,
// or "" if it cleans it.
func leftReason(d Deps, a *rules.Action, path string) string {
	switch mine := under(path, d.Env.CurrentProfile); {
	case !a.Covers(d.Env, path):
		return LeftOwnTool
	case !mine && under(path, d.Env.Users):
		return LeftOtherAccount
	case !mine && !d.Elevated:
		return LeftNeedsAdmin
	}
	return ""
}

// Check works out afresh what stands in the way of running p now: "" if
// nothing, otherwise a Blocked reason, with the programs to close.
func Check(d Deps, p *Plan) (string, []string, error) {
	run, err := running(d, p.NeedsClosed)
	if err != nil {
		return "", nil, err
	}
	q := *p
	q.Running = run
	return blocked(d, &q), run, nil
}

func blocked(d Deps, p *Plan) string {
	switch {
	case p.NeedsAdmin && !d.Elevated:
		return BlockedAdmin
	case len(p.Running) > 0:
		return BlockedPrograms
	case p.Kind == rules.Delete && p.Files == 0:
		return BlockedNothing
	case p.Kind == rules.EmptyRecycleBin && p.Items == 0:
		return BlockedNothing
	}
	return ""
}

// running returns those of names that are running now.
func running(d Deps, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	all, err := d.Programs.Running()
	if err != nil {
		return nil, fmt.Errorf("actions: listing the running programs: %w", err)
	}
	var out []string
	for _, n := range names {
		if slices.ContainsFunc(all, func(r string) bool { return strings.EqualFold(r, n) }) {
			out = append(out, n)
		}
	}
	return out, nil
}

// States of an Outcome.
const (
	Succeeded = "succeeded"
	Partial   = "partial" // some files couldn't be deleted
	Failed    = "failed"
	Cancelled = "cancelled"
)

// Outcome is what a run did.
type Outcome struct {
	State         string           `json:"state"`
	Simulated     bool             `json:"simulated,omitempty"`
	Bytes         int64            `json:"bytes"` // deleted, by the deleter's count
	Files         int64            `json:"files"`
	Skipped       int64            `json:"skipped"`
	Locations     []clean.Location `json:"locations,omitempty"`
	RestartNeeded bool             `json:"restartNeeded,omitempty"`
	Error         string           `json:"error,omitempty"`
}

// Progress is a snapshot of a run.
type Progress struct {
	Percent float64 `json:"percent"` // tools that report it; -1 otherwise
	Files   int64   `json:"files"`
	Bytes   int64   `json:"bytes"`
	Skipped int64   `json:"skipped"`
	Current string  `json:"current,omitempty"`
}

// Run carries out p. With simulate it changes nothing: a Delete action runs
// as a dry run, and the others only say what they would do. progress and
// logf may be called from other goroutines, never at the same time.
func Run(ctx context.Context, d Deps, p *Plan, simulate bool, progress func(Progress), logf func(string)) Outcome {
	switch p.Kind {
	case rules.Delete:
		res, err := clean.Run(ctx, d.Cleaner, p.spec, clean.Options{DryRun: simulate, Policy: d.Policy, Now: d.Now(),
			Progress: func(c clean.Progress) {
				progress(Progress{Percent: -1, Files: c.Files, Bytes: c.Bytes, Skipped: c.Skipped, Current: c.Current})
			}})
		o := Outcome{Simulated: simulate, Bytes: res.Bytes, Files: res.Files, Skipped: res.Skipped, Locations: res.Locations}
		switch {
		case errors.Is(err, context.Canceled):
			o.State = Cancelled
		case err != nil:
			o.State, o.Error = Failed, err.Error()
		case res.Skipped > 0 || res.Refused > 0:
			o.State = Partial
		default:
			o.State = Succeeded
		}
		return o
	case rules.EmptyRecycleBin:
		o := Outcome{State: Succeeded, Simulated: simulate, Bytes: p.Bytes, Files: p.Items}
		if simulate {
			return o
		}
		if d.Mutator == nil {
			return Outcome{State: Failed, Error: "the Recycle Bin can't be emptied here"}
		}
		if err := d.Mutator.EmptyRecycleBin(p.Drive); err != nil {
			return Outcome{State: Failed, Error: err.Error()}
		}
		return o
	case rules.ComponentCleanup, rules.DeliveryOptimization:
		if simulate {
			logf("Simulation: would run " + p.Command)
			return Outcome{State: Succeeded, Simulated: true}
		}
		return runTool(ctx, d, p, progress, logf)
	}
	return Outcome{State: Failed, Error: fmt.Sprintf("unknown action %q", p.Kind)}
}

// progressBar matches the percentage in DISM's progress bar,
// "[====    50.0%      ]".
var progressBar = regexp.MustCompile(`^\[[= ]*(\d{1,3}(?:\.\d)?)%[= ]*\]$`)

func runTool(ctx context.Context, d Deps, p *Plan, progress func(Progress), logf func(string)) Outcome {
	c := *p.cmd
	c.Output = func(line string) {
		if m := progressBar.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			pct, _ := strconv.ParseFloat(m[1], 64)
			progress(Progress{Percent: pct})
			return
		}
		logf(line)
	}
	res, err := d.Runner.Run(ctx, c)
	switch {
	case errors.Is(err, context.Canceled):
		return Outcome{State: Cancelled}
	case err != nil:
		return Outcome{State: Failed, Error: err.Error()}
	case res.ExitCode == 3010: // done; Windows needs a restart to finish
		return Outcome{State: Succeeded, RestartNeeded: true}
	case res.ExitCode != 0:
		return Outcome{State: Failed, Error: fmt.Sprintf("%s exited with code %d", baseName(c.Path), res.ExitCode)}
	}
	return Outcome{State: Succeeded}
}

// componentCleanup is DISM's cleanup of components that updates replaced. It
// can take many minutes. /English keeps its output readable whatever the
// display language.
func componentCleanup(env rules.Env) *execx.Cmd {
	sys32 := env.Windows + `\System32`
	return &execx.Cmd{Path: sys32 + `\dism.exe`, Args: []string{"/Online", "/English", "/Cleanup-Image", "/StartComponentCleanup"},
		Dir: sys32, Timeout: 3 * time.Hour}
}

// deliveryOptimization asks the Delivery Optimization service, through its
// own CIM provider, to delete its cache: what Delete-DeliveryOptimizationCache
// does, without loading that command's script module, which a restrictive
// PowerShell execution policy would block. Pinned files stay.
func deliveryOptimization(env rules.Env) *execx.Cmd {
	sys32 := env.Windows + `\System32`
	return &execx.Cmd{Path: sys32 + `\WindowsPowerShell\v1.0\powershell.exe`,
		Args: []string{"-NoProfile", "-NonInteractive", "-Command",
			"Invoke-CimMethod -Namespace root/Microsoft/Windows/DeliveryOptimization -ClassName MSFT_DeliveryOptimizationFile " +
				"-MethodName Delete -Arguments @{deletePinned=$false} -ErrorAction Stop | Out-Null"},
		Dir: sys32, Timeout: 10 * time.Minute}
}

// commandLine shows a command as it would be typed, for the preview.
func commandLine(c execx.Cmd) string {
	parts := []string{quote(c.Path)}
	for _, a := range c.Args {
		parts = append(parts, quote(a))
	}
	return strings.Join(parts, " ")
}

func quote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func under(path, dir string) bool {
	return dir != "" && (strings.EqualFold(path, dir) ||
		len(path) > len(dir) && path[len(dir)] == '\\' && strings.EqualFold(path[:len(dir)], dir))
}

func parent(path string) string {
	i := strings.LastIndexByte(path, '\\')
	if i <= 2 {
		return path[:3]
	}
	return path[:i]
}

func baseName(path string) string { return path[strings.LastIndexByte(path, '\\')+1:] }
