package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

// keepScans is how many finished scans stay in memory.
const keepScans = 3

// SnapshotStore keeps snapshots of earlier scans, to find what grew.
type SnapshotStore interface {
	Previous(root string, elevated bool) (rules.Snapshot, bool)
	Add(rules.Snapshot) error
}

// scans runs one scan at a time and keeps the last few results.
type scans struct {
	lister    fsx.Lister
	system    sysinfo.Reader
	env       rules.Env
	snapshots SnapshotStore // may be nil
	hub       *hub
	now       func() time.Time
	logf      func(format string, args ...any)

	mu      sync.Mutex
	next    int
	byID    map[string]*scanJob
	order   []string // oldest first
	running *scanJob
}

type scanJob struct {
	id       string
	roots    []string
	state    string // "running", "done", "failed" or "cancelled"
	started  time.Time
	finished time.Time
	err      string
	used     int64 // space in use on the scanned drives when the scan started
	progress scan.Progress
	result   *scan.Result
	report   *rules.Report
	cancel   context.CancelFunc
}

func newScans(cfg Config, h *hub) *scans {
	return &scans{lister: cfg.Lister, system: cfg.System, env: cfg.Env, snapshots: cfg.Snapshots, hub: h,
		now: cfg.Now, logf: cfg.Logf, byID: make(map[string]*scanJob)}
}

// start begins a scan of whole drives, given as roots like `C:\`.
func (m *scans) start(roots []string) (*scanJob, error) {
	if len(roots) == 0 {
		return nil, badRequest("no drives to scan")
	}
	drives, err := m.system.Drives()
	if err != nil {
		return nil, err
	}
	var used int64
	clean := make([]string, 0, len(roots))
	for _, r := range roots {
		d, ok := findDrive(drives, r)
		if !ok {
			return nil, badRequest(fmt.Sprintf("%q is not a local fixed drive", r))
		}
		for _, c := range clean {
			if c == d.Root {
				return nil, badRequest(fmt.Sprintf("%q is listed twice", r))
			}
		}
		clean = append(clean, d.Root)
		used += d.Used()
	}

	m.mu.Lock()
	if m.running != nil {
		m.mu.Unlock()
		return nil, &apiError{Status: 409, Code: "busy", Message: "a scan is already running"}
	}
	m.next++
	ctx, cancel := context.WithCancel(context.Background())
	j := &scanJob{id: fmt.Sprintf("s%d", m.next), roots: clean, state: "running", started: m.now(), used: used, cancel: cancel}
	m.byID[j.id] = j
	m.order = append(m.order, j.id)
	for len(m.order) > keepScans {
		delete(m.byID, m.order[0])
		m.order = m.order[1:]
	}
	m.running = j
	v := j.view()
	m.mu.Unlock()

	m.hub.publish("scan.started", v, true)
	go m.run(ctx, j)
	return j, nil
}

func (m *scans) run(ctx context.Context, j *scanJob) {
	res, err := scan.Run(ctx, m.lister, scan.Options{Roots: j.roots, Progress: func(p scan.Progress) {
		m.mu.Lock()
		j.progress = p
		v := j.progressView()
		m.mu.Unlock()
		m.hub.publish("scan.progress", v, false)
	}})
	finished := m.now()
	var report *rules.Report
	if err == nil {
		report = m.evaluate(res, finished)
	}
	m.mu.Lock()
	j.finished = finished
	j.cancel()
	if m.running == j {
		m.running = nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		j.state = "cancelled"
	case err != nil:
		j.state, j.err = "failed", err.Error()
	default:
		j.state, j.result, j.report = "done", res, report
	}
	v := j.view()
	m.mu.Unlock()
	m.hub.publish("scan.finished", v, true)
}

// evaluate finds the space hogs in a finished scan, comparing it with the
// previous scan of the same drives taken with the same rights, then keeps a
// snapshot of this one for next time.
func (m *scans) evaluate(res *scan.Result, at time.Time) *rules.Report {
	elevated := m.system.Elevated()
	var previous []rules.Snapshot
	if m.snapshots != nil {
		for _, root := range res.Roots {
			if p, ok := m.snapshots.Previous(root.Name, elevated); ok {
				previous = append(previous, p)
			}
		}
	}
	rep := rules.Evaluate(res, m.env, rules.Options{Previous: previous})
	if m.snapshots != nil {
		for _, root := range res.Roots {
			if err := m.snapshots.Add(rules.TakeSnapshot(root, at, elevated)); err != nil {
				m.logf("could not keep a snapshot of the scan of %s: %v", root.Name, err)
			}
		}
	}
	return &rep
}

// get returns the scan with the given ID.
func (m *scans) get(id string) (*scanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.byID[id]
	if j == nil {
		return nil, &apiError{Status: 404, Code: "not_found", Message: "no such scan"}
	}
	return j, nil
}

// result returns the result of a finished scan and its findings.
func (m *scans) result(id string) (*scan.Result, *rules.Report, error) {
	j, err := m.get(id)
	if err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if j.result == nil {
		return nil, nil, &apiError{Status: 409, Code: "not_ready", Message: "the scan has no result (yet)"}
	}
	return j.result, j.report, nil
}

func (m *scans) cancel(id string) (scanView, error) {
	j, err := m.get(id)
	if err != nil {
		return scanView{}, err
	}
	j.cancel()
	return m.view(j), nil
}

func (m *scans) view(j *scanJob) scanView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return j.view()
}

// latest returns the most recent scan, if any.
func (m *scans) latest() *scanView {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.order) == 0 {
		return nil
	}
	v := m.byID[m.order[len(m.order)-1]].view()
	return &v
}

// cancelAll stops a running scan, when the server shuts down.
func (m *scans) cancelAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running != nil {
		m.running.cancel()
	}
}

func findDrive(drives []sysinfo.Drive, root string) (sysinfo.Drive, bool) {
	want := strings.TrimRight(root, `\`) + `\`
	for _, d := range drives {
		if strings.EqualFold(d.Root, want) {
			return d, true
		}
	}
	return sysinfo.Drive{}, false
}

// Views: what the API and the event stream send about a scan. Callers hold
// m.mu.

type scanView struct {
	ID       string       `json:"id"`
	Roots    []string     `json:"roots"`
	State    string       `json:"state"`
	Started  time.Time    `json:"started"`
	Finished *time.Time   `json:"finished,omitempty"`
	Error    string       `json:"error,omitempty"`
	Progress progressView `json:"progress"`
	Summary  *summaryView `json:"summary,omitempty"`
}

type progressView struct {
	ScanID    string  `json:"scanId"`
	Folders   int64   `json:"folders"`
	Files     int64   `json:"files"`
	Errors    int64   `json:"errors"`
	Allocated int64   `json:"allocated"`
	Current   string  `json:"current"`
	ElapsedMS int64   `json:"elapsedMs"`
	Percent   float64 `json:"percent"`
}

type summaryView struct {
	Files       int64                `json:"files"`
	Folders     int64                `json:"folders"`
	Errors      int64                `json:"errors"`
	Size        int64                `json:"size"`
	Allocated   int64                `json:"allocated"`
	Shared      int64                `json:"shared"`
	CloudOnly   int64                `json:"cloudOnly"`
	Unaccounted int64                `json:"unaccounted"`
	Denied      []string             `json:"denied"`
	Totals      map[rules.Risk]int64 `json:"totals"` // findings by risk
}

func (j *scanJob) view() scanView {
	v := scanView{ID: j.id, Roots: j.roots, State: j.state, Started: j.started, Error: j.err, Progress: j.progressView()}
	if !j.finished.IsZero() {
		f := j.finished
		v.Finished = &f
	}
	if r := j.result; r != nil {
		denied := r.Denied
		if len(denied) > 20 {
			denied = denied[:20]
		}
		v.Summary = &summaryView{
			Files: r.Files, Folders: r.Folders, Errors: r.Errors,
			Size: r.Size, Allocated: r.Allocated, Shared: r.Shared, CloudOnly: r.CloudOnly,
			Unaccounted: max(0, j.used-r.Allocated),
			Denied:      append([]string{}, denied...),
		}
		if j.report != nil {
			v.Summary.Totals = j.report.Totals
		}
	}
	return v
}

func (j *scanJob) progressView() progressView {
	p := j.progress
	v := progressView{
		ScanID: j.id, Folders: p.Folders, Files: p.Files, Errors: p.Errors,
		Allocated: p.Allocated, Current: p.Current, ElapsedMS: p.Elapsed.Milliseconds(),
	}
	switch {
	case j.state == "done":
		v.Percent = 100
	case j.used > 0:
		v.Percent = min(99, 100*float64(p.Allocated)/float64(j.used))
	}
	return v
}
