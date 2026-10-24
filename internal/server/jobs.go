package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/actions"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/store"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

const (
	planLifetime = 10 * time.Minute // how long a preview can be confirmed
	keepJobs     = 20               // finished cleanups kept in memory
	maxLog       = 500              // log lines kept per cleanup
)

// HistoryStore keeps the record of past cleanups.
type HistoryStore interface {
	Add(store.HistoryEntry) error
	Recent(n int) ([]store.HistoryEntry, error)
}

// jobs prepares cleanups and runs them one at a time, in the order they were
// confirmed. A preview (plan) approves what an action may do; the run checks
// everything again before and while it acts.
type jobs struct {
	deps    *actions.Deps // nil: no cleanups here
	scans   *scans
	system  sysinfo.Reader
	history HistoryStore
	hub     *hub
	now     func() time.Time
	logf    func(format string, args ...any)
	ctx     context.Context
	stop    context.CancelFunc
	wake    chan struct{}

	mu       sync.Mutex
	simulate bool
	nextPlan int
	nextJob  int
	plans    map[string]*planEntry
	byID     map[string]*job
	order    []string // oldest first
	queue    []*job
	running  *job
	closing  bool          // shutting down: no new cleanups
	done     chan struct{} // closed when the runner has stopped
}

type planEntry struct {
	id       string
	plan     *actions.Plan
	scanID   string
	simulate bool // the preview was a simulation's: so must the run be
	expires  time.Time
	used     bool
}

type job struct {
	id                        string
	plan                      *actions.Plan
	scanID                    string
	state                     string // queued, running, then an outcome state
	simulate                  bool
	queued, started, finished time.Time
	progress                  actions.Progress
	log                       []string
	outcome                   *actions.Outcome
	freed                     int64
	err                       string
	cancel                    context.CancelFunc
}

func newJobs(cfg Config, sc *scans, h *hub) *jobs {
	m := &jobs{deps: cfg.Actions, scans: sc, system: cfg.System, history: cfg.History, hub: h, now: cfg.Now, logf: cfg.Logf,
		simulate: cfg.Simulate, plans: make(map[string]*planEntry), byID: make(map[string]*job),
		wake: make(chan struct{}, 1), done: make(chan struct{})}
	if m.history == nil {
		m.history = &store.MemoryHistory{}
	}
	m.ctx, m.stop = context.WithCancel(context.Background())
	go m.loop()
	return m
}

// close stops the runner. A cleanup that is running is cancelled, even one
// that would otherwise not be: the server is going away.
func (m *jobs) close() {
	m.stop()
	<-m.done
}

func (m *jobs) available() bool { return m.deps != nil }

func errNoCleanups() error {
	return &apiError{Status: 404, Code: "not_found", Message: "cleanups aren't available here"}
}

// planView is a preview as the page sees it.
type planView struct {
	ID       string    `json:"id"`
	ScanID   string    `json:"scanId"`
	Expires  time.Time `json:"expires"`
	Simulate bool      `json:"simulate"`
	*actions.Plan
}

// prepare previews the action of finding ruleID in the latest scan.
func (m *jobs) prepare(ctx context.Context, ruleID string) (planView, error) {
	if !m.available() {
		return planView{}, errNoCleanups()
	}
	scanID, rep, ok := m.scans.latestReport()
	if !ok {
		return planView{}, &apiError{Status: 409, Code: "not_ready", Message: "run a scan first"}
	}
	f, ok := rep.Find(ruleID)
	if !ok {
		return planView{}, &apiError{Status: 404, Code: "not_found", Message: "the latest scan has no such finding"}
	}
	if f.Action == nil {
		return planView{}, badRequest("COptimizer can't clean this finding itself")
	}
	p, err := actions.Prepare(ctx, *m.deps, *rep, f)
	if err != nil {
		return planView{}, err
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, e := range m.plans {
		if now.After(e.expires) || e.used {
			delete(m.plans, id)
		}
	}
	m.nextPlan++
	e := &planEntry{id: fmt.Sprintf("p%d", m.nextPlan), plan: p, scanID: scanID, simulate: m.simulate, expires: now.Add(planLifetime)}
	m.plans[e.id] = e
	return planView{ID: e.id, ScanID: scanID, Expires: e.expires, Simulate: e.simulate, Plan: p}, nil
}

// start queues the cleanup a preview approved.
func (m *jobs) start(planID string) (jobView, error) {
	if !m.available() {
		return jobView{}, errNoCleanups()
	}
	m.mu.Lock()
	e := m.plans[planID]
	switch {
	case m.closing:
		m.mu.Unlock()
		return jobView{}, errClosing()
	case e == nil || m.now().After(e.expires):
		m.mu.Unlock()
		return jobView{}, &apiError{Status: 409, Code: "plan_expired", Message: "this preview has expired; preview the cleanup again"}
	case e.used:
		m.mu.Unlock()
		return jobView{}, &apiError{Status: 409, Code: "plan_used", Message: "this preview has already been carried out"}
	}
	m.mu.Unlock()

	why, running, err := actions.Check(*m.deps, e.plan)
	if err != nil {
		return jobView{}, err
	}
	if why != "" {
		return jobView{}, blockedError(why, running)
	}

	m.mu.Lock()
	switch {
	case m.closing:
		m.mu.Unlock()
		return jobView{}, errClosing()
	case e.used: // confirmed twice at the same moment
		m.mu.Unlock()
		return jobView{}, &apiError{Status: 409, Code: "plan_used", Message: "this preview has already been carried out"}
	case e.simulate != m.simulate:
		// The preview promised a simulation, or a real cleanup: what it
		// showed is what runs, or nothing does.
		m.mu.Unlock()
		return jobView{}, &apiError{Status: 409, Code: "plan_stale", Message: "simulation mode changed since this preview; preview the cleanup again"}
	}
	e.used = true
	m.nextJob++
	j := &job{id: fmt.Sprintf("j%d", m.nextJob), plan: e.plan, scanID: e.scanID, state: "queued", simulate: e.simulate, queued: m.now()}
	m.byID[j.id] = j
	m.order = append(m.order, j.id)
	m.prune()
	m.queue = append(m.queue, j)
	v := j.view(false)
	// Announced before the runner can pick it up, so that job.queued always
	// comes before job.started.
	m.hub.publish("job.queued", v, true)
	m.mu.Unlock()

	select {
	case m.wake <- struct{}{}:
	default:
	}
	return v, nil
}

// prune forgets the oldest finished cleanups beyond keepJobs. Callers hold
// m.mu.
func (m *jobs) prune() {
	for len(m.order) > keepJobs {
		j := m.byID[m.order[0]]
		if j.state == "queued" || j.state == "running" {
			return
		}
		delete(m.byID, j.id)
		m.order = m.order[1:]
	}
}

func errClosing() error {
	return &apiError{Status: 409, Code: "shutting_down", Message: "COptimizer is stopping"}
}

// beginShutdown stops new cleanups from starting. Unless force is set, it
// refuses while a cleanup is queued or running: stopping COptimizer would
// stop that cleanup too.
func (m *jobs) beginShutdown(force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !force && (m.running != nil || len(m.queue) > 0) {
		return &apiError{Status: 409, Code: "busy", Message: "a cleanup is running; wait for it to finish first"}
	}
	m.closing = true
	return nil
}

func blockedError(why string, running []string) error {
	switch why {
	case actions.BlockedAdmin:
		return &apiError{Status: 409, Code: why, Message: "this cleanup needs Administrator rights"}
	case actions.BlockedPrograms:
		return &apiError{Status: 409, Code: why, Message: "close these programs first: " + strings.Join(running, ", ")}
	}
	return &apiError{Status: 409, Code: why, Message: "there is nothing to clean right now"}
}

// loop runs the queued cleanups, one at a time.
func (m *jobs) loop() {
	defer close(m.done)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.wake:
		}
		for m.ctx.Err() == nil {
			m.mu.Lock()
			if len(m.queue) == 0 {
				m.mu.Unlock()
				break
			}
			j := m.queue[0]
			m.queue = m.queue[1:]
			ctx, cancel := context.WithCancel(m.ctx)
			j.cancel, j.state, j.started, m.running = cancel, "running", m.now(), j
			v := j.view(false)
			m.mu.Unlock()

			m.hub.publish("job.started", v, true)
			m.execute(ctx, j)
			cancel()
		}
	}
}

// execute runs one cleanup, measures what it freed, records it, and measures
// the cleaned folders again.
func (m *jobs) execute(ctx context.Context, j *job) {
	p := j.plan
	// Programs may have started while the cleanup waited its turn.
	if why, running, err := actions.Check(*m.deps, p); err != nil || why != "" {
		if err == nil {
			err = blockedError(why, running)
		}
		m.finish(j, actions.Outcome{State: actions.Failed, Error: err.Error()}, 0)
		return
	}
	before := m.free(p.Drive)
	var lastProgress time.Time
	o := actions.Run(ctx, *m.deps, p, j.simulate,
		func(pr actions.Progress) {
			m.mu.Lock()
			j.progress = pr
			v := progressEvent{JobID: j.id, Progress: pr}
			publish := time.Since(lastProgress) >= 250*time.Millisecond || pr.Percent >= 100
			if publish {
				lastProgress = time.Now()
			}
			m.mu.Unlock()
			if publish {
				m.hub.publish("job.progress", v, false)
			}
		},
		func(line string) {
			m.mu.Lock()
			if len(j.log) == maxLog {
				j.log = append(j.log[:0], j.log[1:]...)
			}
			j.log = append(j.log, line)
			m.mu.Unlock()
			m.hub.publish("job.log", logEvent{JobID: j.id, Line: line}, false)
		})
	var freed int64
	if after := m.free(p.Drive); !j.simulate && before >= 0 && after >= 0 {
		freed = after - before
	}
	m.finish(j, o, freed)
	if m.ctx.Err() == nil && !j.simulate && len(p.Rescan()) > 0 && (o.Files > 0 || p.Kind != rules.Delete) {
		if err := m.scans.refresh(m.ctx, j.scanID, p.Rescan()); err != nil && !errors.Is(err, context.Canceled) {
			m.logf("could not measure the cleaned folders again: %v", err)
		}
	}
}

// finish records the end of a cleanup.
func (m *jobs) finish(j *job, o actions.Outcome, freed int64) {
	m.mu.Lock()
	j.state, j.outcome, j.freed, j.finished, j.err = o.State, &o, freed, m.now(), o.Error
	if m.running == j {
		m.running = nil
	}
	v := j.view(false)
	entry := store.HistoryEntry{
		Time: j.finished, Job: j.id, Rule: j.plan.Rule, Action: string(j.plan.Kind), Simulated: j.simulate, State: o.State,
		Estimate: j.plan.Bytes, Unknown: j.plan.Unknown, Deleted: o.Bytes, Files: o.Files, Skipped: o.Skipped, Freed: freed,
		Seconds: j.finished.Sub(j.started).Seconds(), Error: o.Error,
	}
	for _, l := range j.plan.Locations {
		if len(entry.Locations) < 50 {
			entry.Locations = append(entry.Locations, l.Path)
		}
	}
	m.mu.Unlock()
	if err := m.history.Add(entry); err != nil {
		m.logf("could not record the cleanup in the history: %v", err)
	}
	m.hub.publish("job.finished", v, true)
}

// free returns the free space of the drive at root, or -1.
func (m *jobs) free(root string) int64 {
	drives, err := m.system.Drives()
	if err != nil {
		return -1
	}
	if d, ok := findDrive(drives, root); ok {
		return d.Free
	}
	return -1
}

// cancel stops a queued or running cleanup, unless it can't be stopped
// safely.
func (m *jobs) cancel(id string) (jobView, error) {
	m.mu.Lock()
	j := m.byID[id]
	switch {
	case j == nil:
		m.mu.Unlock()
		return jobView{}, &apiError{Status: 404, Code: "not_found", Message: "no such cleanup"}
	case j.state == "queued":
		for i, q := range m.queue {
			if q == j {
				m.queue = append(m.queue[:i], m.queue[i+1:]...)
				break
			}
		}
		j.state, j.finished = actions.Cancelled, m.now()
		j.outcome = &actions.Outcome{State: actions.Cancelled}
		v := j.view(false)
		m.hub.publish("job.finished", v, true)
		m.mu.Unlock()
		return v, nil
	case j.state == "running" && !j.plan.Stoppable && !j.simulate:
		m.mu.Unlock()
		return jobView{}, &apiError{Status: 409, Code: "not_cancellable", Message: "this cleanup can't be stopped safely once it has started"}
	case j.state == "running":
		j.cancel()
	}
	v := j.view(false)
	m.mu.Unlock()
	return v, nil
}

// busy reports whether a cleanup is queued or running.
func (m *jobs) busy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running != nil || len(m.queue) > 0
}

func (m *jobs) get(id string) (jobView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.byID[id]
	if j == nil {
		return jobView{}, &apiError{Status: 404, Code: "not_found", Message: "no such cleanup"}
	}
	return j.view(true), nil
}

// list returns the cleanups kept in memory, newest first.
func (m *jobs) list() []jobView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]jobView, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		out = append(out, m.byID[m.order[i]].view(false))
	}
	return out
}

func (m *jobs) setSimulate(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulate = on
	// Under the lock, so that two changes at once are announced in order.
	m.hub.publish("config.updated", configView{Simulate: on, Cleanups: m.available()}, true)
}

func (m *jobs) config() configView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return configView{Simulate: m.simulate, Cleanups: m.available()}
}

type configView struct {
	Simulate bool `json:"simulate"`
	Cleanups bool `json:"cleanups"` // cleanups are available at all
}

// Views. Callers hold m.mu.

type jobView struct {
	ID        string           `json:"id"`
	RuleID    string           `json:"ruleId"`
	Kind      rules.ActionKind `json:"kind"`
	State     string           `json:"state"`
	Simulated bool             `json:"simulated"`
	Long      bool             `json:"long,omitempty"`
	Stoppable bool             `json:"stoppable"`
	Estimate  int64            `json:"estimate"`
	Unknown   bool             `json:"unknown,omitempty"`
	Command   string           `json:"command,omitempty"`
	Queued    time.Time        `json:"queued"`
	Started   *time.Time       `json:"started,omitempty"`
	Finished  *time.Time       `json:"finished,omitempty"`
	Progress  actions.Progress `json:"progress"`
	Outcome   *actions.Outcome `json:"outcome,omitempty"`
	Freed     int64            `json:"freed"`
	Error     string           `json:"error,omitempty"`
	Log       []string         `json:"log,omitempty"` // only for a single cleanup
}

// view describes the job; full adds the log and the outcome's locations,
// which events leave out to stay small.
func (j *job) view(full bool) jobView {
	v := jobView{ID: j.id, RuleID: j.plan.Rule, Kind: j.plan.Kind, State: j.state, Simulated: j.simulate, Long: j.plan.Long,
		Stoppable: j.plan.Stoppable || j.simulate,
		Estimate:  j.plan.Bytes, Unknown: j.plan.Unknown, Command: j.plan.Command, Queued: j.queued, Progress: j.progress,
		Freed: j.freed, Error: j.err}
	if !j.started.IsZero() {
		t := j.started
		v.Started = &t
	}
	if !j.finished.IsZero() {
		t := j.finished
		v.Finished = &t
	}
	if j.outcome != nil {
		o := *j.outcome
		if !full {
			o.Locations = nil
		}
		v.Outcome = &o
	}
	if full {
		v.Log = append([]string{}, j.log...)
	}
	return v
}

type progressEvent struct {
	JobID    string           `json:"jobId"`
	Progress actions.Progress `json:"progress"`
}

type logEvent struct {
	JobID string `json:"jobId"`
	Line  string `json:"line"`
}
