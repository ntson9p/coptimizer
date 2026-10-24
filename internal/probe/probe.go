// Package probe asks Windows things a folder scan can't see: whether
// hibernation is on and where the page files are, which WSL distributions
// exist, whether reserved storage is on, and (on request) how much of the
// component store DISM could clean up. Every probe only reads.
//
// The probes run only Windows' own dism.exe from System32. Tools installed in
// user folders (docker, wsl, npm…) are never started from here: the server
// runs as Administrator, and a program in a folder the user can write to could
// have been replaced by malware.
package probe

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/execx"
)

// State says where a probe stands.
type State string

const (
	OK         State = "ok"
	NotRun     State = "not-run" // a probe that only runs on request, not yet requested
	Running    State = "running"
	NeedsAdmin State = "needs-admin"
	Failed     State = "failed"
)

// Result is the latest outcome of a probe.
type Result struct {
	Name     string    `json:"name"`
	State    State     `json:"state"`
	OnDemand bool      `json:"onDemand"`
	Message  string    `json:"message,omitempty"`
	Updated  time.Time `json:"updated,omitzero"`
	Data     any       `json:"data,omitempty"`
}

// Deps are what the probes read from.
type Deps struct {
	Registry    Registry
	Stat        func(path string) (size int64, ok bool) // size of an existing file
	Runner      execx.Runner
	Elevated    bool
	SystemRoot  string // `C:\Windows`
	SystemDrive string // `C:`
	Now         func() time.Time
}

type probeFunc func(ctx context.Context, d Deps) (data any, state State, msg string)

var probes = []struct {
	name     string
	onDemand bool
	dism     bool // DISM refuses to run twice at once
	run      probeFunc
}{
	{name: "power", run: probePower},
	{name: "wsl", run: probeWSL},
	{name: "reservedStorage", dism: true, run: probeReservedStorage},
	{name: "componentStore", onDemand: true, dism: true, run: probeComponentStore},
}

var (
	ErrUnknown = errors.New("probe: no such probe")
	ErrBusy    = errors.New("probe: already running")
)

// Manager runs the probes and keeps their latest results.
type Manager struct {
	deps   Deps
	notify func(Result)
	ctx    context.Context
	cancel context.CancelFunc
	dism   sync.Mutex

	mu      sync.Mutex
	results map[string]Result
	running map[string]bool
}

// NewManager prepares the probes; notify, if set, hears about every change.
func NewManager(d Deps, notify func(Result)) *Manager {
	if d.Now == nil {
		d.Now = time.Now
	}
	if notify == nil {
		notify = func(Result) {}
	}
	m := &Manager{deps: d, notify: notify, results: make(map[string]Result), running: make(map[string]bool)}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	for _, p := range probes {
		m.results[p.name] = Result{Name: p.name, State: NotRun, OnDemand: p.onDemand}
	}
	return m
}

// Start runs, in the background, every probe that doesn't wait for a request.
func (m *Manager) Start() {
	for _, p := range probes {
		if !p.onDemand {
			m.Run(p.name)
		}
	}
}

// Run starts one probe in the background. While it runs, its result keeps
// the previous data.
func (m *Manager) Run(name string) error {
	m.mu.Lock()
	r, ok := m.results[name]
	switch {
	case !ok:
		m.mu.Unlock()
		return ErrUnknown
	case m.running[name]:
		m.mu.Unlock()
		return ErrBusy
	}
	m.running[name] = true
	r.State, r.Message = Running, ""
	m.results[name] = r
	m.mu.Unlock()
	m.notify(r)
	go m.run(name)
	return nil
}

func (m *Manager) run(name string) {
	for _, p := range probes {
		if p.name != name {
			continue
		}
		if p.dism {
			m.dism.Lock()
			defer m.dism.Unlock()
		}
		data, state, msg := p.run(m.ctx, m.deps)
		if m.ctx.Err() != nil {
			return // shutting down
		}
		r := Result{Name: name, State: state, OnDemand: p.onDemand, Message: msg, Updated: m.deps.Now(), Data: data}
		m.mu.Lock()
		m.results[name] = r
		delete(m.running, name)
		m.mu.Unlock()
		m.notify(r)
	}
}

// Results returns the latest result of every probe.
func (m *Manager) Results() []Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Result, 0, len(probes))
	for _, p := range probes {
		out = append(out, m.results[p.name])
	}
	return out
}

// Close stops running probes.
func (m *Manager) Close() { m.cancel() }
