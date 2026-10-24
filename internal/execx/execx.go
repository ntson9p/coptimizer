// Package execx runs programs for COptimizer: always from an absolute path
// with an argument list (never through a shell), with a time limit, and inside
// a Windows job object, so that stopping a program also stops every process it
// started.
package execx

import (
	"context"
	"sync"
	"time"
)

// Cmd is a program to run.
type Cmd struct {
	Path    string // absolute path of the program
	Args    []string
	Dir     string        // working folder; "" means the program's own folder
	Timeout time.Duration // 0: only the context limits it
}

// Result is what a program left behind. A program that ran and exited with a
// non-zero code is a Result, not an error.
type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// Runner runs programs. Real runs them; tests and demo mode use Fake.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// Fake answers every Run with Respond and remembers the calls.
type Fake struct {
	Respond func(ctx context.Context, c Cmd) (Result, error)

	mu    sync.Mutex
	calls []Cmd
}

func (f *Fake) Run(ctx context.Context, c Cmd) (Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	return f.Respond(ctx, c)
}

// Calls returns the commands run so far.
func (f *Fake) Calls() []Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Cmd(nil), f.calls...)
}
