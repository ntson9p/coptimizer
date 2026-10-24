// Package execx runs programs for COptimizer: always from an absolute path
// with an argument list (never through a shell), with a time limit, and inside
// a Windows job object, so that stopping a program also stops every process it
// started.
package execx

import (
	"bytes"
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
	// Output, if set, receives the program's output as it comes, one line at
	// a time (stdout and stderr, never at the same time). A line ends at a
	// line feed or a carriage return, so a progress bar redrawn with
	// carriage returns arrives as lines too; empty lines are left out.
	Output func(line string)
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

// maxLine is the longest line passed to Cmd.Output; longer ones are cut.
const maxLine = 4096

// lines splits a program's output into lines for fn. Each output stream
// writes to its own lineStream; calls to fn never overlap.
type lines struct {
	fn      func(string)
	mu      sync.Mutex
	streams []*lineStream
}

func (l *lines) stream() *lineStream {
	s := &lineStream{l: l}
	l.streams = append(l.streams, s)
	return s
}

// flush passes on the last, unterminated line of every stream.
func (l *lines) flush() {
	for _, s := range l.streams {
		s.Write([]byte{'\n'})
	}
}

type lineStream struct {
	l   *lines
	buf bytes.Buffer
}

func (s *lineStream) Write(p []byte) (int, error) {
	for _, c := range p {
		if c != '\n' && c != '\r' {
			if s.buf.Len() < maxLine {
				s.buf.WriteByte(c)
			}
			continue
		}
		if s.buf.Len() > 0 {
			line := s.buf.String()
			s.buf.Reset()
			s.l.mu.Lock()
			s.l.fn(line)
			s.l.mu.Unlock()
		}
	}
	return len(p), nil
}
