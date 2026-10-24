package main

import (
	"errors"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

func TestQuittingDuringACleanupNeedsASecondRequest(t *testing.T) {
	busy, closed, forced := true, false, false
	begin := func(force bool) error {
		if busy && !force {
			return errors.New("busy")
		}
		closed, forced = true, force
		return nil
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	g := &quitGuard{begin: begin, now: func() time.Time { return now }, within: 30 * time.Second}

	if quit, warning := g.request(); quit || warning == "" || closed {
		t.Fatal("the first request during a cleanup quit without a warning")
	}
	now = now.Add(10 * time.Second)
	if quit, _ := g.request(); !quit || !closed || !forced {
		t.Error("a second request within 30 seconds didn't quit, closing the queue first")
	}
	closed, forced = false, false

	// Too late: the warning comes again.
	now = now.Add(time.Minute)
	if quit, _ := g.request(); quit {
		t.Error("a request a minute after the warning quit at once")
	}
	now = now.Add(time.Minute)
	if quit, _ := g.request(); quit {
		t.Error("a request a minute after the last warning quit at once")
	}

	busy = false
	if quit, warning := g.request(); !quit || warning != "" || !closed || forced {
		t.Error("with no cleanup running, a request must close the queue and quit at once")
	}
}
