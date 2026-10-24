package main

import "time"

// quitGuard decides whether a request to quit from the console (Q, or
// Ctrl+C) may stop COptimizer now. Quitting stops a running cleanup too, and
// DISM's can't be stopped safely, so while a cleanup runs the first request
// only warns; a second one soon after quits anyway. The page's Quit button
// is refused outright while a cleanup runs.
type quitGuard struct {
	// begin stops new cleanups from starting; unless force is set, it
	// refuses while a cleanup is queued or running (Server.BeginShutdown).
	begin  func(force bool) error
	now    func() time.Time
	within time.Duration // how soon the second request must come
	warned time.Time     // when the last warning was given
}

const quitWarning = "A cleanup is running, and quitting now would stop it; DISM's cleanup can't be stopped safely.\n" +
	"Wait until it has finished, or repeat within 30 seconds to quit anyway."

// request reports whether to quit now, or else the warning to show. When it
// says to quit, no new cleanup can start any more.
func (g *quitGuard) request() (quit bool, warning string) {
	if g.begin(false) == nil {
		return true, ""
	}
	now := g.now()
	if !g.warned.IsZero() && now.Sub(g.warned) <= g.within {
		g.begin(true)
		return true, ""
	}
	g.warned = now
	return false, quitWarning
}
