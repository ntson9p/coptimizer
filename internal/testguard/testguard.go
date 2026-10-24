// Package testguard is the shared TestMain of every package. It refuses to run
// tests as Administrator, so a bug that slipped past the safety fuses would
// still meet Windows' own permission checks on system files.
//
// The exceptions are GitHub-hosted CI runners, which are thrown away after
// each run, and the explicit read-only smoke mode started by
// scripts\test.ps1 -Smoke -Elevated.
package testguard

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// Main runs the tests in m once the checks pass. Every package with tests
// starts them with
//
//	func TestMain(m *testing.M) { testguard.Main(m) }
func Main(m *testing.M) {
	if err := check(windows.GetCurrentProcessToken().IsElevated(), os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "testguard:", err)
		os.Exit(3)
	}
	if !safety.Armed() {
		fmt.Fprintln(os.Stderr, "testguard: the safety fuses are not armed")
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func check(elevated bool, getenv func(string) string) error {
	switch {
	case !elevated:
		return nil
	case getenv("GITHUB_ACTIONS") == "true" && getenv("RUNNER_ENVIRONMENT") == "github-hosted":
		return nil
	case getenv("COPTIMIZER_SMOKE_ELEVATED") == "1":
		return nil
	}
	return errors.New(`refusing to run tests as Administrator; run scripts\test.ps1 from a normal terminal`)
}
