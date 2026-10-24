package demo_test

import (
	"context"
	"testing"

	"github.com/ntson9p/coptimizer/internal/actions"
	"github.com/ntson9p/coptimizer/internal/demo"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

// TestDemoMachineShowsEveryKindOfFinding checks that the simulated PC scans
// cleanly and that demo mode has something to show for each part of the page.
func TestDemoMachineShowsEveryKindOfFinding(t *testing.T) {
	m := demo.New(0)
	drives, _ := m.System.Drives()
	if m.System.Elevated() || len(drives) != 3 {
		t.Fatalf("drives = %+v, elevated = %v", drives, m.System.Elevated())
	}
	res, err := scan.Run(context.Background(), m.FS, scan.Options{Roots: []string{`C:\`}})
	if err != nil {
		t.Fatal(err)
	}
	if c := drives[0]; res.Allocated <= 0 || res.Allocated > c.Used() {
		t.Errorf("counted %d bytes, but C: uses only %d", res.Allocated, c.Used())
	}
	if res.Shared == 0 || res.CloudOnly == 0 || res.Errors != 1 {
		t.Errorf("shared %d cloud-only %d errors %d; want hard links, online-only files and one unreadable folder",
			res.Shared, res.CloudOnly, res.Errors)
	}

	prev, ok := m.Snapshots.Previous(`C:\`, false)
	if !ok {
		t.Fatal("no earlier scan to compare with")
	}
	rep := rules.Evaluate(res, m.Env, rules.Options{Previous: []rules.Snapshot{prev}})
	got := map[string]bool{}
	for _, f := range rep.Findings {
		got[f.ID] = true
	}
	for _, id := range []string{
		"system.hiberfil", "system.pagefile", "system.restore-points", "system.component-store", "system.windows",
		"system.programs", "system.error-reports", "system.shader-caches", "updates.update-assistant",
		"updates.delivery-optimization",
		"virtual.wsl", "dev.npm-cache", "dev.pnpm", "dev.browser-testing", "dev.node-modules",
		"dev.editor-caches", "dev.editor-workspaces", "dev.editor-extensions", "browsers.chrome-cache",
		"browsers.profile-data", "apps.teams-cache", "media.recordings", "games.installed",
		"personal.downloads", "personal.desktop-documents", "personal.media", "personal.recycle-bin",
		"personal.temp", "personal.other-accounts", "personal.big-files", "other.big-logs",
		"other.unrecognized", "other.growth",
	} {
		if !got[id] {
			t.Errorf("the demo shows no %s finding", id)
		}
	}
}

// TestDemoCleanupsFreeSpace cleans the simulated npm cache and empties the
// simulated Recycle Bin: the drive gains exactly what was deleted.
func TestDemoCleanupsFreeSpace(t *testing.T) {
	m := demo.New(0)
	res, err := scan.Run(context.Background(), m.FS, scan.Options{Roots: []string{`C:\`}})
	if err != nil {
		t.Fatal(err)
	}
	rep := rules.Evaluate(res, m.Env, rules.Options{})
	before, _ := m.System.Drives()
	var freed int64
	for _, id := range []string{"dev.npm-cache", "personal.recycle-bin"} {
		f, _ := rep.Find(id)
		p, err := actions.Prepare(context.Background(), m.Actions, rep, f)
		if err != nil || p.Blocked != "" || p.Bytes == 0 {
			t.Fatalf("%s: plan %+v, %v", id, p, err)
		}
		o := actions.Run(context.Background(), m.Actions, p, false, func(actions.Progress) {}, func(string) {})
		if o.State != actions.Succeeded {
			t.Fatalf("%s: %+v", id, o)
		}
		freed += p.Bytes
	}
	after, _ := m.System.Drives()
	if got := after[0].Free - before[0].Free; got != freed {
		t.Errorf("C: gained %d bytes; the cleanups deleted %d", got, freed)
	}
}
