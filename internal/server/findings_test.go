package server_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/execx"
	"github.com/ntson9p/coptimizer/internal/probe"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/server"
)

// memSnapshots keeps snapshots in memory and can be told to fail.
type memSnapshots struct {
	mu   sync.Mutex
	all  []rules.Snapshot
	fail bool
}

func (m *memSnapshots) Previous(root string, elevated bool) (rules.Snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.all) - 1; i >= 0; i-- {
		if strings.EqualFold(m.all[i].Root, root) && m.all[i].Elevated == elevated {
			return m.all[i], true
		}
	}
	return rules.Snapshot{}, false
}

func (m *memSnapshots) Add(s rules.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("disk full")
	}
	m.all = append(m.all, s)
	return nil
}

type findingsResponse struct {
	ScanID   string          `json:"scanId"`
	Findings []rules.Finding `json:"findings"`
	Totals   map[string]int64
}

func (f *fixture) scanAndWait(tok string) string {
	f.t.Helper()
	resp, data := f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, nil)
	if resp.StatusCode != 200 {
		f.t.Fatalf("start: %d %s", resp.StatusCode, data)
	}
	id := decode[map[string]any](f.t, data)["id"].(string)
	if v := waitForScan(f.t, f, tok, id); v["state"] != "done" {
		f.t.Fatalf("scan = %v", v)
	}
	return id
}

func ids(fs []rules.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestFindingsAfterAScan(t *testing.T) {
	f := newFixture(t)
	f.fs.AddFile(`C:\Users\demo\AppData\Local\npm-cache\_cacache\blob`, 300<<20, time.Now())
	tok := f.login()
	id := f.scanAndWait(tok)

	_, data := f.do("GET", "/api/scans/"+id+"/findings", tok, "", nil)
	rep := decode[findingsResponse](t, data)
	if rep.ScanID != id || !slices.Contains(ids(rep.Findings), "dev.npm-cache") || rep.Totals["safe"] != 300<<20 {
		t.Errorf("findings = %s", data)
	}
	_, data = f.do("GET", "/api/scans/"+id, tok, "", nil)
	sum := decode[map[string]any](t, data)["summary"].(map[string]any)
	if totals := sum["totals"].(map[string]any); totals["safe"] != float64(300<<20) {
		t.Errorf("summary totals = %v", totals)
	}
}

func TestGrowthBetweenScans(t *testing.T) {
	snaps := &memSnapshots{}
	f := newFixture(t, func(c *server.Config) { c.Snapshots = snaps })
	tok := f.login()
	f.scanAndWait(tok)
	if len(snaps.all) != 1 || !snaps.all[0].Elevated {
		t.Fatalf("snapshots after the first scan = %+v", snaps.all)
	}

	f.fs.AddFile(`C:\Users\demo\Videos\new.mp4`, 600<<20, time.Now())
	id := f.scanAndWait(tok)
	_, data := f.do("GET", "/api/scans/"+id+"/findings", tok, "", nil)
	rep := decode[findingsResponse](t, data)
	var growth *rules.Finding
	for i := range rep.Findings {
		if rep.Findings[i].ID == "other.growth" {
			growth = &rep.Findings[i]
		}
	}
	if growth == nil || growth.Items[0].Path != `C:\Users\demo\Videos` || growth.Items[0].Bytes != 600<<20 {
		t.Fatalf("growth = %+v in %s", growth, data)
	}
}

func TestASnapshotThatCantBeSavedDoesntBreakTheScan(t *testing.T) {
	f := newFixture(t, func(c *server.Config) { c.Snapshots = &memSnapshots{fail: true} })
	tok := f.login()
	id := f.scanAndWait(tok)
	if resp, _ := f.do("GET", "/api/scans/"+id+"/findings", tok, "", nil); resp.StatusCode != 200 {
		t.Errorf("findings: status %d", resp.StatusCode)
	}
}

func probeDeps(release <-chan struct{}) *probe.Deps {
	reg := &probe.FakeRegistry{}
	reg.Set(probe.LocalMachine, `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled", uint64(0))
	return &probe.Deps{
		Registry: reg,
		Stat:     func(string) (int64, bool) { return 0, false },
		Runner: &execx.Fake{Respond: func(ctx context.Context, c execx.Cmd) (execx.Result, error) {
			if slices.Contains(c.Args, "/AnalyzeComponentStore") {
				<-release
			}
			return execx.Result{Stdout: []byte("Reserved storage is enabled.")}, nil
		}},
		Elevated:    true,
		SystemRoot:  `C:\Windows`,
		SystemDrive: `C:`,
	}
}

type systemResponse struct {
	Probes []probe.Result `json:"probes"`
}

func probeState(t *testing.T, f *fixture, tok, name string) probe.State {
	t.Helper()
	_, data := f.do("GET", "/api/system", tok, "", nil)
	for _, p := range decode[systemResponse](t, data).Probes {
		if p.Name == name {
			return p.State
		}
	}
	t.Fatalf("no probe %s in %s", name, data)
	return ""
}

func TestSystemInformation(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := newFixture(t, func(c *server.Config) { c.Probes = probeDeps(release) })
	tok := f.login()
	deadline := time.Now().Add(5 * time.Second)
	for probeState(t, f, tok, "power") != probe.OK || probeState(t, f, tok, "reservedStorage") != probe.OK {
		if time.Now().After(deadline) {
			t.Fatal("the probes that run by themselves didn't finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s := probeState(t, f, tok, "componentStore"); s != probe.NotRun {
		t.Errorf("the on-demand probe is %s before anyone asked", s)
	}

	if resp, data := f.do("POST", "/api/system/componentStore", tok, "", nil); resp.StatusCode != 200 {
		t.Fatalf("run: %d %s", resp.StatusCode, data)
	}
	if resp, _ := f.do("POST", "/api/system/componentStore", tok, "", nil); resp.StatusCode != 409 {
		t.Errorf("second run while running: status %d; want 409", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/system/format-c", tok, "", nil); resp.StatusCode != 404 {
		t.Errorf("unknown probe: status %d; want 404", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/system/power", "", "", nil); resp.StatusCode != 401 {
		t.Errorf("without a token: status %d; want 401", resp.StatusCode)
	}
}

func TestNoSystemInformationWithoutProbes(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	_, data := f.do("GET", "/api/system", tok, "", nil)
	if len(decode[systemResponse](t, data).Probes) != 0 {
		t.Errorf("system = %s; want no probes", data)
	}
	if resp, _ := f.do("POST", "/api/system/power", tok, "", nil); resp.StatusCode != 404 {
		t.Errorf("run without probes: status %d; want 404", resp.StatusCode)
	}
}
