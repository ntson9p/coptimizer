package server_test

import (
	"bufio"
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/actions"
	"github.com/ntson9p/coptimizer/internal/execx"
	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/server"
	"github.com/ntson9p/coptimizer/internal/store"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

// freeingSystem is a drive whose free space grows by what the in-memory file
// system has had deleted.
type freeingSystem struct{ fs *memfs.FS }

func (s freeingSystem) Drives() ([]sysinfo.Drive, error) {
	return []sysinfo.Drive{{Root: `C:\`, FS: "NTFS", Total: 100 << 30, Free: 40<<30 + s.fs.Freed("C:")}}, nil
}
func (freeingSystem) Elevated() bool { return true }

type fakePrograms struct {
	mu    sync.Mutex
	names []string
}

func (p *fakePrograms) Running() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.names), nil
}

func (p *fakePrograms) set(names ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.names = names
}

type fakeBin struct{ emptied int }

func (b *fakeBin) RecycleBin(string) (int64, int64, error) { return 100 << 20, 2, nil }
func (b *fakeBin) EmptyRecycleBin(string) error            { b.emptied++; return nil }

type cleanups struct {
	programs *fakePrograms
	runner   *execx.Fake
	history  *store.MemoryHistory
}

// withCleanups gives the fixture's server cleanups on its in-memory C:.
func withCleanups(c *cleanups) func(*server.Config) {
	return func(cfg *server.Config) {
		fs := cfg.Lister.(*memfs.FS)
		env := cfg.Env
		policy, err := safety.NewPolicy(safety.Places{SystemDrive: env.SystemDrive, Windows: env.Windows, ProgramData: env.ProgramData,
			ProgramFiles: env.ProgramFiles, ProgramFilesX86: env.ProgramFilesX86, Users: env.Users})
		if err != nil {
			panic(err)
		}
		if c.programs == nil {
			c.programs = &fakePrograms{}
		}
		if c.runner == nil {
			c.runner = &execx.Fake{Respond: func(context.Context, execx.Cmd) (execx.Result, error) { return execx.Result{}, nil }}
		}
		c.history = &store.MemoryHistory{}
		cfg.System = freeingSystem{fs}
		cfg.Actions = &actions.Deps{Cleaner: fs, Policy: policy, Programs: c.programs, RecycleBin: &fakeBin{}, Mutator: &fakeBin{},
			Runner: c.runner, Elevated: true, Env: env, Now: cfg.Now}
		cfg.History = c.history
	}
}

const npm = `C:\Users\demo\AppData\Local\npm-cache\_cacache`

// oldFile adds a file last changed long before the fixture's clock.
func oldFile(f *fixture, path string, size int64) {
	f.fs.AddFile(path, size, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
}

func (f *fixture) plan(tok, rule string) (int, map[string]any) {
	f.t.Helper()
	resp, data := f.do("POST", "/api/plans", tok, `{"ruleId":"`+rule+`"}`, nil)
	return resp.StatusCode, decode[map[string]any](f.t, data)
}

func (f *fixture) startJob(tok, planID string) (int, map[string]any) {
	f.t.Helper()
	resp, data := f.do("POST", "/api/jobs", tok, `{"planId":"`+planID+`"}`, nil)
	return resp.StatusCode, decode[map[string]any](f.t, data)
}

func (f *fixture) waitForJob(tok, id string) map[string]any {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, data := f.do("GET", "/api/jobs/"+id, tok, "", nil)
		v := decode[map[string]any](f.t, data)
		if s := v["state"]; s != "queued" && s != "running" {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("the cleanup did not finish")
	return nil
}

func TestACleanupFromPreviewToHistory(t *testing.T) {
	c := &cleanups{}
	f := newFixture(t, withCleanups(c))
	oldFile(f, npm+`\index-v5\aa`, 200<<20)
	oldFile(f, npm+`\content-v2\bb`, 100<<20)
	tok := f.login()
	scanID := f.scanAndWait(tok)
	unaccounted := func() any {
		_, data := f.do("GET", "/api/scans/"+scanID, tok, "", nil)
		return decode[map[string]any](t, data)["summary"].(map[string]any)["unaccounted"]
	}
	before := unaccounted()

	req, _ := http.NewRequest("GET", f.ts.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := f.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := bufio.NewReader(resp.Body)
	readEvents(t, events, "hello")

	code, plan := f.plan(tok, "dev.npm-cache")
	if code != 200 || plan["bytes"] != float64(300<<20) || plan["files"] != 2.0 || plan["simulate"] != false || plan["blocked"] != nil {
		t.Fatalf("plan: %d %v", code, plan)
	}
	if locs := plan["locations"].([]any); len(locs) != 1 || locs[0].(map[string]any)["path"] != `C:\Users\demo\AppData\Local\npm-cache` {
		t.Errorf("plan locations = %v", locs)
	}
	if !f.fs.Exists(npm + `\index-v5\aa`) {
		t.Fatal("the preview deleted something")
	}

	code, job := f.startJob(tok, plan["id"].(string))
	if code != 200 || job["state"] != "queued" {
		t.Fatalf("start: %d %v", code, job)
	}
	done := f.waitForJob(tok, job["id"].(string))
	o := done["outcome"].(map[string]any)
	if done["state"] != "succeeded" || done["freed"] != float64(300<<20) || o["files"] != 2.0 || o["bytes"] != float64(300<<20) {
		t.Fatalf("finished cleanup = %v", done)
	}
	if f.fs.Exists(npm+`\index-v5\aa`) || f.fs.Exists(npm+`\content-v2\bb`) || !f.fs.Exists(`C:\Users\demo\AppData\Local\npm-cache`) {
		t.Error("the cache wasn't cleaned, or its folder went too")
	}

	got := readEvents(t, events, "scan.updated")
	var kinds []string
	for _, e := range got {
		kinds = append(kinds, strings.SplitN(e, "#", 2)[0])
	}
	for _, want := range []string{"job.queued", "job.started", "job.finished", "scan.updated"} {
		if !slices.Contains(kinds, want) {
			t.Errorf("events %v lack %s", kinds, want)
		}
	}
	// The findings now show the cleaned cache as gone.
	id := done["id"].(string)
	_, data := f.do("GET", "/api/status", tok, "", nil)
	last := decode[map[string]any](t, data)["lastScan"].(map[string]any)
	if last["updated"] == nil {
		t.Errorf("the scan wasn't marked as measured again: %v", last)
	}
	// Space in use and space counted both shrank by what was freed.
	if after := unaccounted(); after != before {
		t.Errorf("not accounted for: %v before the cleanup, %v after", before, after)
	}
	_, data = f.do("GET", "/api/scans/"+last["id"].(string)+"/findings", tok, "", nil)
	if rep := decode[findingsResponse](t, data); slices.Contains(ids(rep.Findings), "dev.npm-cache") {
		t.Errorf("the npm cache is still a finding after %s", id)
	}
	_, data = f.do("GET", "/api/history", tok, "", nil)
	h := decode[[]store.HistoryEntry](t, data)
	if len(h) != 1 || h[0].Rule != "dev.npm-cache" || h[0].Freed != 300<<20 || h[0].Estimate != 300<<20 || h[0].State != "succeeded" {
		t.Errorf("history = %+v", h)
	}
}

func TestPreviewsWorkOnceAndExpire(t *testing.T) {
	f := newFixture(t, withCleanups(&cleanups{}))
	oldFile(f, npm+`\a`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)

	// Both previews first: once the first cleanup ran, the finding is gone.
	_, plan := f.plan(tok, "dev.npm-cache")
	_, later := f.plan(tok, "dev.npm-cache")
	if code, _ := f.startJob(tok, plan["id"].(string)); code != 200 {
		t.Fatalf("first start: %d", code)
	}
	if code, v := f.startJob(tok, plan["id"].(string)); code != 409 || v["error"].(map[string]any)["code"] != "plan_used" {
		t.Errorf("second start of the same preview: %d %v", code, v)
	}
	f.now.Add(11 * 60)
	if code, v := f.startJob(tok, later["id"].(string)); code != 409 || v["error"].(map[string]any)["code"] != "plan_expired" {
		t.Errorf("an expired preview: %d %v", code, v)
	}
	if code, _ := f.startJob(tok, "p999"); code != 409 {
		t.Errorf("an unknown preview: %d; want 409", code)
	}
}

func TestCleanupsWaitForProgramsToClose(t *testing.T) {
	c := &cleanups{programs: &fakePrograms{names: []string{"chrome.exe"}}}
	f := newFixture(t, withCleanups(c))
	oldFile(f, `C:\Users\demo\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)

	_, plan := f.plan(tok, "browsers.chrome-cache")
	if plan["blocked"] != actions.BlockedPrograms || plan["running"].([]any)[0] != "chrome.exe" {
		t.Fatalf("plan = %v", plan)
	}
	code, v := f.startJob(tok, plan["id"].(string))
	if code != 409 || v["error"].(map[string]any)["code"] != actions.BlockedPrograms {
		t.Fatalf("start while Chrome runs: %d %v", code, v)
	}
	c.programs.set()
	if code, job := f.startJob(tok, plan["id"].(string)); code != 200 || f.waitForJob(tok, job["id"].(string))["state"] != "succeeded" {
		t.Errorf("after closing Chrome: %d", code)
	}
}

func TestSimulationModeDeletesNothing(t *testing.T) {
	c := &cleanups{}
	f := newFixture(t, withCleanups(c))
	oldFile(f, npm+`\a`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)
	if resp, data := f.do("PUT", "/api/config", tok, `{"simulate":true}`, nil); resp.StatusCode != 200 || !strings.Contains(string(data), `"simulate":true`) {
		t.Fatalf("config: %d %s", resp.StatusCode, data)
	}
	_, plan := f.plan(tok, "dev.npm-cache")
	if plan["simulate"] != true {
		t.Errorf("plan = %v", plan)
	}
	_, job := f.startJob(tok, plan["id"].(string))
	done := f.waitForJob(tok, job["id"].(string))
	if done["simulated"] != true || done["freed"] != 0.0 || done["outcome"].(map[string]any)["bytes"] != float64(300<<20) {
		t.Errorf("simulated cleanup = %v", done)
	}
	if !f.fs.Exists(npm + `\a`) {
		t.Error("a simulation deleted a file")
	}
	if h, _ := c.history.Recent(1); len(h) != 1 || !h[0].Simulated {
		t.Errorf("history = %+v", h)
	}
	_, data := f.do("GET", "/api/status", tok, "", nil)
	if st := decode[map[string]any](t, data); st["simulate"] != true || st["cleanups"] != true {
		t.Errorf("status = %v", st)
	}
}

func TestCleanupRequestsCantNameWhatToDelete(t *testing.T) {
	f := newFixture(t, withCleanups(&cleanups{}))
	oldFile(f, npm+`\a`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)
	for path, body := range map[string]string{
		"/api/plans":  `{"ruleId":"dev.npm-cache","folders":["C:\\Windows"]}`,
		"/api/jobs":   `{"planId":"p1","path":"C:\\Users"}`,
		"/api/config": `{"simulate":false,"deleteEverything":true}`,
	} {
		method := "POST"
		if path == "/api/config" {
			method = "PUT"
		}
		if resp, data := f.do(method, path, tok, body, nil); resp.StatusCode != 400 {
			t.Errorf("%s %s: %d %s; want 400", path, body, resp.StatusCode, data)
		}
	}
	if code, _ := f.plan(tok, "personal.downloads"); code != 404 {
		t.Errorf("a finding the scan didn't make: %d; want 404", code)
	}
	if resp, _ := f.do("POST", "/api/plans", "", `{"ruleId":"dev.npm-cache"}`, nil); resp.StatusCode != 401 {
		t.Errorf("without a token: %d", resp.StatusCode)
	}
}

func TestLongCleanupsCantBeStoppedOrQuit(t *testing.T) {
	release := make(chan struct{})
	c := &cleanups{runner: &execx.Fake{Respond: func(ctx context.Context, cmd execx.Cmd) (execx.Result, error) {
		cmd.Output("[=====       50.0%           ]")
		select {
		case <-release:
			return execx.Result{}, nil
		case <-ctx.Done(): // the server closing after a failed test
			return execx.Result{}, ctx.Err()
		}
	}}}
	f := newFixture(t, withCleanups(c))
	oldFile(f, `C:\Windows\WinSxS\amd64_x\big.dll`, 2<<30)
	oldFile(f, npm+`\a`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)

	_, plan := f.plan(tok, "system.component-store")
	if plan["long"] != true || plan["unknown"] != true || !strings.HasSuffix(plan["command"].(string), "/StartComponentCleanup") {
		t.Fatalf("plan = %v", plan)
	}
	_, dism := f.startJob(tok, plan["id"].(string))
	_, plan2 := f.plan(tok, "dev.npm-cache")
	_, queued := f.startJob(tok, plan2["id"].(string))

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, data := f.do("GET", "/api/jobs/"+dism["id"].(string), tok, "", nil)
		if v := decode[map[string]any](t, data); v["state"] == "running" && v["progress"].(map[string]any)["percent"] == 50.0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the DISM cleanup didn't report its progress")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp, _ := f.do("DELETE", "/api/jobs/"+dism["id"].(string), tok, "", nil); resp.StatusCode != 409 {
		t.Errorf("cancelling DISM: %d; want 409", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/shutdown", tok, "", nil); resp.StatusCode != 409 || f.stopped.Load() {
		t.Errorf("quitting during a cleanup: %d", resp.StatusCode)
	}
	if resp, data := f.do("DELETE", "/api/jobs/"+queued["id"].(string), tok, "", nil); resp.StatusCode != 200 ||
		decode[map[string]any](t, data)["state"] != "cancelled" {
		t.Errorf("cancelling the queued cleanup: %d %s", resp.StatusCode, data)
	}
	close(release)
	if v := f.waitForJob(tok, dism["id"].(string)); v["state"] != "succeeded" {
		t.Errorf("DISM cleanup = %v", v)
	}
	if !f.fs.Exists(npm + `\a`) {
		t.Error("the cancelled cleanup ran anyway")
	}
}

func TestARunningDeleteCanBeCancelled(t *testing.T) {
	f := newFixture(t, withCleanups(&cleanups{}))
	for i := range 50 {
		oldFile(f, npm+`\d`+string(rune('a'+i%26))+`\f`+string(rune('a'+i/26)), 10<<20)
	}
	tok := f.login()
	f.scanAndWait(tok)
	_, plan := f.plan(tok, "dev.npm-cache")
	f.fs.SetDelay(50 * time.Millisecond)
	_, job := f.startJob(tok, plan["id"].(string))
	for {
		_, data := f.do("GET", "/api/jobs/"+job["id"].(string), tok, "", nil)
		if decode[map[string]any](t, data)["state"] == "running" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.do("DELETE", "/api/jobs/"+job["id"].(string), tok, "", nil)
	if v := f.waitForJob(tok, job["id"].(string)); v["state"] != "cancelled" {
		t.Errorf("state = %v", v["state"])
	}
}

func TestAPreviewRunsAsItWasShown(t *testing.T) {
	f := newFixture(t, withCleanups(&cleanups{}))
	oldFile(f, npm+`\a`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)
	f.do("PUT", "/api/config", tok, `{"simulate":true}`, nil)
	_, plan := f.plan(tok, "dev.npm-cache")
	// Simulation turned off in another tab: the preview that promised a
	// simulation must not delete anything.
	f.do("PUT", "/api/config", tok, `{"simulate":false}`, nil)
	if code, v := f.startJob(tok, plan["id"].(string)); code != 409 || v["error"].(map[string]any)["code"] != "plan_stale" {
		t.Errorf("confirming a simulation's preview after simulation was turned off: %d %v", code, v)
	}
	if !f.fs.Exists(npm + `\a`) {
		t.Fatal("a preview made in simulation mode deleted a file")
	}
}

func TestNoNewCleanupsOnceStopping(t *testing.T) {
	f := newFixture(t, withCleanups(&cleanups{}))
	oldFile(f, npm+`\a`, 300<<20)
	tok := f.login()
	f.scanAndWait(tok)
	_, plan := f.plan(tok, "dev.npm-cache")
	if resp, _ := f.do("POST", "/api/shutdown", tok, "", nil); resp.StatusCode != 200 {
		t.Fatalf("quit: %d", resp.StatusCode)
	}
	if code, v := f.startJob(tok, plan["id"].(string)); code != 409 || v["error"].(map[string]any)["code"] != "shutting_down" {
		t.Errorf("a cleanup confirmed while stopping: %d %v", code, v)
	}
	if !f.fs.Exists(npm + `\a`) {
		t.Fatal("a cleanup ran while COptimizer was stopping")
	}
}

func TestNoCleanupsWithoutActions(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	f.scanAndWait(tok)
	if code, _ := f.plan(tok, "dev.npm-cache"); code != 404 {
		t.Errorf("plan without cleanups: %d; want 404", code)
	}
	_, data := f.do("GET", "/api/status", tok, "", nil)
	if st := decode[map[string]any](t, data); st["cleanups"] != false {
		t.Errorf("status = %v", st)
	}
	if resp, data := f.do("GET", "/api/history", tok, "", nil); resp.StatusCode != 200 || string(data) != "[]\n" {
		t.Errorf("history: %d %s", resp.StatusCode, data)
	}
}
