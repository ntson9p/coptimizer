package actions_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/actions"
	"github.com/ntson9p/coptimizer/internal/execx"
	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

const (
	mb    = int64(1) << 20
	alice = `C:\Users\alice`
	local = alice + `\AppData\Local`
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type programs []string

func (p programs) Running() ([]string, error) { return p, nil }

type bin struct {
	bytes, items int64
	mu           sync.Mutex
	emptied      []string
}

func (b *bin) RecycleBin(string) (int64, int64, error) { return b.bytes, b.items, nil }
func (b *bin) EmptyRecycleBin(drive string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.emptied = append(b.emptied, drive)
	return nil
}

// machine is a simulated PC with its findings.
type machine struct {
	t    *testing.T
	fs   *memfs.FS
	deps actions.Deps
	bin  *bin
	run  *execx.Fake
}

func newMachine(t *testing.T, elevated bool) *machine {
	t.Helper()
	env := rules.DefaultEnv("alice")
	p, err := safety.NewPolicy(safety.Places{SystemDrive: env.SystemDrive, Windows: env.Windows, ProgramData: env.ProgramData,
		ProgramFiles: env.ProgramFiles, ProgramFilesX86: env.ProgramFilesX86, Users: env.Users})
	if err != nil {
		t.Fatal(err)
	}
	m := &machine{t: t, fs: memfs.New(), bin: &bin{}}
	m.run = &execx.Fake{Respond: func(context.Context, execx.Cmd) (execx.Result, error) { return execx.Result{}, nil }}
	m.deps = actions.Deps{Cleaner: m.fs, Policy: p, Programs: programs{"explorer.exe"}, RecycleBin: m.bin, Mutator: m.bin,
		Runner: m.run, Elevated: elevated, Env: env, Now: func() time.Time { return now }}
	return m
}

func (m *machine) file(path string, size int64, age time.Duration) {
	m.fs.AddFile(path, size, now.Add(-age))
}

// prepare scans the PC and plans the action of finding id.
func (m *machine) prepare(id string) *actions.Plan {
	m.t.Helper()
	res, err := scan.Run(context.Background(), m.fs, scan.Options{Roots: []string{`C:\`}})
	if err != nil {
		m.t.Fatal(err)
	}
	rep := rules.Evaluate(res, m.deps.Env, rules.Options{})
	f, ok := rep.Find(id)
	if !ok {
		m.t.Fatalf("no finding %s", id)
	}
	p, err := actions.Prepare(context.Background(), m.deps, rep, f)
	if err != nil {
		m.t.Fatal(err)
	}
	return p
}

func (m *machine) execute(p *actions.Plan, simulate bool) (actions.Outcome, []float64, []string) {
	var pct []float64
	var logs []string
	o := actions.Run(context.Background(), m.deps, p, simulate,
		func(pr actions.Progress) { pct = append(pct, pr.Percent) }, func(l string) { logs = append(logs, l) })
	return o, pct, logs
}

const old = 30 * 24 * time.Hour

func TestOnlyYourOwnProfileIsCleaned(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\npm-cache\_cacache\a`, 300*mb, old)
	m.file(`C:\Users\bob\AppData\Local\npm-cache\_cacache\b`, 300*mb, old)

	p := m.prepare("dev.npm-cache")
	if p.Blocked != "" || p.Files != 1 || p.Bytes != 300*mb || len(p.Locations) != 1 || p.Locations[0].Path != local+`\npm-cache` {
		t.Fatalf("plan = %+v", p)
	}
	if len(p.Left) != 1 || p.Left[0].Reason != actions.LeftOtherAccount || !strings.Contains(p.Left[0].Path, `\bob\`) {
		t.Errorf("left = %+v", p.Left)
	}
	o, _, _ := m.execute(p, false)
	if o.State != actions.Succeeded || o.Bytes != p.Bytes || o.Files != 1 {
		t.Errorf("outcome = %+v", o)
	}
	if m.fs.Exists(local+`\npm-cache\_cacache\a`) || !m.fs.Exists(`C:\Users\bob\AppData\Local\npm-cache\_cacache\b`) {
		t.Error("cleaned the wrong account")
	}
}

func TestSystemFoldersNeedAdministratorRights(t *testing.T) {
	for _, elevated := range []bool{false, true} {
		m := newMachine(t, elevated)
		m.file(`C:\Windows\Temp\setup.log`, 200*mb, old)
		p := m.prepare("system.temp")
		if elevated {
			if p.Blocked != "" || p.Files != 1 {
				t.Errorf("elevated: plan = %+v", p)
			}
			continue
		}
		if p.Blocked != actions.BlockedNothing || len(p.Left) != 1 || p.Left[0].Reason != actions.LeftNeedsAdmin {
			t.Errorf("not elevated: plan = %+v", p)
		}
	}
}

func TestLocationsForAnotherToolAreLeft(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\pnpm-cache\metadata\a.json`, 300*mb, old)
	m.file(local+`\pnpm\store\v10\files\00\x`, 300*mb, old)
	p := m.prepare("dev.pnpm")
	if len(p.Locations) != 1 || p.Locations[0].Path != local+`\pnpm-cache` || len(p.Left) != 1 || p.Left[0].Reason != actions.LeftOwnTool {
		t.Errorf("plan = %+v", p)
	}
}

func TestOtherFindingsInsideAFolderAreLeftToThem(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\Temp\junk.tmp`, 400*mb, old)
	m.file(local+`\Temp\SymbolCache\x.pdb`, 400*mb, old)
	m.file(local+`\Temp\recent.tmp`, 10*mb, time.Hour)
	p := m.prepare("personal.temp")
	if p.Files != 1 || p.Bytes != 400*mb || p.MinAgeHours != 24 {
		t.Fatalf("plan = %+v", p)
	}
	m.execute(p, false)
	if m.fs.Exists(local+`\Temp\junk.tmp`) || !m.fs.Exists(local+`\Temp\SymbolCache\x.pdb`) || !m.fs.Exists(local+`\Temp\recent.tmp`) {
		t.Error("the Temp cleanup touched another finding's folder or a recent file")
	}
}

func TestProgramsMustBeClosed(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\Google\Chrome\User Data\Default\Cache\Cache_Data\f`, 300*mb, old)
	m.deps.Programs = programs{"explorer.exe", "CHROME.EXE"}
	p := m.prepare("browsers.chrome-cache")
	if p.Blocked != actions.BlockedPrograms || !slices.Equal(p.Running, []string{"chrome.exe"}) {
		t.Fatalf("plan = %+v", p)
	}
	m.deps.Programs = programs{"explorer.exe"}
	if why, run, err := actions.Check(m.deps, p); err != nil || why != "" || len(run) != 0 {
		t.Errorf("after closing Chrome: %q %v %v", why, run, err)
	}
}

func TestSimulationChangesNothing(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\npm-cache\_cacache\a`, 300*mb, old)
	p := m.prepare("dev.npm-cache")
	o, _, _ := m.execute(p, true)
	if !o.Simulated || o.State != actions.Succeeded || o.Bytes != p.Bytes || !m.fs.Exists(local+`\npm-cache\_cacache\a`) {
		t.Errorf("simulated outcome = %+v", o)
	}
}

func TestSkippedFilesMakeAPartialRun(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\npm-cache\_cacache\a`, 300*mb, old)
	m.file(local+`\npm-cache\_cacache\b`, 1*mb, old)
	p := m.prepare("dev.npm-cache")
	m.fs.Lock(local + `\npm-cache\_cacache\b`)
	if o, _, _ := m.execute(p, false); o.State != actions.Partial || o.Skipped != 1 || o.Files != 1 {
		t.Errorf("outcome = %+v", o)
	}
}

func TestCancelledRun(t *testing.T) {
	m := newMachine(t, true)
	m.file(local+`\npm-cache\_cacache\a`, 300*mb, old)
	p := m.prepare("dev.npm-cache")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if o := actions.Run(ctx, m.deps, p, false, func(actions.Progress) {}, func(string) {}); o.State != actions.Cancelled {
		t.Errorf("outcome = %+v", o)
	}
}

func TestRecycleBin(t *testing.T) {
	m := newMachine(t, false)
	m.file(`C:\$Recycle.Bin\S-1-5-21-1\$R1.zip`, 500*mb, old)
	m.bin.bytes, m.bin.items = 450*mb, 3
	p := m.prepare("personal.recycle-bin")
	if p.Bytes != 450*mb || p.Items != 3 || p.Blocked != "" || p.Drive != `C:\` {
		t.Fatalf("plan = %+v", p)
	}
	if o, _, _ := m.execute(p, true); !o.Simulated || len(m.bin.emptied) != 0 {
		t.Fatalf("a simulation emptied the Recycle Bin: %+v", o)
	}
	if o, _, _ := m.execute(p, false); o.State != actions.Succeeded || !slices.Equal(m.bin.emptied, []string{`C:\`}) {
		t.Errorf("outcome %+v, emptied %v", o, m.bin.emptied)
	}
	m.bin.items = 0
	if p := m.prepare("personal.recycle-bin"); p.Blocked != actions.BlockedNothing {
		t.Errorf("an empty Recycle Bin: blocked = %q", p.Blocked)
	}
}

func TestComponentCleanupRunsDISM(t *testing.T) {
	m := newMachine(t, false)
	m.file(`C:\Windows\WinSxS\amd64_x\big.dll`, 2<<30, old)
	if p := m.prepare("system.component-store"); p.Blocked != actions.BlockedAdmin || !p.Unknown || !p.Long {
		t.Fatalf("without Administrator rights: plan = %+v", p)
	}
	m.deps.Elevated = true
	p := m.prepare("system.component-store")
	want := `C:\Windows\System32\dism.exe /Online /English /Cleanup-Image /StartComponentCleanup`
	if p.Blocked != "" || p.Command != want || len(p.Rescan()) != 0 {
		t.Fatalf("plan = %+v", p)
	}
	exit := 0
	m.run.Respond = func(ctx context.Context, c execx.Cmd) (execx.Result, error) {
		for _, l := range []string{"Deployment Image Servicing and Management tool", "[====       50.0%        ]", "[==========100.0%==========]", "The operation completed successfully."} {
			c.Output(l)
		}
		return execx.Result{ExitCode: exit}, nil
	}
	o, pct, logs := m.execute(p, false)
	if o.State != actions.Succeeded || !slices.Equal(pct, []float64{50, 100}) || len(logs) != 2 || logs[1] != "The operation completed successfully." {
		t.Errorf("outcome %+v, progress %v, logs %q", o, pct, logs)
	}
	c := m.run.Calls()[0]
	if c.Dir != `C:\Windows\System32` || c.Timeout < time.Hour {
		t.Errorf("command = %+v", c)
	}
	exit = 3010
	if o, _, _ := m.execute(p, false); o.State != actions.Succeeded || !o.RestartNeeded {
		t.Errorf("exit 3010: %+v", o)
	}
	exit = 2
	if o, _, _ := m.execute(p, false); o.State != actions.Failed || !strings.Contains(o.Error, "dism.exe exited with code 2") {
		t.Errorf("exit 2: %+v", o)
	}
	runs := len(m.run.Calls())
	if o, _, logs := m.execute(p, true); !o.Simulated || len(m.run.Calls()) != runs || !strings.Contains(logs[0], want) {
		t.Errorf("a simulation ran DISM: %+v %q", o, logs)
	}
}

func TestDeliveryOptimizationUsesItsOwnProvider(t *testing.T) {
	m := newMachine(t, true)
	m.file(`C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache\x`, 900*mb, old)
	p := m.prepare("updates.delivery-optimization")
	if p.Bytes != 900*mb || !strings.HasPrefix(p.Command, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -Command "Invoke-CimMethod`) ||
		!strings.Contains(p.Command, "MSFT_DeliveryOptimizationFile -MethodName Delete -Arguments @{deletePinned=$false}") {
		t.Fatalf("plan = %+v", p)
	}
	if o, _, _ := m.execute(p, false); o.State != actions.Succeeded || len(m.run.Calls()) != 1 {
		t.Errorf("outcome = %+v", o)
	}
}

func TestNoActionNoPlan(t *testing.T) {
	m := newMachine(t, true)
	_, err := actions.Prepare(context.Background(), m.deps, rules.Report{}, rules.Finding{ID: "personal.downloads"})
	if !errors.Is(err, actions.ErrNoAction) {
		t.Errorf("err = %v", err)
	}
}
