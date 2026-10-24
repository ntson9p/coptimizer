package probe

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/execx"
)

const gb = int64(1) << 30

// fixture reads a DISM output sample, with Windows line endings as DISM writes
// them.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n", "\r\n"))
}

func stat(sizes map[string]int64) func(string) (int64, bool) {
	return func(p string) (int64, bool) {
		s, ok := sizes[strings.ToUpper(p)]
		return s, ok
	}
}

func TestPower(t *testing.T) {
	var reg FakeRegistry
	reg.Set(LocalMachine, powerKey, "HibernateEnabled", uint64(1))
	reg.Set(LocalMachine, memoryKey, "ExistingPageFiles", []string{`\??\D:\pagefile.sys`})
	reg.Set(LocalMachine, memoryKey, "PagingFiles", []string{`D:\pagefile.sys 8192 8192`, ""})
	d := Deps{Registry: &reg, SystemDrive: `C:`,
		Stat: stat(map[string]int64{`C:\HIBERFIL.SYS`: 5 * gb, `D:\PAGEFILE.SYS`: 8 * gb})}

	data, state, _ := probePower(context.Background(), d)
	p := data.(Power)
	if state != OK || p.Hibernation != "on" || p.HiberFile != 5*gb {
		t.Errorf("hibernation = %+v", p)
	}
	if len(p.PageFiles) != 1 || p.PageFiles[0] != (PageFile{Path: `D:\pagefile.sys`, Bytes: 8 * gb}) {
		t.Errorf("page files = %+v", p.PageFiles)
	}
	if !slices.Equal(p.PageFileConfig, []string{`D:\pagefile.sys 8192 8192`}) {
		t.Errorf("config = %q", p.PageFileConfig)
	}

	var off FakeRegistry
	off.Set(LocalMachine, powerKey, "HibernateEnabled", uint64(0))
	data, _, _ = probePower(context.Background(), Deps{Registry: &off, SystemDrive: `C:`, Stat: stat(nil)})
	if p := data.(Power); p.Hibernation != "off" || p.HiberFile != 0 || len(p.PageFiles) != 0 {
		t.Errorf("hibernation off = %+v", p)
	}
	data, _, _ = probePower(context.Background(), Deps{Registry: &FakeRegistry{}, SystemDrive: `C:`, Stat: stat(nil)})
	if p := data.(Power); p.Hibernation != "unknown" {
		t.Errorf("no registry value and no file = %+v; want unknown", p)
	}
}

func TestWSL(t *testing.T) {
	var reg FakeRegistry
	reg.Set(CurrentUser, lxssKey, "DefaultDistribution", "{aaa}")
	reg.Set(CurrentUser, lxssKey+`\{aaa}`, "DistributionName", "Ubuntu-24.04")
	reg.Set(CurrentUser, lxssKey+`\{aaa}`, "BasePath", `\\?\C:\Users\me\AppData\Local\wsl\{aaa}`)
	reg.Set(CurrentUser, lxssKey+`\{aaa}`, "Version", uint64(2))
	reg.Set(CurrentUser, lxssKey+`\{bbb}`, "DistributionName", "Legacy")
	reg.Set(CurrentUser, lxssKey+`\{bbb}`, "BasePath", `C:\Legacy`)
	reg.Set(CurrentUser, lxssKey+`\{bbb}`, "Version", uint64(1))
	reg.Set(CurrentUser, lxssKey+`\AppxInstallerCache`, "Something", "not a distribution")
	d := Deps{Registry: &reg, Stat: stat(map[string]int64{`C:\USERS\ME\APPDATA\LOCAL\WSL\{AAA}\EXT4.VHDX`: 6 * gb})}

	data, state, _ := probeWSL(context.Background(), d)
	got := data.([]Distro)
	want := []Distro{
		{Name: "Ubuntu-24.04", Disk: `C:\Users\me\AppData\Local\wsl\{aaa}\ext4.vhdx`, Bytes: 6 * gb, Version: 2, Default: true},
		{Name: "Legacy", Disk: `C:\Legacy`, Version: 1},
	}
	if state != OK || !slices.Equal(got, want) {
		t.Errorf("WSL = %+v, %s; want %+v", got, state, want)
	}

	data, state, _ = probeWSL(context.Background(), Deps{Registry: &FakeRegistry{}, Stat: stat(nil)})
	if d := data.([]Distro); state != OK || len(d) != 0 {
		t.Errorf("without WSL = %+v, %s; want an empty list", d, state)
	}
}

func dismDeps(respond func(context.Context, execx.Cmd) (execx.Result, error)) (Deps, *execx.Fake) {
	f := &execx.Fake{Respond: respond}
	return Deps{Runner: f, Elevated: true, SystemRoot: `C:\Windows`}, f
}

func TestDISMNeedsAdministratorRights(t *testing.T) {
	d, f := dismDeps(nil)
	d.Elevated = false
	if _, state, _ := probeComponentStore(context.Background(), d); state != NeedsAdmin {
		t.Errorf("state = %s; want needs-admin", state)
	}
	if len(f.Calls()) != 0 {
		t.Error("DISM must not run without Administrator rights")
	}
}

func TestReservedStorage(t *testing.T) {
	out := fixture(t, "dism-reserved.txt")
	d, f := dismDeps(func(context.Context, execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: out}, nil })
	data, state, msg := probeReservedStorage(context.Background(), d)
	if state != OK || data != (ReservedStorage{Enabled: true}) {
		t.Fatalf("reserved storage = %+v, %s %s", data, state, msg)
	}
	c := f.Calls()[0]
	if c.Path != `C:\Windows\System32\dism.exe` || c.Dir != `C:\Windows\System32` ||
		!slices.Equal(c.Args, []string{"/Online", "/English", "/Get-ReservedStorageState"}) {
		t.Errorf("ran %+v", c)
	}
}

func TestComponentStore(t *testing.T) {
	out := fixture(t, "dism-analyze.txt")
	d, f := dismDeps(func(context.Context, execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: out}, nil })
	data, state, msg := probeComponentStore(context.Background(), d)
	if state != OK {
		t.Fatalf("state %s: %s", state, msg)
	}
	cs := data.(ComponentStore)
	gib := func(v float64) int64 { return int64(v * float64(gb)) }
	want := ComponentStore{
		ExplorerSize: gib(8.71), ActualSize: gib(8.48), Shared: gib(5.89), Backups: gib(2.58), Cache: 0,
		LastCleanup: "2026-09-14 10:12:13", ReclaimablePackages: 3, CleanupRecommended: true,
	}
	if cs != want {
		t.Errorf("component store = %+v; want %+v", cs, want)
	}
	if args := f.Calls()[0].Args; !slices.Equal(args, []string{"/Online", "/English", "/Cleanup-Image", "/AnalyzeComponentStore"}) {
		t.Errorf("args = %q", args)
	}
}

func TestDISMFailures(t *testing.T) {
	out := fixture(t, "dism-740.txt")
	d, _ := dismDeps(func(context.Context, execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: out, ExitCode: 740}, nil
	})
	if _, state, msg := probeComponentStore(context.Background(), d); state != Failed || !strings.Contains(msg, "740") {
		t.Errorf("exit code 740: %s %q", state, msg)
	}
	d, _ = dismDeps(func(context.Context, execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte("something else entirely")}, nil
	})
	if _, state, _ := probeComponentStore(context.Background(), d); state != Failed {
		t.Errorf("unreadable output: %s; want failed", state)
	}
	d, _ = dismDeps(func(context.Context, execx.Cmd) (execx.Result, error) {
		return execx.Result{}, context.DeadlineExceeded
	})
	if _, state, _ := probeReservedStorage(context.Background(), d); state != Failed {
		t.Errorf("timeout: %s; want failed", state)
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{"0 bytes": 0, "512 bytes": 512, "1.50 KB": 1536, "2 MB": 2 << 20, "1 GB": gb, "1,024.00 MB": gb}
	for in, want := range cases {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "12", "x GB", "3 parsecs"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) succeeded", bad)
		}
	}
}

func TestManager(t *testing.T) {
	var reg FakeRegistry
	reg.Set(LocalMachine, powerKey, "HibernateEnabled", uint64(0))
	release := make(chan struct{})
	reserved := fixture(t, "dism-reserved.txt")
	analyze := fixture(t, "dism-analyze.txt")
	runner := &execx.Fake{Respond: func(ctx context.Context, c execx.Cmd) (execx.Result, error) {
		if slices.Contains(c.Args, "/AnalyzeComponentStore") {
			<-release
			return execx.Result{Stdout: analyze}, nil
		}
		return execx.Result{Stdout: reserved}, nil
	}}
	var mu sync.Mutex
	var heard []Result
	m := NewManager(Deps{Registry: &reg, Stat: stat(nil), Runner: runner, Elevated: true,
		SystemRoot: `C:\Windows`, SystemDrive: `C:`}, func(r Result) {
		mu.Lock()
		heard = append(heard, r)
		mu.Unlock()
	})
	defer m.Close()

	if r := find(m.Results(), "componentStore"); r.State != NotRun || !r.OnDemand {
		t.Errorf("before a request: %+v", r)
	}
	m.Start()
	waitFor(t, func() bool {
		rs := m.Results()
		return find(rs, "power").State == OK && find(rs, "wsl").State == OK && find(rs, "reservedStorage").State == OK
	})
	if r := find(m.Results(), "componentStore"); r.State != NotRun {
		t.Errorf("an on-demand probe ran by itself: %+v", r)
	}

	if err := m.Run("componentStore"); err != nil {
		t.Fatal(err)
	}
	if err := m.Run("componentStore"); !errors.Is(err, ErrBusy) {
		t.Errorf("second run while running: %v; want busy", err)
	}
	if err := m.Run("nope"); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown probe: %v", err)
	}
	close(release)
	waitFor(t, func() bool { return find(m.Results(), "componentStore").State == OK })
	mu.Lock()
	defer mu.Unlock()
	if len(heard) < 6 {
		t.Errorf("heard %d updates; want each probe running and done", len(heard))
	}
}

func find(rs []Result, name string) Result {
	for _, r := range rs {
		if r.Name == name {
			return r
		}
	}
	return Result{}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatal("timed out")
}

func TestKnownFolders(t *testing.T) {
	var reg FakeRegistry
	reg.Set(CurrentUser, shellFolders, "Personal", `D:\Documents`)
	reg.Set(CurrentUser, shellFolders, "Desktop", `%USERPROFILE%\Desktop`)
	reg.Set(CurrentUser, shellFolders, "{374DE290-123F-4565-9164-39C4925E467B}", `%UNSET%\Downloads`)
	env := map[string]string{"USERPROFILE": `C:\Users\alice`, "OneDrive": `E:\OneDrive`}
	got := KnownFolders(&reg, func(k string) string { return env[k] })
	want := []string{`C:\Users\alice\Desktop`, `D:\Documents`, `E:\OneDrive`}
	if !slices.Equal(got, want) {
		t.Errorf("KnownFolders = %q; want %q", got, want)
	}
	if got := expand(`%A%\%B%-%%`, func(k string) string { return map[string]string{"A": "x"}[k] }); got != `x\%B%-%%` {
		t.Errorf("expand = %q", got)
	}
}

// TestDISMProbesWaitForADISMCleanup holds the DISM lock, as a cleanup running
// DISM does: the analysis waits instead of starting a second DISM.
func TestDISMProbesWaitForADISMCleanup(t *testing.T) {
	analyze := fixture(t, "dism-analyze.txt")
	d, runner := dismDeps(func(context.Context, execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: analyze}, nil
	})
	d.DISM = execx.NewLock()
	d.DISM.TryAcquire()
	m := NewManager(d, nil)
	defer m.Close()
	if err := m.Run("componentStore"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if r := find(m.Results(), "componentStore"); r.State != Running || len(runner.Calls()) != 0 {
		t.Fatalf("while the cleanup holds DISM: %+v, %d runs", r, len(runner.Calls()))
	}
	d.DISM.Release()
	waitFor(t, func() bool { return find(m.Results(), "componentStore").State == OK })
}
