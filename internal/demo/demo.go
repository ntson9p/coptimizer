// Package demo builds the simulated PC behind demo mode and the UI tests: an
// in-memory C: drive shaped like a real developer machine (the manual scan in
// docs/space-hogs.md, section 5), two data drives, a made-up earlier scan to
// show growth, simulated answers for the system information, and cleanups
// that delete from the in-memory drive. Nothing here touches the real system.
package demo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/actions"
	"github.com/ntson9p/coptimizer/internal/execx"
	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/probe"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/store"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

const (
	mb = 1 << 20
	gb = 1 << 30
)

// Machine is the simulated PC.
type Machine struct {
	FS        *memfs.FS
	System    System
	Env       rules.Env
	Snapshots *Snapshots
	Probes    probe.Deps
	Actions   actions.Deps
	History   *store.MemoryHistory
}

// System is the simulated machine's drives, which gain the space cleanups
// free. Demo mode never claims Administrator rights for itself; its cleanups
// act as if it had them.
type System struct {
	fs     *memfs.FS
	drives []sysinfo.Drive
}

func (s System) Drives() ([]sysinfo.Drive, error) {
	out := slices.Clone(s.drives)
	for i := range out {
		out[i].Free += s.fs.Freed(out[i].Root[:2])
	}
	return out, nil
}

func (System) Elevated() bool { return false }

// blob is a folder filled with generated files.
type blob struct {
	dir     string
	total   int64
	files   int
	subdirs int // spread the files over this many sub-folders
	exts    []string
}

const (
	user  = `C:\Users\Demo`
	local = user + `\AppData\Local`
	roam  = user + `\AppData\Roaming`
	wslVM = local + `\wsl\{4c8a0e4f-6b1d-4d55-9a8e-2f3a6c1b7d90}`
	bin   = `C:\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1001`
	doDir = `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache`
)

var blobs = []blob{
	{`C:\Windows\WinSxS`, 6_400 * mb, 6000, 400, []string{".dll", ".exe", ".mui", ".manifest"}},
	{`C:\Windows\System32`, 5_200 * mb, 4000, 120, []string{".dll", ".exe", ".sys", ".mui"}},
	{`C:\Windows\Installer`, 4_300 * mb, 300, 0, []string{".msi", ".msp"}},
	{`C:\Windows\SoftwareDistribution\Download`, 80 * mb, 20, 4, []string{".cab", ".esd"}},
	{`C:\Windows\Logs\CBS`, 60 * mb, 10, 0, []string{".log", ".cab"}},
	{`C:\Windows\Temp`, 30 * mb, 50, 0, []string{".tmp", ".log"}},
	{`C:\Program Files\Microsoft Office`, 1_400 * mb, 900, 20, []string{".dll", ".exe", ".msi"}},
	{`C:\Program Files\Adobe\Acrobat DC`, 650 * mb, 700, 15, []string{".dll", ".exe", ".api"}},
	{`C:\Program Files\Common Files`, 140 * mb, 400, 10, []string{".dll"}},
	{`C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2`, 2_000 * mb, 1500, 30, []string{".vpk", ".dll", ".exe"}},
	{`C:\Program Files (x86)\Steam\steamapps\shadercache`, 300 * mb, 200, 4, []string{""}},
	{`C:\ProgramData`, 1_040 * mb, 1500, 80, []string{".dat", ".log", ".db"}},
	{`C:\$GetCurrent\media`, 3_810 * mb, 40, 3, []string{".esd", ".wim", ".dll"}},
	{bin, 1_200 * mb, 40, 0, []string{".zip", ".mp4", ".docx"}},
	{doDir, 640 * mb, 60, 6, []string{""}},
	{`C:\GameData\Levels`, 3_100 * mb, 120, 6, []string{".pak"}},
	{local + `\npm-cache\_cacache`, 9_050 * mb, 9000, 256, []string{""}},
	{local + `\Google\Chrome\User Data\Default\Cache\Cache_Data`, 1_650 * mb, 3000, 0, []string{""}},
	{local + `\Google\Chrome\User Data\Default\Service Worker\CacheStorage`, 1_400 * mb, 1200, 40, []string{""}},
	{local + `\Google\Chrome\User Data\Default\IndexedDB`, 1_200 * mb, 600, 30, []string{".ldb", ".log"}},
	{local + `\Google\Chrome\User Data\Default\Code Cache`, 820 * mb, 2000, 2, []string{""}},
	{local + `\Google\Chrome\Application`, 1_000 * mb, 400, 6, []string{".dll", ".exe", ".pak"}},
	{local + `\ms-playwright\chromium-1243`, 1_150 * mb, 600, 8, []string{".dll", ".exe", ".pak"}},
	{local + `\ms-playwright\firefox-1532`, 800 * mb, 500, 6, []string{".dll", ".exe"}},
	{local + `\ms-playwright\webkit-2311`, 610 * mb, 400, 6, []string{".dll", ".exe"}},
	{local + `\pnpm-cache\metadata`, 1_440 * mb, 4000, 64, []string{".json"}},
	{local + `\Programs\DockerDesktop`, 3_330 * mb, 800, 20, []string{".exe", ".dll", ".vhdx", ".iso"}},
	{local + `\Programs\Python\Python313`, 750 * mb, 6000, 300, []string{".py", ".pyc", ".dll", ".pyd"}},
	{local + `\Temp`, 650 * mb, 900, 30, []string{".tmp", ".log", ".msi", ""}},
	{local + `\CrashDumps`, 900 * mb, 6, 0, []string{".dmp"}},
	{local + `\D3DSCache`, 450 * mb, 300, 12, []string{""}},
	{local + `\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams`, 800 * mb, 700, 20, []string{""}},
	{local + `\VendorSync\VideoCache`, 2_600 * mb, 400, 10, []string{".chunk"}},
	{roam + `\Code\Cache\Cache_Data`, 600 * mb, 1500, 0, []string{""}},
	{roam + `\Code\CachedData`, 700 * mb, 900, 8, []string{".js", ".map"}},
	{roam + `\Code\CachedExtensionVSIXs`, 450 * mb, 40, 0, []string{".vsix"}},
	{roam + `\Code\logs`, 460 * mb, 600, 30, []string{".log"}},
	{roam + `\Code\User\workspaceStorage`, 1_200 * mb, 500, 40, []string{".json", ".vscdb"}},
	{user + `\.vscode\extensions`, 1_110 * mb, 7000, 120, []string{".js", ".json", ".map", ".wasm"}},
	{user + `\Documents\Projects\shop-app\node_modules`, 900 * mb, 6000, 300, []string{".js", ".json", ".map"}},
	{user + `\Documents\Projects\api\node_modules`, 650 * mb, 4000, 200, []string{".js", ".json"}},
	{user + `\Documents\Projects\shop-app\src`, 40 * mb, 300, 10, []string{".ts", ".tsx"}},
	{user + `\Downloads`, 5_000 * mb, 60, 0, []string{".exe", ".msi", ".iso", ".zip"}},
	{user + `\Videos\Captures`, 4_200 * mb, 25, 0, []string{".mp4"}},
	{user + `\Documents`, 1_200 * mb, 800, 20, []string{".docx", ".pdf", ".xlsx", ".pptx"}},
	{user + `\Pictures`, 2_300 * mb, 1500, 12, []string{".jpg", ".png", ".heic"}},
	{`C:\Users\Lan\Documents`, 1_500 * mb, 900, 20, []string{".docx", ".pdf", ".jpg"}},
	{`C:\Users\Lan\Saved Games`, 1_600 * mb, 300, 8, []string{".sav", ".dat"}},
	{`D:\Projects`, 42 * gb, 3000, 80, []string{".go", ".js", ".json", ".ts", ""}},
	{`D:\Media`, 210 * gb, 400, 10, []string{".mp4", ".mkv", ".jpg"}},
	{`D:\Backups`, 96 * gb, 30, 0, []string{".zip", ".7z", ".vhdx"}},
	{`E:\Archive`, 380 * gb, 500, 20, []string{".zip", ".iso", ".mkv"}},
	{`E:\dev`, 9 * gb, 2000, 40, []string{".dll", ".exe", ".nupkg"}},
}

// now is the demo's present: everything in it is dated relative to it.
var now = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

// New builds the simulated machine. Each folder listing takes delay, so that
// a scan of the demo takes a few seconds, like a real one.
func New(delay time.Duration) *Machine {
	f := memfs.New()
	rng := rand.New(rand.NewPCG(1, 2)) // fixed seed: the demo is the same every time

	// System files at the root of C:, and a few big single files.
	sys := uint32(fsx.AttrHidden | fsx.AttrSystem)
	f.Add(`C:\hiberfil.sys`, fsx.Entry{Size: 5_104_570_368, Allocated: 5_104_570_368, Attrs: sys, Modified: now})
	f.Add(`C:\pagefile.sys`, fsx.Entry{Size: 5_426_000_896, Allocated: 5_426_000_896, Attrs: sys, Modified: now})
	f.Add(`C:\swapfile.sys`, fsx.Entry{Size: 16 * mb, Allocated: 16 * mb, Attrs: sys, Modified: now})
	f.AddFile(wslVM+`\ext4.vhdx`, 6_399_655_936, now.Add(-2*time.Hour))
	f.AddFile(user+`\old-laptop-backup.vhdx`, 4_300*mb, now.AddDate(-1, -2, 0))
	f.AddFile(`C:\ProgramData\VendorAgent\logs\agent.log`, 1_100*mb, now.Add(-time.Hour))

	for _, b := range blobs {
		fill(f, rng, b)
	}

	// Windows keeps most of System32 as hard links into WinSxS: counted once.
	for i := range 800 {
		name := fmt.Sprintf(`file%04d.dll`, i)
		f.AddFile(`C:\Windows\WinSxS\amd64_shared\`+name, int64(200_000+rng.IntN(2_000_000)), now.AddDate(0, -3, 0))
		f.AddHardLink(`C:\Windows\System32\shared\`+name, `C:\Windows\WinSxS\amd64_shared\`+name)
	}

	// Online-only OneDrive files: big, but not on the disk.
	for i := range 30 {
		size := int64(20*mb + rng.IntN(120*mb))
		f.Add(fmt.Sprintf(user+`\OneDrive\Archive\video-%02d.mp4`, i),
			fsx.Entry{Size: size, Attrs: fsx.AttrRecallOnDataAccess | fsx.AttrOffline, Modified: now.AddDate(-1, 0, -i)})
	}

	// Links that a scan must not follow, and a folder it can't read.
	f.AddJunction(`C:\Users\All Users`)
	f.AddJunction(`C:\Documents and Settings`)
	f.AddJunction(user + `\Application Data`)
	f.Deny(`C:\System Volume Information`)

	m := &Machine{
		FS: f,
		System: System{fs: f, drives: []sysinfo.Drive{
			{Root: `C:\`, Label: "", FS: "NTFS", Total: 118_642_237_440, Free: 7_900_000_000},
			{Root: `D:\`, Label: "Data", FS: "NTFS", Total: 500_096_983_040, Free: 115_200_000_000},
			{Root: `E:\`, Label: "Storage", FS: "NTFS", Total: 500_104_687_616, Free: 79_500_000_000},
		}},
		Env:       rules.DefaultEnv("Demo"),
		Snapshots: &Snapshots{all: []rules.Snapshot{earlierScan(f)}},
		Probes:    probes(),
		History:   &store.MemoryHistory{},
	}
	m.Actions = cleanups(f, m.Env)
	m.Probes.DISM = execx.NewLock() // DISM refuses to run twice at once
	m.Actions.DISM = m.Probes.DISM
	f.SetDelay(delay)
	return m
}

// cleanups are the demo's cleanup actions: they delete from the in-memory
// drive, as if with Administrator rights. The simulated VS Code is running
// at first, to show how a cleanup waits for a program to close; it "closes"
// a few seconds after a preview asked for it.
func cleanups(f *memfs.FS, env rules.Env) actions.Deps {
	policy, err := safety.NewPolicy(safety.Places{SystemDrive: env.SystemDrive, Windows: env.Windows,
		ProgramData: env.ProgramData, ProgramFiles: env.ProgramFiles, ProgramFilesX86: env.ProgramFilesX86, Users: env.Users})
	if err != nil {
		panic(err) // can't happen: the places are fixed
	}
	return actions.Deps{
		Cleaner: f, Policy: policy, Programs: &programs{}, RecycleBin: recycleBin{f}, Mutator: recycleBin{f},
		Runner: &execx.Fake{Respond: tools(f)}, Elevated: true, Env: env, Now: time.Now,
	}
}

// programs is what runs on the demo PC.
type programs struct {
	mu     sync.Mutex
	closes time.Time // when the simulated VS Code closes; zero until asked
}

func (p *programs) Running() ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closes.IsZero() {
		p.closes = time.Now().Add(3 * time.Second)
	}
	if time.Now().Before(p.closes) {
		return []string{"explorer.exe", "Code.exe"}, nil
	}
	return []string{"explorer.exe"}, nil
}

// recycleBin is the demo user's Recycle Bin on C:.
type recycleBin struct{ fs *memfs.FS }

func (b recycleBin) RecycleBin(string) (bytes, items int64, err error) {
	entries, err := b.fs.List(bin)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, 0, nil
	}
	for _, e := range entries {
		bytes += e.Allocated
	}
	return bytes, int64(len(entries)), err
}

func (b recycleBin) EmptyRecycleBin(string) error { return removeAll(b.fs, bin) }

// removeAll deletes what is in dir and its sub-folders, keeping dir.
func removeAll(f *memfs.FS, dir string) error {
	tree, err := f.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var walk func(rel string) error
	walk = func(rel string) error {
		entries, err := tree.List(rel)
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name
			if rel != "" {
				name = rel + `\` + name
			}
			if e.IsDir() {
				if err := walk(name); err != nil {
					return err
				}
			}
			if err := tree.Remove(name); err != nil {
				return err
			}
		}
		return nil
	}
	return walk("")
}

// tools imitates the Windows tools cleanups run: DISM's component cleanup,
// which draws a progress bar for a few seconds and frees part of WinSxS, and
// the deletion of the Delivery Optimization cache.
func tools(f *memfs.FS) func(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	return func(ctx context.Context, c execx.Cmd) (execx.Result, error) {
		say := func(line string) {
			if c.Output != nil {
				c.Output(line)
			}
		}
		if slices.Contains(c.Args, "/StartComponentCleanup") {
			say("Deployment Image Servicing and Management tool")
			for i := 0; i <= 10; i++ {
				select {
				case <-time.After(300 * time.Millisecond):
				case <-ctx.Done():
					return execx.Result{}, ctx.Err()
				}
				say(fmt.Sprintf("[%s%5.1f%%%s]", strings.Repeat("=", 2*i), float64(10*i), strings.Repeat(" ", 20-2*i)))
			}
			for i := range 40 {
				removeAll(f, fmt.Sprintf(`C:\Windows\WinSxS\%02x`, i))
			}
			say("The operation completed successfully.")
			return execx.Result{}, nil
		}
		return execx.Result{}, removeAll(f, doDir)
	}
}

// fill adds b.files files totalling about b.total bytes.
func fill(f *memfs.FS, rng *rand.Rand, b blob) {
	weights := make([]float64, b.files)
	var sum float64
	for i := range weights {
		// Mostly small files with a few big ones, like real folders.
		w := rng.ExpFloat64()
		w *= w
		weights[i] = w
		sum += w
	}
	for i, w := range weights {
		dir := b.dir
		if b.subdirs > 0 {
			dir = fmt.Sprintf(`%s\%02x`, b.dir, rng.IntN(b.subdirs))
		}
		ext := b.exts[rng.IntN(len(b.exts))]
		size := int64(w / sum * float64(b.total))
		modified := now.Add(-time.Duration(rng.IntN(700*24)) * time.Hour)
		f.AddFile(fmt.Sprintf(`%s\f%05d%s`, dir, i, ext), size, modified)
	}
}

// earlierScan makes up a scan of C: from nine days ago: the same as now, but
// with a smaller npm cache and fewer game recordings, so that demo mode can
// show what grew.
func earlierScan(f *memfs.FS) rules.Snapshot {
	res, err := scan.Run(context.Background(), f, scan.Options{Roots: []string{`C:\`}})
	if err != nil {
		panic(err) // can't happen: the file system is in memory
	}
	s := rules.TakeSnapshot(res.Roots[0], now.AddDate(0, 0, -9), false)
	shrink(s, local+`\npm-cache\_cacache`, 3_500*mb)
	shrink(s, user+`\Videos\Captures`, 1_800*mb)
	return s
}

// shrink makes folder, and every folder above it, smaller by bytes.
func shrink(s rules.Snapshot, folder string, bytes int64) {
	for p := folder; ; {
		s.Folders[p] -= bytes
		i := strings.LastIndexByte(p, '\\')
		if i < 0 || p == `C:\` {
			return
		}
		if p = p[:i]; p == `C:` {
			p = `C:\`
		}
	}
}

// Snapshots is demo mode's memory of earlier scans: it forgets them when the
// program ends.
type Snapshots struct {
	mu  sync.Mutex
	all []rules.Snapshot
}

func (s *Snapshots) Previous(root string, elevated bool) (rules.Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.all) - 1; i >= 0; i-- {
		if strings.EqualFold(s.all[i].Root, root) && s.all[i].Elevated == elevated {
			return s.all[i], true
		}
	}
	return rules.Snapshot{}, false
}

func (s *Snapshots) Add(snap rules.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = append(s.all, snap)
	return nil
}

// probes simulates the system information of a PC with Administrator rights:
// hibernation on, a page file on C:, one WSL distribution, and DISM answers.
func probes() probe.Deps {
	reg := &probe.FakeRegistry{}
	reg.Set(probe.LocalMachine, `SYSTEM\CurrentControlSet\Control\Power`, "HibernateEnabled", uint64(1))
	memory := `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
	reg.Set(probe.LocalMachine, memory, "ExistingPageFiles", []string{`\??\C:\pagefile.sys`})
	reg.Set(probe.LocalMachine, memory, "PagingFiles", []string{`?:\pagefile.sys`})
	lxss := `Software\Microsoft\Windows\CurrentVersion\Lxss`
	reg.Set(probe.CurrentUser, lxss, "DefaultDistribution", "{4c8a0e4f-6b1d-4d55-9a8e-2f3a6c1b7d90}")
	reg.Set(probe.CurrentUser, lxss+`\{4c8a0e4f-6b1d-4d55-9a8e-2f3a6c1b7d90}`, "DistributionName", "Ubuntu-24.04")
	reg.Set(probe.CurrentUser, lxss+`\{4c8a0e4f-6b1d-4d55-9a8e-2f3a6c1b7d90}`, "BasePath", wslVM)
	reg.Set(probe.CurrentUser, lxss+`\{4c8a0e4f-6b1d-4d55-9a8e-2f3a6c1b7d90}`, "Version", uint64(2))
	sizes := map[string]int64{
		`C:\HIBERFIL.SYS`:                     5_104_570_368,
		`C:\PAGEFILE.SYS`:                     5_426_000_896,
		strings.ToUpper(wslVM + `\ext4.vhdx`): 6_399_655_936,
	}
	return probe.Deps{
		Registry: reg,
		Stat: func(p string) (int64, bool) {
			s, ok := sizes[strings.ToUpper(p)]
			return s, ok
		},
		Runner:      &execx.Fake{Respond: dismAnswer},
		Elevated:    true,
		SystemRoot:  `C:\Windows`,
		SystemDrive: `C:`,
	}
}

// dismAnswer imitates DISM, taking a moment as the real one does.
func dismAnswer(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	wait, out := 500*time.Millisecond, "\r\nReserved storage is enabled.\r\n\r\nThe operation completed successfully.\r\n"
	for _, a := range c.Args {
		if a == "/AnalyzeComponentStore" {
			wait, out = 4*time.Second, componentStore
		}
	}
	select {
	case <-time.After(wait):
		return execx.Result{Stdout: []byte(out)}, nil
	case <-ctx.Done():
		return execx.Result{}, ctx.Err()
	}
}

const componentStore = "\r\nComponent Store (WinSxS) information:\r\n\r\n" +
	"Windows Explorer Reported Size of Component Store : 12.40 GB\r\n\r\n" +
	"Actual Size of Component Store : 7.95 GB\r\n\r\n" +
	"    Shared with Windows : 4.62 GB\r\n" +
	"    Backups and Disabled Features : 3.21 GB\r\n" +
	"    Cache and Temporary Data : 125.40 MB\r\n\r\n" +
	"Date of Last Cleanup : 2026-05-02 08:31:55\r\n\r\n" +
	"Number of Reclaimable Packages : 4\r\n" +
	"Component Store Cleanup Recommended : Yes\r\n\r\n" +
	"The operation completed successfully.\r\n"
