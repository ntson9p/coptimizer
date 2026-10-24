// Package demo builds the simulated PC behind demo mode and the UI tests: an
// in-memory C: drive shaped like a real developer machine (the manual scan in
// docs/space-hogs.md, section 5), plus two data drives. Nothing here touches
// the real system.
package demo

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

const (
	mb = 1 << 20
	gb = 1 << 30
)

// System is the simulated machine's drives. Demo mode never claims
// Administrator rights.
type System struct{ drives []sysinfo.Drive }

func (s System) Drives() ([]sysinfo.Drive, error) { return s.drives, nil }
func (System) Elevated() bool                     { return false }

// blob is a folder filled with generated files.
type blob struct {
	dir     string
	total   int64
	files   int
	subdirs int // spread the files over this many sub-folders
	exts    []string
}

var blobs = []blob{
	{`C:\Windows\WinSxS`, 7_400 * mb, 6000, 400, []string{".dll", ".exe", ".mui", ".manifest"}},
	{`C:\Windows\System32`, 5_200 * mb, 4000, 120, []string{".dll", ".exe", ".sys", ".mui"}},
	{`C:\Windows\Installer`, 4_300 * mb, 300, 0, []string{".msi", ".msp"}},
	{`C:\Windows\SoftwareDistribution\Download`, 80 * mb, 20, 4, []string{".cab", ".esd"}},
	{`C:\Windows\Logs\CBS`, 60 * mb, 10, 0, []string{".log", ".cab"}},
	{`C:\Windows\Temp`, 30 * mb, 50, 0, []string{".tmp", ".log"}},
	{`C:\Program Files`, 2_390 * mb, 3000, 60, []string{".dll", ".exe", ".pak", ".dat"}},
	{`C:\Program Files (x86)`, 2_360 * mb, 2500, 50, []string{".dll", ".exe", ".dat"}},
	{`C:\ProgramData`, 1_040 * mb, 1500, 80, []string{".dat", ".log", ".db"}},
	{`C:\$GetCurrent\media`, 3_810 * mb, 40, 3, []string{".esd", ".wim", ".dll"}},
	{`C:\Users\Demo\AppData\Local\npm-cache\_cacache`, 9_050 * mb, 9000, 256, []string{""}},
	{`C:\Users\Demo\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data`, 1_650 * mb, 3000, 0, []string{""}},
	{`C:\Users\Demo\AppData\Local\Google\Chrome\User Data\Default\Service Worker\CacheStorage`, 1_400 * mb, 1200, 40, []string{""}},
	{`C:\Users\Demo\AppData\Local\Google\Chrome\User Data\Default\IndexedDB`, 1_200 * mb, 600, 30, []string{".ldb", ".log"}},
	{`C:\Users\Demo\AppData\Local\Google\Chrome\User Data\Default\Code Cache`, 820 * mb, 2000, 2, []string{""}},
	{`C:\Users\Demo\AppData\Local\Google\Chrome\Application`, 1_000 * mb, 400, 6, []string{".dll", ".exe", ".pak"}},
	{`C:\Users\Demo\AppData\Local\ms-playwright\chromium-1200`, 1_150 * mb, 600, 8, []string{".dll", ".exe", ".pak"}},
	{`C:\Users\Demo\AppData\Local\ms-playwright\firefox-1490`, 800 * mb, 500, 6, []string{".dll", ".exe"}},
	{`C:\Users\Demo\AppData\Local\ms-playwright\webkit-2210`, 610 * mb, 400, 6, []string{".dll", ".exe"}},
	{`C:\Users\Demo\AppData\Local\pnpm-cache\metadata`, 1_440 * mb, 4000, 64, []string{".json"}},
	{`C:\Users\Demo\AppData\Local\Programs\DockerDesktop`, 3_330 * mb, 800, 20, []string{".exe", ".dll", ".vhdx", ".iso"}},
	{`C:\Users\Demo\AppData\Local\Programs\Python\Python313`, 750 * mb, 6000, 300, []string{".py", ".pyc", ".dll", ".pyd"}},
	{`C:\Users\Demo\AppData\Local\Temp`, 650 * mb, 900, 30, []string{".tmp", ".log", ".msi", ""}},
	{`C:\Users\Demo\AppData\Roaming\Code`, 3_410 * mb, 2500, 60, []string{".json", ".log", ".vsix", ""}},
	{`C:\Users\Demo\.vscode\extensions`, 1_110 * mb, 7000, 120, []string{".js", ".json", ".map", ".wasm"}},
	{`C:\Users\Demo\Downloads`, 7_500 * mb, 60, 0, []string{".exe", ".msi", ".iso", ".zip"}},
	{`C:\Users\Demo\Videos\Captures`, 4_200 * mb, 25, 0, []string{".mp4"}},
	{`C:\Users\Demo\Documents`, 1_200 * mb, 800, 20, []string{".docx", ".pdf", ".xlsx", ".pptx"}},
	{`C:\Users\Demo\Pictures`, 2_300 * mb, 1500, 12, []string{".jpg", ".png", ".heic"}},
	{`D:\Projects`, 42 * gb, 3000, 80, []string{".go", ".js", ".json", ".ts", ""}},
	{`D:\Media`, 210 * gb, 400, 10, []string{".mp4", ".mkv", ".jpg"}},
	{`D:\Backups`, 96 * gb, 30, 0, []string{".zip", ".7z", ".vhdx"}},
	{`E:\Archive`, 380 * gb, 500, 20, []string{".zip", ".iso", ".mkv"}},
	{`E:\dev`, 9 * gb, 2000, 40, []string{".dll", ".exe", ".nupkg"}},
}

// New returns the simulated file system and machine. Each folder listing
// takes delay, so a scan of the demo takes a few seconds, like a real one.
func New(delay time.Duration) (*memfs.FS, System) {
	f := memfs.New()
	rng := rand.New(rand.NewPCG(1, 2)) // fixed seed: the demo is the same every time
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

	// System files at the root of C:.
	sys := uint32(fsx.AttrHidden | fsx.AttrSystem)
	f.Add(`C:\hiberfil.sys`, fsx.Entry{Size: 5_104_570_368, Allocated: 5_104_570_368, Attrs: sys, Modified: now})
	f.Add(`C:\pagefile.sys`, fsx.Entry{Size: 5_426_000_896, Allocated: 5_426_000_896, Attrs: sys, Modified: now})
	f.Add(`C:\swapfile.sys`, fsx.Entry{Size: 16 * mb, Allocated: 16 * mb, Attrs: sys, Modified: now})
	f.AddFile(`C:\Users\Demo\AppData\Local\wsl\{4c8a0e4f-6b1d-4d55-9a8e-2f3a6c1b7d90}\ext4.vhdx`, 6_399_655_936, now.Add(-2*time.Hour))

	for _, b := range blobs {
		fill(f, rng, b, now)
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
		f.Add(fmt.Sprintf(`C:\Users\Demo\OneDrive\Archive\video-%02d.mp4`, i),
			fsx.Entry{Size: size, Attrs: fsx.AttrRecallOnDataAccess | fsx.AttrOffline, Modified: now.AddDate(-1, 0, -i)})
	}

	// Links that a scan must not follow, and a folder it can't read.
	f.AddJunction(`C:\Users\All Users`)
	f.AddJunction(`C:\Documents and Settings`)
	f.AddJunction(`C:\Users\Demo\Application Data`)
	f.Deny(`C:\System Volume Information`)

	f.SetDelay(delay)
	return f, System{drives: []sysinfo.Drive{
		{Root: `C:\`, Label: "", FS: "NTFS", Total: 118_642_237_440, Free: 24_100_000_000},
		{Root: `D:\`, Label: "Data", FS: "NTFS", Total: 500_096_983_040, Free: 115_200_000_000},
		{Root: `E:\`, Label: "Storage", FS: "NTFS", Total: 500_104_687_616, Free: 79_500_000_000},
	}}
}

// fill adds b.files files totalling about b.total bytes.
func fill(f *memfs.FS, rng *rand.Rand, b blob, now time.Time) {
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
