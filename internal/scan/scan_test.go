package scan_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/sandbox"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/testguard"
	"github.com/ntson9p/coptimizer/internal/winfs"
)

func TestMain(m *testing.M) { testguard.Main(m) }

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func run(t *testing.T, l fsx.Lister, opts scan.Options) *scan.Result {
	t.Helper()
	res, err := scan.Run(context.Background(), l, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTotals(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\a\x.bin`, 10_000, t0)               // 12 KiB on disk
	f.AddFile(`C:\a\b\y.txt`, 100, t0.Add(time.Hour)) // 4 KiB
	f.AddFile(`C:\z.log`, 5000, t0)                   // 8 KiB
	f.AddDir(`C:\empty`)

	res := run(t, f, scan.Options{Roots: []string{`C:\`}})
	root := res.Roots[0]
	if root.Files != 3 || root.Folders != 3 || root.Allocated != 24576 || root.Size != 15100 {
		t.Errorf("root totals = files %d folders %d allocated %d size %d", root.Files, root.Folders, root.Allocated, root.Size)
	}
	if root.OwnFiles != 1 || root.OwnAllocated != 8192 {
		t.Errorf("root own files = %d, %d bytes", root.OwnFiles, root.OwnAllocated)
	}
	if !root.Newest.Equal(t0.Add(time.Hour)) {
		t.Errorf("newest = %v", root.Newest)
	}
	if names := []string{root.Children[0].Name, root.Children[1].Name}; names[0] != "a" || names[1] != "empty" {
		t.Errorf("children = %v; want largest first", names)
	}
	if res.Files != 3 || res.Folders != 3 || res.Allocated != 24576 || res.Errors != 0 {
		t.Errorf("result totals = %+v", res)
	}

	b := res.Find(`C:\a\b`)
	if b == nil || b.Files != 1 || b.Path() != `C:\a\b` {
		t.Fatalf("Find(C:\\a\\b) = %+v", b)
	}
	if res.Find(`c:\A\B`) != b {
		t.Error("Find should ignore case")
	}
	if res.Find(`C:\nope`) != nil || res.Find(`D:\a`) != nil {
		t.Error("Find found folders that don't exist")
	}
	if res.Find(`C:\`) != root {
		t.Error("Find(root) should return the root")
	}
}

func TestLinksAreNeverFollowed(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\ProgramData\data.bin`, 1<<20, t0)
	f.AddJunction(`C:\Users\All Users`)

	res := run(t, f, scan.Options{Roots: []string{`C:\`}})
	if n := f.Listed(`C:\Users\All Users`); n != 0 {
		t.Errorf("the junction was listed %d times", n)
	}
	link := res.Find(`C:\Users\All Users`)
	if link == nil || !link.Link || link.Allocated != 0 {
		t.Errorf("junction node = %+v; want a link with nothing counted", link)
	}
	if res.Allocated != 1<<20 {
		t.Errorf("allocated = %d; want only ProgramData", res.Allocated)
	}
}

func TestHardLinksCountOnce(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\WinSxS\big.dll`, 1<<20, t0)
	f.AddHardLink(`C:\System32\big.dll`, `C:\WinSxS\big.dll`)

	res := run(t, f, scan.Options{Roots: []string{`C:\`}})
	if res.Allocated != 1<<20 || res.Shared != 1<<20 || res.Files != 2 {
		t.Errorf("allocated %d shared %d files %d; want 1 MiB once, 1 MiB shared, 2 names", res.Allocated, res.Shared, res.Files)
	}
}

// shuffledLister delays each listing by an amount that depends on the folder
// and a seed, so the workers meet folders in a different order per seed.
type shuffledLister struct {
	fsx.Lister
	seed int
}

func (s shuffledLister) List(dir string) ([]fsx.Entry, error) {
	h := s.seed
	for _, c := range dir {
		h = h*31 + int(c)
	}
	time.Sleep(time.Duration(h&3) * time.Millisecond)
	return s.Lister.List(dir)
}

func TestHardLinksCountWhereThePathSortsFirst(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Windows\WinSxS\amd64_x\big.dll`, 1<<20, t0)
	f.AddHardLink(`C:\Windows\System32\big.dll`, `C:\Windows\WinSxS\amd64_x\big.dll`)
	f.AddHardLink(`C:\Windows\SysWOW64\big.dll`, `C:\Windows\WinSxS\amd64_x\big.dll`)
	for seed := range 30 {
		res := run(t, shuffledLister{f, seed}, scan.Options{Roots: []string{`C:\`}, Workers: 1 + seed%8})
		sys32, wow, sxs := res.Find(`C:\Windows\System32`), res.Find(`C:\Windows\SysWOW64`), res.Find(`C:\Windows\WinSxS`)
		if sys32.Allocated != 1<<20 || wow.Allocated != 0 || sxs.Allocated != 0 {
			t.Fatalf("seed %d: System32 %d, SysWOW64 %d, WinSxS %d; want everything in System32",
				seed, sys32.Allocated, wow.Allocated, sxs.Allocated)
		}
		if res.Allocated != 1<<20 || res.Shared != 2<<20 {
			t.Fatalf("seed %d: allocated %d shared %d", seed, res.Allocated, res.Shared)
		}
		if len(res.Largest) != 1 || res.Largest[0].Path != `C:\Windows\System32\big.dll` {
			t.Fatalf("seed %d: largest = %+v; want the file once, under System32", seed, res.Largest)
		}
	}
}

func TestHardLinkWithAnOutdatedEntryCountsTheLargerSize(t *testing.T) {
	f := memfs.New()
	f.Add(`C:\a\file.bin`, fsx.Entry{Size: 4096, Allocated: 4096, FileID: 7})
	f.Add(`C:\b\file.bin`, fsx.Entry{Size: 8192, Allocated: 8192, FileID: 7})
	for seed := range 10 {
		res := run(t, shuffledLister{f, seed}, scan.Options{Roots: []string{`C:\`}, Workers: 2})
		if a, b := res.Find(`C:\a`), res.Find(`C:\b`); a.Allocated != 8192 || b.Allocated != 0 || res.Allocated != 8192 {
			t.Fatalf("seed %d: a %d, b %d, total %d; want 8192 once, in a", seed, a.Allocated, b.Allocated, res.Allocated)
		}
	}
}

func TestDeniedFoldersAreSorted(t *testing.T) {
	f := memfs.New()
	for _, d := range []string{`C:\z`, `C:\a`, `C:\m`} {
		f.Deny(d)
	}
	res := run(t, f, scan.Options{Roots: []string{`C:\`}})
	if !slices.Equal(res.Denied, []string{`C:\a`, `C:\m`, `C:\z`}) {
		t.Errorf("denied = %v; want sorted", res.Denied)
	}
}

func TestFileIDsArePerDrive(t *testing.T) {
	f := memfs.New()
	f.Add(`C:\f.bin`, fsx.Entry{Size: 4096, Allocated: 4096, FileID: 42})
	f.Add(`D:\f.bin`, fsx.Entry{Size: 4096, Allocated: 4096, FileID: 42})

	res := run(t, f, scan.Options{Roots: []string{`C:\`, `D:\`}})
	if res.Allocated != 8192 || res.Shared != 0 {
		t.Errorf("allocated %d shared %d; the same ID on two drives means two files", res.Allocated, res.Shared)
	}
}

func TestCloudOnlyFilesTakeNoSpace(t *testing.T) {
	f := memfs.New()
	f.Add(`C:\OneDrive\movie.mp4`, fsx.Entry{Size: 1 << 30, Attrs: fsx.AttrRecallOnDataAccess})

	res := run(t, f, scan.Options{Roots: []string{`C:\`}})
	if res.Allocated != 0 || res.Size != 1<<30 || res.CloudOnly != 1 {
		t.Errorf("allocated %d size %d cloud-only %d", res.Allocated, res.Size, res.CloudOnly)
	}
}

func TestUnreadableFoldersAreReported(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\ok\file.bin`, 4096, t0)
	f.Deny(`C:\System Volume Information`)

	res := run(t, f, scan.Options{Roots: []string{`C:\`}})
	svi := res.Find(`C:\System Volume Information`)
	if svi == nil || !svi.Denied {
		t.Errorf("denied folder = %+v", svi)
	}
	if res.Errors != 1 || len(res.Denied) != 1 || res.Denied[0] != `C:\System Volume Information` {
		t.Errorf("errors %d denied %v", res.Errors, res.Denied)
	}
	if res.Allocated != 4096 {
		t.Errorf("the rest of the scan must still count: allocated %d", res.Allocated)
	}
}

func TestLargestFilesAndTypes(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Downloads\setup.ISO`, 4<<30, t0)
	f.AddFile(`C:\Downloads\video.mp4`, 2<<30, t0)
	f.AddFile(`C:\Other\disk.iso`, 3<<30, t0)
	f.AddFile(`C:\Other\notes`, 10, t0)
	for i := range 50 {
		f.AddFile(fmt.Sprintf(`C:\Small\f%d.txt`, i), 100, t0)
	}

	res := run(t, f, scan.Options{Roots: []string{`C:\`}, TopFiles: 3})
	if len(res.Largest) != 3 {
		t.Fatalf("largest = %d files; want 3", len(res.Largest))
	}
	want := []string{`C:\Downloads\setup.ISO`, `C:\Other\disk.iso`, `C:\Downloads\video.mp4`}
	for i, w := range want {
		if res.Largest[i].Path != w {
			t.Errorf("largest[%d] = %s; want %s", i, res.Largest[i].Path, w)
		}
	}
	under := res.LargestUnder(`C:\Downloads`, 10)
	if len(under) != 2 || under[0].Path != want[0] || under[1].Path != want[2] {
		t.Errorf("LargestUnder(Downloads) = %v", under)
	}
	if got := res.LargestUnder(`C:\Down`, 10); len(got) != 0 {
		t.Errorf("LargestUnder must respect folder boundaries: %v", got)
	}

	if res.Types[0].Ext != ".iso" || res.Types[0].Files != 2 || res.Types[0].Allocated != 7<<30 {
		t.Errorf("top type = %+v; want .iso (both cases) with 2 files, 7 GiB", res.Types[0])
	}
	var noExt *scan.TypeStat
	for i := range res.Types {
		if res.Types[i].Ext == "" {
			noExt = &res.Types[i]
		}
	}
	if noExt == nil || noExt.Files != 1 {
		t.Errorf("files without an extension = %+v", noExt)
	}
}

// slowLister makes every listing take a while, for cancellation tests.
type slowLister struct{ fsx.Lister }

func (s slowLister) List(dir string) ([]fsx.Entry, error) {
	time.Sleep(5 * time.Millisecond)
	return s.Lister.List(dir)
}

func TestCancel(t *testing.T) {
	f := memfs.New()
	for i := range 2000 {
		f.AddFile(fmt.Sprintf(`C:\d%d\f.bin`, i), 4096, t0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	start := time.Now()
	_, err := scan.Run(ctx, slowLister{f}, scan.Options{Roots: []string{`C:\`}, Workers: 4})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cancelling took %v", d)
	}
}

func TestProgressMovesForward(t *testing.T) {
	f := memfs.New()
	for i := range 300 {
		f.AddFile(fmt.Sprintf(`C:\d%d\f.bin`, i), 4096, t0)
	}
	var mu sync.Mutex
	var seen []scan.Progress
	res := run(t, slowLister{f}, scan.Options{Roots: []string{`C:\`}, Workers: 4, Progress: func(p scan.Progress) {
		mu.Lock()
		seen = append(seen, p)
		mu.Unlock()
	}})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("got %d progress reports; want several", len(seen))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i].Files < seen[i-1].Files || seen[i].Folders < seen[i-1].Folders || seen[i].Allocated < seen[i-1].Allocated {
			t.Fatalf("progress went backwards: %+v then %+v", seen[i-1], seen[i])
		}
	}
	last := seen[len(seen)-1]
	if last.Files != res.Files || last.Allocated != res.Allocated {
		t.Errorf("final progress %+v doesn't match the result (%d files, %d bytes)", last, res.Files, res.Allocated)
	}
}

// TestRealFolderMatchesWalkDir scans a real folder and checks the totals
// against an independent count made with filepath.WalkDir.
func TestRealFolderMatchesWalkDir(t *testing.T) {
	sb := sandbox.New(t)
	for i := range 40 {
		sb.WriteFile(fmt.Sprintf(`d%d\sub%d\file%d.bin`, i%5, i%3, i), make([]byte, 1000*i))
	}
	sb.Mkdir(`empty\deeper`)

	var wantFiles, wantSize, wantFolders int64
	err := filepath.WalkDir(sb.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == sb.Root {
			return nil
		}
		if d.IsDir() {
			wantFolders++
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		wantFiles++
		wantSize += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	res := run(t, winfs.Lister{}, scan.Options{Roots: []string{sb.Root}})
	if res.Files != wantFiles || res.Size != wantSize || res.Folders != wantFolders || res.Errors != 0 {
		t.Errorf("scan: %d files, %d bytes, %d folders, %d errors; WalkDir: %d files, %d bytes, %d folders",
			res.Files, res.Size, res.Folders, res.Errors, wantFiles, wantSize, wantFolders)
	}
	if res.Allocated < res.Size-40*1024 {
		t.Errorf("allocated %d is implausibly below size %d", res.Allocated, res.Size)
	}
}

func TestRefreshMeasuresFoldersAgainInACopy(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Users\a\cache\big.bin`, 8<<20, t0)
	f.AddFile(`C:\Users\a\cache\sub\small.bin`, 4096, t0)
	f.AddFile(`C:\Users\a\NVIDIA\setup.exe`, 2<<20, t0)
	f.AddFile(`C:\other.bin`, 1<<20, t0)
	res := run(t, f, scan.Options{Roots: []string{`C:\`}})

	tree, err := f.Open(`C:\Users\a\cache`)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{`big.bin`, `sub\small.bin`, `sub`} {
		if err := tree.Remove(rel); err != nil {
			t.Fatal(err)
		}
	}
	nvidia, _ := f.Open(`C:\Users\a\NVIDIA`)
	nvidia.Remove("setup.exe")
	users, _ := f.Open(`C:\Users\a`)
	users.Remove("NVIDIA")

	got, err := scan.Refresh(context.Background(), f, res, []string{`C:\Users\a\cache`, `C:\Users\a\NVIDIA`, `C:\not\scanned`})
	if err != nil {
		t.Fatal(err)
	}
	if n := got.Find(`C:\Users\a\cache`); n == nil || n.Allocated != 0 || len(n.Children) != 0 {
		t.Errorf("cache after the refresh = %+v", n)
	}
	if got.Find(`C:\Users\a\NVIDIA`) != nil {
		t.Error("a folder that is gone is still in the result")
	}
	if got.Allocated != 1<<20 || got.Roots[0].Allocated != 1<<20 || got.Find(`C:\Users`).Allocated != 0 {
		t.Errorf("totals after the refresh: %d, %d", got.Allocated, got.Find(`C:\Users`).Allocated)
	}
	if len(got.Largest) != 1 || got.Largest[0].Path != `C:\other.bin` {
		t.Errorf("largest = %+v", got.Largest)
	}
	// The original is untouched.
	if res.Find(`C:\Users\a\cache`).Allocated != 8<<20+4096 || res.Find(`C:\Users\a\NVIDIA`) == nil || len(res.Largest) != 4 {
		t.Error("Refresh changed the result it was given")
	}
	if p := got.Find(`C:\Users\a\cache`).Parent; p != got.Find(`C:\Users\a`) {
		t.Error("parent links point into the old result")
	}
}
