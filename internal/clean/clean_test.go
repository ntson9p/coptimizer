package clean_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/clean"
	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

const temp = `C:\Users\alice\AppData\Local\Temp`

func policy(t testing.TB) *safety.Policy {
	t.Helper()
	p, err := safety.NewPolicy(safety.Places{
		SystemDrive: `C:`, Windows: `C:\Windows`, ProgramData: `C:\ProgramData`,
		ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`, Users: `C:\Users`,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, f *memfs.FS, spec clean.Spec, dry bool) clean.Result {
	t.Helper()
	res, err := clean.Run(context.Background(), f, spec, clean.Options{DryRun: dry, Policy: policy(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func old(f *memfs.FS, path string, size int64) { f.AddFile(path, size, now.AddDate(0, 0, -30)) }

func TestDeletesTheContentsAndKeepsTheFolder(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\a.tmp`, 1000)
	old(f, temp+`\sub\b.tmp`, 5000)
	old(f, temp+`\sub\deeper\c.tmp`, 9000)
	f.AddDir(temp + `\empty`)

	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	loc := res.Locations[0]
	// On disk the files take whole 4 KiB clusters: 4096 + 8192 + 12288.
	if loc.State != clean.Done || loc.Files != 3 || loc.Bytes != 24576 || loc.Folders != 3 || loc.Skipped != 0 {
		t.Errorf("location = %+v", loc)
	}
	if !f.Exists(temp) {
		t.Error("the folder itself was removed")
	}
	if entries, _ := f.List(temp); len(entries) != 0 {
		t.Errorf("left %v", entries)
	}
	if f.Freed("C:") != 24576 {
		t.Errorf("freed %d", f.Freed("C:"))
	}
}

func TestDryRunDeletesNothing(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\a.tmp`, 1000)
	old(f, temp+`\sub\b.tmp`, 5000)
	res := run(t, f, clean.Spec{Folders: []string{temp}, RemoveRoot: true}, true)
	if !res.DryRun || res.Files != 2 || res.Folders != 2 || len(res.Locations[0].Samples) != 2 {
		t.Errorf("dry run = %+v", res)
	}
	if !f.Exists(temp+`\a.tmp`) || !f.Exists(temp+`\sub\b.tmp`) || f.Freed("C:") != 0 {
		t.Error("a dry run deleted something")
	}
}

func TestLinksAreNeverEntered(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\a.tmp`, 1000)
	f.AddJunction(temp + `\link-to-documents`)
	old(f, `C:\Users\alice\Documents\canary.docx`, 100)
	f.Add(temp+`\file-link`, fsx.Entry{Attrs: fsx.AttrReparsePoint, ReparseTag: 0xA000000C, Modified: now.AddDate(-1, 0, 0)})

	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	loc := res.Locations[0]
	if loc.Files != 1 || loc.Kept != 2 {
		t.Errorf("location = %+v; want 1 file deleted and both links kept", loc)
	}
	if !f.Exists(temp+`\link-to-documents`) || !f.Exists(temp+`\file-link`) || !f.Exists(`C:\Users\alice\Documents\canary.docx`) {
		t.Error("a link or what it points to was removed")
	}
}

func TestARootThatIsALinkIsRefused(t *testing.T) {
	f := memfs.New()
	f.AddJunction(temp)
	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	if loc := res.Locations[0]; loc.State != clean.Refused || loc.Reason != clean.ReasonLink || res.Refused != 1 {
		t.Errorf("location = %+v", loc)
	}
	// Turned into a junction between the preview and the real run.
	g := memfs.New()
	old(g, temp+`\x.tmp`, 10)
	if res := run(t, g, clean.Spec{Folders: []string{temp}}, true); res.Files != 1 {
		t.Fatalf("preview = %+v", res)
	}
	h := memfs.New()
	h.AddJunction(temp)
	if res := run(t, h, clean.Spec{Folders: []string{temp}}, false); res.Locations[0].State != clean.Refused {
		t.Errorf("real run through a swapped junction = %+v", res.Locations[0])
	}
}

// redirecting opens another folder than the one asked for, as a junction on
// the way would make Windows do.
type redirecting struct {
	*memfs.FS
	to string
}

func (r redirecting) Open(string) (fsx.Tree, error) { return r.FS.Open(r.to) }

func TestAFolderThatResolvesElsewhereIsRefused(t *testing.T) {
	f := memfs.New()
	old(f, `C:\Users\alice\Documents\cv.docx`, 1000)
	old(f, temp+`\x.tmp`, 1000)
	res, err := clean.Run(context.Background(), redirecting{f, `C:\Users\alice\Documents`},
		clean.Spec{Folders: []string{temp}}, clean.Options{Policy: policy(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if loc := res.Locations[0]; loc.State != clean.Refused || loc.Reason != clean.ReasonLink {
		t.Errorf("location = %+v", loc)
	}
	if !f.Exists(`C:\Users\alice\Documents\cv.docx`) {
		t.Fatal("deleted in the folder it was led to")
	}
}

func TestThePolicyDecides(t *testing.T) {
	f := memfs.New()
	old(f, `C:\Windows\System32\kernel32.dll`, 1000)
	old(f, `C:\Users\alice\Documents\cv.docx`, 1000)
	old(f, `C:\Windows\Temp\x.tmp`, 1000)
	res := run(t, f, clean.Spec{
		Folders: []string{`C:\Windows\System32`, `C:\Users\alice\Documents`, `C:\Users\alice`, `C:\`, `C:\Windows\Temp`},
		Files:   []string{`C:\Windows\System32\kernel32.dll`},
	}, false)
	for _, loc := range res.Locations[:4] {
		if loc.State != clean.Refused || loc.Reason != clean.ReasonPolicy {
			t.Errorf("%s: %+v; want refused by the policy", loc.Path, loc)
		}
	}
	if loc := res.Locations[5]; loc.State != clean.Refused {
		t.Errorf("single file in System32: %+v", loc)
	}
	if !f.Exists(`C:\Windows\System32\kernel32.dll`) || !f.Exists(`C:\Users\alice\Documents\cv.docx`) {
		t.Fatal("a protected file was deleted")
	}
	if f.Exists(`C:\Windows\Temp\x.tmp`) {
		t.Error("the allowed folder wasn't cleaned")
	}
}

func TestProtectedFoldersInsideARootStay(t *testing.T) {
	// A folder the policy protects, found inside a folder being cleaned,
	// is left alone.
	f := memfs.New()
	old(f, `C:\Users\alice\AppData\Local\Temp\x.tmp`, 10)
	p, err := safety.NewPolicy(safety.Places{
		SystemDrive: `C:`, Windows: `C:\Windows`, ProgramData: `C:\ProgramData`,
		ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`, Users: `C:\Users`,
		KnownFolders: []string{temp + `\Moved Documents`},
	})
	if err != nil {
		t.Fatal(err)
	}
	old(f, temp+`\Moved Documents\thesis.docx`, 10)
	res, err := clean.Run(context.Background(), f, clean.Spec{Folders: []string{temp}}, clean.Options{Policy: p, Now: now})
	if err != nil || res.Files != 1 || !f.Exists(temp+`\Moved Documents\thesis.docx`) {
		t.Errorf("res = %+v, %v", res, err)
	}
}

func TestFilesInUseAndWithoutPermissionAreSkipped(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\open.tmp`, 1000)
	old(f, temp+`\locked\inner.tmp`, 1000)
	old(f, temp+`\free.tmp`, 1000)
	f.Lock(temp + `\open.tmp`)
	f.DenyDelete(temp + `\locked\inner.tmp`)

	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	loc := res.Locations[0]
	if loc.Files != 1 || loc.Skipped != 2 || loc.SkippedBytes != 2*4096 || res.Skipped != 2 {
		t.Fatalf("location = %+v", loc)
	}
	reasons := map[string]string{}
	for _, p := range loc.Problems {
		reasons[p.Path] = p.Reason
	}
	if reasons[temp+`\open.tmp`] != clean.ReasonInUse || reasons[temp+`\locked\inner.tmp`] != clean.ReasonDenied {
		t.Errorf("problems = %+v", loc.Problems)
	}
	if !f.Exists(temp + `\locked`) {
		t.Error("a folder that still holds a file was removed")
	}
}

func TestMinAgeCountsFromTheLaterOfCreationAndChange(t *testing.T) {
	f := memfs.New()
	day := 24 * time.Hour
	add := func(name string, modified, created time.Time) {
		f.Add(temp+`\`+name, fsx.Entry{Size: 10, Allocated: 4096, Modified: modified, Created: created})
	}
	add("old.tmp", now.Add(-48*time.Hour), now.Add(-48*time.Hour))
	add("boundary.tmp", now.Add(-day), time.Time{})
	add("recent.tmp", now.Add(-time.Hour), now.Add(-48*time.Hour))
	// Unpacked a minute ago, but carrying an old modification time.
	add("unpacked.tmp", now.AddDate(-1, 0, 0), now.Add(-time.Minute))
	// A fresh empty folder, maybe about to be used.
	f.Add(temp+`\new-dir`, fsx.Entry{Attrs: fsx.AttrDirectory, Modified: now.Add(-time.Minute), Created: now.Add(-time.Minute)})

	res := run(t, f, clean.Spec{Folders: []string{temp}, MinAge: day}, false)
	for name, gone := range map[string]bool{"old.tmp": true, "boundary.tmp": true, "recent.tmp": false, "unpacked.tmp": false, "new-dir": false} {
		if f.Exists(temp+`\`+name) == gone {
			t.Errorf("%s: gone = %v; want %v", name, !gone, gone)
		}
	}
	if loc := res.Locations[0]; loc.Files != 2 || loc.Kept != 2 {
		t.Errorf("location = %+v", loc)
	}
}

func TestIncludeAndExclude(t *testing.T) {
	f := memfs.New()
	explorer := `C:\Users\alice\AppData\Local\Microsoft\Windows\Explorer`
	old(f, explorer+`\thumbcache_256.db`, 1000)
	old(f, explorer+`\THUMBCACHE_1024.DB`, 1000)
	old(f, explorer+`\iconcache_16.db`, 1000)
	old(f, explorer+`\ExplorerStartupLog.etl`, 1000)
	old(f, temp+`\SymbolCache\x.pdb`, 1000)
	old(f, temp+`\Photoshop Temp1234`, 1000)
	old(f, temp+`\other.tmp`, 1000)

	run(t, f, clean.Spec{Folders: []string{explorer}, Include: []string{"thumbcache_*.db"}}, false)
	if f.Exists(explorer+`\thumbcache_256.db`) || f.Exists(explorer+`\THUMBCACHE_1024.DB`) ||
		!f.Exists(explorer+`\iconcache_16.db`) || !f.Exists(explorer+`\ExplorerStartupLog.etl`) {
		t.Error("Include matched the wrong files")
	}
	res := run(t, f, clean.Spec{Folders: []string{temp}, Exclude: []string{temp + `\SymbolCache`, temp + `\photoshop temp1234`}}, false)
	if !f.Exists(temp+`\SymbolCache\x.pdb`) || !f.Exists(temp+`\Photoshop Temp1234`) || f.Exists(temp+`\other.tmp`) {
		t.Error("Exclude didn't leave the excluded locations alone")
	}
	if loc := res.Locations[0]; loc.Kept != 2 {
		t.Errorf("kept %d; want 2", loc.Kept)
	}
}

func TestRemoveRootAndSingleFiles(t *testing.T) {
	f := memfs.New()
	old(f, `C:\NVIDIA\DisplayDriver\552.44\setup.exe`, 1000)
	old(f, `C:\Windows\MEMORY.DMP`, 5000)
	old(f, `C:\Windows\notepad.exe`, 100)

	res := run(t, f, clean.Spec{
		Folders:    []string{`C:\NVIDIA`, `C:\AMD`},
		Files:      []string{`C:\Windows\MEMORY.DMP`, `C:\Windows\Minidump\gone.dmp`, `C:\Windows\other.dmp`},
		RemoveRoot: true,
	}, false)
	if f.Exists(`C:\NVIDIA`) || f.Exists(`C:\Windows\MEMORY.DMP`) || !f.Exists(`C:\Windows\notepad.exe`) {
		t.Errorf("after the cleanup: NVIDIA %v, MEMORY.DMP %v, notepad %v",
			f.Exists(`C:\NVIDIA`), f.Exists(`C:\Windows\MEMORY.DMP`), f.Exists(`C:\Windows\notepad.exe`))
	}
	states := []string{}
	for _, l := range res.Locations {
		states = append(states, l.State)
	}
	// Only MEMORY.DMP may be deleted from C:\Windows itself.
	if !slices.Equal(states, []string{clean.Done, clean.Missing, clean.Done, clean.Missing, clean.Refused}) {
		t.Errorf("states = %v", states)
	}
	if loc := res.Locations[0]; loc.Folders != 3 || loc.Files != 1 {
		t.Errorf("NVIDIA = %+v; want 1 file and 3 folders (the root too)", loc)
	}
}

func TestOnlineOnlyFilesAreLeftAlone(t *testing.T) {
	f := memfs.New()
	f.Add(temp+`\cloud.mp4`, fsx.Entry{Size: 1 << 30, Attrs: fsx.AttrRecallOnDataAccess, Modified: now.AddDate(-1, 0, 0)})
	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	if !f.Exists(temp+`\cloud.mp4`) || res.Kept != 1 {
		t.Errorf("res = %+v", res)
	}
}

func TestCancelStopsAndCountsStayConsistent(t *testing.T) {
	f := memfs.New()
	for i := range 2000 {
		old(f, fmt.Sprintf(`%s\d%02d\f%04d.tmp`, temp, i%40, i), 100)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	res, err := clean.Run(ctx, f, clean.Spec{Folders: []string{temp}}, clean.Options{Policy: policy(t), Now: now,
		Progress: func(clean.Progress) {
			if calls++; calls == 1 {
				cancel()
			}
		}})
	if err != context.Canceled {
		t.Fatalf("err = %v; want cancelled", err)
	}
	remaining := 0
	for i := range 2000 {
		if f.Exists(fmt.Sprintf(`%s\d%02d\f%04d.tmp`, temp, i%40, i)) {
			remaining++
		}
	}
	if int64(2000-remaining) != res.Files || remaining == 0 {
		t.Errorf("deleted %d files, reported %d (remaining %d)", 2000-remaining, res.Files, remaining)
	}
}

func TestProgressIsReported(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\a.tmp`, 10)
	var last clean.Progress
	if _, err := clean.Run(context.Background(), f, clean.Spec{Folders: []string{temp}}, clean.Options{Policy: policy(t), Now: now,
		Progress: func(p clean.Progress) { last = p }}); err != nil {
		t.Fatal(err)
	}
	if last.Files != 1 || last.Bytes != 4096 {
		t.Errorf("last progress = %+v", last)
	}
}

func TestNoPolicyNoCleanup(t *testing.T) {
	if _, err := clean.Run(context.Background(), memfs.New(), clean.Spec{Folders: []string{temp}}, clean.Options{}); err == nil {
		t.Error("Run without a policy worked")
	}
}

// TestDryRunMatchesTheRealRun builds random folders and checks that a dry
// run reports exactly what the real run then deletes.
func TestDryRunMatchesTheRealRun(t *testing.T) {
	for seed := range uint64(30) {
		rng := rand.New(rand.NewPCG(seed, 7))
		build := func() *memfs.FS {
			r := rand.New(rand.NewPCG(seed, 7))
			f := memfs.New()
			for i := range 200 {
				dir := temp
				for d := r.IntN(4); d > 0; d-- {
					dir += fmt.Sprintf(`\d%d`, r.IntN(3))
				}
				age := time.Duration(r.IntN(72)) * time.Hour
				name := fmt.Sprintf(`%s\f%03d%s`, dir, i, []string{".tmp", ".log", ".db"}[r.IntN(3)])
				switch r.IntN(10) {
				case 0:
					f.AddJunction(dir + fmt.Sprintf(`\link%d`, i))
				case 1:
					f.AddDir(dir + fmt.Sprintf(`\empty%d`, i))
				default:
					f.Add(name, fsx.Entry{Size: int64(r.IntN(100000)), Allocated: int64(r.IntN(100000)), Modified: now.Add(-age)})
				}
			}
			return f
		}
		spec := clean.Spec{
			Folders: []string{temp},
			MinAge:  time.Duration(rng.IntN(48)) * time.Hour,
			Exclude: []string{temp + `\d1`},
		}
		if rng.IntN(2) == 0 {
			spec.Include = []string{"*.tmp", "*.db"}
		}
		dry := run(t, build(), spec, true)
		f := build()
		before := allFiles(f, temp)
		real := run(t, f, spec, false)
		gone := slices.DeleteFunc(before, func(p string) bool { return f.Exists(p) })
		if dry.Files != real.Files || dry.Bytes != real.Bytes || dry.Folders != real.Folders || dry.Kept != real.Kept {
			t.Fatalf("seed %d: dry run %d files %d bytes %d folders %d kept; real run %d, %d, %d, %d",
				seed, dry.Files, dry.Bytes, dry.Folders, dry.Kept, real.Files, real.Bytes, real.Folders, real.Kept)
		}
		if int64(len(gone)) != real.Files+real.Folders {
			t.Fatalf("seed %d: %d paths gone; the run reported %d files and %d folders", seed, len(gone), real.Files, real.Folders)
		}
		for _, p := range gone {
			if strings.HasPrefix(strings.ToUpper(p), strings.ToUpper(temp+`\d1\`)) || strings.Contains(p, `\link`) {
				t.Fatalf("seed %d: %s was excluded or a link, but is gone", seed, p)
			}
		}
	}
}

// allFiles lists every path below dir, folders included.
func allFiles(f *memfs.FS, dir string) []string {
	var out []string
	entries, _ := f.List(dir)
	for _, e := range entries {
		p := dir + `\` + e.Name
		out = append(out, p)
		if e.IsDir() && !e.IsReparse() {
			out = append(out, allFiles(f, p)...)
		}
	}
	return out
}

func TestAHundredThousandFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	f := memfs.New()
	for i := range 100_000 {
		old(f, fmt.Sprintf(`%s\cache\%02x\%03x\f%d`, temp, i%256, i%1000, i), 10)
	}
	start := time.Now()
	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	if res.Files != 100_000 {
		t.Fatalf("deleted %d files", res.Files)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestPathsThatArentPlainLocalPathsAreRefused(t *testing.T) {
	res := run(t, memfs.New(), clean.Spec{Folders: []string{`relative\path`, `C:\Temp\..\Windows`}, Files: []string{`C:\x.txt:hidden`}}, false)
	for _, loc := range res.Locations {
		if loc.State != clean.Refused || loc.Reason != clean.ReasonPolicy {
			t.Errorf("%s: %+v; want refused", loc.Path, loc)
		}
	}
}

func TestUnreadableFoldersAreReportedAndKept(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\a.tmp`, 10)
	old(f, temp+`\locked\b.tmp`, 10)
	f.Deny(temp + `\locked`)
	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	loc := res.Locations[0]
	if loc.Files != 1 || len(loc.Problems) != 1 || loc.Problems[0].Reason != clean.ReasonDenied || !f.Exists(temp+`\locked\b.tmp`) {
		t.Errorf("location = %+v", loc)
	}
}

func TestSingleFilesThatArentFilesOrCantBeSeen(t *testing.T) {
	f := memfs.New()
	f.AddDir(`C:\Windows\MEMORY.DMP`) // a folder with the dump's name
	old(f, `C:\Windows\Minidump\x.dmp`, 10)
	f.Deny(`C:\Windows\Minidump`)
	res := run(t, f, clean.Spec{Files: []string{`C:\Windows\MEMORY.DMP`, `C:\Windows\Minidump\x.dmp`}}, false)
	if loc := res.Locations[0]; loc.State != clean.Refused || loc.Reason != clean.ReasonError || !f.Exists(`C:\Windows\MEMORY.DMP`) {
		t.Errorf("a folder named like the file: %+v", loc)
	}
	if loc := res.Locations[1]; loc.State != clean.Refused || loc.Reason != clean.ReasonDenied || !f.Exists(`C:\Windows\Minidump\x.dmp`) {
		t.Errorf("a file whose folder can't be listed: %+v", loc)
	}
}

func TestAnEmptiedFolderThatCantBeRemovedStays(t *testing.T) {
	f := memfs.New()
	old(f, `C:\NVIDIA\setup.exe`, 10)
	f.Lock(`C:\NVIDIA`) // held open by another program
	res := run(t, f, clean.Spec{Folders: []string{`C:\NVIDIA`}, RemoveRoot: true}, false)
	loc := res.Locations[0]
	if loc.Files != 1 || loc.Folders != 0 || len(loc.Problems) != 1 || loc.Problems[0].Reason != clean.ReasonInUse || !f.Exists(`C:\NVIDIA`) {
		t.Errorf("location = %+v", loc)
	}
}

// parentElsewhere opens the parent of the folder being removed somewhere
// else, as a junction swapped in above it would.
type parentElsewhere struct {
	*memfs.FS
	parent, to string
}

func (p parentElsewhere) Open(path string) (fsx.Tree, error) {
	if strings.EqualFold(path, p.parent) {
		return p.FS.Open(p.to)
	}
	return p.FS.Open(path)
}

func TestAFolderIsRemovedOnlyFromItsRealParent(t *testing.T) {
	f := memfs.New()
	old(f, `C:\NVIDIA\setup.exe`, 10)
	f.AddDir(`C:\Users\alice\Documents\NVIDIA`)
	res, err := clean.Run(context.Background(), parentElsewhere{f, `C:\`, `C:\Users\alice\Documents`},
		clean.Spec{Folders: []string{`C:\NVIDIA`}, RemoveRoot: true}, clean.Options{Policy: policy(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	loc := res.Locations[0]
	if len(loc.Problems) != 1 || loc.Problems[0].Reason != clean.ReasonLink || !f.Exists(`C:\Users\alice\Documents\NVIDIA`) {
		t.Errorf("location = %+v", loc)
	}
}

// refusing opens nothing, with the given error.
type refusing struct{ err error }

func (r refusing) Open(string) (fsx.Tree, error) { return nil, r.err }

func TestWhyAFolderCouldntBeOpened(t *testing.T) {
	for err, want := range map[error]string{
		fsx.ErrNotLocal:          clean.ReasonPolicy,
		fsx.ErrLink:              clean.ReasonLink,
		fs.ErrPermission:         clean.ReasonDenied,
		errors.New("disk error"): clean.ReasonError,
	} {
		res, _ := clean.Run(context.Background(), refusing{err}, clean.Spec{Folders: []string{temp}}, clean.Options{Policy: policy(t), Now: now})
		if loc := res.Locations[0]; loc.State != clean.Refused || loc.Reason != want {
			t.Errorf("%v: %+v; want %s", err, loc, want)
		}
	}
}

func TestSingleFilesAmongOthersAndMissingOnes(t *testing.T) {
	f := memfs.New()
	old(f, `C:\Windows\Minidump\a.dmp`, 10)
	old(f, `C:\Windows\Minidump\b.dmp`, 10)
	res := run(t, f, clean.Spec{Files: []string{`C:\Windows\Minidump\b.dmp`, `C:\Windows\Minidump\gone.dmp`}}, false)
	if res.Locations[0].Files != 1 || f.Exists(`C:\Windows\Minidump\b.dmp`) || !f.Exists(`C:\Windows\Minidump\a.dmp`) {
		t.Errorf("b.dmp: %+v", res.Locations[0])
	}
	if res.Locations[1].State != clean.Missing {
		t.Errorf("a file that isn't there: %+v", res.Locations[1])
	}
}

func TestCancelledBeforeTheSingleFiles(t *testing.T) {
	f := memfs.New()
	old(f, `C:\Windows\MEMORY.DMP`, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := clean.Run(ctx, f, clean.Spec{Files: []string{`C:\Windows\MEMORY.DMP`}}, clean.Options{Policy: policy(t), Now: now})
	if err != context.Canceled || len(res.Locations) != 0 || !f.Exists(`C:\Windows\MEMORY.DMP`) {
		t.Errorf("res = %+v, %v", res, err)
	}
}

func TestASubfolderThatCantBeRemovedStays(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\sub\a.tmp`, 10)
	f.Lock(temp + `\sub`)
	res := run(t, f, clean.Spec{Folders: []string{temp}}, false)
	if loc := res.Locations[0]; loc.Files != 1 || loc.Folders != 0 || !f.Exists(temp+`\sub`) {
		t.Errorf("location = %+v", loc)
	}
}

// vanishing is a file system where one file disappears just before the
// deleter gets to it, as when its program deletes it first.
type vanishing struct {
	*memfs.FS
	name string
}

func (v vanishing) Open(path string) (fsx.Tree, error) {
	t, err := v.FS.Open(path)
	if err != nil {
		return nil, err
	}
	return vanishingTree{t, v.name}, nil
}

type vanishingTree struct {
	fsx.Tree
	name string
}

func (t vanishingTree) Remove(rel string) error {
	if rel == t.name {
		t.Tree.Remove(rel)
		return fs.ErrNotExist
	}
	return t.Tree.Remove(rel)
}

func TestAFileGoneBeforeItsTurnCountsAsGone(t *testing.T) {
	f := memfs.New()
	old(f, temp+`\a.tmp`, 10)
	res, err := clean.Run(context.Background(), vanishing{f, "a.tmp"}, clean.Spec{Folders: []string{temp}}, clean.Options{Policy: policy(t), Now: now})
	if err != nil || res.Skipped != 0 || len(res.Locations[0].Problems) != 0 || f.Exists(temp+`\a.tmp`) {
		t.Errorf("res = %+v, %v", res.Locations[0], err)
	}
}

func TestAParentThatCantBeOpenedKeepsTheFolder(t *testing.T) {
	f := memfs.New()
	old(f, `C:\NVIDIA\setup.exe`, 10)
	res, err := clean.Run(context.Background(), parentRefusing{f, `C:\`}, clean.Spec{Folders: []string{`C:\NVIDIA`}, RemoveRoot: true},
		clean.Options{Policy: policy(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if loc := res.Locations[0]; loc.Files != 1 || len(loc.Problems) != 1 || loc.Problems[0].Reason != clean.ReasonDenied || !f.Exists(`C:\NVIDIA`) {
		t.Errorf("location = %+v", loc)
	}
}

// parentRefusing can't open one folder: no permission.
type parentRefusing struct {
	*memfs.FS
	parent string
}

func (p parentRefusing) Open(path string) (fsx.Tree, error) {
	if strings.EqualFold(path, p.parent) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}
	return p.FS.Open(path)
}
