package winfs_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/clean"
	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/sandbox"
	"github.com/ntson9p/coptimizer/internal/winfs"
)

// These tests delete real files, only ever inside their own sandboxes: the
// safety fuses would stop the test at the first deletion anywhere else.

func cleanPolicy(t *testing.T) *safety.Policy {
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

func cleanRun(t *testing.T, spec clean.Spec, dry bool) clean.Result {
	t.Helper()
	res, err := clean.Run(context.Background(), winfs.Cleaner{}, spec, clean.Options{DryRun: dry, Policy: cleanPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func TestCleanerDeletesContentsOfARealFolder(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`cache\plain.bin`, make([]byte, 5000))
	sb.WriteFile(`cache\sub\deeper\file.txt`, []byte("x"))
	sb.WriteFile(`cache\Thư mục\ảnh.jpg`, []byte("unicode"))
	sb.WriteFile(`cache\flags\readonly.txt`, []byte("r"))
	sb.SetAttributes(`cache\flags\readonly.txt`, 0x1|0x2|0x4) // read-only, hidden, system
	long := `cache\` + strings.Repeat(`segment-of-a-long-path\`, 14) + `end.txt`
	sb.WriteFile(long, []byte("long"))
	if len(sb.Path(long)) <= 260 {
		t.Fatalf("the long path is only %d characters", len(sb.Path(long)))
	}

	dry := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}}, true)
	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}}, false)
	loc := res.Locations[0]
	if loc.State != clean.Done || loc.Files != 5 || loc.Skipped != 0 {
		t.Fatalf("location = %+v", loc)
	}
	if dry.Files != res.Files || dry.Bytes != res.Bytes || dry.Folders != res.Folders {
		t.Errorf("dry run %d/%d/%d; real run %d/%d/%d", dry.Files, dry.Bytes, dry.Folders, res.Files, res.Bytes, res.Folders)
	}
	if !exists(t, sb.Path("cache")) {
		t.Error("the folder itself was removed")
	}
	if entries, err := os.ReadDir(sb.Path("cache")); err != nil || len(entries) != 0 {
		t.Errorf("left %v, %v", entries, err)
	}
}

// The canaries live in the same sandbox as the folder being cleaned, so the
// safety fuses would let a buggy deleter reach them: what these tests check
// is the deleter itself.

func TestCleanerNeverFollowsJunctions(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`canary\important.docx`, []byte("must survive"))
	sb.WriteFile(`canary\sub\notes.txt`, []byte("must survive"))
	sb.WriteFile(`cache\junk.tmp`, []byte("junk"))
	sb.Junction(`cache\link`, sb.Path("canary"))

	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}}, false)
	if loc := res.Locations[0]; loc.Files != 1 || loc.Kept != 1 {
		t.Errorf("location = %+v", loc)
	}
	for _, p := range []string{sb.Path(`canary\important.docx`), sb.Path(`canary\sub\notes.txt`), sb.Path(`cache\link`)} {
		if !exists(t, p) {
			t.Errorf("%s is gone", p)
		}
	}
}

func TestCleanerRefusesARootThatIsAJunction(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`canary\important.docx`, []byte("must survive"))
	sb.Junction(`cache`, sb.Path("canary"))

	if _, err := (winfs.Cleaner{}).Open(sb.Path("cache")); !errors.Is(err, fsx.ErrLink) {
		t.Errorf("Open(junction) = %v; want ErrLink", err)
	}
	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}, RemoveRoot: true}, false)
	if loc := res.Locations[0]; loc.State != clean.Refused || loc.Reason != clean.ReasonLink {
		t.Errorf("location = %+v", loc)
	}
	if !exists(t, sb.Path(`canary\important.docx`)) || !exists(t, sb.Path("cache")) {
		t.Error("the junction or its target was touched")
	}
}

// TestATreeCantBeLedOutBySwappingAFolder replaces a folder with a junction
// after the tree was opened, as malware racing the deleter might. The tree
// must neither list nor delete through it.
func TestATreeCantBeLedOutBySwappingAFolder(t *testing.T) {
	sb := sandbox.New(t)
	victim := sb.WriteFile(`canary\victim.txt`, []byte("must survive"))
	sb.Mkdir(`cache\sub`)
	tree, err := winfs.Cleaner{}.Open(sb.Path("cache"))
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if err := tree.Remove("sub"); err != nil {
		t.Fatal(err)
	}
	sb.Junction(`cache\sub`, sb.Path("canary"))

	if entries, err := tree.List("sub"); err == nil {
		t.Errorf("listed through the junction: %v", entries)
	}
	err = tree.Remove(`sub\victim.txt`)
	if err == nil || !errors.Is(err, fsx.ErrLink) {
		t.Errorf("Remove through the junction = %v; want refused as a link", err)
	}
	if !exists(t, victim) {
		t.Fatal("deleted a file through a junction")
	}
	// The junction itself can be removed; its target stays.
	if err := tree.Remove("sub"); err != nil {
		t.Errorf("removing the junction itself: %v", err)
	}
	if !exists(t, victim) {
		t.Fatal("removing the junction removed its target's contents")
	}
}

func TestFilesInUseAreSkipped(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`cache\open.dat`, []byte("held open"))
	sb.WriteFile(`cache\free.dat`, []byte("free"))
	f, err := os.Open(sb.Path(`cache\open.dat`)) // Go shares read and write, not delete
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}}, false)
	loc := res.Locations[0]
	if loc.Files != 1 || loc.Skipped != 1 || len(loc.Problems) != 1 || loc.Problems[0].Reason != clean.ReasonInUse {
		t.Errorf("location = %+v", loc)
	}
	if !exists(t, sb.Path(`cache\open.dat`)) || exists(t, sb.Path(`cache\free.dat`)) {
		t.Error("wrong file deleted")
	}
}

func TestFilesWithoutPermissionAreSkipped(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`cache\protected\keep.dat`, []byte("no delete right"))
	sb.WriteFile(`cache\other.dat`, []byte("x"))
	sb.DenyDelete(`cache\protected\keep.dat`)

	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}}, false)
	loc := res.Locations[0]
	if loc.Files != 1 || loc.Skipped != 1 || loc.Problems[0].Reason != clean.ReasonDenied {
		t.Errorf("location = %+v", loc)
	}
	if !exists(t, sb.Path(`cache\protected\keep.dat`)) {
		t.Error("deleted a file the user may not delete")
	}
}

func TestHardLinksLeaveTheOtherNameAlone(t *testing.T) {
	sb := sandbox.New(t)
	original := sb.WriteFile(`outside\original.bin`, []byte("shared data"))
	sb.Mkdir("cache")
	sb.HardLink(`cache\second-name.bin`, `outside\original.bin`)

	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("cache")}}, false)
	if res.Files != 1 || exists(t, sb.Path(`cache\second-name.bin`)) {
		t.Errorf("result = %+v", res.Locations[0])
	}
	if data, err := os.ReadFile(original); err != nil || string(data) != "shared data" {
		t.Errorf("the other name: %q, %v", data, err)
	}
}

func TestMinAgeOnRealFiles(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`temp\old.tmp`, []byte("old"))
	sb.WriteFile(`temp\new.tmp`, []byte("new"))
	sb.WriteFile(`temp\olddir\inside.tmp`, []byte("old"))
	sb.Age(`temp\old.tmp`, 72*time.Hour)
	sb.Age(`temp\olddir\inside.tmp`, 72*time.Hour)
	sb.Age(`temp\olddir`, 72*time.Hour)

	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("temp")}, MinAge: 24 * time.Hour}, false)
	if exists(t, sb.Path(`temp\old.tmp`)) || exists(t, sb.Path(`temp\olddir`)) || !exists(t, sb.Path(`temp\new.tmp`)) {
		t.Errorf("result = %+v", res.Locations[0])
	}
}

func TestRemoveRootOnRealFolders(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`NVIDIA\DisplayDriver\setup.exe`, []byte("x"))
	res := cleanRun(t, clean.Spec{Folders: []string{sb.Path("NVIDIA")}, RemoveRoot: true}, false)
	if exists(t, sb.Path("NVIDIA")) || res.Locations[0].Folders != 2 {
		t.Errorf("location = %+v", res.Locations[0])
	}
}

func TestShortNamesAreRefused(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile(`A long folder name\x.tmp`, []byte("x"))
	short, ok := sb.ShortName(`A long folder name`)
	if !ok {
		t.Skip("this volume keeps no 8.3 short names")
	}
	if _, err := (winfs.Cleaner{}).Open(short); !errors.Is(err, fsx.ErrLink) {
		t.Errorf("Open(%q) = %v; want refused", short, err)
	}
}

func TestCleanerRefusesFilesAndMissingFolders(t *testing.T) {
	sb := sandbox.New(t)
	file := sb.WriteFile("file.txt", []byte("x"))
	if _, err := (winfs.Cleaner{}).Open(file); err == nil {
		t.Error("opened a file as a folder")
	}
	if _, err := (winfs.Cleaner{}).Open(sb.Path("missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing folder: %v", err)
	}
}
