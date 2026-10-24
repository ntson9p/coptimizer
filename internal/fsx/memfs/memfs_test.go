package memfs_test

import (
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

func TestListing(t *testing.T) {
	f := memfs.New()
	now := time.Now()
	f.AddFile(`C:\a\b.txt`, 5000, now)
	f.AddDir(`C:\a\empty`)
	f.AddJunction(`C:\a\link`)
	f.Deny(`C:\secret`)

	entries, err := f.List(`C:\a`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name] = true
		switch e.Name {
		case "b.txt":
			if e.Size != 5000 || e.Allocated != 8192 || e.IsDir() || e.FileID == 0 {
				t.Errorf("b.txt = %+v", e)
			}
		case "empty":
			if !e.IsDir() || e.IsReparse() {
				t.Errorf("empty = %+v", e)
			}
		case "link":
			if !e.IsDir() || !e.IsReparse() {
				t.Errorf("link = %+v", e)
			}
		}
	}
	if len(got) != 3 {
		t.Errorf("entries = %v; want b.txt, empty, link", got)
	}
	if _, err := f.List(`c:\A`); err != nil {
		t.Errorf("names should ignore case: %v", err)
	}
	if _, err := f.List(`C:\secret`); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("denied folder: err = %v", err)
	}
	if _, err := f.List(`C:\missing`); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing folder: err = %v", err)
	}
	if n := f.Listed(`C:\a`); n != 2 {
		t.Errorf("Listed = %d; want 2", n)
	}
}

func TestHardLinkSharesFileID(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\x\one.dll`, 100, time.Now())
	f.AddHardLink(`C:\y\two.dll`, `C:\x\one.dll`)
	a, _ := f.List(`C:\x`)
	b, _ := f.List(`C:\y`)
	if a[0].FileID != b[0].FileID || b[0].Name != "two.dll" {
		t.Errorf("hard link: %+v vs %+v", a[0], b[0])
	}
}
