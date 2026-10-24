package winfs_test

import (
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/sandbox"
	"github.com/ntson9p/coptimizer/internal/winfs"
)

func TestListRealFolder(t *testing.T) {
	sb, other := sandbox.New(t), sandbox.New(t)
	sb.WriteFile("small.txt", make([]byte, 10))
	sb.WriteFile("big.bin", make([]byte, 100_000))
	sb.Mkdir("sub")
	sb.Junction("link", other.Root)
	sb.HardLink("small-again.txt", "small.txt")
	sb.WriteFile("Thư mục ảnh.txt", []byte("Vietnamese name"))

	entries, err := winfs.Lister{}.List(sb.Root)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]fsx.Entry)
	for _, e := range entries {
		byName[e.Name] = e
	}
	if len(byName) != 6 {
		t.Fatalf("got %d entries %v; want 6 (no . or ..)", len(byName), byName)
	}
	small, big := byName["small.txt"], byName["big.bin"]
	if small.Size != 10 || small.IsDir() || small.FileID == 0 {
		t.Errorf("small.txt = %+v", small)
	}
	if big.Size != 100_000 || big.Allocated < big.Size {
		t.Errorf("big.bin = %+v; want size 100000, allocated at least that", big)
	}
	if time.Since(big.Modified) > time.Hour || time.Since(big.Modified) < -time.Minute {
		t.Errorf("big.bin modified %v; want about now", big.Modified)
	}
	if again := byName["small-again.txt"]; again.FileID != small.FileID {
		t.Errorf("a hard link must share the file ID: %d vs %d", again.FileID, small.FileID)
	}
	if big.FileID == small.FileID {
		t.Error("different files must have different file IDs")
	}
	if sub := byName["sub"]; !sub.IsDir() || sub.IsReparse() {
		t.Errorf("sub = %+v", sub)
	}
	if link := byName["link"]; !link.IsDir() || !link.IsReparse() || link.ReparseTag != fsx.TagMountPoint {
		t.Errorf("link = %+v; want a folder reparse point with the mount-point tag", link)
	}
	if _, ok := byName["Thư mục ảnh.txt"]; !ok {
		t.Error("Unicode names must come back unchanged")
	}
}

func TestListMissingFolder(t *testing.T) {
	sb := sandbox.New(t)
	if _, err := (winfs.Lister{}).List(sb.Path("missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v; want fs.ErrNotExist", err)
	}
}
