package sandbox_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ntson9p/coptimizer/internal/sandbox"
)

func TestWriteFileAndMkdir(t *testing.T) {
	sb := sandbox.New(t)
	p := sb.WriteFile(`a\b\c.txt`, []byte("hello"))
	if got, err := os.ReadFile(p); err != nil || string(got) != "hello" {
		t.Fatalf("read back %q, %v", got, err)
	}
	d := sb.Mkdir(`x\y`)
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatalf("Mkdir: %v, %v", fi, err)
	}
}

func TestJunctionLeadsToTarget(t *testing.T) {
	sb, other := sandbox.New(t), sandbox.New(t)
	other.WriteFile("canary.txt", []byte("canary"))
	link := sb.Junction("link", other.Root)

	if got, err := os.ReadFile(filepath.Join(link, "canary.txt")); err != nil || string(got) != "canary" {
		t.Fatalf("read through the junction: %q, %v", got, err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) == 0 {
		t.Fatalf("the junction looks like a plain folder: mode %v", fi.Mode())
	}
}
