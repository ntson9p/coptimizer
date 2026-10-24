// Package sandbox gives tests real, empty folders to work in. It is the only
// place where test code creates or changes files, and every helper asks the
// safety fuses first.
package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// Box is a folder that belongs to one test and is removed when it ends.
type Box struct {
	t    testing.TB
	Root string
}

// New creates an empty folder for t and registers it with the safety fuses.
func New(t testing.TB) *Box {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(safety.RegisterSandbox(root))
	return &Box{t: t, Root: root}
}

// Path returns the absolute path of rel inside the box, failing the test if
// it would lead outside.
func (b *Box) Path(rel ...string) string {
	b.t.Helper()
	p := filepath.Join(append([]string{b.Root}, rel...)...)
	if !safety.Contains(b.Root, p) {
		b.t.Fatalf("sandbox: %q is outside the sandbox %q", p, b.Root)
	}
	return p
}

// WriteFile writes data to rel inside the box, creating folders as needed,
// and returns the file's path.
func (b *Box) WriteFile(rel string, data []byte) string {
	b.t.Helper()
	p := b.Path(rel)
	safety.GuardWrite(p)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		b.t.Fatal(err)
	}
	return p
}

// Mkdir creates the folder rel inside the box, with any missing parents, and
// returns its path.
func (b *Box) Mkdir(rel string) string {
	b.t.Helper()
	p := b.Path(rel)
	safety.GuardWrite(p)
	if err := os.MkdirAll(p, 0o755); err != nil {
		b.t.Fatal(err)
	}
	return p
}

// Junction creates a directory junction at rel pointing to target and
// returns its path. The target may be anywhere: tests use junctions to prove
// that nothing follows links out of a folder.
func (b *Box) Junction(rel, target string) string {
	b.t.Helper()
	link := b.Path(rel)
	safety.GuardWrite(link)
	if err := createJunction(link, target); err != nil {
		b.t.Fatalf("sandbox: junction %q -> %q: %v", link, target, err)
	}
	return link
}
