package safety

import (
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"testing"
)

// The fuses make it impossible for a test to change anything outside the
// folders it was given. They are armed only inside test binaries; in the real
// app they do nothing and the app's own safety rules apply instead.
//
// Every function that creates, changes or deletes files, starts a program or
// changes a system setting must call the matching guard first. The
// forbidden-API test (forbidden_test.go) keeps such functions in a few
// reviewed files.

var armed = testing.Testing()

var fuse struct {
	sync.Mutex
	sandboxes map[*sandbox]bool
	programs  map[*string]bool
}

// sandbox is a folder a test may change, as written and after following
// links.
type sandbox struct{ path, resolved string }

// Armed reports whether the fuses are active, which is only inside tests.
func Armed() bool { return armed }

// RegisterSandbox lets the running test change files inside dir, which must
// exist, until release is called. Outside tests it panics: the real app has no
// sandboxes.
func RegisterSandbox(dir string) (release func()) {
	onlyInTests("RegisterSandbox")
	p := normalizeOrTrip("register a sandbox at", dir)
	resolved, err := realPath(p)
	if err != nil {
		trip("register a sandbox at", dir, err.Error())
	}
	sb := &sandbox{path: p, resolved: resolved}
	fuse.Lock()
	defer fuse.Unlock()
	if fuse.sandboxes == nil {
		fuse.sandboxes = make(map[*sandbox]bool)
	}
	fuse.sandboxes[sb] = true
	return func() {
		fuse.Lock()
		defer fuse.Unlock()
		delete(fuse.sandboxes, sb)
	}
}

// RegisterTestProgram lets the running test start the program at path until
// release is called. Outside tests it panics.
func RegisterTestProgram(path string) (release func()) {
	onlyInTests("RegisterTestProgram")
	resolved, err := realPath(normalizeOrTrip("register a test program at", path))
	if err != nil {
		trip("register a test program at", path, err.Error())
	}
	fuse.Lock()
	defer fuse.Unlock()
	if fuse.programs == nil {
		fuse.programs = make(map[*string]bool)
	}
	fuse.programs[&resolved] = true
	return func() {
		fuse.Lock()
		defer fuse.Unlock()
		delete(fuse.programs, &resolved)
	}
}

// GuardDelete must be called before deleting path. In tests it panics unless
// the folder holding path is inside a registered sandbox, both as written and
// after following every junction and link on the way. Deleting a link removes
// only the link, so path itself may be a link to anywhere.
func GuardDelete(path string) {
	if !armed {
		return
	}
	p := normalizeOrTrip("delete", path)
	parent, name, ok := splitParent(p)
	if !ok {
		trip("delete", path, "a drive root can never be deleted")
	}
	resolved, err := resolveAllowMissing(parent)
	if err != nil {
		trip("delete", path, err.Error())
	}
	requireSandbox("delete", path, p, joinPath(resolved, name))
}

// GuardWrite must be called before creating or changing the file or folder at
// path. In tests it panics unless path is inside a registered sandbox, both as
// written and after following links, including path itself if it is a link:
// writing through a link changes its target.
func GuardWrite(path string) {
	if !armed {
		return
	}
	p := normalizeOrTrip("write", path)
	resolved, err := resolveAllowMissing(p)
	if err != nil {
		trip("write", path, err.Error())
	}
	requireSandbox("write", path, p, resolved)
}

// GuardRun must be called before starting a program. In tests it panics
// unless the program was registered with RegisterTestProgram.
func GuardRun(program string) {
	if !armed {
		return
	}
	resolved, err := realPath(normalizeOrTrip("run", program))
	if err != nil {
		trip("run", program, err.Error())
	}
	fuse.Lock()
	defer fuse.Unlock()
	for p := range fuse.programs {
		if *p == resolved {
			return
		}
	}
	trip("run", program, "only registered test programs may run in tests")
}

// GuardSystemChange must be called before changing any system setting: the
// registry, power options, restore points, services, the Recycle Bin. Tests
// must never do that, so in tests it always panics.
func GuardSystemChange(what string) {
	if armed {
		trip("change", what, "tests may never change system settings")
	}
}

func requireSandbox(op, original, p, resolved string) {
	fuse.Lock()
	defer fuse.Unlock()
	for sb := range fuse.sandboxes {
		if Contains(sb.path, p) && Contains(sb.resolved, resolved) {
			return
		}
	}
	trip(op, original, "it is outside every test sandbox")
}

// resolveAllowMissing is realPath for a path that may not exist yet: it
// resolves the nearest existing ancestor and appends the missing names, which
// can't be links because they don't exist.
func resolveAllowMissing(p string) (string, error) {
	var missing []string
	for {
		resolved, err := realPath(p)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = joinPath(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent, name, ok := splitParent(p)
		if !ok {
			return "", err
		}
		missing = append(missing, name)
		p = parent
	}
}

func normalizeOrTrip(op, path string) string {
	p, err := Normalize(path)
	if err != nil {
		trip(op, path, err.Error())
	}
	return p
}

func onlyInTests(fn string) {
	if !armed {
		panic("safety." + fn + " may only be called from tests")
	}
}

func trip(op, path, why string) {
	panic(fmt.Sprintf("SAFETY FUSE: refusing to %s %q during a test: %s", op, path, why))
}
