package safety_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/sandbox"
)

// mustTrip fails the test unless f trips a safety fuse.
func mustTrip(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		t.Helper()
		r := recover()
		if r == nil {
			t.Errorf("%s: the safety fuse did not trip", name)
		} else if msg := fmt.Sprint(r); !strings.Contains(msg, "SAFETY FUSE") {
			t.Errorf("%s: unexpected panic: %s", name, msg)
		}
	}()
	f()
}

func TestFusesAreArmed(t *testing.T) {
	if !safety.Armed() {
		t.Fatal("the fuses must be armed inside tests")
	}
}

func TestGuardsAllowTheSandbox(t *testing.T) {
	sb := sandbox.New(t)
	file := sb.WriteFile(`dir\file.txt`, []byte("x"))

	safety.GuardWrite(file)
	safety.GuardWrite(sb.Path("not", "created", "yet.txt"))
	safety.GuardWrite(strings.ToUpper(file))
	safety.GuardDelete(file)
	safety.GuardDelete(sb.Path("dir"))
}

func TestGuardsTripOutsideTheSandbox(t *testing.T) {
	sandbox.New(t) // a sandbox exists, but none of these paths is in it
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(){
		"delete a system file":       func() { safety.GuardDelete(`C:\Windows\System32\drivers\etc\hosts`) },
		"write into Windows":         func() { safety.GuardWrite(`C:\Windows\coptimizer-test.txt`) },
		"write into Documents":       func() { safety.GuardWrite(filepath.Join(home, "Documents", "coptimizer-test.txt")) },
		"delete the repo's go.mod":   func() { safety.GuardDelete(filepath.Join(wd, "..", "..", "go.mod")) },
		"delete a drive root":        func() { safety.GuardDelete(`C:\`) },
		"delete a relative path":     func() { safety.GuardDelete(`go.mod`) },
		"write to a network share":   func() { safety.GuardWrite(`\\server\share\x.txt`) },
		"write to a stream":          func() { safety.GuardWrite(`C:\Windows\win.ini:x`) },
		"climb out with dot-dot":     func() { safety.GuardWrite(wd + `\..\..\escape.txt`) },
		"delete a missing far path":  func() { safety.GuardDelete(`C:\coptimizer-missing\a\b\c.txt`) },
		"write a missing drive root": func() { safety.GuardWrite(`Q:\coptimizer-test.txt`) },
	}
	for name, f := range cases {
		mustTrip(t, name, f)
	}
}

func TestGuardsSeeThroughJunctions(t *testing.T) {
	sb := sandbox.New(t)
	outside := t.TempDir() // a real folder that is not a sandbox
	link := sb.Junction("link", outside)

	safety.GuardDelete(link) // removing the link itself stays inside the sandbox
	mustTrip(t, "write through a junction", func() { safety.GuardWrite(filepath.Join(link, "x.txt")) })
	mustTrip(t, "write deep through a junction", func() { safety.GuardWrite(filepath.Join(link, "a", "b", "c.txt")) })
	mustTrip(t, "delete through a junction", func() { safety.GuardDelete(filepath.Join(link, "x.txt")) })
	mustTrip(t, "write the junction itself", func() { safety.GuardWrite(link) })
}

func TestGuardsTripAfterRelease(t *testing.T) {
	dir := t.TempDir()
	release := safety.RegisterSandbox(dir)
	safety.GuardWrite(filepath.Join(dir, "x.txt"))
	release()
	mustTrip(t, "write after release", func() { safety.GuardWrite(filepath.Join(dir, "x.txt")) })
}

func TestGuardRun(t *testing.T) {
	sb := sandbox.New(t)
	helper := sb.WriteFile("helper.exe", []byte("not really a program"))

	mustTrip(t, "run cmd.exe", func() { safety.GuardRun(`C:\Windows\System32\cmd.exe`) })
	mustTrip(t, "run an unregistered helper", func() { safety.GuardRun(helper) })
	release := safety.RegisterTestProgram(helper)
	safety.GuardRun(helper)
	release()
	mustTrip(t, "run after release", func() { safety.GuardRun(helper) })
}

func TestGuardSystemChangeAlwaysTrips(t *testing.T) {
	mustTrip(t, "system change", func() { safety.GuardSystemChange("the Recycle Bin") })
}

func TestRegisterSandboxRejectsBadFolders(t *testing.T) {
	mustTrip(t, "relative folder", func() { safety.RegisterSandbox(`relative\dir`) })
	mustTrip(t, "missing folder", func() { safety.RegisterSandbox(`C:\coptimizer-does-not-exist`) })
}
