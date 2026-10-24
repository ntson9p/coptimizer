//go:build smoke

package sysinfo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

// TestSmokeDrives reads the real drives (read-only).
func TestSmokeDrives(t *testing.T) {
	drives, err := sysinfo.Real{}.Drives()
	if err != nil {
		t.Fatal(err)
	}
	system := strings.ToUpper(os.Getenv("SystemDrive")) + `\`
	for _, d := range drives {
		t.Logf("%s %q %s: %d of %d bytes free", d.Root, d.Label, d.FS, d.Free, d.Total)
		if d.Total <= 0 || d.Free < 0 || d.Free > d.Total {
			t.Errorf("%s: implausible sizes %+v", d.Root, d)
		}
		if strings.EqualFold(d.Root, system) {
			system = ""
		}
	}
	if system != "" {
		t.Errorf("the system drive %s is missing from %+v", system, drives)
	}
}

// TestSmokeRunningAndRecycleBin lists the running programs and asks how much
// the Recycle Bin on the system drive holds. Both only read.
func TestSmokeRunningAndRecycleBin(t *testing.T) {
	names, err := sysinfo.Real{}.Running()
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range names {
		found = found || strings.EqualFold(n, filepath.Base(self))
	}
	if !found || len(names) < 10 {
		t.Errorf("%d programs, this test among them: %v", len(names), found)
	}
	bytes, items, err := sysinfo.Real{}.RecycleBin(os.Getenv("SystemDrive") + `\`)
	if err != nil || bytes < 0 || items < 0 {
		t.Errorf("RecycleBin = %d bytes, %d items, %v", bytes, items, err)
	}
	t.Logf("%d programs running; Recycle Bin: %d bytes in %d items", len(names), bytes, items)
}
