//go:build smoke

package sysinfo_test

import (
	"os"
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
