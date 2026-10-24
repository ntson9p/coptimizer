//go:build smoke

package scan_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
	"github.com/ntson9p/coptimizer/internal/winfs"
)

// TestSmokeScanSystemDrive scans the real system drive, read-only, and checks
// that the result is plausible. COPTIMIZER_SMOKE_WORKERS sets the number of
// parallel listings (default: the scanner's own).
func TestSmokeScanSystemDrive(t *testing.T) {
	root := strings.ToUpper(os.Getenv("SystemDrive")) + `\`
	workers, _ := strconv.Atoi(os.Getenv("COPTIMIZER_SMOKE_WORKERS"))
	drives, err := sysinfo.Real{}.Drives()
	if err != nil {
		t.Fatal(err)
	}
	var used int64
	for _, d := range drives {
		if strings.EqualFold(d.Root, root) {
			used = d.Used()
		}
	}
	start := time.Now()
	res, err := scan.Run(context.Background(), winfs.Lister{}, scan.Options{Roots: []string{root}, Workers: workers})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	const gib = 1 << 30
	t.Logf("%s: %d files, %d folders in %v (%.0f entries/s, workers=%d)", root, res.Files, res.Folders,
		elapsed.Round(time.Millisecond), float64(res.Files+res.Folders)/elapsed.Seconds(), workers)
	t.Logf("counted %.1f GiB of %.1f GiB in use; %d unreadable folders; %.2f GiB of hard links counted once",
		float64(res.Allocated)/gib, float64(used)/gib, res.Errors, float64(res.Shared)/gib)
	if res.Files < 1000 || res.Allocated <= 0 {
		t.Errorf("implausibly little found: %d files, %d bytes", res.Files, res.Allocated)
	}
	if res.Allocated > used+used/20 {
		t.Errorf("counted %d bytes, more than the %d in use", res.Allocated, used)
	}
}
