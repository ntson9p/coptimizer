package demo_test

import (
	"context"
	"testing"

	"github.com/ntson9p/coptimizer/internal/demo"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

// TestDemoMachineLooksReal checks that the simulated C: drive scans cleanly
// and shows what demo mode is meant to show.
func TestDemoMachineLooksReal(t *testing.T) {
	f, sys := demo.New(0)
	drives, _ := sys.Drives()
	if sys.Elevated() || len(drives) != 3 {
		t.Fatalf("drives = %+v, elevated = %v", drives, sys.Elevated())
	}
	res, err := scan.Run(context.Background(), f, scan.Options{Roots: []string{`C:\`}})
	if err != nil {
		t.Fatal(err)
	}
	c := drives[0]
	if res.Allocated <= 0 || res.Allocated > c.Used() {
		t.Errorf("counted %d bytes, but C: uses only %d", res.Allocated, c.Used())
	}
	if res.Shared == 0 || res.CloudOnly == 0 || res.Errors != 1 {
		t.Errorf("shared %d cloud-only %d errors %d; want hard links, online-only files and one unreadable folder", res.Shared, res.CloudOnly, res.Errors)
	}
	if n := res.Find(`C:\Users\All Users`); n == nil || !n.Link {
		t.Error("the All Users junction is missing")
	}
	if npm := res.Find(`C:\Users\Demo\AppData\Local\npm-cache`); npm == nil || npm.Allocated < 8<<30 {
		t.Errorf("npm cache = %+v; want about 9 GB", npm)
	}
}
