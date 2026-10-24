package store_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/sandbox"
	"github.com/ntson9p/coptimizer/internal/store"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func snap(root string, day int, elevated bool) rules.Snapshot {
	return rules.Snapshot{Root: root, Time: t0.AddDate(0, 0, day), Elevated: elevated,
		Folders: map[string]int64{root: int64(day) << 30}}
}

func TestSnapshotsSurviveARestart(t *testing.T) {
	sb := sandbox.New(t)
	dir := sb.Path("data") // created on the first save
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Previous(`C:\`, true); ok {
		t.Fatal("a new store should be empty")
	}
	for day := 1; day <= 4; day++ {
		if err := s.Add(snap(`C:\`, day, day%2 == 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Add(snap(`D:\`, 1, true)); err != nil {
		t.Fatal(err)
	}

	again, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := again.Previous(`c:\`, true); !ok || !p.Time.Equal(t0.AddDate(0, 0, 4)) || p.Folders[`C:\`] != 4<<30 {
		t.Errorf("newest C: snapshot with Administrator rights = %+v", p)
	}
	if p, ok := again.Previous(`C:\`, false); !ok || !p.Time.Equal(t0.AddDate(0, 0, 3)) {
		t.Errorf("newest C: snapshot without them = %+v", p)
	}
	if _, ok := again.Previous(`D:\`, false); ok {
		t.Error("D: has no snapshot taken without Administrator rights")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "snapshots.json.gz" {
		t.Errorf("the data folder holds %v; want only snapshots.json.gz", entries)
	}
}

func TestOnlyTheLastTenPerDriveAreKept(t *testing.T) {
	sb := sandbox.New(t)
	s, _ := store.Open(sb.Root)
	for day := 1; day <= 15; day++ {
		s.Add(snap(`C:\`, day, false))
	}
	s.Add(snap(`D:\`, 1, false))
	again, _ := store.Open(sb.Root)
	if c, d := again.Count(`C:\`), again.Count(`D:\`); c != 10 || d != 1 {
		t.Errorf("kept %d snapshots of C: and %d of D:; want 10 and 1", c, d)
	}
	if p, _ := again.Previous(`C:\`, false); !p.Time.Equal(t0.AddDate(0, 0, 15)) {
		t.Errorf("newest = %v; want day 15", p.Time)
	}
}

func TestABrokenFileIsReplaced(t *testing.T) {
	sb := sandbox.New(t)
	sb.WriteFile("snapshots.json.gz", []byte("not a gzip file"))
	s, err := store.Open(sb.Root)
	if err == nil {
		t.Error("a broken file should be reported")
	}
	if err := s.Add(snap(`C:\`, 1, true)); err != nil {
		t.Fatal(err)
	}
	if again, err := store.Open(sb.Root); err != nil {
		t.Errorf("after saving: %v", err)
	} else if _, ok := again.Previous(`C:\`, true); !ok {
		t.Error("the new snapshot is missing")
	}
}

func TestSavingOutsideTheSandboxTripsTheFuse(t *testing.T) {
	s, _ := store.Open(`C:\Windows\coptimizer-test`)
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprint(r), "SAFETY FUSE") {
			t.Errorf("saving outside a sandbox: %v; want the fuse to trip", r)
		}
	}()
	s.Add(snap(`C:\`, 1, true))
}
