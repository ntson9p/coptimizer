package store_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/sandbox"
	"github.com/ntson9p/coptimizer/internal/store"
)

func entry(i int) store.HistoryEntry {
	return store.HistoryEntry{Time: t0.Add(time.Duration(i) * time.Hour), Job: "j" + string(rune('0'+i)),
		Rule: "dev.npm-cache", Action: "delete", State: "succeeded", Deleted: int64(i) << 20, Freed: int64(i) << 20}
}

func TestHistoryIsAppendedAndReadNewestFirst(t *testing.T) {
	sb := sandbox.New(t)
	h := store.OpenHistory(sb.Path("data")) // the folder appears with the first entry
	if got, err := h.Recent(10); err != nil || len(got) != 0 {
		t.Fatalf("empty history = %v, %v", got, err)
	}
	for i := 1; i <= 5; i++ {
		if err := h.Add(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.OpenHistory(sb.Path("data")).Recent(3)
	if err != nil || len(got) != 3 || got[0].Job != "j5" || got[2].Job != "j3" || got[0].Freed != 5<<20 {
		t.Fatalf("recent = %+v, %v", got, err)
	}
	data, err := os.ReadFile(h.Path())
	if err != nil || strings.Count(string(data), "\n") != 5 {
		t.Errorf("history.jsonl = %q, %v; want five lines", data, err)
	}
}

func TestHistorySkipsBrokenLines(t *testing.T) {
	sb := sandbox.New(t)
	h := store.OpenHistory(sb.Path("data"))
	if err := h.Add(entry(1)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.Path())
	sb.WriteFile(`data\history.jsonl`, append(append(data, "not json\n{}\n"...), data...))
	if got, err := h.Recent(10); err != nil || len(got) != 2 {
		t.Errorf("recent = %+v, %v; want the two good lines", got, err)
	}
}

func TestMemoryHistory(t *testing.T) {
	var m store.MemoryHistory
	for i := 1; i <= 3; i++ {
		m.Add(entry(i))
	}
	if got, _ := m.Recent(2); len(got) != 2 || got[0].Job != "j3" {
		t.Errorf("recent = %+v", got)
	}
}

// TestADataFolderReachedThroughAJunctionIsRefused stands for an unprivileged
// user who turned the data folder into a junction, hoping COptimizer, with
// Administrator rights, would write wherever it leads.
func TestADataFolderReachedThroughAJunctionIsRefused(t *testing.T) {
	sb := sandbox.New(t)
	sb.Mkdir("elsewhere")
	sb.Junction("data", sb.Path("elsewhere"))
	if err := store.OpenHistory(sb.Path("data")).Add(entry(1)); err == nil {
		t.Error("wrote the history through a junction")
	}
	s, err := store.Open(sb.Path("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(snap(`C:\`, 1, true)); err == nil {
		t.Error("wrote the snapshots through a junction")
	}
	if entries, _ := os.ReadDir(sb.Path("elsewhere")); len(entries) != 0 {
		t.Errorf("files appeared behind the junction: %v", entries)
	}
}

func TestATornLastLineDoesntHideTheNextEntry(t *testing.T) {
	sb := sandbox.New(t)
	h := store.OpenHistory(sb.Path("data"))
	if err := h.Add(entry(1)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.Path())
	sb.WriteFile(`data\history.jsonl`, append(data, `{"time":"2026-10-0`...)) // cut off mid-write
	if err := h.Add(entry(2)); err != nil {
		t.Fatal(err)
	}
	if got, err := h.Recent(10); err != nil || len(got) != 2 || got[0].Job != "j2" {
		t.Errorf("recent = %+v, %v; want the entries before and after the torn line", got, err)
	}
}
