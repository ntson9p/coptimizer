package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// HistoryEntry records one cleanup.
type HistoryEntry struct {
	Time      time.Time `json:"time"` // when it finished
	Job       string    `json:"job"`
	Rule      string    `json:"rule"`
	Action    string    `json:"action"`
	Simulated bool      `json:"simulated,omitempty"`
	State     string    `json:"state"`             // succeeded, partial, failed or cancelled
	Estimate  int64     `json:"estimate"`          // bytes the preview expected
	Unknown   bool      `json:"unknown,omitempty"` // the tool decided: there was no estimate
	Deleted   int64     `json:"deleted"`           // bytes deleted, by the deleter's count
	Files     int64     `json:"files"`
	Skipped   int64     `json:"skipped"`
	Freed     int64     `json:"freed"` // measured change in free space; 0 for simulations
	Seconds   float64   `json:"seconds"`
	Locations []string  `json:"locations,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// History is the audit log of cleanups: history.jsonl in the data folder, one
// JSON object per line, only ever appended to.
type History struct {
	path string
	mu   sync.Mutex
}

const historyFile = "history.jsonl"

// maxHistoryRead is how much of the end of the log Recent reads.
const maxHistoryRead = 4 << 20

// OpenHistory returns the log in dir. The file appears with the first entry.
func OpenHistory(dir string) *History { return &History{path: filepath.Join(dir, historyFile)} }

// Path is the log's file.
func (h *History) Path() string { return h.path }

// Add appends e to the log.
func (h *History) Add(e HistoryEntry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	dir := filepath.Dir(h.path)
	safety.GuardWrite(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	safety.GuardWrite(h.path)
	f, err := os.OpenFile(h.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Recent returns up to n entries, newest first. Lines it can't read are
// skipped.
func (h *History) Recent(n int) ([]HistoryEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, err := os.Open(h.path)
	if errors.Is(err, fs.ErrNotExist) {
		return []HistoryEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxHistoryRead {
		if _, err := f.Seek(-maxHistoryRead, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHistoryRead))
	if err != nil {
		return nil, err
	}
	var all []HistoryEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), maxHistoryRead)
	for sc.Scan() {
		var e HistoryEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.IsZero() {
			all = append(all, e)
		}
	}
	return newest(all, n), nil
}

// MemoryHistory is a History that forgets everything when the program ends,
// for demo mode and tests.
type MemoryHistory struct {
	mu  sync.Mutex
	all []HistoryEntry
}

func (m *MemoryHistory) Add(e HistoryEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.all = append(m.all, e)
	return nil
}

func (m *MemoryHistory) Recent(n int) ([]HistoryEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return newest(m.all, n), nil
}

// newest returns the last n of all (oldest first), newest first.
func newest(all []HistoryEntry, n int) []HistoryEntry {
	if len(all) > n {
		all = all[len(all)-n:]
	}
	out := slices.Clone(all)
	slices.Reverse(out)
	if out == nil {
		out = []HistoryEntry{}
	}
	return out
}
