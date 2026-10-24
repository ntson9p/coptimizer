// Package store keeps what COptimizer remembers between runs, in its own data
// folder: for now, snapshots of earlier scans, to show what grew. It writes
// one file and nothing else.
package store

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/safety"
)

// keepPerDrive is how many snapshots of each drive are kept.
const keepPerDrive = 10

// maxFileSize guards against loading a file that can't be ours.
const maxFileSize = 64 << 20

const fileName = "snapshots.json.gz"

// Snapshots are the kept snapshots of earlier scans.
type Snapshots struct {
	path string
	mu   sync.Mutex
	all  []rules.Snapshot // oldest first
}

type file struct {
	Version   int              `json:"version"`
	Snapshots []rules.Snapshot `json:"snapshots"`
}

// Open loads the snapshots kept in dir. A missing file means none yet; a file
// that can't be read is reported as an error, ignored, and replaced on the
// next save.
func Open(dir string) (*Snapshots, error) {
	s := &Snapshots{path: filepath.Join(dir, fileName)}
	err := s.load()
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return s, err
}

func (s *Snapshots) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(io.LimitReader(f, maxFileSize))
	if err != nil {
		return err
	}
	var data file
	if err := json.NewDecoder(io.LimitReader(zr, maxFileSize)).Decode(&data); err != nil {
		return err
	}
	if data.Version != 1 {
		return errors.New("store: unknown snapshot file version")
	}
	s.all = data.Snapshots
	return nil
}

// Previous returns the newest snapshot of root taken with the same rights. A
// scan with Administrator rights sees folders a scan without them can't, so
// comparing the two would show growth that isn't there.
func (s *Snapshots) Previous(root string, elevated bool) (rules.Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.all) - 1; i >= 0; i-- {
		if strings.EqualFold(s.all[i].Root, root) && s.all[i].Elevated == elevated {
			return s.all[i], true
		}
	}
	return rules.Snapshot{}, false
}

// Count returns how many snapshots of root are kept.
func (s *Snapshots) Count(root string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, x := range s.all {
		if strings.EqualFold(x.Root, root) {
			n++
		}
	}
	return n
}

// Add keeps snap, drops the oldest snapshots of its drive beyond the limit,
// and saves.
func (s *Snapshots) Add(snap rules.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = append(s.all, snap)
	n := 0
	for i := len(s.all) - 1; i >= 0; i-- {
		if strings.EqualFold(s.all[i].Root, snap.Root) {
			if n++; n > keepPerDrive {
				s.all = slices.Delete(s.all, i, i+1)
			}
		}
	}
	return s.save()
}

// save writes the snapshots to a temporary file and renames it over the old
// one, so a crash never leaves a half-written file behind.
func (s *Snapshots) save() error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(file{Version: 1, Snapshots: s.all}); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	dir, tmp := filepath.Dir(s.path), s.path+".tmp"
	safety.GuardWrite(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	safety.GuardWrite(tmp)
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	safety.GuardDelete(tmp)
	safety.GuardWrite(s.path)
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
