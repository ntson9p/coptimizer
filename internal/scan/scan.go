// Package scan walks folders in parallel and adds up where the space goes. It
// only reads: folder listings come from an fsx.Lister, and no file is opened.
package scan

import (
	"container/heap"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
)

// Options configures a scan.
type Options struct {
	Roots    []string // folders to scan, e.g. `C:\`
	Workers  int      // folders listed in parallel; 0 means 2 × CPU cores
	TopFiles int      // how many of the largest files to keep; 0 means 1000
	// Progress, if set, is called about four times a second, and once at the
	// end.
	Progress func(Progress)
}

// Progress is a snapshot of a running scan.
type Progress struct {
	Folders, Files, Errors int64
	Allocated              int64 // bytes on disk counted so far
	Current                string
	Elapsed                time.Duration
}

// Node is a folder in the scan result.
type Node struct {
	Name     string
	Parent   *Node
	Children []*Node // sub-folders, largest first

	// Totals for the folder and everything below it.
	Size, Allocated int64
	Files, Folders  int64
	Newest          time.Time // most recent change to a file below

	// Files directly in this folder.
	OwnSize, OwnAllocated, OwnFiles int64

	Link   bool // a junction or other link: listed, never followed
	Denied bool // could not be listed (fully)

	ownNewest time.Time
}

// File is one of the largest files found.
type File struct {
	Path            string
	Size, Allocated int64
	Modified        time.Time
}

// TypeStat sums up the files with one extension.
type TypeStat struct {
	Ext             string // lower case, with the dot; "" for none
	Files           int64
	Size, Allocated int64
}

// Result is what a finished scan found.
type Result struct {
	Roots   []*Node
	Largest []File     // largest first
	Types   []TypeStat // largest first

	Files, Folders, Errors int64
	Size, Allocated        int64
	Shared                 int64    // bytes of hard-linked files, counted only once
	CloudOnly              int64    // files whose content is only in the cloud
	Denied                 []string // up to maxDenied folders that could not be listed

	Started, Finished time.Time
}

const maxDenied = 200

// Run scans opts.Roots and returns where the space goes. It stops early, with
// ctx's error, when ctx is cancelled.
func Run(ctx context.Context, l fsx.Lister, opts Options) (*Result, error) {
	if len(opts.Roots) == 0 {
		return nil, errors.New("scan: nothing to scan")
	}
	workers := opts.Workers
	if workers <= 0 {
		workers = 2 * runtime.NumCPU()
	}
	topN := opts.TopFiles
	if topN <= 0 {
		topN = 1000
	}
	s := &state{ctx: ctx, lister: l, top: topFiles{n: topN}}
	s.q.cond = sync.NewCond(&s.q.mu)
	res := &Result{Started: time.Now()}
	volumes := make(map[string]*idSet) // file IDs are unique per volume
	for _, root := range opts.Roots {
		vol := strings.ToUpper(filepath.VolumeName(root))
		if volumes[vol] == nil {
			volumes[vol] = new(idSet)
		}
		n := &Node{Name: root}
		res.Roots = append(res.Roots, n)
		s.q.push(job{node: n, path: root, seen: volumes[vol]})
	}

	stop := context.AfterFunc(ctx, s.q.close)
	defer stop()
	done := make(chan struct{})
	if opts.Progress != nil {
		go s.report(opts.Progress, res.Started, done)
	}
	var wg sync.WaitGroup
	types := make([]map[string]*TypeStat, workers)
	for i := range workers {
		types[i] = make(map[string]*TypeStat)
		wg.Go(func() {
			for {
				j, ok := s.q.pop()
				if !ok {
					return
				}
				s.process(j, types[i])
				s.q.done()
			}
		})
	}
	wg.Wait()
	close(done)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res.Finished = time.Now()
	for _, root := range res.Roots {
		total(root)
		res.Size += root.Size
		res.Allocated += root.Allocated
		res.Files += root.Files
		res.Folders += root.Folders
	}
	res.Errors = s.errors.Load()
	res.Shared = s.shared.Load()
	res.CloudOnly = s.cloudOnly.Load()
	res.Denied = s.denied
	res.Largest = s.top.sorted()
	res.Types = mergeTypes(types)
	if opts.Progress != nil {
		opts.Progress(s.snapshot(res.Started))
	}
	return res, nil
}

// job is a folder waiting to be listed.
type job struct {
	node *Node
	path string
	seen *idSet
}

type state struct {
	ctx    context.Context
	lister fsx.Lister
	q      queue
	top    topFiles

	folders, files, errors       atomic.Int64
	allocated, shared, cloudOnly atomic.Int64
	current                      atomic.Pointer[string]

	deniedMu sync.Mutex
	denied   []string
}

// process lists one folder: it adds up its files and queues its sub-folders.
// Only this call writes to j.node, so no locking is needed for it.
func (s *state) process(j job, types map[string]*TypeStat) {
	s.current.Store(&j.path)
	entries, err := s.lister.List(j.path)
	s.folders.Add(1)
	if err != nil {
		j.node.Denied = true
		s.errors.Add(1)
		s.deniedMu.Lock()
		if len(s.denied) < maxDenied {
			s.denied = append(s.denied, j.path)
		}
		s.deniedMu.Unlock()
	}
	n := j.node
	for _, e := range entries {
		if s.ctx.Err() != nil {
			return
		}
		if e.IsDir() {
			child := &Node{Name: e.Name, Parent: n}
			n.Children = append(n.Children, child)
			if e.IsReparse() {
				child.Link = true // a junction, symlink or mount point: never followed
				continue
			}
			s.q.push(job{node: child, path: join(j.path, e.Name), seen: j.seen})
			continue
		}
		size, alloc := e.Size, e.Allocated
		if e.FileID != 0 && alloc > 0 && !j.seen.addFirst(e.FileID) {
			s.shared.Add(alloc) // another name for a file already counted
			size, alloc = 0, 0
		}
		if e.IsCloudOnly() {
			s.cloudOnly.Add(1)
		}
		n.OwnFiles++
		n.OwnSize += size
		n.OwnAllocated += alloc
		if e.Modified.After(n.ownNewest) {
			n.ownNewest = e.Modified
		}
		s.files.Add(1)
		s.allocated.Add(alloc)
		addType(types, e.Name, size, alloc)
		s.top.offer(j.path, e, size, alloc)
	}
}

func (s *state) report(fn func(Progress), started time.Time, done <-chan struct{}) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			fn(s.snapshot(started))
		}
	}
}

func (s *state) snapshot(started time.Time) Progress {
	p := Progress{
		Folders:   s.folders.Load(),
		Files:     s.files.Load(),
		Errors:    s.errors.Load(),
		Allocated: s.allocated.Load(),
		Elapsed:   time.Since(started),
	}
	if c := s.current.Load(); c != nil {
		p.Current = *c
	}
	return p
}

// total adds up the totals of n and everything below it, and sorts every
// folder's children largest first.
func total(n *Node) {
	n.Size, n.Allocated, n.Files, n.Folders = n.OwnSize, n.OwnAllocated, n.OwnFiles, 0
	n.Newest = n.ownNewest
	for _, c := range n.Children {
		total(c)
		n.Size += c.Size
		n.Allocated += c.Allocated
		n.Files += c.Files
		n.Folders += 1 + c.Folders
		if c.Newest.After(n.Newest) {
			n.Newest = c.Newest
		}
	}
	slices.SortStableFunc(n.Children, func(a, b *Node) int {
		switch {
		case a.Allocated > b.Allocated:
			return -1
		case a.Allocated < b.Allocated:
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
}

func join(dir, name string) string {
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}

// queue holds the folders still to list. It hands out the most recently
// added folder first, which keeps the walk roughly depth-first and the queue
// short. pop blocks until there is work or no work can appear any more.
type queue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	items   []job
	pending int // queued or being processed
	closed  bool
}

func (q *queue) push(j job) {
	q.mu.Lock()
	q.items = append(q.items, j)
	q.pending++
	q.mu.Unlock()
	q.cond.Signal()
}

func (q *queue) pop() (job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && q.pending > 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed || len(q.items) == 0 {
		return job{}, false
	}
	j := q.items[len(q.items)-1]
	q.items = q.items[:len(q.items)-1]
	return j, true
}

func (q *queue) done() {
	q.mu.Lock()
	q.pending--
	last := q.pending == 0
	q.mu.Unlock()
	if last {
		q.cond.Broadcast()
	}
}

func (q *queue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// idSet remembers file IDs, to count hard-linked files once. It is split in
// shards so that parallel workers rarely wait for each other.
type idSet struct {
	shards [64]struct {
		sync.Mutex
		ids map[uint64]struct{}
	}
}

// addFirst records id and reports whether it was new.
func (s *idSet) addFirst(id uint64) bool {
	sh := &s.shards[id%uint64(len(s.shards))]
	sh.Lock()
	defer sh.Unlock()
	if _, ok := sh.ids[id]; ok {
		return false
	}
	if sh.ids == nil {
		sh.ids = make(map[uint64]struct{})
	}
	sh.ids[id] = struct{}{}
	return true
}

// topFiles keeps the n largest files. Files smaller than the smallest kept
// one are turned away without taking the lock.
type topFiles struct {
	n     int
	mu    sync.Mutex
	h     fileHeap
	floor atomic.Int64
}

func (t *topFiles) offer(dir string, e fsx.Entry, size, alloc int64) {
	if alloc <= t.floor.Load() {
		return
	}
	f := File{Path: join(dir, e.Name), Size: size, Allocated: alloc, Modified: e.Modified}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case len(t.h) < t.n:
		heap.Push(&t.h, f)
	case alloc > t.h[0].Allocated:
		t.h[0] = f
		heap.Fix(&t.h, 0)
	default:
		return
	}
	if len(t.h) == t.n {
		t.floor.Store(t.h[0].Allocated)
	}
}

func (t *topFiles) sorted() []File {
	files := slices.Clone(t.h)
	slices.SortFunc(files, func(a, b File) int {
		switch {
		case a.Allocated > b.Allocated:
			return -1
		case a.Allocated < b.Allocated:
			return 1
		}
		return strings.Compare(a.Path, b.Path)
	})
	return files
}

// fileHeap is a min-heap by size on disk.
type fileHeap []File

func (h fileHeap) Len() int           { return len(h) }
func (h fileHeap) Less(i, j int) bool { return h[i].Allocated < h[j].Allocated }
func (h fileHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *fileHeap) Push(x any)        { *h = append(*h, x.(File)) }
func (h *fileHeap) Pop() any {
	old := *h
	f := old[len(old)-1]
	*h = old[:len(old)-1]
	return f
}

func addType(types map[string]*TypeStat, name string, size, alloc int64) {
	ext := strings.ToLower(filepath.Ext(name))
	if len(ext) > 16 {
		ext = "" // not a real extension, just a long name with a dot
	}
	t := types[ext]
	if t == nil {
		t = &TypeStat{Ext: ext}
		types[ext] = t
	}
	t.Files++
	t.Size += size
	t.Allocated += alloc
}

func mergeTypes(perWorker []map[string]*TypeStat) []TypeStat {
	all := make(map[string]*TypeStat)
	for _, m := range perWorker {
		for ext, t := range m {
			a := all[ext]
			if a == nil {
				a = &TypeStat{Ext: ext}
				all[ext] = a
			}
			a.Files += t.Files
			a.Size += t.Size
			a.Allocated += t.Allocated
		}
	}
	out := make([]TypeStat, 0, len(all))
	for _, t := range all {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b TypeStat) int {
		switch {
		case a.Allocated > b.Allocated:
			return -1
		case a.Allocated < b.Allocated:
			return 1
		}
		return strings.Compare(a.Ext, b.Ext)
	})
	return out
}
