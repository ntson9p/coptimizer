// Package server is COptimizer's local web server: the embedded web page, a
// JSON API, and an event stream with live progress. It listens on 127.0.0.1
// only and trusts no caller: every API call needs the session token, and
// requests naming another host or coming from another web page are refused.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/probe"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
)

// Config is what the server needs.
type Config struct {
	Port       int    // the port it listens on; requests must name it in Host
	LaunchCode string // one-time code for the first browser tab; may be empty
	Instance   string // returned by /healthz, so the launcher knows it reached us
	Version    string
	Demo       bool
	Lister     fsx.Lister
	System     sysinfo.Reader
	Env        rules.Env     // where Windows keeps things, for the findings
	Snapshots  SnapshotStore // earlier scans, for growth; nil: none kept
	Probes     *probe.Deps   // for the system information; nil: none
	Web        fs.FS         // the web page; index.html at the top
	Logf       func(format string, args ...any)
	Shutdown   func()           // called when the page asks the server to stop
	Now        func() time.Time // nil means time.Now
}

// Server handles every HTTP request.
type Server struct {
	cfg      Config
	user     string
	sessions *sessions
	hub      *hub
	scans    *scans
	probes   *probe.Manager // nil without Config.Probes
	handler  http.Handler
}

// New returns a server for cfg.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Server{cfg: cfg, user: "Demo", sessions: newSessions(cfg.Now), hub: newHub(1000)}
	if !cfg.Demo {
		s.user = ""
		if u, err := user.Current(); err == nil {
			s.user = u.Username
		}
	}
	s.scans = newScans(cfg, s.hub)
	if cfg.LaunchCode != "" {
		s.sessions.addCode(cfg.LaunchCode)
	}
	if cfg.Probes != nil {
		s.probes = probe.NewManager(*cfg.Probes, func(r probe.Result) { s.hub.publish("system.updated", r, true) })
		s.probes.Start()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /", staticFiles(cfg.Web))
	mux.Handle("POST /api/session", s.api(s.session, false))
	mux.Handle("GET /api/status", s.api(s.status, true))
	mux.Handle("GET /api/drives", s.api(s.drives, true))
	mux.Handle("POST /api/scans", s.api(s.startScan, true))
	mux.Handle("GET /api/scans/{id}", s.api(s.getScan, true))
	mux.Handle("DELETE /api/scans/{id}", s.api(s.cancelScan, true))
	mux.Handle("GET /api/scans/{id}/tree", s.api(s.tree, true))
	mux.Handle("GET /api/scans/{id}/files", s.api(s.files, true))
	mux.Handle("GET /api/scans/{id}/types", s.api(s.types, true))
	mux.Handle("GET /api/scans/{id}/findings", s.api(s.findings, true))
	mux.Handle("GET /api/system", s.api(s.system, true))
	mux.Handle("POST /api/system/{name}", s.api(s.runProbe, true))
	mux.HandleFunc("GET /api/events", s.events)
	mux.Handle("POST /api/shutdown", s.api(s.shutdown, true))
	mux.Handle("GET /api/", s.api(func(*http.Request) (any, error) {
		return nil, &apiError{Status: 404, Code: "not_found", Message: "no such API"}
	}, true))
	s.handler = s.checkHost(securityHeaders(mux))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// Link returns the address of the web page that signs in with code.
func (s *Server) Link(code string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/#code=%s", s.cfg.Port, code)
}

// NewLaunchLink makes another one-time code and returns the link using it.
func (s *Server) NewLaunchLink() string { return s.Link(s.sessions.newCode()) }

// Close stops a running scan and running probes, and ends open event
// streams.
func (s *Server) Close() {
	s.scans.cancelAll()
	if s.probes != nil {
		s.probes.Close()
	}
	s.hub.close()
}

// checkHost refuses requests whose Host header isn't ours. A web page can
// point a DNS name of its own at 127.0.0.1 ("DNS rebinding"), but it can't
// make the browser send our host name.
func (s *Server) checkHost(next http.Handler) http.Handler {
	ok := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", s.cfg.Port): true,
		fmt.Sprintf("localhost:%d", s.cfg.Port): true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok[strings.ToLower(r.Host)] {
			http.Error(w, "unknown host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// api turns fn into a JSON handler. Changing requests from other web pages
// are refused, and with auth the session token is required.
func (s *Server) api(fn func(*http.Request) (any, error), auth bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.checkCaller(r, auth); err != nil {
			s.writeError(w, err)
			return
		}
		v, err := fn(r)
		if err != nil {
			s.writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
}

func (s *Server) checkCaller(r *http.Request, auth bool) error {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// Browsers always send Origin with these requests; other programs may
		// not, and then the token alone decides.
		if o := r.Header.Get("Origin"); o != "" && !s.ourOrigin(o) {
			return &apiError{Status: 403, Code: "bad_origin", Message: "requests from other web pages are not allowed"}
		}
	}
	if auth {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !s.sessions.valid(token) {
			return &apiError{Status: 401, Code: "unauthorized", Message: "missing or invalid session token"}
		}
	}
	return nil
}

func (s *Server) ourOrigin(origin string) bool {
	return origin == fmt.Sprintf("http://127.0.0.1:%d", s.cfg.Port) || origin == fmt.Sprintf("http://localhost:%d", s.cfg.Port)
}

// Handlers.

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"app": "coptimizer", "instance": s.cfg.Instance})
}

func (s *Server) session(r *http.Request) (any, error) {
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	token, ok := s.sessions.exchange(req.Code)
	if !ok {
		return nil, &apiError{Status: 401, Code: "bad_code", Message: "this link has already been used or has expired"}
	}
	return map[string]string{"token": token}, nil
}

type statusView struct {
	Version  string    `json:"version"`
	Demo     bool      `json:"demo"`
	Elevated bool      `json:"elevated"`
	User     string    `json:"user"`
	LastScan *scanView `json:"lastScan"`
}

func (s *Server) status(*http.Request) (any, error) { return s.statusValue(), nil }

func (s *Server) statusValue() statusView {
	return statusView{Version: s.cfg.Version, Demo: s.cfg.Demo, Elevated: s.cfg.System.Elevated(), User: s.user, LastScan: s.scans.latest()}
}

type driveView struct {
	Root  string `json:"root"`
	Label string `json:"label"`
	FS    string `json:"fs"`
	Total int64  `json:"total"`
	Free  int64  `json:"free"`
	Used  int64  `json:"used"`
}

func (s *Server) drives(*http.Request) (any, error) {
	drives, err := s.cfg.System.Drives()
	if err != nil {
		return nil, err
	}
	out := make([]driveView, 0, len(drives))
	for _, d := range drives {
		out = append(out, driveView{Root: d.Root, Label: d.Label, FS: d.FS, Total: d.Total, Free: d.Free, Used: d.Used()})
	}
	return out, nil
}

func (s *Server) startScan(r *http.Request) (any, error) {
	var req struct {
		Drives []string `json:"drives"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	j, err := s.scans.start(req.Drives)
	if err != nil {
		return nil, err
	}
	return s.scans.view(j), nil
}

func (s *Server) getScan(r *http.Request) (any, error) {
	j, err := s.scans.get(r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return s.scans.view(j), nil
}

func (s *Server) cancelScan(r *http.Request) (any, error) {
	return s.scans.cancel(r.PathValue("id"))
}

type nodeView struct {
	Name         string     `json:"name"`
	Path         string     `json:"path"`
	Size         int64      `json:"size"`
	Allocated    int64      `json:"allocated"`
	Files        int64      `json:"files"`
	Folders      int64      `json:"folders"`
	OwnSize      int64      `json:"ownSize"`
	OwnAllocated int64      `json:"ownAllocated"`
	OwnFiles     int64      `json:"ownFiles"`
	Newest       *time.Time `json:"newest,omitempty"`
	Link         bool       `json:"link"`
	Denied       bool       `json:"denied"`
	HasChildren  bool       `json:"hasChildren"`
	Children     []nodeView `json:"children,omitempty"`
	MoreChildren int        `json:"moreChildren,omitempty"`
}

// maxChildren caps how many sub-folders one tree response lists.
const maxChildren = 500

func (s *Server) tree(r *http.Request) (any, error) {
	res, _, err := s.scans.result(r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	p := r.URL.Query().Get("path")
	var n *scan.Node
	if p == "" {
		n = res.Roots[0]
	} else if n = res.Find(p); n == nil {
		return nil, &apiError{Status: 404, Code: "not_found", Message: "the scan has no folder " + strconv.Quote(p)}
	}
	v := makeNodeView(n)
	for i, c := range n.Children {
		if i == maxChildren {
			v.MoreChildren = len(n.Children) - maxChildren
			break
		}
		v.Children = append(v.Children, makeNodeView(c))
	}
	return v, nil
}

func makeNodeView(n *scan.Node) nodeView {
	v := nodeView{
		Name: n.Name, Path: n.Path(), Size: n.Size, Allocated: n.Allocated, Files: n.Files, Folders: n.Folders,
		OwnSize: n.OwnSize, OwnAllocated: n.OwnAllocated, OwnFiles: n.OwnFiles,
		Link: n.Link, Denied: n.Denied, HasChildren: len(n.Children) > 0,
	}
	if !n.Newest.IsZero() {
		t := n.Newest
		v.Newest = &t
	}
	return v
}

type fileView struct {
	Path      string     `json:"path"`
	Size      int64      `json:"size"`
	Allocated int64      `json:"allocated"`
	Modified  *time.Time `json:"modified,omitempty"`
}

func (s *Server) files(r *http.Request) (any, error) {
	res, _, err := s.scans.result(r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	limit := intParam(r, "limit", 50, 1000)
	files := res.Largest
	if p := r.URL.Query().Get("path"); p != "" {
		files = res.LargestUnder(p, limit)
	}
	out := make([]fileView, 0, min(limit, len(files)))
	for _, f := range files[:min(limit, len(files))] {
		v := fileView{Path: f.Path, Size: f.Size, Allocated: f.Allocated}
		if !f.Modified.IsZero() {
			m := f.Modified
			v.Modified = &m
		}
		out = append(out, v)
	}
	return out, nil
}

type typeView struct {
	Ext       string `json:"ext"`
	Files     int64  `json:"files"`
	Size      int64  `json:"size"`
	Allocated int64  `json:"allocated"`
}

func (s *Server) types(r *http.Request) (any, error) {
	res, _, err := s.scans.result(r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	limit := intParam(r, "limit", 30, 500)
	out := make([]typeView, 0, min(limit, len(res.Types)))
	for _, t := range res.Types[:min(limit, len(res.Types))] {
		out = append(out, typeView{Ext: t.Ext, Files: t.Files, Size: t.Size, Allocated: t.Allocated})
	}
	return out, nil
}

type findingsView struct {
	ScanID string `json:"scanId"`
	rules.Report
}

func (s *Server) findings(r *http.Request) (any, error) {
	id := r.PathValue("id")
	_, rep, err := s.scans.result(id)
	if err != nil {
		return nil, err
	}
	return findingsView{ScanID: id, Report: *rep}, nil
}

func (s *Server) system(*http.Request) (any, error) {
	results := []probe.Result{}
	if s.probes != nil {
		results = s.probes.Results()
	}
	return map[string]any{"probes": results}, nil
}

func (s *Server) runProbe(r *http.Request) (any, error) {
	if s.probes == nil {
		return nil, &apiError{Status: 404, Code: "not_found", Message: "no system information here"}
	}
	switch err := s.probes.Run(r.PathValue("name")); {
	case errors.Is(err, probe.ErrUnknown):
		return nil, &apiError{Status: 404, Code: "not_found", Message: "no such probe"}
	case errors.Is(err, probe.ErrBusy):
		return nil, &apiError{Status: 409, Code: "busy", Message: "this probe is already running"}
	case err != nil:
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Server) shutdown(*http.Request) (any, error) {
	if s.cfg.Shutdown != nil {
		// Let this response reach the page first.
		time.AfterFunc(200*time.Millisecond, s.cfg.Shutdown)
	}
	return map[string]bool{"ok": true}, nil
}

// events streams server-sent events: a hello with the current status, any
// kept events after the Last-Event-ID the page sends, then new events as they
// happen, with a heartbeat every 15 seconds.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if err := s.checkCaller(r, true); err != nil {
		s.writeError(w, err)
		return
	}
	after, _ := strconv.ParseInt(r.Header.Get("Last-Event-ID"), 10, 64)
	replay, ch, cancel := s.hub.subscribe(after)
	defer cancel()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	hello, _ := json.Marshal(s.statusValue())
	writeEvent(w, event{Type: "hello", Data: hello})
	for _, e := range replay {
		writeEvent(w, e)
	}
	if rc.Flush() != nil {
		return
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			writeEvent(w, e)
		case <-heartbeat.C:
			writeEvent(w, event{Type: "heartbeat", Data: []byte("{}")})
		}
		if rc.Flush() != nil {
			return
		}
	}
}

// staticFiles serves the web page. It never lists folders.
func staticFiles(files fs.FS) http.Handler {
	types := map[string]string{
		".html": "text/html; charset=utf-8",
		".css":  "text/css; charset=utf-8",
		".js":   "text/javascript; charset=utf-8",
		".json": "application/json; charset=utf-8",
		".svg":  "image/svg+xml",
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		f, err := files.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		rs, seekable := f.(io.ReadSeeker)
		if err != nil || st.IsDir() || !seekable {
			http.NotFound(w, r)
			return
		}
		// Set explicitly: Windows can map .js to text/plain in its registry,
		// which browsers refuse for module scripts.
		if ct, ok := types[path.Ext(name)]; ok {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, name, st.ModTime(), rs)
	})
}

// JSON helpers.

type apiError struct {
	Status        int
	Code, Message string
}

func (e *apiError) Error() string { return e.Message }

func badRequest(msg string) error { return &apiError{Status: 400, Code: "bad_request", Message: msg} }

func (s *Server) writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		s.cfg.Logf("internal error: %v", err)
		ae = &apiError{Status: 500, Code: "internal", Message: "internal error"}
	}
	writeJSON(w, ae.Status, map[string]any{"error": map[string]string{"code": ae.Code, "message": ae.Message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// readJSON decodes a small JSON request body into v, rejecting unknown fields
// so that nothing unexpected can be slipped in.
func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid request: " + err.Error())
	}
	if dec.More() {
		return badRequest("invalid request: more than one JSON value")
	}
	return nil
}

func intParam(r *http.Request, name string, def, maxValue int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, maxValue)
}
