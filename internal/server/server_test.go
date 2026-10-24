package server_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/server"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

func TestMain(m *testing.M) { testguard.Main(m) }

type fakeSystem struct{}

func (fakeSystem) Drives() ([]sysinfo.Drive, error) {
	return []sysinfo.Drive{{Root: `C:\`, FS: "NTFS", Total: 100 << 30, Free: 40 << 30}}, nil
}
func (fakeSystem) Elevated() bool { return true }

// fixture is a server on a real loopback port, with a fake C: drive.
type fixture struct {
	t       *testing.T
	srv     *server.Server
	ts      *httptest.Server
	fs      *memfs.FS
	now     atomic.Int64 // Unix seconds that the server sees
	stopped atomic.Bool
}

func newFixture(t *testing.T, options ...func(*server.Config)) *fixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, fs: memfs.New()}
	f.now.Store(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC).Unix())
	f.fs.AddFile(`C:\Windows\big.dll`, 3<<20, time.Now())
	f.fs.AddFile(`C:\Users\demo\video.mp4`, 7<<20, time.Now())
	f.fs.AddFile(`C:\Users\demo\notes.txt`, 100, time.Now())
	cfg := server.Config{
		Port:       ln.Addr().(*net.TCPAddr).Port,
		LaunchCode: "launch1",
		Instance:   "inst",
		Version:    "test",
		Lister:     f.fs,
		System:     fakeSystem{},
		Env:        rules.DefaultEnv("demo"),
		Web: fstest.MapFS{
			"index.html":  {Data: []byte("<!doctype html><title>t</title>")},
			"js/main.js":  {Data: []byte("export {}")},
			"css/app.css": {Data: []byte("body{}")},
		},
		Shutdown: func() { f.stopped.Store(true) },
		Now:      func() time.Time { return time.Unix(f.now.Load(), 0) },
	}
	for _, o := range options {
		o(&cfg)
	}
	f.srv = server.New(cfg)
	f.ts = &httptest.Server{Listener: ln, Config: &http.Server{Handler: f.srv}}
	f.ts.Start()
	t.Cleanup(func() {
		f.srv.Close()
		f.ts.Close()
	})
	return f
}

func (f *fixture) do(method, path, token, body string, header map[string]string) (*http.Response, []byte) {
	f.t.Helper()
	req, err := http.NewRequest(method, f.ts.URL+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := f.ts.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

// login trades the launch code for a token.
func (f *fixture) login() string {
	f.t.Helper()
	resp, data := f.do("POST", "/api/session", "", `{"code":"launch1"}`, nil)
	if resp.StatusCode != 200 {
		f.t.Fatalf("login: %d %s", resp.StatusCode, data)
	}
	var v struct{ Token string }
	json.Unmarshal(data, &v)
	return v.Token
}

func decode[T any](t *testing.T, data []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%v in %s", err, data)
	}
	return v
}

func TestOnlyOurHostIsServed(t *testing.T) {
	f := newFixture(t)
	port := f.ts.Listener.Addr().(*net.TCPAddr).Port
	cases := map[string]int{
		fmt.Sprintf("127.0.0.1:%d", port):    200,
		fmt.Sprintf("localhost:%d", port):    200,
		fmt.Sprintf("LocalHost:%d", port):    200,
		fmt.Sprintf("evil.example:%d", port): http.StatusMisdirectedRequest,
		"127.0.0.1:1":                        http.StatusMisdirectedRequest,
		"127.0.0.1":                          http.StatusMisdirectedRequest,
	}
	for host, want := range cases {
		if resp, _ := f.do("GET", "/healthz", "", "", map[string]string{"Host": host}); resp.StatusCode != want {
			t.Errorf("Host %q: status %d; want %d", host, resp.StatusCode, want)
		}
	}
}

func TestHealthzIdentifiesTheInstance(t *testing.T) {
	f := newFixture(t)
	resp, data := f.do("GET", "/healthz", "", "", nil)
	v := decode[map[string]string](t, data)
	if resp.StatusCode != 200 || v["app"] != "coptimizer" || v["instance"] != "inst" {
		t.Errorf("healthz = %d %s", resp.StatusCode, data)
	}
}

func TestAPINeedsTheToken(t *testing.T) {
	f := newFixture(t)
	for _, tok := range []string{"", "wrong"} {
		if resp, _ := f.do("GET", "/api/status", tok, "", nil); resp.StatusCode != 401 {
			t.Errorf("token %q: status %d; want 401", tok, resp.StatusCode)
		}
		if resp, _ := f.do("GET", "/api/events", tok, "", nil); resp.StatusCode != 401 {
			t.Errorf("events with token %q: status %d; want 401", tok, resp.StatusCode)
		}
	}
	tok := f.login()
	resp, data := f.do("GET", "/api/status", tok, "", nil)
	st := decode[map[string]any](t, data)
	if resp.StatusCode != 200 || st["version"] != "test" || st["elevated"] != true {
		t.Errorf("status = %d %s", resp.StatusCode, data)
	}
}

func TestLaunchCodeWorksOnce(t *testing.T) {
	f := newFixture(t)
	f.login()
	if resp, _ := f.do("POST", "/api/session", "", `{"code":"launch1"}`, nil); resp.StatusCode != 401 {
		t.Errorf("second use of the code: status %d; want 401", resp.StatusCode)
	}
}

func TestLaunchCodeExpires(t *testing.T) {
	f := newFixture(t)
	f.now.Add(3 * 60) // three minutes later
	if resp, _ := f.do("POST", "/api/session", "", `{"code":"launch1"}`, nil); resp.StatusCode != 401 {
		t.Errorf("expired code: status %d; want 401", resp.StatusCode)
	}
	link := f.srv.NewLaunchLink()
	code := link[strings.Index(link, "#code=")+len("#code="):]
	if resp, _ := f.do("POST", "/api/session", "", `{"code":"`+code+`"}`, nil); resp.StatusCode != 200 {
		t.Errorf("fresh code from NewLaunchLink: status %d", resp.StatusCode)
	}
}

func TestOtherWebPagesAreRefused(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	port := f.ts.Listener.Addr().(*net.TCPAddr).Port
	evil := map[string]string{"Origin": "https://evil.example"}
	if resp, _ := f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, evil); resp.StatusCode != 403 {
		t.Errorf("foreign origin: status %d; want 403", resp.StatusCode)
	}
	if resp, _ := f.do("POST", "/api/session", "", `{"code":"x"}`, evil); resp.StatusCode != 403 {
		t.Errorf("foreign origin on session: status %d; want 403", resp.StatusCode)
	}
	ours := map[string]string{"Origin": fmt.Sprintf("http://127.0.0.1:%d", port)}
	if resp, data := f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, ours); resp.StatusCode != 200 {
		t.Errorf("our origin: status %d %s", resp.StatusCode, data)
	}
}

func TestRequestsCantSmuggleFields(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	cases := []string{
		`{"drives":["C:\\"],"path":"C:\\Windows"}`,
		`{"drives":["C:\\"]}{"drives":["C:\\"]}`,
		`not json`,
		`{"drives":["Z:\\"]}`,
		`{"drives":["C:\\Windows"]}`,
		`{"drives":[]}`,
		`{"drives":["C:\\","c:"]}`,
	}
	for _, body := range cases {
		if resp, data := f.do("POST", "/api/scans", tok, body, nil); resp.StatusCode != 400 {
			t.Errorf("%s: status %d %s; want 400", body, resp.StatusCode, data)
		}
	}
}

func waitForScan(t *testing.T, f *fixture, tok, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, data := f.do("GET", "/api/scans/"+id, tok, "", nil)
		v := decode[map[string]any](t, data)
		if v["state"] != "running" {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the scan did not finish")
	return nil
}

func TestScanAndBrowseTheResult(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	resp, data := f.do("POST", "/api/scans", tok, `{"drives":["c:"]}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("start: %d %s", resp.StatusCode, data)
	}
	id := decode[map[string]any](t, data)["id"].(string)
	v := waitForScan(t, f, tok, id)
	if v["state"] != "done" {
		t.Fatalf("scan = %v", v)
	}
	sum := v["summary"].(map[string]any)
	if sum["files"] != 3.0 || sum["allocated"] != float64(10<<20+4096) {
		t.Errorf("summary = %v", sum)
	}
	if sum["unaccounted"] != float64(60<<30-(10<<20+4096)) {
		t.Errorf("unaccounted = %v", sum["unaccounted"])
	}

	_, data = f.do("GET", "/api/scans/"+id+"/tree?path=C:%5C", tok, "", nil)
	tree := decode[map[string]any](t, data)
	kids := tree["children"].([]any)
	if len(kids) != 2 || kids[0].(map[string]any)["name"] != "Users" {
		t.Errorf("tree = %s", data)
	}
	_, data = f.do("GET", "/api/scans/"+id+"/files?path=C:%5CUsers&limit=1", tok, "", nil)
	files := decode[[]map[string]any](t, data)
	if len(files) != 1 || files[0]["path"] != `C:\Users\demo\video.mp4` {
		t.Errorf("files = %s", data)
	}
	_, data = f.do("GET", "/api/scans/"+id+"/types", tok, "", nil)
	if types := decode[[]map[string]any](t, data); len(types) != 3 || types[0]["ext"] != ".mp4" {
		t.Errorf("types = %s", data)
	}
	if resp, _ := f.do("GET", "/api/scans/"+id+"/tree?path=C:%5Cnope", tok, "", nil); resp.StatusCode != 404 {
		t.Errorf("missing folder: status %d", resp.StatusCode)
	}
	if resp, _ := f.do("GET", "/api/scans/nope", tok, "", nil); resp.StatusCode != 404 {
		t.Errorf("missing scan: status %d", resp.StatusCode)
	}
	_, data = f.do("GET", "/api/status", tok, "", nil)
	if last := decode[map[string]any](t, data)["lastScan"].(map[string]any); last["id"] != id {
		t.Errorf("lastScan = %v", last)
	}
}

func TestOneScanAtATimeAndCancel(t *testing.T) {
	f := newFixture(t)
	f.fs.SetDelay(200 * time.Millisecond)
	tok := f.login()
	_, data := f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, nil)
	id := decode[map[string]any](t, data)["id"].(string)
	if resp, _ := f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, nil); resp.StatusCode != 409 {
		t.Errorf("second scan while busy: status %d; want 409", resp.StatusCode)
	}
	if resp, _ := f.do("GET", "/api/scans/"+id+"/tree", tok, "", nil); resp.StatusCode != 409 {
		t.Errorf("tree of a running scan: status %d; want 409", resp.StatusCode)
	}
	f.do("DELETE", "/api/scans/"+id, tok, "", nil)
	if v := waitForScan(t, f, tok, id); v["state"] != "cancelled" {
		t.Errorf("state = %v; want cancelled", v["state"])
	}
}

// readEvents reads server-sent events until it has seen want, or fails.
func readEvents(t *testing.T, r *bufio.Reader, want string) []string {
	t.Helper()
	var types []string
	var lastID string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended after %v: %v", types, err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case strings.HasPrefix(line, "id: "):
			lastID = line[4:]
		case strings.HasPrefix(line, "event: "):
			types = append(types, line[7:]+"#"+lastID)
			lastID = ""
			if line[7:] == want {
				return types
			}
		}
	}
}

func TestEventStreamAndReplay(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	open := func(lastID string) (*bufio.Reader, func()) {
		req, _ := http.NewRequest("GET", f.ts.URL+"/api/events", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if lastID != "" {
			req.Header.Set("Last-Event-ID", lastID)
		}
		resp, err := f.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("content type %q", ct)
		}
		return bufio.NewReader(resp.Body), func() { resp.Body.Close() }
	}

	r, done := open("")
	if got := readEvents(t, r, "hello"); got[0] != "hello#0" {
		t.Fatalf("first event = %v; want hello with ID 0, the point to resume from", got)
	}
	f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, nil)
	got := readEvents(t, r, "scan.finished")
	done()
	if got[0] != "scan.started#1" || got[len(got)-1] != "scan.finished#2" {
		t.Errorf("events = %v; want scan.started#1 … scan.finished#2", got)
	}

	// A page that saw event 1 gets event 2 again after reconnecting.
	r, done = open("1")
	if got := readEvents(t, r, "scan.finished"); got[0] != "hello#2" || got[1] != "scan.finished#2" {
		t.Errorf("replay = %v", got)
	}
	done()

	// A page that saw only a hello (ID 2) and lost its connection gets what
	// happened meanwhile when it reconnects.
	f.do("POST", "/api/scans", tok, `{"drives":["C:\\"]}`, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, data := f.do("GET", "/api/status", tok, "", nil)
		if last := decode[map[string]any](t, data)["lastScan"].(map[string]any); last["state"] == "done" && last["id"] == "s2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second scan didn't finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r, done = open("2")
	defer done()
	if got := readEvents(t, r, "scan.finished"); got[0] != "hello#4" || got[1] != "scan.started#3" || got[2] != "scan.finished#4" {
		t.Errorf("after a gap = %v", got)
	}
}

func TestStaticFiles(t *testing.T) {
	f := newFixture(t)
	resp, data := f.do("GET", "/", "", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(data), "<title>") || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("index: %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), data)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff missing")
	}
	resp, _ = f.do("GET", "/js/main.js", "", "", nil)
	if resp.Header.Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("js content type %q", resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/js/", "/js", "/missing.html", "/api/nothing"} {
		if resp, _ := f.do("GET", p, "", "", nil); resp.StatusCode != 404 && resp.StatusCode != 401 {
			t.Errorf("%s: status %d; want 404 (or 401 for the API)", p, resp.StatusCode)
		}
	}
}

func TestShutdownCallsTheHook(t *testing.T) {
	f := newFixture(t)
	tok := f.login()
	if resp, _ := f.do("POST", "/api/shutdown", tok, "", nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !f.stopped.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !f.stopped.Load() {
		t.Error("Shutdown was not called")
	}
}
