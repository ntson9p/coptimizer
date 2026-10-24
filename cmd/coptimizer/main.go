// Command coptimizer finds what fills the Windows system drive and helps
// reclaim the space safely. See docs/plan.md.
//
// Started normally it is the launcher: it starts a second copy of itself with
// Administrator rights (one UAC prompt), waits until that copy serves the web
// page, and opens the page in your normal, unelevated browser.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/ntson9p/coptimizer/internal/demo"
	"github.com/ntson9p/coptimizer/internal/fsx"
	"github.com/ntson9p/coptimizer/internal/server"
	"github.com/ntson9p/coptimizer/internal/sysinfo"
	"github.com/ntson9p/coptimizer/internal/winfs"
	"github.com/ntson9p/coptimizer/web"
)

// version is set at build time: -ldflags "-X main.version=…".
var version = "dev"

type options struct {
	serve      bool
	demo       bool
	port       int
	launchCode string
	instance   string
	noBrowser  bool
}

func main() {
	var o options
	flag.BoolVar(&o.serve, "serve", false, "run the server in this process (the launcher starts it with Administrator rights)")
	flag.BoolVar(&o.demo, "demo", false, "serve a simulated PC: needs no Administrator rights and reads nothing real")
	flag.IntVar(&o.port, "port", 0, "port on 127.0.0.1; 0 picks a free one")
	flag.StringVar(&o.launchCode, "launch-code", "", "one-time code for the first browser tab (set by the launcher)")
	flag.StringVar(&o.instance, "instance", "", "identifier that /healthz returns (set by the launcher)")
	flag.BoolVar(&o.noBrowser, "no-browser", false, "don't open a browser, just print the link")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("coptimizer", version)
	case o.serve || o.demo || sysinfo.Real{}.Elevated():
		os.Exit(serve(o))
	default:
		os.Exit(launch())
	}
}

// launch starts the elevated server and opens the page once it answers.
func launch() int {
	port, err := freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, "coptimizer:", err)
		return 1
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "coptimizer:", err)
		return 1
	}
	code, instance := server.RandomHex(16), server.RandomHex(8)
	fmt.Println("COptimizer needs Administrator rights to measure every folder. Please accept the Windows prompt.")
	args := fmt.Sprintf("-serve -port %d -launch-code %s -instance %s", port, code, instance)
	if err := runElevated(exe, args); err != nil {
		if errors.Is(err, errDeclined) {
			fmt.Fprintln(os.Stderr, "The prompt was declined, so COptimizer did not start. (To look around without Administrator rights, run: coptimizer -demo)")
		} else {
			fmt.Fprintln(os.Stderr, "coptimizer: could not start the server:", err)
		}
		return 1
	}
	if !waitHealthy(port, instance, time.Minute) {
		fmt.Fprintln(os.Stderr, "coptimizer: the server did not start; look at its window for details")
		return 1
	}
	link := fmt.Sprintf("http://127.0.0.1:%d/#code=%s", port, code)
	if err := openInBrowser(link, false); err != nil {
		fmt.Println("Open this link in your browser:", link)
	}
	return 0
}

// serve runs the web server until the page, the console or Ctrl+C stops it.
func serve(o options) int {
	var sys sysinfo.Reader = sysinfo.Real{}
	var lister fsx.Lister = winfs.Lister{}
	switch {
	case o.demo:
		lister, sys = demoMachine()
	case sys.Elevated():
		if err := winfs.EnableBackupPrivilege(); err != nil {
			log.Printf("could not enable SeBackupPrivilege (%v); protected folders will count as unreadable", err)
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", o.port))
	if err != nil {
		log.Printf("cannot listen on port %d: %v", o.port, err)
		return 1
	}
	port := ln.Addr().(*net.TCPAddr).Port
	code := o.launchCode
	if code == "" {
		code = server.RandomHex(16)
	}

	var once sync.Once
	done := make(chan struct{})
	stop := func() { once.Do(func() { close(done) }) }
	srv := server.New(server.Config{
		Port: port, LaunchCode: code, Instance: o.instance, Version: version, Demo: o.demo,
		Lister: lister, System: sys, Web: web.Files, Logf: log.Printf, Shutdown: stop,
	})
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped: %v", err)
			stop()
		}
	}()

	link := srv.Link(code)
	printBanner(port, link, sys.Elevated(), o.demo)
	if o.launchCode == "" && !o.noBrowser {
		if err := openInBrowser(link, sys.Elevated()); err != nil {
			fmt.Println("Open the link above in your browser.")
		}
	}
	go readConsole(srv, stop)
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	select {
	case <-done:
	case <-interrupt:
	}

	fmt.Println("Stopping COptimizer…")
	srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hs.Shutdown(ctx)
	return 0
}

func demoMachine() (fsx.Lister, sysinfo.Reader) {
	f, sys := demo.New(20 * time.Millisecond)
	return f, sys
}

func printBanner(port int, link string, elevated, demoMode bool) {
	rights := "Administrator: every folder can be measured"
	switch {
	case demoMode:
		rights = "Demo: a simulated PC, nothing real is read"
	case !elevated:
		rights = "Limited: without Administrator rights some folders can't be read"
	}
	fmt.Printf("COptimizer %s is running on http://127.0.0.1:%d\n", version, port)
	fmt.Printf("  Rights: %s\n", rights)
	fmt.Printf("  One-time link: %s\n", link)
	fmt.Println("  Keep this window open while you use COptimizer.")
	fmt.Println("  Type L and press Enter for a new one-time link, or Q to quit.")
}

// readConsole handles the keys the banner mentions. When stdin isn't a
// console (it ends at once), it just stops reading.
func readConsole(srv *server.Server, stop func()) {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		switch strings.ToLower(strings.TrimSpace(sc.Text())) {
		case "l":
			fmt.Println("New one-time link:", srv.NewLaunchLink())
		case "q":
			stop()
			return
		}
	}
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// waitHealthy polls /healthz until the server started with instance answers.
func waitHealthy(port int, instance string, timeout time.Duration) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		var h struct{ App, Instance string }
		err = json.NewDecoder(resp.Body).Decode(&h)
		resp.Body.Close()
		if err == nil && h.App == "coptimizer" && h.Instance == instance {
			return true
		}
	}
	return false
}
