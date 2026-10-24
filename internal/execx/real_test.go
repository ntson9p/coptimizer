package execx_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/execx"
	"github.com/ntson9p/coptimizer/internal/safety"
	"github.com/ntson9p/coptimizer/internal/testguard"
)

// The test binary doubles as the program the tests run: started with
// COPTIMIZER_EXECX_HELPER set, it does what that variable says and exits. It is
// the only program these tests ever start.
const helperVar = "COPTIMIZER_EXECX_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperVar); mode != "" {
		helper(mode, os.Args[1:])
		return
	}
	testguard.Main(m)
}

func helper(mode string, args []string) {
	switch mode {
	case "echo":
		fmt.Print(strings.Join(args, " "))
		fmt.Fprint(os.Stderr, "on stderr")
	case "exit":
		code, _ := strconv.Atoi(args[0])
		os.Exit(code)
	case "sleep":
		time.Sleep(time.Minute)
	case "spawn":
		// Start a grandchild that sleeps, tell the test its process ID, wait.
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), helperVar+"=sleep")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		fmt.Println(child.Process.Pid)
		time.Sleep(time.Minute)
	case "loud":
		chunk := strings.Repeat("x", 1<<20)
		for range 10 {
			fmt.Print(chunk)
		}
	case "console":
		// Which processes share this process's console.
		for _, id := range consoleProcesses() {
			fmt.Println(id)
		}
	case "progress":
		// Like DISM: a progress bar redrawn with carriage returns.
		fmt.Print("Starting\r\n\r\n[==   10.0%   ]\r[=====50.0%   ]\r[====100.0%===]\r\nDone, no newline")
	}
	os.Exit(0)
}

// helperCmd registers the test binary as a program the fuses let run, and
// returns a command that runs it in mode.
func helperCmd(t *testing.T, mode string, args ...string) execx.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(safety.RegisterTestProgram(exe))
	t.Setenv(helperVar, mode)
	return execx.Cmd{Path: exe, Args: args}
}

func TestOutputAndExitCode(t *testing.T) {
	res, err := execx.Real{}.Run(context.Background(), helperCmd(t, "echo", "hello", "world"))
	if err != nil || string(res.Stdout) != "hello world" || string(res.Stderr) != "on stderr" || res.ExitCode != 0 {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	res, err = execx.Real{}.Run(context.Background(), helperCmd(t, "exit", "3"))
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("exit code: %+v, %v; want 3 and no error", res, err)
	}
}

func TestArgumentsArePassedAsIs(t *testing.T) {
	args := []string{`with space`, `"quoted"`, `back\slash\`, `Thư mục`, `&|<>^`}
	res, err := execx.Real{}.Run(context.Background(), helperCmd(t, "echo", args...))
	if err != nil || string(res.Stdout) != strings.Join(args, " ") {
		t.Fatalf("got %q, %v", res.Stdout, err)
	}
}

func TestTimeoutStopsTheWholeTree(t *testing.T) {
	c := helperCmd(t, "spawn")
	c.Timeout = 2 * time.Second
	start := time.Now()
	res, err := execx.Real{}.Run(context.Background(), c)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v; want the deadline", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("stopping took %v", d)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if err != nil {
		t.Fatalf("no grandchild PID in %q", res.Stdout)
	}
	if !exited(uint32(pid), 5*time.Second) {
		t.Errorf("the grandchild %d still runs; the job should have stopped it", pid)
	}
}

func TestCancelStopsTheProgram(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	_, err := execx.Real{}.Run(ctx, helperCmd(t, "sleep"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want cancelled", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("cancelling took %v", d)
	}
}

func TestOutputIsCapped(t *testing.T) {
	res, err := execx.Real{}.Run(context.Background(), helperCmd(t, "loud"))
	if err != nil || len(res.Stdout) != 8<<20 {
		t.Fatalf("kept %d bytes, %v; want 8 MiB", len(res.Stdout), err)
	}
}

func TestOutputArrivesLineByLine(t *testing.T) {
	c := helperCmd(t, "progress")
	var got []string
	c.Output = func(line string) { got = append(got, line) }
	res, err := execx.Real{}.Run(context.Background(), c)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	want := []string{"Starting", "[==   10.0%   ]", "[=====50.0%   ]", "[====100.0%===]", "Done, no newline"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("lines = %q; want %q", got, want)
	}
	if !strings.Contains(string(res.Stdout), "Done, no newline") {
		t.Errorf("the whole output must still be kept: %q", res.Stdout)
	}
}

// TestProgramsDontShareOurConsole checks that a program run through execx
// isn't attached to COptimizer's console, so Ctrl+C typed there can't reach
// it. Windows gives it a console of its own, without a window.
func TestProgramsDontShareOurConsole(t *testing.T) {
	if len(consoleProcesses()) == 0 {
		t.Skip("this test runs without a console, so there is none to share")
	}
	res, err := execx.Real{}.Run(context.Background(), helperCmd(t, "console"))
	if err != nil {
		t.Fatal(err)
	}
	me := strconv.Itoa(os.Getpid())
	for _, id := range strings.Fields(string(res.Stdout)) {
		if id == me {
			t.Fatalf("the program shares this test's console: %q", res.Stdout)
		}
	}
}

func TestOnlyRegisteredProgramsRun(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "SAFETY FUSE") {
			t.Errorf("running an unregistered program: %v; want the fuse to trip", r)
		}
	}()
	execx.Real{}.Run(context.Background(), execx.Cmd{Path: `C:\Windows\System32\whoami.exe`})
}

func TestFakeRecordsCalls(t *testing.T) {
	f := &execx.Fake{Respond: func(ctx context.Context, c execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte("ok")}, nil
	}}
	res, _ := f.Run(context.Background(), execx.Cmd{Path: `C:\x.exe`, Args: []string{"/a"}})
	if string(res.Stdout) != "ok" || len(f.Calls()) != 1 || f.Calls()[0].Args[0] != "/a" {
		t.Errorf("fake: %+v, calls %+v", res, f.Calls())
	}
}

// exited reports whether process pid ends within wait (or is already gone).
func exited(pid uint32, wait time.Duration) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return true // no such process any more
	}
	defer windows.CloseHandle(h)
	ev, err := windows.WaitForSingleObject(h, uint32(wait.Milliseconds()))
	return err == nil && ev == windows.WAIT_OBJECT_0
}

var getConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// consoleProcesses returns the IDs of the processes attached to this
// process's console, or none if it has no console. It only reads.
func consoleProcesses() []uint32 {
	ids := make([]uint32, 64)
	n, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	if n == 0 || int(n) > len(ids) {
		return nil
	}
	return ids[:n]
}
