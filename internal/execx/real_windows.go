package execx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// maxOutput is how much of a program's output is kept, per stream.
const maxOutput = 8 << 20

// Real runs programs on this computer.
type Real struct{}

// Run starts c suspended, puts it in a job object that ends with the run, and
// only then lets it go. When the time limit passes or ctx ends, the whole job
// is stopped: the program and anything it started.
func (Real) Run(ctx context.Context, c Cmd) (Result, error) {
	safety.GuardRun(c.Path)
	if !filepath.IsAbs(c.Path) {
		return Result{}, errors.New("execx: the program's path must be absolute")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	job, err := newJob()
	if err != nil {
		return Result{}, err
	}
	defer windows.CloseHandle(job) // ends anything still running in the job

	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Dir = c.Dir
	if cmd.Dir == "" {
		cmd.Dir = filepath.Dir(c.Path)
	}
	var stdout, stderr capped
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	var out *lines
	if c.Output != nil {
		out = &lines{fn: c.Output}
		cmd.Stdout = io.MultiWriter(&stdout, out.stream())
		cmd.Stderr = io.MultiWriter(&stderr, out.stream())
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	cmd.Cancel = func() error { return windows.TerminateJobObject(job, 1) }
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	if err := enter(job, cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return Result{}, err
	}
	err = cmd.Wait()
	if out != nil {
		out.flush() // the output copiers are done once Wait returns
	}
	res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), ExitCode: -1}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, ctxErr
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return res, err
	}
	return res, nil
}

// newJob creates a job object whose processes all end when its last handle
// closes.
func newJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// enter puts the suspended process pid into job, then resumes it. Because it
// was suspended, it couldn't start other processes outside the job meanwhile.
func enter(job windows.Handle, pid int) error {
	p, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(p)
	if err := windows.AssignProcessToJobObject(job, p); err != nil {
		return err
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	te := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	resumed := 0
	for err := windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != uint32(pid) {
			continue
		}
		t, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return err
		}
		_, err = windows.ResumeThread(t)
		windows.CloseHandle(t)
		if err != nil {
			return err
		}
		resumed++
	}
	if resumed == 0 {
		return errors.New("execx: the program's thread was not found")
	}
	return nil
}

// capped keeps the first maxOutput bytes written to it.
type capped struct{ buf bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
