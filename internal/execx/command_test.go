package execx

import (
	"context"
	"testing"
)

// Process creation flags, as Windows numbers them.
const (
	createSuspended = 0x00000004
	createNoWindow  = 0x08000000
)

// TestProgramsStartSuspendedWithoutAConsole checks how programs are started:
// suspended until their job object holds them, and without a console, so
// that Ctrl+C typed in COptimizer's window never reaches them.
func TestProgramsStartSuspendedWithoutAConsole(t *testing.T) {
	cmd := command(context.Background(), Cmd{Path: `C:\Windows\System32\dism.exe`, Args: []string{"/English"}}, 0)
	flags := cmd.SysProcAttr.CreationFlags
	if flags&createSuspended == 0 || flags&createNoWindow == 0 {
		t.Errorf("creation flags = %#x; want CREATE_SUSPENDED and CREATE_NO_WINDOW", flags)
	}
	if cmd.Dir != `C:\Windows\System32` || cmd.Cancel == nil || cmd.WaitDelay <= 0 {
		t.Errorf("command = dir %q, cancel %v, wait delay %v", cmd.Dir, cmd.Cancel != nil, cmd.WaitDelay)
	}
}
