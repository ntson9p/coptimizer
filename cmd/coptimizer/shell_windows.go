package main

import (
	"errors"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/safety"
)

var errDeclined = errors.New("the Administrator prompt was declined")

// runElevated starts exe with args and Administrator rights, which shows the
// UAC prompt.
func runElevated(exe, args string) error {
	safety.GuardShellOpen(exe)
	err := windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(args), nil, windows.SW_SHOWNORMAL)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return errDeclined
	}
	return err
}

// openInBrowser opens link in the default browser. A browser started by an
// elevated process would run elevated too, so then the link goes through
// explorer.exe, which hands it to the user's normal, unelevated shell.
func openInBrowser(link string, elevated bool) error {
	file, args := link, ""
	if elevated {
		file, args = "explorer.exe", link
	}
	safety.GuardShellOpen(file)
	var a *uint16
	if args != "" {
		a = windows.StringToUTF16Ptr(args)
	}
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(file), a, nil, windows.SW_SHOWNORMAL)
}
