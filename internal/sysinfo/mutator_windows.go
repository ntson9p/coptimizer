package sysinfo

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// Flags of SHEmptyRecycleBin.
const (
	sherbNoConfirmation = 0x1
	sherbNoProgressUI   = 0x2
	sherbNoSound        = 0x4
)

// EmptyRecycleBin implements Mutator through the shell, which empties only
// the current user's Recycle Bin on that drive.
func (RealMutator) EmptyRecycleBin(drive string) error {
	safety.GuardSystemChange("the Recycle Bin on " + drive)
	root, err := windows.UTF16PtrFromString(drive)
	if err != nil {
		return err
	}
	hr, _, _ := shEmptyRecycleBinW.Call(0, uintptr(unsafe.Pointer(root)), sherbNoConfirmation|sherbNoProgressUI|sherbNoSound)
	if hr != 0 {
		return fmt.Errorf("SHEmptyRecycleBin(%s): HRESULT 0x%08X", drive, uint32(hr))
	}
	return nil
}
