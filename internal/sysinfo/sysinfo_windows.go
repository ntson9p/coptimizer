package sysinfo

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Drives lists the local fixed drives with their size and free space.
func (Real) Drives() ([]Drive, error) {
	buf := make([]uint16, 256)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil {
		return nil, err
	}
	var drives []Drive
	for _, root := range splitMultiSZ(buf[:n]) {
		r := windows.StringToUTF16Ptr(root)
		if windows.GetDriveType(r) != windows.DRIVE_FIXED {
			continue
		}
		var free, total, totalFree uint64
		if err := windows.GetDiskFreeSpaceEx(r, &free, &total, &totalFree); err != nil {
			continue // e.g. a drive locked by BitLocker
		}
		label := make([]uint16, windows.MAX_PATH+1)
		fsName := make([]uint16, windows.MAX_PATH+1)
		_ = windows.GetVolumeInformation(r, &label[0], uint32(len(label)), nil, nil, nil, &fsName[0], uint32(len(fsName)))
		drives = append(drives, Drive{
			Root:  root,
			Label: windows.UTF16ToString(label),
			FS:    windows.UTF16ToString(fsName),
			Total: int64(total),
			Free:  int64(totalFree),
		})
	}
	return drives, nil
}

// Elevated reports whether the process runs with Administrator rights.
func (Real) Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// splitMultiSZ splits a buffer of NUL-terminated strings, such as the one
// GetLogicalDriveStrings fills.
func splitMultiSZ(buf []uint16) []string {
	var out []string
	start := 0
	for i, c := range buf {
		if c == 0 {
			if i > start {
				out = append(out, windows.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// Running lists the programs running now, from a process snapshot. It only
// reads their names; no process is opened.
func (Real) Running() ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	pe := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	var names []string
	for err := windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		names = append(names, windows.UTF16ToString(pe.ExeFile[:]))
	}
	return names, nil
}

var (
	shell32            = windows.NewLazySystemDLL("shell32.dll")
	shQueryRecycleBin  = shell32.NewProc("SHQueryRecycleBinW")
	shEmptyRecycleBinW = shell32.NewProc("SHEmptyRecycleBinW")
)

// shQueryRBInfo is SHQUERYRBINFO, which 64-bit Windows aligns naturally.
type shQueryRBInfo struct {
	size  uint32
	_     uint32
	bytes int64
	items int64
}

// RecycleBin asks the shell how much the current user's Recycle Bin holds on
// drive. It only reads.
func (Real) RecycleBin(drive string) (bytes, items int64, err error) {
	root, err := windows.UTF16PtrFromString(drive)
	if err != nil {
		return 0, 0, err
	}
	info := shQueryRBInfo{size: uint32(unsafe.Sizeof(shQueryRBInfo{}))}
	if hr, _, _ := shQueryRecycleBin.Call(uintptr(unsafe.Pointer(root)), uintptr(unsafe.Pointer(&info))); hr != 0 {
		return 0, 0, fmt.Errorf("SHQueryRecycleBin(%s): HRESULT 0x%08X", drive, uint32(hr))
	}
	return info.bytes, info.items, nil
}
