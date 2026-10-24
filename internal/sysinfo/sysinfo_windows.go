package sysinfo

import "golang.org/x/sys/windows"

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
