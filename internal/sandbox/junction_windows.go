package sandbox

import (
	"encoding/binary"
	"os"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// createJunction makes a new folder at link and turns it into a directory
// junction to target. The caller has already checked link with the fuses.
func createJunction(link, target string) error {
	target, err := safety.Normalize(target)
	if err != nil {
		return err
	}
	if err := os.Mkdir(link, 0o755); err != nil {
		return err
	}
	if err := setMountPoint(link, target); err != nil {
		safety.GuardDelete(link)
		os.Remove(link)
		return err
	}
	return nil
}

func setMountPoint(dir, target string) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	data := mountPointData(target)
	var n uint32
	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &n, nil)
}

// mountPointData builds the REPARSE_DATA_BUFFER of a junction to target: the
// reparse header, four offsets and lengths, then the substitute name (an NT
// path) and the display name, each NUL-terminated.
func mountPointData(target string) []byte {
	substitute := utf16.Encode([]rune(`\??\` + target))
	display := utf16.Encode([]rune(target))
	subLen, dispLen := 2*len(substitute), 2*len(display)
	dataLen := 8 + subLen + 2 + dispLen + 2
	buf := make([]byte, 8+dataLen)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], windows.IO_REPARSE_TAG_MOUNT_POINT)
	le.PutUint16(buf[4:], uint16(dataLen))
	le.PutUint16(buf[8:], 0)
	le.PutUint16(buf[10:], uint16(subLen))
	le.PutUint16(buf[12:], uint16(subLen+2))
	le.PutUint16(buf[14:], uint16(dispLen))
	off := 16
	for _, c := range substitute {
		le.PutUint16(buf[off:], c)
		off += 2
	}
	off += 2
	for _, c := range display {
		le.PutUint16(buf[off:], c)
		off += 2
	}
	return buf
}
