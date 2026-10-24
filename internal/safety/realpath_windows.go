package safety

import "golang.org/x/sys/windows"

// GetFinalPathNameByHandle flags FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
// which x/sys/windows doesn't name.
const finalPathFlags = 0x0

// realPath returns where the existing path p really leads once every
// junction, symbolic link and mount point on the way is followed, normalized.
func realPath(p string) (string, error) {
	// p is normalized, so the `\\?\` form means the same path and also works
	// beyond 260 characters.
	name, err := windows.UTF16PtrFromString(`\\?\` + p)
	if err != nil {
		return "", err
	}
	// Read-only: FILE_READ_ATTRIBUTES is enough to ask for the final path, and
	// backup semantics is what lets CreateFile open folders.
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), finalPathFlags)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return Normalize(windows.UTF16ToString(buf[:n]))
		}
		buf = make([]uint16, n) // too small: n is the size needed, terminator included
	}
}
