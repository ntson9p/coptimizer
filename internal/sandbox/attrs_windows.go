package sandbox

import (
	"time"

	"golang.org/x/sys/windows"

	"github.com/ntson9p/coptimizer/internal/safety"
)

// Age sets the creation and last-write times of rel to d ago, as if it had
// been created then and never changed.
func (b *Box) Age(rel string, d time.Duration) {
	b.t.Helper()
	p := b.Path(rel)
	safety.GuardWrite(p)
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		b.t.Fatalf("sandbox: age %q: %v", p, err)
	}
	defer windows.CloseHandle(h)
	ft := windows.NsecToFiletime(time.Now().Add(-d).UnixNano())
	if err := windows.SetFileTime(h, &ft, nil, &ft); err != nil {
		b.t.Fatalf("sandbox: age %q: %v", p, err)
	}
}

// SetAttributes sets the Windows attributes of rel (FILE_ATTRIBUTE_READONLY,
// _HIDDEN, _SYSTEM…).
func (b *Box) SetAttributes(rel string, attrs uint32) {
	b.t.Helper()
	p := b.Path(rel)
	safety.GuardWrite(p)
	if err := windows.SetFileAttributes(windows.StringToUTF16Ptr(p), attrs); err != nil {
		b.t.Fatalf("sandbox: attributes of %q: %v", p, err)
	}
}

// DenyDelete makes Windows refuse to delete the file rel for the current
// user until the test ends: the file denies DELETE, and its folder denies
// deleting its children (either right alone would allow it).
func (b *Box) DenyDelete(rel string) {
	b.t.Helper()
	file := b.Path(rel)
	dir := b.Path(rel, "..")
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		b.t.Fatal(err)
	}
	me := tu.User.Sid.String()
	allow := "(A;;FA;;;" + me + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	allowTree := "(A;OICI;FA;;;" + me + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// Rights as numbers: SDDL's letter codes are named for directory
	// objects, and "DC" would mean adding a file. 0x10000 is DELETE, 0x40 is
	// FILE_DELETE_CHILD.
	b.setDACL(file, "D:P(D;;0x10000;;;"+me+")"+allow)
	b.setDACL(dir, "D:P(D;;0x40;;;"+me+")"+allowTree)
	b.t.Cleanup(func() {
		b.setDACL(file, "D:P"+allow)
		b.setDACL(dir, "D:P"+allowTree)
	})
}

func (b *Box) setDACL(p, sddl string) {
	b.t.Helper()
	safety.GuardWrite(p)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		b.t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		b.t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		b.t.Fatalf("sandbox: permissions of %q: %v", p, err)
	}
}

// ShortName returns the 8.3 short name of rel's path, if the volume keeps
// short names and it differs from the long one. It only reads.
func (b *Box) ShortName(rel string) (string, bool) {
	b.t.Helper()
	p := b.Path(rel)
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(windows.StringToUTF16Ptr(p), &buf[0], uint32(len(buf)))
	if err != nil || int(n) >= len(buf) {
		return "", false
	}
	short := windows.UTF16ToString(buf[:n])
	return short, short != p
}
