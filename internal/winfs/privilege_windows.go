package winfs

import "golang.org/x/sys/windows"

// EnableBackupPrivilege turns on SeBackupPrivilege for this process, so that
// an Administrator can measure folders whose permissions hide them even from
// Administrators (System Volume Information, WindowsApps). It only grants
// reading: changing protected files would need SeRestorePrivilege, which the
// app never enables. The change lasts until the process exits.
func EnableBackupPrivilege() error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeBackupPrivilege"), &luid); err != nil {
		return err
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
