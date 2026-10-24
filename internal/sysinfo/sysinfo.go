// Package sysinfo answers read-only questions about the machine: its drives
// and whether the app runs with Administrator rights.
package sysinfo

// Drive is a local fixed drive.
type Drive struct {
	Root  string // `C:\`
	Label string
	FS    string // "NTFS", "ReFS", …
	Total int64
	Free  int64
}

// Used is the space in use on the drive.
func (d Drive) Used() int64 { return d.Total - d.Free }

// Reader is the read-only system view the server needs. Real reads the actual
// machine; demo mode has its own.
type Reader interface {
	Drives() ([]Drive, error)
	Elevated() bool
}

// Real reads the actual machine.
type Real struct{}
