// Package sysinfo answers questions about the machine: its drives, whether the
// app runs with Administrator rights, which programs run, how full the Recycle
// Bin is. Reading is split from changing: Real only reads, and the one change
// COptimizer makes through Windows itself, emptying the Recycle Bin, is
// Mutator's alone.
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

// Programs lists the names of the programs running now, like "chrome.exe".
type Programs interface {
	Running() ([]string, error)
}

// RecycleBinReader tells how much the user's Recycle Bin holds on a drive.
type RecycleBinReader interface {
	RecycleBin(drive string) (bytes, items int64, err error)
}

// Mutator changes the system. Only cleanup jobs get one; read-only code,
// such as the smoke tests, never sees it.
type Mutator interface {
	// EmptyRecycleBin empties the user's Recycle Bin on drive (`C:\`),
	// without asking: COptimizer's own preview has asked already.
	EmptyRecycleBin(drive string) error
}

// RealMutator changes the actual machine.
type RealMutator struct{}
