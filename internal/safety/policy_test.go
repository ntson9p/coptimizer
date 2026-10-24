package safety_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ntson9p/coptimizer/internal/safety"
)

func testPolicy(t testing.TB) *safety.Policy {
	t.Helper()
	p, err := safety.NewPolicy(safety.Places{
		SystemDrive:     `C:`,
		Windows:         `C:\Windows`,
		ProgramData:     `C:\ProgramData`,
		ProgramFiles:    `C:\Program Files`,
		ProgramFilesX86: `C:\Program Files (x86)`,
		Users:           `C:\Users`,
		KnownFolders:    []string{`D:\My Documents`, `\\server\share\Pictures`, `E:\Thư mục\Ảnh`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyAllows(t *testing.T) {
	p := testPolicy(t)
	for _, path := range []string{
		`C:\Users\alice\AppData\Local\Temp`,
		`C:\Users\alice\AppData\Local\Temp\x\y.tmp`,
		`C:\Users\alice\AppData\Local\npm-cache`,
		`C:\Users\alice\AppData\Roaming\Code\Cache\data_0`,
		`C:\Users\Nguyễn Văn A\AppData\Local\D3DSCache`,
		`C:\Windows\Temp`,
		`c:\windows\temp\x.log`,
		`C:\Windows\SystemTemp\a`,
		`C:\Windows\Logs\CBS\CBS.log`,
		`C:\Windows\Logs\DISM\dism.log`,
		`C:\Windows\Minidump\102426-1.dmp`,
		`C:\Windows\LiveKernelReports\WATCHDOG\x.dmp`,
		`C:\Windows\MEMORY.DMP`,
		`C:\ProgramData\Microsoft\Windows\WER\ReportArchive\x`,
		`C:\Program Files (x86)\Steam\steamapps\shadercache\730`,
		`C:\Program Files\Steam\steamapps\temp\x`,
		`C:\Program Files (x86)\Epic Games\Launcher\VaultCache\x`,
		`C:\$GetCurrent\media`,
		`C:\NVIDIA`,
		`\\?\C:\Users\alice\AppData\Local\Temp\x`,
		`D:\Other\cache`,
	} {
		if err := p.Check(path); err != nil {
			t.Errorf("Check(%q) = %v; want allowed", path, err)
		}
	}
}

func TestPolicyRefuses(t *testing.T) {
	p := testPolicy(t)
	for _, path := range []string{
		// Drive roots and paths that aren't plain local paths.
		`C:\`, `D:\`, `c:`, `C:\Temp\..\Windows`, `\\server\share\x`, `C:\a.txt:stream`, ``, `Temp`,
		// Windows, except for the listed folders.
		`C:\Windows`, `C:\windows\system32`, `C:\Windows\System32\drivers\etc\hosts`, `C:\Windows\WinSxS\x`,
		`C:\Windows\Installer\x.msi`, `C:\Windows\Logs`, `C:\Windows\Logs\WindowsUpdate\x.etl`,
		`C:\Windows\SoftwareDistribution\Download\x`, `C:\Windows\Prefetch\x.pf`, `C:\Windows\Temp2`,
		`C:\Windows\MEMORY.DMP2`, `C:\Windows\System32\spool\PRINTERS\x`,
		// Installed programs, except Steam's and Epic's leftovers.
		`C:\Program Files`, `C:\Program Files\App\app.exe`, `C:\Program Files\WindowsApps\x`,
		`C:\Program Files (x86)\Steam\steamapps\common\Game\x.vpk`, `C:\Program Files (x86)\Steam\steamapps\downloading\x`,
		`C:\Program Files (x86)\Steam`,
		// Other system folders.
		`C:\ProgramData`, `C:\ProgramData\Microsoft`, `C:\ProgramData\Microsoft\Windows`,
		`C:\ProgramData\Package Cache\x`, `C:\System Volume Information\x`, `C:\$Recycle.Bin\S-1-5-21\x`,
		`C:\Recovery\x`, `C:\$WinREAgent\x`, `C:\Windows.old\x`, `C:\Windows.old(1)`, `C:\$Windows.~BT\x`,
		// Accounts and personal files.
		`C:\Users`, `C:\Users\alice`, `C:\Users\Nguyễn Văn A`, `C:\Users\alice\AppData`, `C:\Users\alice\AppData\Local`,
		`C:\Users\alice\AppData\LocalLow`, `C:\Users\alice\AppData\Roaming`, `C:\Users\alice\AppData\Local\Microsoft`,
		`C:\Users\alice\AppData\Local\Packages`, `C:\Users\alice\AppData\Local\Programs`,
		`C:\Users\alice\Desktop\x`, `C:\Users\alice\documents\report.docx`, `C:\Users\alice\Downloads`,
		`C:\Users\alice\Pictures\a.jpg`, `C:\Users\alice\Videos\Captures\x.mp4`, `C:\Users\alice\Music`,
		`C:\Users\alice\OneDrive\x`, `C:\Users\alice\OneDrive - Contoso\x`, `C:\Users\alice\Saved Games\x`,
		`C:\Users\Public\Documents\x`, `C:\Users\Default\NTUSER.DAT`, `C:\Users\All Users\x`,
		// Known folders moved elsewhere, in any case.
		`D:\My Documents`, `d:\my documents\x`, `E:\Thư mục\Ảnh\x`, `E:\THƯ MỤC\ẢNH\x`,
	} {
		err := p.Check(path)
		if err == nil {
			t.Errorf("Check(%q) = nil; want refused", path)
		} else if !errors.Is(err, safety.ErrRefused) {
			t.Errorf("Check(%q) = %v; want an error wrapping ErrRefused", path, err)
		}
	}
}

func TestPolicyExceptionsDontOpenPersonalFolders(t *testing.T) {
	// A known folder inside an exception stays protected: an exception only
	// counts against a shallower tree.
	p, err := safety.NewPolicy(safety.Places{
		SystemDrive: `C:`, Windows: `C:\Windows`, ProgramData: `C:\ProgramData`,
		ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`, Users: `C:\Users`,
		KnownFolders: []string{`C:\Windows\Temp\Docs`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(`C:\Windows\Temp\Docs\x.docx`); err == nil {
		t.Error("a known folder inside C:\\Windows\\Temp may be deleted")
	}
	if err := p.Check(`C:\Windows\Temp\other.tmp`); err != nil {
		t.Errorf("the rest of the exception: %v", err)
	}
}

func TestPolicyNeedsEveryPlace(t *testing.T) {
	good := safety.Places{
		SystemDrive: `C:`, Windows: `C:\Windows`, ProgramData: `C:\ProgramData`,
		ProgramFiles: `C:\Program Files`, ProgramFilesX86: `C:\Program Files (x86)`, Users: `C:\Users`,
	}
	for _, broken := range []func(*safety.Places){
		func(p *safety.Places) { p.Windows = "" },
		func(p *safety.Places) { p.ProgramFiles = `Program Files` },
		func(p *safety.Places) { p.Users = `\\server\Users` },
		func(p *safety.Places) { p.SystemDrive = "" },
	} {
		pl := good
		broken(&pl)
		if _, err := safety.NewPolicy(pl); err == nil {
			t.Errorf("NewPolicy(%+v) worked; want an error", pl)
		}
	}
}

// FuzzPolicy checks that spellings Windows treats as the same path get the
// same answer, and that nothing in System32 or a profile root is ever
// allowed.
func FuzzPolicy(f *testing.F) {
	p := testPolicy(f)
	for _, s := range []string{`C:\Windows\Temp\x`, `C:\Users\a\AppData\Local\Temp`, `C:\Windows\System32`, `C:\Users\a\Desktop`, `C:\NVIDIA`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		err := p.Check(path)
		if err != nil && !errors.Is(err, safety.ErrRefused) {
			t.Fatalf("Check(%q) = %v, not wrapping ErrRefused", path, err)
		}
		variants := []string{asciiCase(path, true), asciiCase(path, false), strings.ReplaceAll(path, `\`, `/`)}
		if len(path) >= 2 && path[1] == ':' {
			variants = append(variants, `\\?\`+path)
		}
		for _, v := range variants {
			if (p.Check(v) == nil) != (err == nil) {
				t.Fatalf("Check(%q) = %v but Check(%q) = %v", path, err, v, p.Check(v))
			}
		}
		if err != nil {
			return
		}
		n, _ := safety.Normalize(path)
		if safety.Contains(`C:\Windows\System32`, n) || safety.Contains(`C:\Program Files\WindowsApps`, n) {
			t.Fatalf("Check(%q) allowed a path in a system folder", path)
		}
		if segs := strings.Split(n, `\`); len(segs) == 3 && strings.EqualFold(segs[1], "Users") {
			t.Fatalf("Check(%q) allowed a profile root", path)
		}
	})
}

func asciiCase(s string, upper bool) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case upper && 'a' <= c && c <= 'z':
			b[i] = c - 32
		case !upper && 'A' <= c && c <= 'Z':
			b[i] = c + 32
		}
	}
	return string(b)
}
