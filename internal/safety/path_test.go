package safety_test

import (
	"strings"
	"testing"

	"github.com/ntson9p/coptimizer/internal/safety"
)

func TestNormalizeAccepts(t *testing.T) {
	long := `C:\` + strings.Repeat(`dir\`, 250) + "f"
	cases := []struct{ in, want string }{
		{`C:\`, `C:\`},
		{`c:\`, `C:\`},
		{`C:\Temp`, `C:\Temp`},
		{`C:/Temp/x`, `C:\Temp\x`},
		{`C:\\Temp\\\x\`, `C:\Temp\x`},
		{`\\?\C:\Temp`, `C:\Temp`},
		{`\??\C:\Temp`, `C:\Temp`},
		{`\\?\c:\`, `C:\`},
		{`C:\Thư mục\Ảnh 2026`, `C:\Thư mục\Ảnh 2026`},
		{`C:\a b\c.d`, `C:\a b\c.d`},
		{`C:\.git\config`, `C:\.git\config`},
		{`C:\backup~1`, `C:\backup~1`},
		{long, long},
	}
	for _, c := range cases {
		got, err := safety.Normalize(c.in)
		if err != nil || got != c.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := []string{
		``, `Temp`, `.\Temp`, `\Temp`, `C:`, `C:Temp`, `1:\x`,
		`C:\Temp\..\Windows`, `C:\Temp\.\x`, `C:\..`,
		`\\server\share\x`, `//server/share/x`, `\\?\UNC\server\share\x`,
		`\\.\C:\x`, `\\.\PhysicalDrive0`, `\\?\GLOBALROOT\Device\HarddiskVolume1\x`,
		`\\?\Volume{12345678-1234-1234-1234-123456789abc}\x`,
		`C:\Temp\a.txt:hidden`, `C:\Temp\a.txt::$DATA`,
		`C:\Temp.`, `C:\Temp \x`, `C:\Temp\x.`, `C:\...`,
		`C:\a*b`, `C:\a?b`, `C:\a<b`, `C:\a>b`, `C:\a|b`, `C:\a"b`, "C:\\a\x01b",
		`C:\CON`, `C:\Temp\nul.txt`, `C:\Temp\COM1`, `C:\Temp\lpt9.log`,
		`C:\Temp\COM¹`, `C:\Temp\CONOUT$`, `C:\Temp\aux .txt`,
		"C:\\bad\xffutf8",
		`C:\` + strings.Repeat("a", 32765),
	}
	for _, in := range cases {
		if got, err := safety.Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q; want an error", in, got)
		}
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		root, p string
		want    bool
	}{
		{`C:\Temp`, `C:\Temp`, true},
		{`C:\Temp`, `C:\Temp\x`, true},
		{`C:\Temp`, `c:\temp\X`, true},
		{`C:\Temp`, `\\?\C:\Temp\x`, true},
		{`C:\`, `C:\anything\at\all`, true},
		{`C:\Temp\`, `C:\Temp\x`, true},
		{`C:\Temp`, `C:\Temp2`, false},
		{`C:\Temp`, `C:\Temp2\x`, false},
		{`C:\Temp`, `C:\`, false},
		{`C:\Temp`, `D:\Temp`, false},
		{`C:\Temp`, `C:\Temp\..\Windows`, false},
		{`C:\Temp`, `C:\Temp\x:stream`, false},
		{`relative`, `relative\x`, false},
		// Non-ASCII case variants count as outside: the safe answer.
		{`C:\Đ`, `C:\đ\x`, false},
	}
	for _, c := range cases {
		if got := safety.Contains(c.root, c.p); got != c.want {
			t.Errorf("Contains(%q, %q) = %v; want %v", c.root, c.p, got, c.want)
		}
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{`C:\`, `c:/x/y`, `\\?\C:\a`, `C:\a\..\b`, `\\server\s`, `C:\a.`, `C:\nul`, `C:\\a\\\b\`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n, err := safety.Normalize(p)
		if err != nil {
			return
		}
		if again, err := safety.Normalize(n); err != nil || again != n {
			t.Fatalf("Normalize(%q) = %q, which normalizes again to %q, %v", p, n, again, err)
		}
		if n[0] < 'A' || n[0] > 'Z' || n[1:3] != `:\` {
			t.Fatalf("Normalize(%q) = %q: no upper-case drive root", p, n)
		}
		if strings.Contains(n, "/") || strings.Contains(n, `\\`) {
			t.Fatalf("Normalize(%q) = %q: stray separators", p, n)
		}
		for _, seg := range strings.Split(n[3:], `\`) {
			if seg == "." || seg == ".." || (seg == "" && len(n) > 3) {
				t.Fatalf("Normalize(%q) = %q: bad segment %q", p, n, seg)
			}
		}
	})
}

func FuzzContains(f *testing.F) {
	f.Add(`C:\Temp`, `C:\Temp\x`)
	f.Add(`C:\Temp`, `C:\Temp2`)
	f.Add(`C:\Temp`, `c:/temp/../windows`)
	f.Add(`C:\`, `C:\x`)
	f.Fuzz(func(t *testing.T, root, p string) {
		if !safety.Contains(root, p) {
			return
		}
		r, err1 := safety.Normalize(root)
		q, err2 := safety.Normalize(p)
		if err1 != nil || err2 != nil {
			t.Fatalf("Contains(%q, %q) is true but a path is invalid", root, p)
		}
		inside := len(q) >= len(r) && strings.EqualFold(q[:len(r)], r) &&
			(len(q) == len(r) || strings.HasSuffix(r, `\`) || q[len(r)] == '\\')
		if !inside {
			t.Fatalf("Contains(%q, %q) is true, but %q does not continue %q", root, p, q, r)
		}
	})
}
