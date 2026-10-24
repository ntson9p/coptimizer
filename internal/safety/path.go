// Package safety holds the checks that keep COptimizer from touching what it
// shouldn't: strict Windows path normalization and containment, and the fuses
// that stop tests from changing the real machine.
package safety

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxPathLen is the longest path Windows can address, in UTF-16 code units.
const maxPathLen = 32767

// Normalize returns the canonical spelling of an absolute, local Windows path:
// `/` turned into `\`, a `\\?\` prefix removed, repeated and trailing
// separators dropped, and the drive letter upper-cased.
//
// It rejects, rather than guesses at, every path whose meaning Windows could
// change behind our back: relative and drive-relative paths, `.` and `..`
// segments, network and device paths, alternate data streams, wildcard and
// control characters, reserved device names, and segments that end in a dot
// or a space (Win32 silently strips those).
func Normalize(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if !utf8.ValidString(p) {
		return "", fmt.Errorf("%q is not valid UTF-8", p)
	}
	if utf16Len(p) > maxPathLen {
		return "", fmt.Errorf("path is longer than %d characters", maxPathLen)
	}
	s := strings.ReplaceAll(p, "/", `\`)
	switch {
	case strings.HasPrefix(s, `\\?\`), strings.HasPrefix(s, `\??\`):
		s = s[4:]
		if !hasDrivePrefix(s) {
			// \\?\UNC\…, \\?\GLOBALROOT\…, \\?\Volume{…}\…
			return "", fmt.Errorf("%q: only drive-letter paths are allowed", p)
		}
	case strings.HasPrefix(s, `\\.\`):
		return "", fmt.Errorf("%q: device paths are not allowed", p)
	case strings.HasPrefix(s, `\\`):
		return "", fmt.Errorf("%q: network paths are not allowed", p)
	}
	if !hasDrivePrefix(s) {
		return "", fmt.Errorf("%q: not an absolute path starting with a drive letter", p)
	}
	segs := make([]string, 0, strings.Count(s, `\`))
	for _, seg := range strings.Split(s[3:], `\`) {
		if seg == "" {
			continue // repeated or trailing separator
		}
		if err := checkSegment(seg); err != nil {
			return "", fmt.Errorf("%q: %w", p, err)
		}
		segs = append(segs, seg)
	}
	return strings.ToUpper(s[:1]) + `:\` + strings.Join(segs, `\`), nil
}

// Contains reports whether p is root or lies inside it. Both are normalized
// first; if either is invalid the answer is false.
//
// Only ASCII letters compare case-insensitively. NTFS ignores case for other
// letters too, so a path that differs from root only in, say, "Đ" versus "đ"
// counts as outside. That is the safe answer when the question is "may this
// be touched?". Checks against protected folders need the opposite bias.
func Contains(root, p string) bool {
	r, err := Normalize(root)
	if err != nil {
		return false
	}
	q, err := Normalize(p)
	if err != nil {
		return false
	}
	rs, qs := segments(r), segments(q)
	if len(qs) < len(rs) {
		return false
	}
	for i, seg := range rs {
		if !equalFoldASCII(seg, qs[i]) {
			return false
		}
	}
	return true
}

func hasDrivePrefix(s string) bool {
	return len(s) >= 3 && isASCIILetter(s[0]) && s[1] == ':' && s[2] == '\\'
}

func checkSegment(seg string) error {
	if seg == "." || seg == ".." {
		return errors.New("relative segments (. and ..) are not allowed")
	}
	if last := seg[len(seg)-1]; last == '.' || last == ' ' {
		return fmt.Errorf("segment %q ends in a dot or a space", seg)
	}
	for _, r := range seg {
		if r < 0x20 || strings.ContainsRune(`<>:"|?*`, r) {
			return fmt.Errorf("segment %q contains %q", seg, r)
		}
	}
	if isReservedName(seg) {
		return fmt.Errorf("segment %q is a reserved device name", seg)
	}
	return nil
}

// isReservedName reports whether Windows would treat seg as a device (NUL,
// COM1, …), which it does even with an extension: "nul.txt" is NUL too.
func isReservedName(seg string) bool {
	base := seg
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}

// segments splits a normalized path into its drive ("C:") and its names.
func segments(p string) []string {
	return strings.Split(strings.TrimSuffix(p, `\`), `\`)
}

// splitParent splits a normalized path into its parent and its last name.
// A drive root has no parent, so ok is false for it.
func splitParent(p string) (parent, name string, ok bool) {
	i := strings.LastIndexByte(p, '\\')
	if i < 0 || i == len(p)-1 {
		return "", "", false
	}
	parent = p[:i]
	if i == 2 {
		parent = p[:3] // keep the root's separator: `C:\`
	}
	return parent, p[i+1:], true
}

// joinPath appends name to a normalized path.
func joinPath(dir, name string) string {
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if upperASCII(a[i]) != upperASCII(b[i]) {
			return false
		}
	}
	return true
}

func upperASCII(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func isASCIILetter(c byte) bool {
	return 'A' <= upperASCII(c) && upperASCII(c) <= 'Z'
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}
