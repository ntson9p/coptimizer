package probe

import (
	"slices"
	"strings"
)

// shellFolders is where Windows records the user's personal folders,
// wherever they have been moved.
const shellFolders = `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

// knownFolderValues are the personal folders in shellFolders: Desktop,
// Documents, Pictures, Music, Videos, Favorites, and those named by GUID
// (Downloads, Saved Games, Contacts, Links, Searches).
var knownFolderValues = []string{
	"Desktop", "Personal", "My Pictures", "My Music", "My Video", "Favorites",
	"{374DE290-123F-4565-9164-39C4925E467B}", "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}",
	"{56784854-C6CB-462B-8169-88E350ACB882}", "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}",
	"{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}",
}

// KnownFolders returns where the current user's personal folders and
// OneDrive folders are, for the deny list. It only reads. Folders it can't
// work out are left out: the deny list protects their standard places anyway.
func KnownFolders(reg Registry, getenv func(string) string) []string {
	var out []string
	add := func(p string) {
		if p != "" && !strings.Contains(p, "%") && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, name := range knownFolderValues {
		if v, err := reg.String(CurrentUser, shellFolders, name); err == nil {
			add(expand(v, getenv))
		}
	}
	for _, name := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		add(getenv(name))
	}
	return out
}

// expand fills in %NAME% variables, as Windows does for REG_EXPAND_SZ values.
// A variable that isn't set stays as it is.
func expand(s string, getenv func(string) string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		name := s[i+1 : i+1+j]
		if v := getenv(name); v != "" && name != "" {
			b.WriteString(s[:i] + v)
		} else {
			b.WriteString(s[:i+2+j])
		}
		s = s[i+2+j:]
	}
	b.WriteString(s)
	return b.String()
}
