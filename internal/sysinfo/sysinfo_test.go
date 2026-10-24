package sysinfo

import (
	"testing"
	"unicode/utf16"
)

func TestSplitMultiSZ(t *testing.T) {
	buf := utf16.Encode([]rune(`C:\` + "\x00" + `D:\` + "\x00\x00"))
	got := splitMultiSZ(buf)
	if len(got) != 2 || got[0] != `C:\` || got[1] != `D:\` {
		t.Errorf("splitMultiSZ = %q", got)
	}
}

func TestUsed(t *testing.T) {
	if got := (Drive{Total: 100, Free: 30}).Used(); got != 70 {
		t.Errorf("Used = %d", got)
	}
}
