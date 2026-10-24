package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ntson9p/coptimizer/internal/execx"
)

// Both DISM probes only read: /Get-ReservedStorageState reports a setting and
// /AnalyzeComponentStore measures WinSxS. /English keeps the output parseable
// whatever the Windows display language.

// ReservedStorage says whether Windows holds back space for updates.
type ReservedStorage struct {
	Enabled bool `json:"enabled"`
}

// ComponentStore is DISM's analysis of WinSxS.
type ComponentStore struct {
	ExplorerSize        int64  `json:"explorerSize"` // what Explorer reports, hard links counted again
	ActualSize          int64  `json:"actualSize"`
	Shared              int64  `json:"shared"`  // shared with the rest of Windows
	Backups             int64  `json:"backups"` // backups and disabled features
	Cache               int64  `json:"cache"`   // cache and temporary data
	LastCleanup         string `json:"lastCleanup,omitempty"`
	ReclaimablePackages int    `json:"reclaimablePackages"`
	CleanupRecommended  bool   `json:"cleanupRecommended"`
}

func probeReservedStorage(ctx context.Context, d Deps) (any, State, string) {
	out, state, msg := dism(ctx, d, 2*time.Minute, "/Get-ReservedStorageState")
	if state != OK {
		return nil, state, msg
	}
	rs, err := parseReservedStorage(out)
	if err != nil {
		return nil, Failed, err.Error()
	}
	return rs, OK, ""
}

func probeComponentStore(ctx context.Context, d Deps) (any, State, string) {
	out, state, msg := dism(ctx, d, 20*time.Minute, "/Cleanup-Image", "/AnalyzeComponentStore")
	if state != OK {
		return nil, state, msg
	}
	cs, err := parseComponentStore(out)
	if err != nil {
		return nil, Failed, err.Error()
	}
	return cs, OK, ""
}

// dism runs Windows' own dism.exe with args, in English. It needs
// Administrator rights, so without them it doesn't run at all.
func dism(ctx context.Context, d Deps, timeout time.Duration, args ...string) (string, State, string) {
	if !d.Elevated {
		return "", NeedsAdmin, ""
	}
	sys32 := d.SystemRoot + `\System32`
	res, err := d.Runner.Run(ctx, execx.Cmd{
		Path:    sys32 + `\dism.exe`,
		Args:    append([]string{"/Online", "/English"}, args...),
		Dir:     sys32,
		Timeout: timeout,
	})
	if err != nil {
		return "", Failed, err.Error()
	}
	out := string(res.Stdout)
	if res.ExitCode != 0 {
		return "", Failed, fmt.Sprintf("DISM exited with code %d: %s", res.ExitCode, lastLine(out))
	}
	return out, OK, ""
}

func parseReservedStorage(out string) (ReservedStorage, error) {
	switch s := strings.ToLower(out); {
	case strings.Contains(s, "reserved storage is enabled"):
		return ReservedStorage{Enabled: true}, nil
	case strings.Contains(s, "reserved storage is disabled"):
		return ReservedStorage{Enabled: false}, nil
	}
	return ReservedStorage{}, errors.New("DISM's answer about reserved storage wasn't understood")
}

func parseComponentStore(out string) (ComponentStore, error) {
	var cs ComponentStore
	found := 0
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), " : ")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		var err error
		switch key {
		case "Windows Explorer Reported Size of Component Store":
			cs.ExplorerSize, err = parseSize(value)
		case "Actual Size of Component Store":
			cs.ActualSize, err = parseSize(value)
		case "Shared with Windows":
			cs.Shared, err = parseSize(value)
		case "Backups and Disabled Features":
			cs.Backups, err = parseSize(value)
		case "Cache and Temporary Data":
			cs.Cache, err = parseSize(value)
		case "Date of Last Cleanup":
			cs.LastCleanup = value
		case "Number of Reclaimable Packages":
			cs.ReclaimablePackages, err = strconv.Atoi(value)
		case "Component Store Cleanup Recommended":
			cs.CleanupRecommended = strings.EqualFold(value, "Yes")
		default:
			continue
		}
		if err != nil {
			return cs, fmt.Errorf("DISM: %s: %w", key, err)
		}
		found++
	}
	if found < 5 {
		return cs, errors.New("DISM's component store analysis wasn't understood")
	}
	return cs, nil
}

// parseSize reads sizes like "8.71 GB", "512.33 MB" or "0 bytes" (binary
// units, as DISM shows them).
func parseSize(s string) (int64, error) {
	num, unit, ok := strings.Cut(strings.TrimSpace(s), " ")
	if !ok {
		return 0, fmt.Errorf("size %q has no unit", s)
	}
	v, err := strconv.ParseFloat(strings.ReplaceAll(num, ",", ""), 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, err)
	}
	mult := map[string]float64{"bytes": 1, "byte": 1, "kb": 1 << 10, "mb": 1 << 20, "gb": 1 << 30, "tb": 1 << 40}[strings.ToLower(unit)]
	if mult == 0 {
		return 0, fmt.Errorf("size %q has an unknown unit", s)
	}
	return int64(v * mult), nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r", "")), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
