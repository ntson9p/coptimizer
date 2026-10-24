package probe

import (
	"context"
	"errors"
	"io/fs"
	"strings"
)

// Distro is a WSL distribution of the current user.
type Distro struct {
	Name    string `json:"name"`
	Disk    string `json:"disk"` // the virtual disk (WSL 2) or the folder (WSL 1)
	Bytes   int64  `json:"bytes"`
	Version int    `json:"version"`
	Default bool   `json:"default"`
}

const lxssKey = `Software\Microsoft\Windows\CurrentVersion\Lxss`

// probeWSL lists WSL distributions from the registry, without starting WSL.
func probeWSL(ctx context.Context, d Deps) (any, State, string) {
	distros := []Distro{}
	keys, err := d.Registry.SubKeys(CurrentUser, lxssKey)
	if errors.Is(err, fs.ErrNotExist) {
		return distros, OK, ""
	}
	if err != nil {
		return nil, Failed, err.Error()
	}
	def, _ := d.Registry.String(CurrentUser, lxssKey, "DefaultDistribution")
	for _, k := range keys {
		key := lxssKey + `\` + k
		name, err := d.Registry.String(CurrentUser, key, "DistributionName")
		if err != nil {
			continue // not a distribution
		}
		base, _ := d.Registry.String(CurrentUser, key, "BasePath")
		base = strings.TrimPrefix(base, `\\?\`)
		version := 2
		if v, err := d.Registry.Integer(CurrentUser, key, "Version"); err == nil {
			version = int(v)
		}
		ds := Distro{Name: name, Disk: base, Version: version, Default: strings.EqualFold(k, def)}
		if version >= 2 {
			vhd, err := d.Registry.String(CurrentUser, key, "VhdFileName")
			if err != nil || vhd == "" {
				vhd = "ext4.vhdx"
			}
			ds.Disk = base + `\` + vhd
			ds.Bytes, _ = d.Stat(ds.Disk)
		}
		distros = append(distros, ds)
	}
	return distros, OK, ""
}
