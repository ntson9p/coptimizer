package probe

import (
	"context"
	"errors"
	"io/fs"
	"strings"
)

// Power is how hibernation and the page files are set up.
type Power struct {
	Hibernation    string     `json:"hibernation"` // "on", "off" or "unknown"
	HiberFile      int64      `json:"hiberFile"`   // bytes of hiberfil.sys; 0 if there is none
	PageFiles      []PageFile `json:"pageFiles"`
	PageFileConfig []string   `json:"pageFileConfig"` // as set in Virtual memory, e.g. `D:\pagefile.sys 8192 8192`
}

// PageFile is a page file in use.
type PageFile struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

const (
	powerKey  = `SYSTEM\CurrentControlSet\Control\Power`
	memoryKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
)

func probePower(ctx context.Context, d Deps) (any, State, string) {
	p := Power{Hibernation: "unknown", PageFiles: []PageFile{}, PageFileConfig: []string{}}
	if size, ok := d.Stat(d.SystemDrive + `\hiberfil.sys`); ok {
		p.HiberFile = size
	}
	switch on, err := d.Registry.Integer(LocalMachine, powerKey, "HibernateEnabled"); {
	case err == nil && on != 0:
		p.Hibernation = "on"
	case err == nil:
		p.Hibernation = "off"
	case errors.Is(err, fs.ErrNotExist) && p.HiberFile > 0:
		p.Hibernation = "on"
	}
	existing, _ := d.Registry.Strings(LocalMachine, memoryKey, "ExistingPageFiles")
	for _, e := range existing {
		path := strings.TrimPrefix(e, `\??\`)
		size, _ := d.Stat(path)
		p.PageFiles = append(p.PageFiles, PageFile{Path: path, Bytes: size})
	}
	if cfg, err := d.Registry.Strings(LocalMachine, memoryKey, "PagingFiles"); err == nil {
		for _, c := range cfg {
			if c = strings.TrimSpace(c); c != "" {
				p.PageFileConfig = append(p.PageFileConfig, c)
			}
		}
	}
	return p, OK, ""
}
