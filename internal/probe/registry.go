package probe

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// Root is a registry hive.
type Root int

const (
	LocalMachine Root = iota
	CurrentUser
)

// Registry reads values from the Windows registry. It never writes.
type Registry interface {
	Integer(root Root, key, name string) (uint64, error)
	String(root Root, key, name string) (string, error)
	Strings(root Root, key, name string) ([]string, error)
	SubKeys(root Root, key string) ([]string, error)
}

// FakeRegistry is a Registry in memory, for tests and demo mode. Missing keys
// and values give errors that match fs.ErrNotExist, like the real one.
type FakeRegistry struct {
	values map[fakeName]any
}

type fakeName struct {
	root      Root
	key, name string
}

// Set stores a value: a uint64, a string or a []string.
func (f *FakeRegistry) Set(root Root, key, name string, v any) {
	if f.values == nil {
		f.values = make(map[fakeName]any)
	}
	f.values[fakeName{root, strings.ToLower(key), strings.ToLower(name)}] = v
}

func (f *FakeRegistry) get(root Root, key, name string) (any, error) {
	v, ok := f.values[fakeName{root, strings.ToLower(key), strings.ToLower(name)}]
	if !ok {
		return nil, fmt.Errorf("registry %s\\%s: %w", key, name, fs.ErrNotExist)
	}
	return v, nil
}

func (f *FakeRegistry) Integer(root Root, key, name string) (uint64, error) {
	v, err := f.get(root, key, name)
	if err != nil {
		return 0, err
	}
	n, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("registry %s\\%s is not an integer", key, name)
	}
	return n, nil
}

func (f *FakeRegistry) String(root Root, key, name string) (string, error) {
	v, err := f.get(root, key, name)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("registry %s\\%s is not a string", key, name)
	}
	return s, nil
}

func (f *FakeRegistry) Strings(root Root, key, name string) ([]string, error) {
	v, err := f.get(root, key, name)
	if err != nil {
		return nil, err
	}
	s, ok := v.([]string)
	if !ok {
		return nil, fmt.Errorf("registry %s\\%s is not a list of strings", key, name)
	}
	return s, nil
}

func (f *FakeRegistry) SubKeys(root Root, key string) ([]string, error) {
	prefix := strings.ToLower(key) + `\`
	var out []string
	for n := range f.values {
		if n.root != root || !strings.HasPrefix(n.key, prefix) {
			continue
		}
		sub, _, _ := strings.Cut(n.key[len(prefix):], `\`)
		if !slices.Contains(out, sub) {
			out = append(out, sub)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("registry %s: %w", key, fs.ErrNotExist)
	}
	slices.Sort(out)
	return out, nil
}
