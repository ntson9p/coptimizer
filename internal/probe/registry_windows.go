package probe

import "golang.org/x/sys/windows/registry"

// SystemRegistry reads this computer's registry. Keys are opened with query
// and enumerate rights only, so nothing can be changed through it.
type SystemRegistry struct{}

const readOnly = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS

func open(root Root, key string) (registry.Key, error) {
	hive := registry.LOCAL_MACHINE
	if root == CurrentUser {
		hive = registry.CURRENT_USER
	}
	return registry.OpenKey(hive, key, readOnly)
}

func (SystemRegistry) Integer(root Root, key, name string) (uint64, error) {
	k, err := open(root, key)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	return v, err
}

func (SystemRegistry) String(root Root, key, name string) (string, error) {
	k, err := open(root, key)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	return v, err
}

func (SystemRegistry) Strings(root Root, key, name string) ([]string, error) {
	k, err := open(root, key)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	v, _, err := k.GetStringsValue(name)
	return v, err
}

func (SystemRegistry) SubKeys(root Root, key string) ([]string, error) {
	k, err := open(root, key)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(0)
}
