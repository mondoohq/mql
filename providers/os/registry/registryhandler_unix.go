// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package registry

import (
	"fmt"
	"strings"
	"sync"
)

// loadedHives holds the hive files mounted by LoadRegistrySubkey, keyed by the
// lower-cased mount key (e.g. "tmpreg_software"). There is no registry to mount
// them in on non-windows platforms, so the native readers in registrykey_unix.go
// resolve paths under HKLM\<mount key> against this map instead.
//
// It is package-level on purpose: it stands in for the machine-wide HKLM that
// RegLoadKey mounts into on Windows, where a mount key is just as global. Two
// loads of the same mount key conflict on both platforms, so tests that load a
// hive under the same id must not run in parallel.
var (
	loadedHivesLock sync.Mutex
	loadedHives     = map[string]*hiveFile{}
)

// LoadRegistrySubkey opens the hive file at path and makes it readable under
// HKLM\<key>, as RegLoadKey does on Windows.
func LoadRegistrySubkey(key, path string) error {
	id := strings.ToLower(key)
	loadedHivesLock.Lock()
	defer loadedHivesLock.Unlock()
	if _, ok := loadedHives[id]; ok {
		return fmt.Errorf("registry hive %s is already loaded", key)
	}
	h, err := openHiveFile(path)
	if err != nil {
		return err
	}
	loadedHives[id] = h
	return nil
}

// UnloadRegistrySubkey closes the hive loaded under key. Unloading a key that
// is not loaded is a no-op.
func UnloadRegistrySubkey(key string) error {
	id := strings.ToLower(key)
	loadedHivesLock.Lock()
	h, ok := loadedHives[id]
	delete(loadedHives, id)
	loadedHivesLock.Unlock()
	if !ok {
		return nil
	}
	return h.Close()
}

// resolveLoadedHive splits a fully-qualified path of the form
// HKLM\<mount key>\<key path> (or HKEY_LOCAL_MACHINE\...) into the loaded hive
// and the key path inside it. ok is false for any path that does not point into
// a loaded hive.
func resolveLoadedHive(fullPath string) (h *hiveFile, keyPath string, ok bool) {
	hive, rest, _ := strings.Cut(fullPath, "\\")
	if !strings.EqualFold(hive, "HKLM") && !strings.EqualFold(hive, "HKEY_LOCAL_MACHINE") {
		return nil, "", false
	}
	mount, keyPath, _ := strings.Cut(rest, "\\")
	loadedHivesLock.Lock()
	h, ok = loadedHives[strings.ToLower(mount)]
	loadedHivesLock.Unlock()
	return h, keyPath, ok
}
