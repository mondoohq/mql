// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package registry

import "errors"

// There is no live registry on non-windows platforms. The native readers only
// resolve paths into hive files loaded with LoadRegistrySubkey (see
// registryhandler_unix.go); every other path is not supported.

// IsUserHiveLoaded always reports false on non-windows platforms — there is no
// HKEY_USERS to inspect.
func IsUserHiveLoaded(sid string) bool {
	return false
}

func NativeRegistryKeyExists(path string) (bool, error) {
	if h, keyPath, ok := resolveLoadedHive(path); ok {
		return h.Exists(keyPath), nil
	}
	return false, errors.New("native registry key existence not supported on non-windows platforms")
}

func GetNativeRegistryKeyItems(path string) ([]RegistryKeyItem, error) {
	if h, keyPath, ok := resolveLoadedHive(path); ok {
		return h.Items(keyPath)
	}
	return nil, errors.New("native registry key items not supported on non-windows platforms")
}

func GetNativeRegistryKeyChildren(path string) ([]RegistryKeyChild, error) {
	if h, keyPath, ok := resolveLoadedHive(path); ok {
		names, err := h.Children(keyPath)
		if err != nil {
			return nil, err
		}
		res := make([]RegistryKeyChild, len(names))
		for i, name := range names {
			// like on Windows, Path is the requested (parent) path
			res[i] = RegistryKeyChild{Path: path, Name: name}
		}
		return res, nil
	}
	return nil, errors.New("native registry key children not supported on non-windows platforms")
}

// GetNativeRegistryKeyItem returns the named value of the key. Value names
// match case-insensitively, as the registry does.
func GetNativeRegistryKeyItem(path, key string) (RegistryKeyItem, error) {
	if h, keyPath, ok := resolveLoadedHive(path); ok {
		return h.Item(keyPath, key)
	}
	return RegistryKeyItem{}, errors.New("native registry key item not supported on non-windows platforms")
}
