// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package registry

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
	"golang.org/x/sys/windows/registry"
)

// parseRegistryKeyPath parses a registry key path into the hive and the path
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives
//
// The hive name is matched case-insensitively, as Windows and the PowerShell
// registry provider do: registrykey resources share one cache entry per key
// whatever the spelling, so every spelling has to resolve here too.
func parseRegistryKeyPath(path string) (registry.Key, string, error) {
	hive, rest, _ := strings.Cut(path, "\\")
	switch strings.ToUpper(hive) {
	case "HKEY_LOCAL_MACHINE", "HKLM":
		return registry.LOCAL_MACHINE, rest, nil
	case "HKEY_CURRENT_USER", "HKCU":
		return registry.CURRENT_USER, rest, nil
	case "HKEY_USERS":
		return registry.USERS, rest, nil
	}
	return registry.LOCAL_MACHINE, "", errors.New("invalid registry key hive: " + path)
}

// IsUserHiveLoaded reports whether the given user's registry hive is currently
// loaded under HKEY_USERS. This is true while the user has an active logon
// session; for logged-off users the hive must be loaded from NTUSER.DAT (see
// RegistryHandler.LoadUserHive) before it can be read.
func IsUserHiveLoaded(sid string) bool {
	if sid == "" {
		return false
	}
	regKey, err := registry.OpenKey(registry.USERS, sid, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	regKey.Close()
	return true
}

func GetNativeRegistryKeyItems(fullPath string) ([]RegistryKeyItem, error) {
	log.Debug().Str("path", fullPath).Msg("search registry key values using native registry api")
	key, path, err := parseRegistryKeyPath(fullPath)
	if err != nil {
		return nil, err
	}
	regKey, err := registry.OpenKey(key, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil && registry.ErrNotExist == err {
		return nil, status.Error(codes.NotFound, "registry key not found: "+path)
	} else if err != nil {
		return nil, classifyOpenKeyError(fullPath, err)
	}
	defer regKey.Close()

	res := []RegistryKeyItem{}
	values, err := regKey.ReadValueNames(0)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		data, valtype, err := readRawRegistryValue(regKey, value)
		if err != nil {
			return nil, err
		}
		res = append(res, RegistryKeyItem{
			Key:   value,
			Value: decodeRawRegistryValue(valtype, data),
		})
	}
	return res, nil
}

// readRawRegistryValue returns a value's kind and data as stored. Every kind
// is read this way, including the ones golang.org/x/sys/windows/registry has
// no typed getter for (REG_DWORD_BIG_ENDIAN, REG_LINK, the resource lists), so
// decodeRawRegistryValue gives them the same data the PowerShell path does.
func readRawRegistryValue(k registry.Key, name string) ([]byte, uint32, error) {
	n, valtype, err := k.GetValue(name, nil)
	if err != nil {
		return nil, 0, err
	}
	for {
		buf := make([]byte, n)
		n, valtype, err = k.GetValue(name, buf)
		if err == registry.ErrShortBuffer {
			// the value grew between the two reads
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		return buf[:n], valtype, nil
	}
}

func GetNativeRegistryKeyChildren(fullPath string) ([]RegistryKeyChild, error) {
	log.Debug().Str("path", fullPath).Msg("search registry key children using native registry api")
	key, path, err := parseRegistryKeyPath(fullPath)
	if err != nil {
		return nil, err
	}

	regKey, err := registry.OpenKey(key, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil && registry.ErrNotExist == err {
		return nil, status.Error(codes.NotFound, "registry key not found: "+path)
	} else if err != nil {
		return nil, classifyOpenKeyError(fullPath, err)
	}
	defer regKey.Close()

	// reads all child keys
	entries, err := regKey.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}

	res := make([]RegistryKeyChild, len(entries))

	for i, entry := range entries {
		res[i] = RegistryKeyChild{
			Path: fullPath,
			Name: entry,
		}
	}

	return res, nil
}

func GetNativeRegistryKeyItem(path, key string) (RegistryKeyItem, error) {
	values, err := GetNativeRegistryKeyItems(path)
	if err != nil {
		return RegistryKeyItem{}, err
	}
	for _, value := range values {
		if value.Key == key {
			return value, nil
		}
	}
	return RegistryKeyItem{}, status.Error(codes.NotFound, fmt.Sprintf("registry value %s not found under %s", key, path))
}
