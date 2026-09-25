// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// userHiveLoader is implemented by connections that can load a user's NTUSER.DAT
// hive on demand (currently the local connection on Windows). registrykey uses it
// to read the HKCU of a user who is not logged in.
type userHiveLoader interface {
	UserHiveRegistryHandler() *registry.RegistryHandler
}

// userHivePath builds the absolute HKEY_USERS path for a SID's hive plus an
// optional sub-path, e.g. ("S-1-5-21-…", "Software\\X") -> "HKEY_USERS\\S-1-5-21-…\\Software\\X".
func userHivePath(sid, subPath string) string {
	subPath = strings.Trim(subPath, "\\")
	if subPath == "" {
		return `HKEY_USERS\` + sid
	}
	return `HKEY_USERS\` + sid + `\` + subPath
}

func (k *mqlRegistrykey) id() (string, error) {
	// When reading a per-user hive, `path` is relative to that user's HKCU and is
	// shared across users — fold the SID into the id so each user's key (and the
	// properties derived from it) caches separately.
	if k.UserSid.Data != "" {
		return userHivePath(k.UserSid.Data, k.Path.Data), nil
	}
	return k.Path.Data, nil
}

// isUserHive reports whether this key targets a specific user's registry hive.
func (k *mqlRegistrykey) isUserHive() bool {
	return k.UserSid.Data != ""
}

// userHiveReader resolves how to read this key's per-user hive natively on a
// local Windows host. It returns either a non-empty livePath to read directly
// (the user is logged in, so HKEY_USERS\<sid> is live) or a non-nil handler to
// read sub-paths through (the hive was loaded from NTUSER.DAT). When the hive
// can't be read at all — no loader, missing NTUSER.DAT, or a load failure — it
// returns ok=false, and callers treat the key as absent rather than erroring, so
// a check degrades to a vacuous pass instead of a false positive.
func (k *mqlRegistrykey) userHiveReader(conn shared.Connection) (livePath string, rh *registry.RegistryHandler, ok bool) {
	sid := k.UserSid.Data
	if registry.IsUserHiveLoaded(sid) {
		return userHivePath(sid, k.Path.Data), nil, true
	}
	loader, isLoader := conn.(userHiveLoader)
	if !isLoader || k.NtuserDat.Data == "" {
		return "", nil, false
	}
	h := loader.UserHiveRegistryHandler()
	if err := h.LoadUserHive(sid, k.NtuserDat.Data); err != nil {
		log.Debug().Err(err).Str("sid", sid).Str("ntuserDat", k.NtuserDat.Data).
			Msg("could not load user registry hive")
		return "", nil, false
	}
	return "", h, true
}

func (k *mqlRegistrykey) nativeUserHiveItems(conn shared.Connection) ([]registry.RegistryKeyItem, error) {
	livePath, rh, ok := k.userHiveReader(conn)
	if !ok {
		return nil, nil
	}
	if rh != nil {
		return rh.GetUserHiveKeyItems(k.UserSid.Data, k.Path.Data)
	}
	return registry.GetNativeRegistryKeyItems(livePath)
}

func (k *mqlRegistrykey) nativeUserHiveChildren(conn shared.Connection) ([]registry.RegistryKeyChild, error) {
	livePath, rh, ok := k.userHiveReader(conn)
	if !ok {
		return nil, nil
	}
	if rh != nil {
		return rh.GetUserHiveKeyChildren(k.UserSid.Data, k.Path.Data)
	}
	return registry.GetNativeRegistryKeyChildren(livePath)
}

func (k *mqlRegistrykey) exists() (bool, error) {
	conn := k.MqlRuntime.Connection.(shared.Connection)

	// per-user hive read: resolve against the live HKEY_USERS\<sid> hive or the
	// profile's NTUSER.DAT loaded on demand (local Windows), else fall back to the
	// live hive over PowerShell (remote).
	if k.isUserHive() {
		if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
			items, err := k.nativeUserHiveItems(conn)
			if err != nil {
				if std, ok := status.FromError(err); ok && std.Code() == codes.NotFound {
					return false, nil
				}
				return false, err
			}
			return len(items) > 0, nil
		}
		return k.powershellExists(userHivePath(k.UserSid.Data, k.Path.Data))
	}

	// if we are running locally on windows, we can use native api
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		items, err := registry.GetNativeRegistryKeyItems(k.Path.Data)
		if err == nil && len(items) > 0 {
			return true, nil
		}
		std, ok := status.FromError(err)
		if ok && std.Code() == codes.NotFound {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}

	return k.powershellExists(k.Path.Data)
}

// powershellExists checks key existence at an absolute registry path by running
// the PowerShell probe through the command resource (used for remote targets and
// as the non-native fallback).
func (k *mqlRegistrykey) powershellExists(path string) (bool, error) {
	script := powershell.Encode(registry.GetRegistryKeyItemScript(path))
	o, err := CreateResource(k.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(script),
	})
	if err != nil {
		return false, err
	}
	cmd := o.(*mqlCommand)

	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return false, exit.Error
	}
	if exit.Data != 0 {
		stderr := cmd.GetStderr()
		_, isMock := k.MqlRuntime.Connection.(*mock.Connection)
		// this would be an expected error and would ensure that we do not throw an error on windows systems
		// TODO: revisit how this is handled for non-english systems
		if strings.Contains(stderr.Data, "not exist") ||
			strings.Contains(stderr.Data, "ObjectNotFound") ||
			isMock {
			return false, nil
		}

		return false, errors.New("could not retrieve registry key")
	}
	return true, nil
}

// GetEntries returns a list of registry key property resources
func (k *mqlRegistrykey) getEntries() ([]registry.RegistryKeyItem, error) {
	conn := k.MqlRuntime.Connection.(shared.Connection)

	if k.isUserHive() {
		if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
			return k.nativeUserHiveItems(conn)
		}
		return k.powershellItems(userHivePath(k.UserSid.Data, k.Path.Data))
	}

	// if we are running locally on windows, we can use native api
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		return registry.GetNativeRegistryKeyItems(k.Path.Data)
	}

	return k.powershellItems(k.Path.Data)
}

// powershellItems reads the values of a key at an absolute registry path via the
// PowerShell command resource (used for remote targets and the non-native fallback).
func (k *mqlRegistrykey) powershellItems(path string) ([]registry.RegistryKeyItem, error) {
	script := powershell.Encode(registry.GetRegistryKeyItemScript(path))
	o, err := CreateResource(k.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(script),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	if exit.Data != 0 {
		stderr := cmd.GetStderr()
		_, isMock := k.MqlRuntime.Connection.(*mock.Connection)
		// this would be an expected error and would ensure that we do not throw an error on windows systems
		// TODO: revisit how this is handled for non-english systems
		if strings.Contains(stderr.Data, "not exist") ||
			strings.Contains(stderr.Data, "ObjectNotFound") ||
			isMock {
			return nil, nil
		}

		return nil, errors.New("could not retrieve registry key")
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, stdout.Error
	}

	items, err := registry.ParsePowershellRegistryKeyItems(strings.NewReader(stdout.Data))
	if err != nil {
		return nil, fmt.Errorf("could not read the values of registry key %s: %w", path, err)
	}
	return items, nil
}

// Deprecated: properties returns the properties of a registry key
// This function is deprecated and will be removed in a future release
func (k *mqlRegistrykey) properties() (map[string]any, error) {
	entries, err := k.getEntries()
	if err != nil {
		return nil, err
	}
	if entries == nil {
		k.Properties.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := map[string]any{}
	for i := range entries {
		rkey := entries[i]
		res[rkey.Key] = rkey.String()
	}

	return res, nil
}

// items returns a list of registry key property resources
func (k *mqlRegistrykey) items() ([]any, error) {
	entries, err := k.getEntries()
	if err != nil {
		return nil, err
	}
	if entries == nil {
		k.Items.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// create a registry property resource for each value. userSid/ntuserDat are
	// carried over so each property's id stays user-distinct (the path alone is
	// shared across users) and so direct reads resolve the same hive.
	items := make([]any, len(entries))
	for i, entry := range entries {
		o, err := CreateResource(k.MqlRuntime, "registrykey.property", map[string]*llx.RawData{
			"path":      llx.StringData(k.Path.Data),
			"name":      llx.StringData(entry.Key),
			"value":     llx.StringData(entry.String()),
			"type":      llx.StringData(entry.Kind()),
			"data":      llx.DictData(entry.GetRawValue()),
			"exists":    llx.BoolData(true),
			"userSid":   llx.StringData(k.UserSid.Data),
			"ntuserDat": llx.StringData(k.NtuserDat.Data),
		})
		if err != nil {
			return nil, err
		}

		items[i] = o.(*mqlRegistrykeyProperty)
	}

	return items, nil
}

// getChildren returns the child keys of this registry key, resolving the same
// way getEntries does: natively on a local Windows host, through PowerShell
// otherwise, and against the per-user hive when one is selected.
func (k *mqlRegistrykey) getChildren() ([]registry.RegistryKeyChild, error) {
	conn := k.MqlRuntime.Connection.(shared.Connection)
	switch {
	case k.isUserHive() && conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		return k.nativeUserHiveChildren(conn)
	case k.isUserHive():
		return k.powershellChildren(userHivePath(k.UserSid.Data, k.Path.Data))
	case conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		return registry.GetNativeRegistryKeyChildren(k.Path.Data)
	default:
		return k.powershellChildren(k.Path.Data)
	}
}

func (k *mqlRegistrykey) children() ([]any, error) {
	children, err := k.getChildren()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range children {
		child := children[i]
		res = append(res, child.Name)
	}

	return res, nil
}

// powershellChildren reads the child keys at an absolute registry path via the
// PowerShell command resource (used for remote targets and the non-native fallback).
func (k *mqlRegistrykey) powershellChildren(path string) ([]registry.RegistryKeyChild, error) {
	script := powershell.Encode(registry.GetRegistryKeyChildItemsScript(path))
	o, err := CreateResource(k.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(script),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	exitcode := cmd.GetExitcode()
	if exitcode.Error != nil {
		return nil, exitcode.Error
	}
	if exitcode.Data != 0 {
		return nil, errors.New("could not retrieve registry key")
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, stdout.Error
	}
	return registry.ParsePowershellRegistryKeyChildren(strings.NewReader(stdout.Data))
}

func (p *mqlRegistrykeyProperty) id() (string, error) {
	// Fold the SID in for per-user hive reads — see mqlRegistrykey.id.
	if p.UserSid.Data != "" {
		return userHivePath(p.UserSid.Data, p.Path.Data) + " - " + p.Name.Data, nil
	}
	return p.Path.Data + " - " + p.Name.Data, nil
}

func initRegistrykeyProperty(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// If the resolved fields are already present (e.g. the property was built
	// internally by registrykey.items), it is fully initialized — nothing to look
	// up. Otherwise we only have the selectors (path, name, and optional userSid/
	// ntuserDat) and need to resolve the value below.
	if args["exists"] != nil || args["data"] != nil {
		return args, nil, nil
	}

	path := args["path"]
	if path == nil {
		return args, nil, nil
	}

	name := args["name"]
	if name == nil {
		return args, nil, nil
	}

	// create resource here, but do not use it yet. Forward the per-user hive
	// selectors so the lookup resolves against the right hive.
	regArgs := map[string]*llx.RawData{"path": path}
	if v := args["userSid"]; v != nil {
		regArgs["userSid"] = v
	}
	if v := args["ntuserDat"]; v != nil {
		regArgs["ntuserDat"] = v
	}
	obj, err := CreateResource(runtime, "registrykey", regArgs)
	if err != nil {
		return nil, nil, err
	}
	key := obj.(*mqlRegistrykey)

	// An unreadable key (exists.Error != nil) is intentionally treated the same
	// as a missing one: the defaults below mark the property absent so the
	// lookup fails cleanly instead of erroring the whole check. (The previous
	// `if err != nil` here inspected a stale, always-nil err from the
	// CreateResource above and was dead code.)
	exists := key.GetExists()

	// set default values
	args["exists"] = llx.BoolFalse
	args["data"] = llx.DictData(nil)
	args["value"] = llx.NilData
	args["type"] = llx.NilData

	// path exists
	if exists.Data {
		items := key.GetItems()
		if items.Error != nil {
			return nil, nil, items.Error
		}

		for i := range items.Data {
			property := items.Data[i].(*mqlRegistrykeyProperty)
			iname := property.GetName()
			if iname.Error != nil {
				return nil, nil, iname.Error
			}

			// property exists, return it
			if strings.EqualFold(iname.Data, name.Value.(string)) {
				return nil, property, nil
			}
		}
	}
	return args, nil, nil
}

// The fields below are normally populated by initRegistrykeyProperty. These
// compute fallbacks are only reached when the resource was created without
// those fields pre-set — e.g. replaying a recording that did not capture them.
// In that case the property is treated as absent and the fields fail cleanly
// (false / null) rather than erroring the whole check, mirroring the leniency
// of init (which already defaults a missing property to exists=false, data=nil)
// and matching how a missing key on an array/map now fails gracefully.

func (p *mqlRegistrykeyProperty) exists() (bool, error) {
	return false, nil
}

func (p *mqlRegistrykeyProperty) compute_type() (string, error) {
	return "", nil
}

func (p *mqlRegistrykeyProperty) data() (any, error) {
	return nil, nil
}

func (p *mqlRegistrykeyProperty) value() (string, error) {
	return "", nil
}
