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
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/types"
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

// registryReadPath is the path a registry key is read with: the spelling of
// the query, with its separators collapsed and trimmed. Spellings that differ
// only in separators share one resource (see registryIDPath), so the read must
// not depend on which of them created it: Windows refuses an empty segment
// right after the hive (HKLM\\SOFTWARE), PowerShell reports such a key as
// missing and RegOpenKeyEx as an invalid path, while the collapsed path reads
// the key in both.
func registryReadPath(path string) string {
	var parts []string
	for _, p := range strings.Split(path, `\`) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, `\`)
}

// registryIDPath is the form of a registry key path that the resource ids use.
// Registry paths are case-insensitive, so every spelling of a key maps to one
// id: the resources share one cache entry, and a remote scan reads the key
// with one PowerShell run instead of one per spelling. It is the read path
// (registryReadPath), lower-cased, with the HKLM and HKCU abbreviations
// replaced by the hive's full name. The resource's `path` field keeps the
// spelling of the query that created it.
func registryIDPath(path string) string {
	parts := strings.Split(strings.ToLower(registryReadPath(path)), `\`)
	switch parts[0] {
	case "hklm":
		parts[0] = "hkey_local_machine"
	case "hkcu":
		parts[0] = "hkey_current_user"
	}
	return strings.Join(parts, `\`)
}

func (k *mqlRegistrykey) id() (string, error) {
	// When reading a per-user hive, `path` is relative to that user's HKCU and is
	// shared across users — fold the SID into the id so each user's key (and the
	// properties derived from it) caches separately.
	if k.UserSid.Data != "" {
		return registryIDPath(userHivePath(k.UserSid.Data, k.Path.Data)), nil
	}
	return registryIDPath(k.Path.Data), nil
}

// readPath is the key's path to read with; see registryReadPath.
func (k *mqlRegistrykey) readPath() string {
	return registryReadPath(k.Path.Data)
}

// isUserHive reports whether this key targets a specific user's registry hive.
func (k *mqlRegistrykey) isUserHive() bool {
	return k.UserSid.Data != ""
}

// registryApplicable reports a registry read on an asset that is known not to
// be Windows as not applicable. An asset without a platform is left to try.
func registryApplicable(conn shared.Connection) error {
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil || asset.Platform.Name == "" {
		return nil
	}
	if asset.Platform.IsFamily(inventory.FAMILY_WINDOWS) {
		return nil
	}
	return llx.NotApplicable(errors.New("the Windows registry is only available on Windows"))
}

// classifyRegistryStderr reads the error record a failed registry script left
// on stderr, decoded from CLIXML by the transport. It reports whether the key
// is absent, and otherwise returns the failure: forbidden when the record's
// category is PermissionDenied, unclassified with the record's message for
// anything else. The category and the exception type are identifiers, which
// Windows does not translate, so this holds on a localized host.
func classifyRegistryStderr(path string, stderr string) (absent bool, err error) {
	// the SSH, WinRM and local transports decode CLIXML already; others do not
	stderr = string(powershell.DecodeCLIXML([]byte(stderr)))
	switch {
	case strings.Contains(stderr, "ObjectNotFound") || strings.Contains(stderr, "PathNotFound"):
		return true, nil
	case strings.Contains(stderr, "PermissionDenied") ||
		strings.Contains(stderr, "SecurityException") ||
		strings.Contains(stderr, "UnauthorizedAccessException"):
		return false, llx.Forbidden(fmt.Errorf("could not read registry key %s: %s", path, powershellErrorMessage(stderr)))
	}
	msg := powershellErrorMessage(stderr)
	if msg == "" {
		return false, fmt.Errorf("could not read registry key %s", path)
	}
	return false, fmt.Errorf("could not read registry key %s: %s", path, msg)
}

// powershellErrorMessage returns the first line of a PowerShell error record,
// the message, without the "Get-Item : " prefix that names the command.
func powershellErrorMessage(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if cmd, msg, ok := strings.Cut(line, " : "); ok && !strings.ContainsAny(cmd, " \t") {
			return strings.TrimSpace(msg)
		}
		return line
	}
	return ""
}

// userHiveReader resolves how to read this key's per-user hive natively on a
// local Windows host. It returns either a non-empty livePath to read directly
// (the user is logged in, so HKEY_USERS\<sid> is live) or a non-nil handler to
// read sub-paths through (the hive was loaded from NTUSER.DAT). When the hive
// can't be read at all — no loader, missing NTUSER.DAT, or a load failure — it
// returns ok=false, and callers treat the key as absent.
//
// A hive that exists but fails to load is not an absence: with structured
// errors (ADR 046) the load failure is returned. v13 treats it as absent too.
func (k *mqlRegistrykey) userHiveReader(conn shared.Connection) (livePath string, rh *registry.RegistryHandler, ok bool, err error) {
	sid := k.UserSid.Data
	if registry.IsUserHiveLoaded(sid) {
		return userHivePath(sid, k.readPath()), nil, true, nil
	}
	loader, isLoader := conn.(userHiveLoader)
	if !isLoader || k.NtuserDat.Data == "" {
		return "", nil, false, nil
	}
	h := loader.UserHiveRegistryHandler()
	if err := h.LoadUserHive(sid, k.NtuserDat.Data); err != nil {
		log.Debug().Err(err).Str("sid", sid).Str("ntuserDat", k.NtuserDat.Data).
			Msg("could not load user registry hive")
		if !plugin.StructuredErrors() {
			return "", nil, false, nil
		}
		return "", nil, false, fmt.Errorf("could not load the registry hive of %s from %s: %w", sid, k.NtuserDat.Data, err)
	}
	return "", h, true, nil
}

func (k *mqlRegistrykey) nativeUserHiveItems(conn shared.Connection) ([]registry.RegistryKeyItem, error) {
	livePath, rh, ok, err := k.userHiveReader(conn)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if rh != nil {
		return rh.GetUserHiveKeyItems(k.UserSid.Data, k.readPath())
	}
	return registry.GetNativeRegistryKeyItems(livePath)
}

func (k *mqlRegistrykey) nativeUserHiveChildren(conn shared.Connection) ([]registry.RegistryKeyChild, error) {
	livePath, rh, ok, err := k.userHiveReader(conn)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if rh != nil {
		return rh.GetUserHiveKeyChildren(k.UserSid.Data, k.readPath())
	}
	return registry.GetNativeRegistryKeyChildren(livePath)
}

func (k *mqlRegistrykey) exists() (bool, error) {
	conn := k.MqlRuntime.Connection.(shared.Connection)
	if err := registryApplicable(conn); err != nil {
		return false, err
	}
	local := conn.Type() == shared.Type_Local && runtime.GOOS == "windows"

	// A key exists when it can be opened, whether or not it holds values or
	// subkeys: an empty key such as a policy root without settings exists, as
	// the PowerShell probe (Get-Item) reports it for remote targets.

	// per-user hive read: resolve against the live HKEY_USERS\<sid> hive or the
	// profile's NTUSER.DAT loaded on demand (local Windows), else fall back to the
	// live hive over PowerShell (remote).
	if k.isUserHive() {
		if local {
			livePath, rh, ok, err := k.userHiveReader(conn)
			if err != nil {
				return false, err
			}
			if !ok {
				// The hive cannot be read at all; see userHiveReader.
				return false, nil
			}
			if rh != nil {
				return rh.UserHiveKeyExists(k.UserSid.Data, k.readPath())
			}
			return registry.NativeRegistryKeyExists(livePath)
		}
		return k.powershellExists(userHivePath(k.UserSid.Data, k.readPath()))
	}

	// Locally on Windows the native API answers; PowerShell is only the
	// fallback for a key the native API cannot open (for example access denied).
	if local {
		exists, err := registry.NativeRegistryKeyExists(k.readPath())
		if err == nil {
			return exists, nil
		}
		log.Debug().Err(err).Str("path", k.Path.Data).Msg("native registry key check failed, falling back to PowerShell")
	}

	return k.powershellExists(k.readPath())
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
		if _, isMock := k.MqlRuntime.Connection.(*mock.Connection); isMock {
			return false, nil
		}
		absent, err := classifyRegistryStderr(path, cmd.GetStderr().Data)
		if absent {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetEntries returns a list of registry key property resources
// getEntries returns the values of the key and fails when any of them could
// not be read. The typed Windows resources (LSA, Schannel, the spooler, ...)
// read Value.Number and Value.String directly, so an unread value would reach
// them as 0 or "" and report a setting as off. Only items() tolerates a
// per-value failure, because it can hand the error to that value's fields.
func (k *mqlRegistrykey) getEntries() ([]registry.RegistryKeyItem, error) {
	entries, err := k.readEntries()
	if err != nil {
		return nil, err
	}
	if err := registryValueError(k.Path.Data, entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// registryValueError returns the error of the first value of a key that could
// not be read, or nil.
func registryValueError(path string, entries []registry.RegistryKeyItem) error {
	for i := range entries {
		if entries[i].Value.Err != nil {
			return fmt.Errorf("could not read registry value %s of %s: %w", entries[i].Key, path, entries[i].Value.Err)
		}
	}
	return nil
}

// readEntries returns the values of the key, each carrying its own read error.
func (k *mqlRegistrykey) readEntries() ([]registry.RegistryKeyItem, error) {
	conn := k.MqlRuntime.Connection.(shared.Connection)
	if err := registryApplicable(conn); err != nil {
		return nil, err
	}

	if k.isUserHive() {
		if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
			return k.nativeUserHiveItems(conn)
		}
		return k.powershellItems(userHivePath(k.UserSid.Data, k.readPath()))
	}

	// if we are running locally on windows, we can use native api
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		return nativeItemsOrAbsent(registry.GetNativeRegistryKeyItems(k.readPath()))
	}

	return k.powershellItems(k.readPath())
}

// nativeItemsOrAbsent reports a key the native API cannot find as absent (no
// values, no error), as powershellItems does for ObjectNotFound: otherwise
// registrykey(...).items on a missing key is null over SSH and an error on a
// local scan of the same machine.
func nativeItemsOrAbsent(items []registry.RegistryKeyItem, err error) ([]registry.RegistryKeyItem, error) {
	if std, ok := status.FromError(err); ok && std.Code() == codes.NotFound {
		return nil, nil
	}
	return items, err
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
		if _, isMock := k.MqlRuntime.Connection.(*mock.Connection); isMock {
			return nil, nil
		}
		absent, err := classifyRegistryStderr(path, cmd.GetStderr().Data)
		if absent {
			return nil, nil
		}
		return nil, err
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
	entries, err := k.readEntries()
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
		value := llx.StringData(entry.String())
		typ := llx.StringData(entry.Kind())
		data := llx.DictData(entry.GetRawValue())
		// A value whose type could not be read exists, but its type and data
		// are unknown: each of those fields carries the error rather than a
		// NONE that reads as "empty".
		if entry.Value.Err != nil {
			err := fmt.Errorf("could not read registry value %s of %s: %w", entry.Key, k.Path.Data, entry.Value.Err)
			value = &llx.RawData{Type: types.String, Error: err}
			typ = &llx.RawData{Type: types.String, Error: err}
			data = &llx.RawData{Type: types.Dict, Error: err}
		}
		o, err := CreateResource(k.MqlRuntime, "registrykey.property", map[string]*llx.RawData{
			"path":      llx.StringData(k.Path.Data),
			"name":      llx.StringData(entry.Key),
			"value":     value,
			"type":      typ,
			"data":      data,
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
	if err := registryApplicable(conn); err != nil {
		return nil, err
	}
	switch {
	case k.isUserHive() && conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		return k.nativeUserHiveChildren(conn)
	case k.isUserHive():
		return k.powershellChildren(userHivePath(k.UserSid.Data, k.readPath()))
	case conn.Type() == shared.Type_Local && runtime.GOOS == "windows":
		return registry.GetNativeRegistryKeyChildren(k.readPath())
	default:
		return k.powershellChildren(k.readPath())
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
		absent, err := classifyRegistryStderr(path, cmd.GetStderr().Data)
		if absent {
			return nil, nil
		}
		return nil, err
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, stdout.Error
	}
	return registry.ParsePowershellRegistryKeyChildren(strings.NewReader(stdout.Data))
}

func (p *mqlRegistrykeyProperty) id() (string, error) {
	// Fold the SID in for per-user hive reads, and fold the case of the path and
	// the value name, which the registry treats case-insensitively too — see
	// mqlRegistrykey.id.
	name := strings.ToLower(p.Name.Data)
	if p.UserSid.Data != "" {
		return registryIDPath(userHivePath(p.UserSid.Data, p.Path.Data)) + " - " + name, nil
	}
	return registryIDPath(p.Path.Data) + " - " + name, nil
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

	// A key that could not be read is not a missing key. With structured
	// errors (ADR 046) every field of the property carries the failure, so a
	// refused key does not make `exists == false` pass. The fields carry it
	// rather than init returning it: an init error crosses the plugin boundary
	// as a bare message and loses its kind. v13 treats an unreadable key as
	// missing: the defaults below mark the property absent.
	exists := key.GetExists()
	if exists.Error != nil && plugin.StructuredErrors() {
		args["exists"] = &llx.RawData{Type: types.Bool, Error: exists.Error}
		args["data"] = &llx.RawData{Type: types.Dict, Error: exists.Error}
		args["value"] = &llx.RawData{Type: types.String, Error: exists.Error}
		args["type"] = &llx.RawData{Type: types.String, Error: exists.Error}
		return args, nil, nil
	}

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
