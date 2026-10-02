// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/firefox"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry roots Firefox reads its policies from, in increasing order of
// precedence. WindowsGPOPoliciesProvider reads the user hive first and then
// lets the machine hive replace what it found:
//
//	// Machine policies override user policies, so we read
//	// user policies first and then replace them if necessary.
const (
	firefoxUserPolicyKey    = `HKEY_CURRENT_USER\SOFTWARE\Policies\Mozilla\Firefox`
	firefoxMachinePolicyKey = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Mozilla\Firefox`
)

// mqlFirefoxPoliciesInternal caches the one resolution every field on the
// resource is derived from, so probing the candidate paths and walking the
// registry happens once no matter how many fields a check reads.
type mqlFirefoxPoliciesInternal struct {
	lock          sync.Mutex
	resolved      bool
	policySources []firefox.Source
	policyFile    *mqlFile
	err           error
}

func (f *mqlFirefoxPolicies) id() (string, error) {
	return "firefox.policies", nil
}

// resolve reads every source that could carry policy on this host and returns
// them in increasing order of precedence.
//
// An unmanaged host — no policy file, no registry key — is the normal state and
// resolves to zero sources with no error. Callers turn that into an explicit
// null rather than an empty value, so a check reads false instead of passing
// vacuously.
func (f *mqlFirefoxPolicies) resolve() ([]firefox.Source, *mqlFile, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.resolved {
		return f.policySources, f.policyFile, f.err
	}
	f.resolved = true

	conn, ok := f.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, nil, nil
	}

	platform := firefoxPlatform(conn)

	// Lowest precedence first: the policy file.
	fileRes, params, err := f.readPolicyFile(conn, platform)
	if err != nil {
		f.err = err
		return nil, nil, err
	}
	f.policyFile = fileRes
	if fileRes != nil && params != nil {
		f.policySources = append(f.policySources, firefox.Source{
			Kind:   firefox.KindFile,
			Path:   fileRes.Path.Data,
			Params: params,
		})
	}

	// Then the registry, which outranks the file per top-level policy key.
	if platform == "windows" {
		for _, key := range []string{firefoxUserPolicyKey, firefoxMachinePolicyKey} {
			registryParams, err := f.readRegistryPolicies(conn, key)
			if err != nil {
				f.err = err
				return nil, nil, err
			}
			if registryParams == nil {
				continue
			}
			f.policySources = append(f.policySources, firefox.Source{
				Kind:   firefox.KindRegistry,
				Path:   key,
				Params: registryParams,
			})
		}
	}

	return f.policySources, f.policyFile, nil
}

// firefoxPlatform reduces the asset's platform to the three policy layouts that
// differ.
func firefoxPlatform(conn shared.Connection) string {
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return ""
	}
	switch {
	case asset.Platform.IsFamily("windows"):
		return "windows"
	case asset.Platform.IsFamily("darwin"):
		return "darwin"
	default:
		return "linux"
	}
}

// readPolicyFile finds the policy file Firefox would read on this host and
// parses it.
//
// Firefox reads exactly one file and never merges two, so the first candidate
// that exists ends the search. A candidate that is not there contributes
// nothing and is not an error — most hosts have none of them.
//
// The returned file resource is the file that was found, even when it declares
// no policies. The proposal describes this field as the file that
// *contributed*, which would make it null for a file that parses to an empty
// policy set; we expose it whenever a file is there instead, because the fact
// that an administrator deployed a policy file is worth reporting on its own,
// and because permission and ownership checks compose onto the file resource
// and stay useful for a file whose contents are empty.
func (f *mqlFirefoxPolicies) readPolicyFile(conn shared.Connection, platform string) (*mqlFile, map[string]any, error) {
	candidates := firefox.PolicyFileCandidates(platform)
	if platform == "linux" {
		candidates = firefox.LinuxPolicyFileCandidates(f.linuxHost(conn))
	}

	for _, candidate := range candidates {
		fileRes, exists, err := f.probeFile(candidate)
		if err != nil {
			return nil, nil, err
		}
		if !exists {
			continue
		}

		content := fileRes.GetContent()
		if content.Error != nil {
			return nil, nil, content.Error
		}

		params, err := firefox.ParsePolicyFile([]byte(content.Data))
		if err != nil {
			// Name the file. A host can have a policy file in any of several
			// locations, and "the JSON is broken" is not actionable until you
			// know which one to go and fix.
			return fileRes, nil, fmt.Errorf("%w (%s)", err, candidate)
		}
		return fileRes, params, nil
	}
	return nil, nil, nil
}

// probeFile returns the file resource for path and whether it exists. A path
// that cannot be stat'ed reads as absent, as it always has for the candidate
// list: most hosts have none of these paths, and a non-root scan cannot look
// inside other users' homes.
func (f *mqlFirefoxPolicies) probeFile(path string) (*mqlFile, bool, error) {
	raw, err := CreateResource(f.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, false, err
	}
	fileRes := raw.(*mqlFile)
	exists := fileRes.GetExists()
	return fileRes, exists.Error == nil && exists.Data, nil
}

// linuxHost answers firefox.LinuxPolicyFileCandidates' questions about which
// Firefox installs this host has.
func (f *mqlFirefoxPolicies) linuxHost(conn shared.Connection) firefox.LinuxHost {
	host := firefox.LinuxHost{
		Exists: func(path string) bool {
			_, exists, err := f.probeFile(path)
			return err == nil && exists
		},
		Homes: func() []string {
			users, err := targetUserHomes(f.MqlRuntime)
			if err != nil {
				log.Debug().Err(err).Msg("firefox.policies> could not list user homes for flatpak installations")
				return nil
			}
			homes := make([]string, 0, len(users))
			for _, u := range users {
				homes = append(homes, u.home)
			}
			return homes
		},
	}
	if asset := conn.Asset(); asset != nil && asset.Platform != nil {
		host.Arch = asset.Platform.Arch
	}
	return host
}

// readRegistryPolicies walks a Mozilla policy key and normalizes it into the
// same shape a policies.json file produces. It returns nil when the key is
// absent or carries nothing, which is what an unmanaged Windows host looks
// like.
func (f *mqlFirefoxPolicies) readRegistryPolicies(conn shared.Connection, path string) (map[string]any, error) {
	key, err := f.readRegistryKey(conn, path, "")
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, nil
	}
	return firefox.NormalizeRegistry(*key), nil
}

// readRegistryKey reads one key and everything below it.
func (f *mqlFirefoxPolicies) readRegistryKey(conn shared.Connection, path, name string) (*firefox.RegistryKey, error) {
	values, err := f.readRegistryValues(path)
	if err != nil {
		return nil, err
	}

	childNames, err := f.readRegistryChildNames(conn, path)
	if err != nil {
		return nil, err
	}

	if len(values) == 0 && len(childNames) == 0 {
		return nil, nil
	}

	key := &firefox.RegistryKey{Name: name, Values: values}
	for _, childName := range childNames {
		child, err := f.readRegistryKey(conn, path+`\`+childName, childName)
		if err != nil {
			return nil, err
		}
		if child == nil {
			continue
		}
		key.Children = append(key.Children, *child)
	}
	return key, nil
}

// readRegistryValues reads a key's value entries through the registrykey
// resource, which already handles reading natively on a local Windows host and
// over PowerShell everywhere else.
func (f *mqlFirefoxPolicies) readRegistryValues(path string) ([]firefox.RegistryValue, error) {
	raw, err := CreateResource(f.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	key := raw.(*mqlRegistrykey)

	items := key.GetItems()
	if items.Error != nil {
		if isRegistryKeyAbsent(items.Error) {
			return nil, nil
		}
		return nil, items.Error
	}

	res := make([]firefox.RegistryValue, 0, len(items.Data))
	for i := range items.Data {
		prop, ok := items.Data[i].(*mqlRegistrykeyProperty)
		if !ok {
			continue
		}
		name := prop.GetName()
		if name.Error != nil || name.Data == "" {
			continue
		}
		// a value that could not be read fails the read: skipping it would
		// report its policy as not set
		kind := prop.GetType()
		if kind.Error != nil {
			return nil, kind.Error
		}
		data := prop.GetData()
		if data.Error != nil {
			return nil, data.Error
		}
		res = append(res, firefox.RegistryValue{
			Name: name.Data,
			Kind: kind.Data,
			Data: data.Data,
		})
	}
	return res, nil
}

// firefoxRegistryChildNamesScript lists the immediate sub-key names of a
// registry key, one per line, and stays silent when the key is not there.
//
// registrykey.children is deliberately not used for this. Its two backends do
// not agree on what they return — the PowerShell one enumerates recursively and
// yields full paths, the native one yields the parent's own path once per
// child — and neither gives the child name this walk needs.
const firefoxRegistryChildNamesScript = `Get-ChildItem -Path ('Registry::' + '%PATH%') -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }`

func (f *mqlFirefoxPolicies) readRegistryChildNames(conn shared.Connection, path string) ([]string, error) {
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		children, err := registry.GetNativeRegistryKeyChildren(path)
		if err != nil {
			if isRegistryKeyAbsent(err) {
				return nil, nil
			}
			return nil, err
		}
		names := make([]string, 0, len(children))
		for i := range children {
			if children[i].Name != "" {
				names = append(names, children[i].Name)
			}
		}
		return names, nil
	}

	// The path goes into a single-quoted PowerShell string, where the only
	// escape is doubling the quote.
	quoted := strings.ReplaceAll(path, "'", "''")
	script := powershell.Encode(strings.ReplaceAll(firefoxRegistryChildNamesScript, "%PATH%", quoted))
	raw, err := CreateResource(f.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(script),
	})
	if err != nil {
		return nil, err
	}
	cmd := raw.(*mqlCommand)

	exit := cmd.GetExitcode()
	if exit.Error != nil || exit.Data != 0 {
		// A key that is not there is the normal unmanaged state, not a failure.
		return nil, nil
	}
	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, nil
	}

	names := []string{}
	for _, line := range strings.Split(stdout.Data, "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// isRegistryKeyAbsent reports whether an error just means the key is not on
// this host. An unmanaged Firefox has no Mozilla policy key at all, so this has
// to read as "nothing configured" rather than propagate as a resource error.
func isRegistryKeyAbsent(err error) bool {
	if err == nil {
		return false
	}
	if std, ok := status.FromError(err); ok && std.Code() == codes.NotFound {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "ObjectNotFound") ||
		strings.Contains(msg, "could not retrieve registry key")
}

func (f *mqlFirefoxPolicies) configured() (bool, error) {
	sources, _, err := f.resolve()
	if err != nil {
		return false, err
	}
	return len(sources) > 0, nil
}

func (f *mqlFirefoxPolicies) source() (string, error) {
	sources, _, err := f.resolve()
	if err != nil {
		return "", err
	}
	return firefox.Describe(sources), nil
}

func (f *mqlFirefoxPolicies) file() (*mqlFile, error) {
	_, fileRes, err := f.resolve()
	if err != nil {
		return nil, err
	}
	if fileRes == nil {
		// No policy file on this host. The field is resolved — the answer is
		// "there is none" — so it has to be marked null explicitly. Returning a
		// bare nil would leave the runtime believing the field was never
		// resolved, and it would either re-fetch forever or panic on the
		// missing value.
		f.File = plugin.TValue[*mqlFile]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return fileRes, nil
}

func (f *mqlFirefoxPolicies) params() (any, error) {
	sources, _, err := f.resolve()
	if err != nil {
		return nil, err
	}

	params := firefox.Merge(sources)
	if params == nil {
		// An unmanaged host resolves to null, not to an empty dict. Null is the
		// honest answer and it keeps a check false: reading a key out of it
		// yields null, and null never equals the value a check looks for.
		f.Params = plugin.TValue[any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return params, nil
}

func (f *mqlFirefoxPolicies) inputs() ([]any, error) {
	sources, _, err := f.resolve()
	if err != nil {
		return nil, err
	}

	// An empty list rather than null: `inputs.any(...)` on a host with no
	// configuration is false, which is what a check expects.
	res := make([]any, 0, len(sources))
	for _, source := range sources {
		raw, err := CreateResource(f.MqlRuntime, "firefox.policies.input", map[string]*llx.RawData{
			"source": llx.StringData(source.Kind),
			"path":   llx.StringData(source.Path),
			"params": llx.DictData(source.Params),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, raw)
	}
	return res, nil
}

func (s *mqlFirefoxPoliciesInput) id() (string, error) {
	return "firefox.policies.input/" + s.Source.Data + "/" + s.Path.Data, nil
}
