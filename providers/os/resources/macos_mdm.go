// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// =============================================================================
// macos.mdm — `profiles status -type enrollment`
// =============================================================================

// initMacosMdm guards the resource so that callers on non-macOS targets get a
// clear error instead of a cryptic failure from invoking `profiles` on a
// platform that doesn't ship the binary.
func initMacosMdm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)
	if !conn.Asset().Platform.IsFamily("darwin") {
		return nil, nil, errors.New("macos.mdm is only available on macOS")
	}
	return args, nil, nil
}

func (m *mqlMacosMdm) id() (string, error) {
	return "macos.mdm", nil
}

type mqlMacosMdmInternal struct {
	fetched bool
	state   mdmEnrollment
	lock    sync.Mutex
}

type mdmEnrollment struct {
	enrolled     bool
	dep          bool
	userApproved bool
	serverUrl    string
}

func (m *mqlMacosMdm) fetchEnrollment() (mdmEnrollment, error) {
	if m.fetched {
		return m.state, nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.fetched {
		return m.state, nil
	}

	// `profiles status -type enrollment` outputs key/value lines like:
	//   Enrolled via DEP: No
	//   MDM enrollment: No
	// or
	//   Enrolled via DEP: Yes
	//   MDM enrollment: Yes (User Approved)
	//   MDM server: https://mdm.example.com/MDMServiceConfig?id=...
	res, err := NewResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("profiles status -type enrollment"),
	})
	if err != nil {
		return mdmEnrollment{}, err
	}
	cmd := res.(*mqlCommand)
	stdout, err := commandOutput(cmd, "profiles status")
	if err != nil {
		return mdmEnrollment{}, err
	}

	m.state = parseMdmEnrollment(stdout)
	m.fetched = true
	return m.state, nil
}

// parseMdmEnrollment parses the `profiles status -type enrollment`
// output. Keys are case-insensitive in practice across macOS
// versions; we lowercase both sides before comparing.
func parseMdmEnrollment(out string) mdmEnrollment {
	state := mdmEnrollment{}
	for _, line := range strings.Split(out, "\n") {
		// IndexByte(line, ':') splits at the first colon only, preserving any
		// colons within the URL value (e.g., "ServerURL: https://mdm.example.com:443/...").
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		valueLower := strings.ToLower(value)

		switch key {
		case "enrolled via dep":
			state.dep = strings.HasPrefix(valueLower, "yes")
		case "mdm enrollment":
			// "No" / "Yes" / "Yes (User Approved)"
			state.enrolled = strings.HasPrefix(valueLower, "yes")
			state.userApproved = strings.Contains(valueLower, "user approved")
		case "mdm server":
			state.serverUrl = value
		}
	}
	return state
}

func (m *mqlMacosMdm) enrolled() (bool, error) {
	s, err := m.fetchEnrollment()
	if err != nil {
		return false, err
	}
	return s.enrolled, nil
}

func (m *mqlMacosMdm) dep() (bool, error) {
	s, err := m.fetchEnrollment()
	if err != nil {
		return false, err
	}
	return s.dep, nil
}

func (m *mqlMacosMdm) userApproved() (bool, error) {
	s, err := m.fetchEnrollment()
	if err != nil {
		return false, err
	}
	return s.userApproved, nil
}

func (m *mqlMacosMdm) serverUrl() (string, error) {
	s, err := m.fetchEnrollment()
	if err != nil {
		return "", err
	}
	return s.serverUrl, nil
}

// =============================================================================
// macos.profiles — `profiles list -all -output stdout-xml`
// =============================================================================

// initMacosProfiles guards the resource so that callers on non-macOS targets
// get a clear error instead of a cryptic failure from invoking `profiles` on
// a platform that doesn't ship the binary.
func initMacosProfiles(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)
	if !conn.Asset().Platform.IsFamily("darwin") {
		return nil, nil, errors.New("macos.profiles is only available on macOS")
	}
	return args, nil, nil
}

func (p *mqlMacosProfiles) id() (string, error) {
	return "macos.profiles", nil
}

func (p *mqlMacosProfiles) list() ([]any, error) {
	res, err := NewResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("profiles list -all -output stdout-xml"),
	})
	if err != nil {
		return nil, err
	}
	cmd := res.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	if run.exitcode != 0 {
		// `profiles list` exits non-zero on argument errors (missing
		// action, unknown flag) — surface those as real errors so
		// authors notice when the command shape changes upstream.
		stderr := strings.TrimSpace(run.stderr)
		if stderr == "" {
			stderr = strings.TrimSpace(run.stdout)
		}
		return nil, errors.New("profiles list failed: " + stderr)
	}

	// `profiles list` exits 0 even when it can't actually enumerate
	// system profiles — for example, without root it prints
	// "profiles: this command requires root privileges" to stdout
	// instead of failing. Detect that diagnostic up front so callers
	// don't see a misleading XML parse error.
	stdout := run.stdout
	trimmed := strings.TrimSpace(stdout)
	if strings.HasPrefix(trimmed, "profiles:") {
		return nil, errors.New("profiles list failed: " + trimmed)
	}
	// Some macOS versions emit "There are no configuration profiles
	// installed" plain text (exit 0, no XML) when the user has no
	// profiles. That's a benign empty state.
	lowerTrimmed := strings.ToLower(trimmed)
	if strings.HasPrefix(lowerTrimmed, "there are no configuration profiles") {
		return []any{}, nil
	}

	parsed, err := parseMacosProfilesXML([]byte(stdout))
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(parsed))
	for _, prof := range parsed {
		payloadResources, err := p.buildPayloadResources(prof.payloads)
		if err != nil {
			return nil, err
		}
		profile, err := CreateResource(p.MqlRuntime, "macos.profile", map[string]*llx.RawData{
			"identifier":        llx.StringData(prof.identifier),
			"uuid":              llx.StringData(prof.uuid),
			"displayName":       llx.StringData(prof.displayName),
			"description":       llx.StringData(prof.description),
			"organization":      llx.StringData(prof.organization),
			"type":              llx.StringData(prof.profileType),
			"removalDisallowed": llx.BoolData(prof.removalDisallowed),
			"scope":             llx.StringData(prof.scope),
			"payloads":          llx.ArrayData(payloadResources, payloadResourceType),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, profile)
	}
	return out, nil
}

var payloadResourceType = llx.ResourceData(nil, "macos.profile.payload").Type

func (p *mqlMacosProfiles) buildPayloadResources(payloads []parsedMacosPayload) ([]any, error) {
	out := make([]any, 0, len(payloads))
	for _, pl := range payloads {
		dict, err := convert.JsonToDict(pl.content)
		if err != nil {
			return nil, err
		}
		payload, err := CreateResource(p.MqlRuntime, "macos.profile.payload", map[string]*llx.RawData{
			"uuid":        llx.StringData(pl.uuid),
			"type":        llx.StringData(pl.payloadType),
			"identifier":  llx.StringData(pl.identifier),
			"displayName": llx.StringData(pl.displayName),
			"content":     llx.DictData(dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	return out, nil
}

func (p *mqlMacosProfile) id() (string, error) {
	// Profiles can ship with the same identifier across scopes; combine
	// with the UUID to make the cache key unique.
	if p.Uuid.Data != "" {
		return "macos.profile/" + p.Uuid.Data, nil
	}
	return "macos.profile/" + p.Identifier.Data, nil
}

func (p *mqlMacosProfilePayload) id() (string, error) {
	if p.Uuid.Data != "" {
		return "macos.profile.payload/" + p.Uuid.Data, nil
	}
	return "macos.profile.payload/" + p.Identifier.Data + "/" + p.Type.Data, nil
}

// =============================================================================
// profiles XML parsing
// =============================================================================

type parsedMacosProfile struct {
	identifier        string
	uuid              string
	displayName       string
	description       string
	organization      string
	profileType       string
	removalDisallowed bool
	scope             string
	payloads          []parsedMacosPayload
}

type parsedMacosPayload struct {
	uuid        string
	payloadType string
	identifier  string
	displayName string
	content     map[string]any
}

// parseMacosProfilesXML decodes the plist returned by `profiles list
// -output stdout-xml`. The top-level dictionary contains
// `_computerlevel` for system profiles and per-user keyed entries for
// user-level profiles; we flatten both into a single flat list,
// tagging each profile with its `scope`.
func parseMacosProfilesXML(xml []byte) ([]parsedMacosProfile, error) {
	if len(bytes.TrimSpace(xml)) == 0 {
		return nil, nil
	}

	root, err := plist.Decode(bytes.NewReader(xml))
	if err != nil {
		return nil, err
	}

	var out []parsedMacosProfile
	for scopeKey, raw := range root {
		profiles, ok := raw.([]any)
		if !ok {
			continue
		}
		scope := "user"
		if scopeKey == "_computerlevel" {
			scope = "system"
		}
		for _, item := range profiles {
			profileDict, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, parseMacosProfileDict(profileDict, scope))
		}
	}
	return out, nil
}

func parseMacosProfileDict(d map[string]any, scope string) parsedMacosProfile {
	p := parsedMacosProfile{
		identifier:   stringFromDict(d, "ProfileIdentifier"),
		uuid:         stringFromDict(d, "ProfileUUID"),
		displayName:  stringFromDict(d, "ProfileDisplayName"),
		description:  stringFromDict(d, "ProfileDescription"),
		organization: stringFromDict(d, "ProfileOrganization"),
		profileType:  stringFromDict(d, "ProfileType"),
		scope:        scope,
	}

	// ProfileRemovalDisallowed shows up as a string "true"/"false" in
	// `profiles` output rather than a plist <true/>, so accept both.
	switch v := d["ProfileRemovalDisallowed"].(type) {
	case bool:
		p.removalDisallowed = v
	case string:
		p.removalDisallowed = strings.EqualFold(v, "true")
	}

	if items, ok := d["ProfileItems"].([]any); ok {
		for _, item := range items {
			payload, ok := item.(map[string]any)
			if !ok {
				continue
			}
			p.payloads = append(p.payloads, parseMacosPayloadDict(payload))
		}
	}
	return p
}

func parseMacosPayloadDict(d map[string]any) parsedMacosPayload {
	pl := parsedMacosPayload{
		uuid:        stringFromDict(d, "PayloadUUID"),
		payloadType: stringFromDict(d, "PayloadType"),
		identifier:  stringFromDict(d, "PayloadIdentifier"),
		displayName: stringFromDict(d, "PayloadDisplayName"),
	}
	// PayloadContent carries the policy directives for this payload
	// (the firewall rules, Wi-Fi credentials, FileVault key, etc.).
	// Its shape varies wildly per payload type; we hand the dict
	// through as-is so MQL queries can introspect any field.
	if content, ok := d["PayloadContent"].(map[string]any); ok {
		pl.content = content
	} else {
		pl.content = map[string]any{}
	}
	return pl
}

func stringFromDict(d map[string]any, key string) string {
	if v, ok := d[key].(string); ok {
		return v
	}
	return ""
}
