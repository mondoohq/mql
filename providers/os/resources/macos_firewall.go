// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

type mqlMacosFirewallInternal struct {
	lock    sync.Mutex
	fetched bool
	config  plist.Data

	managedLock    sync.Mutex
	managedFetched bool
	managed        plist.Data
}

func alfConfigFloat(config plist.Data, key string) (float64, error) {
	v, ok := config[key].(float64)
	if !ok {
		return 0, fmt.Errorf("ALF config key %q not found or not a number", key)
	}
	return v, nil
}

func alfConfigString(config plist.Data, key string) (string, error) {
	v, ok := config[key].(string)
	if !ok {
		return "", fmt.Errorf("ALF config key %q not found or not a string", key)
	}
	return v, nil
}

func alfConfigSlice(config plist.Data, key string) ([]any, error) {
	v, ok := config[key].([]any)
	if !ok {
		return nil, fmt.Errorf("ALF config key %q not found or not an array", key)
	}
	return v, nil
}

func (m *mqlMacosFirewall) fetchConfig() (plist.Data, error) {
	if m.fetched {
		return m.config, nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.fetched {
		return m.config, nil
	}

	conn := m.MqlRuntime.Connection.(shared.Connection)
	fs := conn.FileSystem()

	var plistLocation string
	for _, loc := range alfPlistLocations {
		log.Debug().Str("location", loc).Msg("Checking for ALF configuration")
		s, err := fs.Stat(loc)
		if err == nil && !s.IsDir() {
			log.Debug().Str("location", loc).Msg("Found ALF configuration")
			plistLocation = loc
			break
		}
	}

	if plistLocation == "" {
		// No preferences file. Modern macOS stops writing one; the live state
		// is read from socketfilterfw instead. Cache the empty result so the
		// lookup is not repeated per field.
		m.fetched = true
		m.config = nil
		return nil, nil
	}

	f, err := fs.Open(plistLocation)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	config, err := plist.Decode(f)
	if err != nil {
		return nil, err
	}

	m.fetched = true
	m.config = config
	return config, nil
}

func (m *mqlMacosFirewall) globalState() (int64, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return 0, err
	}
	if v, err := alfConfigFloat(config, "globalstate"); err == nil {
		return int64(v), nil
	}

	stdout, liveErr := m.runSocketfilterfw("--getglobalstate")
	if liveErr == nil {
		if v, ok := parseGlobalState(stdout); ok {
			return v, nil
		}
	}

	managed, err := m.fetchManaged()
	if err != nil {
		return 0, err
	}
	if enabled, ok := managed["EnableFirewall"].(bool); ok {
		switch {
		case !enabled:
			return 0, nil
		case managed["BlockAllIncoming"] == true:
			return 2, nil
		default:
			return 1, nil
		}
	}
	return 0, firewallUnavailable(liveErr)
}

func (m *mqlMacosFirewall) enabled() (bool, error) {
	state, err := m.globalState()
	if err != nil {
		return false, err
	}
	return state >= 1, nil
}

func (m *mqlMacosFirewall) blockAllIncoming() (bool, error) {
	state, err := m.globalState()
	if err != nil {
		return false, err
	}
	return state == 2, nil
}

func (m *mqlMacosFirewall) stealthEnabled() (bool, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return false, err
	}
	if v, err := alfConfigFloat(config, "stealthenabled"); err == nil {
		return int64(v) != 0, nil
	}

	return m.liveOrManagedToggle("--getstealthmode", "EnableStealthMode")
}

func (m *mqlMacosFirewall) loggingEnabled() (bool, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return false, err
	}
	if v, err := alfConfigFloat(config, "loggingenabled"); err == nil {
		return int64(v) != 0, nil
	}

	return m.liveOrManagedToggle("--getloggingmode", "EnableLogging")
}

func (m *mqlMacosFirewall) loggingDetail() (string, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return "", err
	}
	v, err := alfConfigFloat(config, "loggingoption")
	if err != nil {
		// No preferences file. A configuration profile states the option by
		// name, with the same three values the preferences file numbers.
		managed, merr := m.fetchManaged()
		if merr != nil {
			return "", merr
		}
		opt, _ := managed["LoggingOption"].(string)
		switch opt {
		case "detail", "brief", "throttled":
			return opt, nil
		case "":
			return "", errFirewallLoggingDetailUnavailable
		}
		return "", fmt.Errorf("%w: the configuration profile sets LoggingOption %q, which is not detail, brief, or throttled",
			errFirewallLoggingDetailUnavailable, opt)
	}
	switch int64(v) {
	case 0:
		return "disabled", nil
	case 1:
		return "detail", nil
	case 2:
		return "brief", nil
	case 3:
		return "throttled", nil
	default:
		return "unknown", nil
	}
}

func (m *mqlMacosFirewall) allowSignedApps() (bool, error) {
	return m.signedAppsFlag("allowsignedenabled", false)
}

func (m *mqlMacosFirewall) allowDownloadSignedApps() (bool, error) {
	return m.signedAppsFlag("allowdownloadsignedenabled", true)
}

// signedAppsFlag reads one of the two auto-allow toggles. socketfilterfw
// reports both in a single --getallowsigned reply, so `downloaded` picks the
// line rather than the command.
func (m *mqlMacosFirewall) signedAppsFlag(plistKey string, downloaded bool) (bool, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return false, err
	}
	if v, err := alfConfigFloat(config, plistKey); err == nil {
		return int64(v) != 0, nil
	}

	stdout, err := m.runSocketfilterfw("--getallowsigned")
	if err != nil {
		return false, err
	}
	builtin, download, ok := parseAllowSigned(stdout)
	if !ok {
		return false, errFirewallStateUnavailable
	}
	if downloaded {
		return download, nil
	}
	return builtin, nil
}

func (m *mqlMacosFirewall) version() (string, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return "", err
	}
	return alfConfigString(config, "version")
}

func (m *mqlMacosFirewall) exceptions() ([]any, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return nil, err
	}
	return alfConfigSlice(config, "exceptions")
}

func (m *mqlMacosFirewall) explicitAuths() ([]any, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return nil, err
	}
	explicitAuthsRaw, err := alfConfigSlice(config, "explicitauths")
	if err != nil {
		return nil, err
	}
	result := []any{}
	for i := range explicitAuthsRaw {
		entry, ok := explicitAuthsRaw[i].(map[string]any)
		if !ok {
			continue
		}
		result = append(result, entry["id"])
	}
	return result, nil
}

func (m *mqlMacosFirewall) applications() ([]any, error) {
	config, err := m.fetchConfig()
	if err != nil {
		return nil, err
	}

	if config == nil {
		// No preferences file: modern macOS keeps the per-app rules out of
		// it. socketfilterfw lists them without root.
		stdout, err := m.runSocketfilterfw("--listapps")
		if err != nil {
			return nil, err
		}
		return m.createApps(parseListApps(stdout))
	}

	appsRaw, err := alfConfigSlice(config, "applications")
	if err != nil {
		return nil, err
	}
	entries := make([]firewallAppEntry, 0, len(appsRaw))
	for i, raw := range appsRaw {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		bundleId, _ := entry["bundleid"].(string)
		name := bundleId
		if path, ok := entry["path"].(string); ok && path != "" {
			name = path
		}
		if name == "" {
			name = fmt.Sprintf("unknown-%d", i)
		}
		state := int64(0)
		if s, ok := entry["state"].(float64); ok {
			state = int64(s)
		}
		entries = append(entries, firewallAppEntry{name: name, bundleId: bundleId, state: state})
	}

	return m.createApps(entries)
}

// firewallAppEntry is one per-application rule, from either source.
type firewallAppEntry struct {
	name     string
	bundleId string
	state    int64
}

func (m *mqlMacosFirewall) createApps(entries []firewallAppEntry) ([]any, error) {
	apps := make([]any, 0, len(entries))
	for _, e := range entries {
		app, err := CreateResource(m.MqlRuntime, "macos.firewall.app", map[string]*llx.RawData{
			"__id":     llx.StringData("macos.firewall.app/" + e.name),
			"name":     llx.StringData(e.name),
			"bundleId": llx.StringData(e.bundleId),
			"state":    llx.IntData(e.state),
		})
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, nil
}

// mdmFirewallPayloadType is the Configuration Profile payload type that
// Apple defines for the application firewall. A profile carrying this
// payload (typically delivered via MDM) declares enable state, stealth
// mode, blocking behaviour, and per-app rules for the firewall.
const mdmFirewallPayloadType = "com.apple.security.firewall"

func (m *mqlMacosFirewall) managedByMDM() (bool, error) {
	res, err := CreateResource(m.MqlRuntime, "macos.profiles", nil)
	if err != nil {
		return false, err
	}
	profiles := res.(*mqlMacosProfiles)
	list := profiles.GetList()
	if list.Error != nil {
		return false, list.Error
	}
	for _, raw := range list.Data {
		profile, ok := raw.(*mqlMacosProfile)
		if !ok {
			continue
		}
		payloads := profile.GetPayloads()
		if payloads.Error != nil {
			return false, payloads.Error
		}
		for _, p := range payloads.Data {
			payload, ok := p.(*mqlMacosProfilePayload)
			if !ok {
				continue
			}
			ptype := payload.GetType()
			if ptype.Error != nil {
				return false, ptype.Error
			}
			if ptype.Data == mdmFirewallPayloadType {
				return true, nil
			}
		}
	}
	return false, nil
}

// id is required for the macos.firewall.app sub-resource
func (m *mqlMacosFirewallApp) id() (string, error) {
	return "macos.firewall.app/" + m.Name.Data, nil
}
