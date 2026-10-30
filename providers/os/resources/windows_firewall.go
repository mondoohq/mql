// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
)

func (w *mqlWindowsFirewallProfile) id() (string, error) {
	return w.InstanceID.Data, nil
}

func (w *mqlWindowsFirewallRule) id() (string, error) {
	return w.InstanceID.Data, nil
}

func (w *mqlWindowsFirewall) settings() (map[string]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	// query firewall profiles
	encodedCmd := powershell.Encode(windows.FIREWALL_SETTINGS)
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, err
	}

	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve computer info: " + string(stderr))
	}

	fwSettings, err := windows.ParseWindowsFirewallSettings(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(fwSettings)
}

func (w *mqlWindowsFirewall) profiles() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	// query firewall profiles
	encodedCmd := powershell.Encode(windows.FIREWALL_PROFILES)
	executedCmd, err := conn.RunCommand(encodedCmd)
	if err != nil {
		return nil, err
	}

	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve firewall profiles: " + string(stderr))
	}

	fwProfiles, err := windows.ParseWindowsFirewallProfiles(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	// convert firewall profiles to MQL resource
	mqlFwProfiles := make([]any, len(fwProfiles))
	for i, p := range fwProfiles {

		mqlFwProfile, err := CreateResource(w.MqlRuntime, "windows.firewall.profile", map[string]*llx.RawData{
			"instanceID":                      llx.StringData(p.InstanceID),
			"name":                            llx.StringData(p.Name),
			"enabled":                         llx.IntData(p.Enabled),
			"defaultInboundAction":            llx.IntData(p.DefaultInboundAction),
			"defaultOutboundAction":           llx.IntData(p.DefaultOutboundAction),
			"allowInboundRules":               llx.IntData(p.AllowInboundRules),
			"allowLocalFirewallRules":         llx.IntData(p.AllowLocalFirewallRules),
			"allowLocalIPsecRules":            llx.IntData(p.AllowLocalIPsecRules),
			"allowUserApps":                   llx.IntData(p.AllowUserApps),
			"allowUserPorts":                  llx.IntData(p.AllowUserPorts),
			"allowUnicastResponseToMulticast": llx.IntData(p.AllowUnicastResponseToMulticast),
			"notifyOnListen":                  llx.IntData(p.NotifyOnListen),
			"enableStealthModeForIPsec":       llx.IntData(p.EnableStealthModeForIPsec),
			"logMaxSizeKilobytes":             llx.IntData(p.LogMaxSizeKilobytes),
			"logAllowed":                      llx.IntData(p.LogAllowed),
			"logBlocked":                      llx.IntData(p.LogBlocked),
			"logIgnored":                      llx.IntData(p.LogIgnored),
			"logFileName":                     llx.StringData(p.LogFileName),
		})
		if err != nil {
			return nil, err
		}

		mqlFwProfiles[i] = mqlFwProfile
	}

	return mqlFwProfiles, nil
}

// runPowershell runs a PowerShell script on the target and returns its
// stdout, turning a non-zero exit into an error that carries stderr.
func runPowershell(conn shared.Connection, script string, what string) (io.Reader, error) {
	executedCmd, err := conn.RunCommand(powershell.Encode(script))
	if err != nil {
		return nil, err
	}

	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve " + what + ": " + string(stderr))
	}

	return executedCmd.Stdout, nil
}

// stringListData converts a decoded PowerShell string list into MQL data.
// An absent filter is reported as null rather than as an empty list, so a
// condition that was never read cannot be mistaken for a rule that matches
// nothing.
func stringListData(values []string, present bool) *llx.RawData {
	if !present {
		return llx.NilData
	}
	list := make([]any, len(values))
	for i := range values {
		list[i] = values[i]
	}
	return llx.ArrayData(list, types.String)
}

// stringData reports a scalar condition, or null when the host reported no
// filter of that kind for the rule. Reporting "" for an absent application
// filter would state as fact that the rule is scoped to no program.
func stringData(value string, present bool) *llx.RawData {
	if !present {
		return llx.NilData
	}
	return llx.StringData(value)
}

func (w *mqlWindowsFirewall) rules() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	// query firewall rules
	stdout, err := runPowershell(conn, windows.FIREWALL_RULES, "firewall rules")
	if err != nil {
		return nil, err
	}

	fwRules, err := windows.ParseWindowsFirewallRules(stdout)
	if err != nil {
		return nil, err
	}

	// The conditions a rule matches on live in separate filter objects that
	// join back to the rule on InstanceID. Every filter collection is
	// fetched once and joined in memory: asking per rule would be six extra
	// round trips for each of the several hundred rules a stock Windows
	// install ships with.
	stdout, err = runPowershell(conn, windows.FIREWALL_RULE_FILTERS, "firewall rule filters")
	if err != nil {
		return nil, err
	}

	fwFilters, err := windows.ParseWindowsFirewallRuleFilters(stdout)
	if err != nil {
		return nil, err
	}

	// convert firewall rules to MQL resource
	mqlFwRules := make([]any, len(fwRules))
	for i, r := range fwRules {
		// A rule with no matching filter object keeps every condition null.
		f := fwFilters[r.InstanceID]
		if f == nil {
			f = &windows.WindowsFirewallRuleFilters{}
		}

		var protocol string
		var localPorts, remotePorts, icmpTypes []string
		if f.Port != nil {
			protocol = string(f.Port.Protocol)
			localPorts = f.Port.LocalPort
			remotePorts = f.Port.RemotePort
			icmpTypes = f.Port.IcmpType
		}

		var localAddresses, remoteAddresses []string
		if f.Address != nil {
			localAddresses = f.Address.LocalAddress
			remoteAddresses = f.Address.RemoteAddress
		}

		var program string
		if f.Application != nil {
			program = string(f.Application.Program)
		}

		var serviceName string
		if f.Service != nil {
			serviceName = string(f.Service.Service)
		}

		var interfaceTypes []string
		if f.InterfaceType != nil {
			interfaceTypes = f.InterfaceType.InterfaceType
		}

		var authorizedUsers, authorizedComputers string
		if f.Security != nil {
			authorizedUsers = string(f.Security.RemoteUser)
			authorizedComputers = string(f.Security.RemoteMachine)
		}

		mqlFwRule, err := CreateResource(w.MqlRuntime, "windows.firewall.rule", map[string]*llx.RawData{
			"instanceID":            llx.StringData(r.InstanceID),
			"name":                  llx.StringData(r.Name),
			"displayName":           llx.StringData(r.DisplayName),
			"description":           llx.StringData(r.Description),
			"displayGroup":          llx.StringData(r.DisplayGroup),
			"enabled":               llx.IntData(r.Enabled),
			"direction":             llx.IntData(r.Direction),
			"action":                llx.IntData(r.Action),
			"edgeTraversalPolicy":   llx.IntData(r.EdgeTraversalPolicy),
			"looseSourceMapping":    llx.BoolData(r.LooseSourceMapping),
			"localOnlyMapping":      llx.BoolData(r.LocalOnlyMapping),
			"primaryStatus":         llx.IntData(r.PrimaryStatus),
			"status":                llx.StringData(r.Status),
			"enforcementStatus":     llx.StringData(r.EnforcementStatus),
			"policyStoreSource":     llx.StringData(r.PolicyStoreSource),
			"policyStoreSourceType": llx.IntData(r.PolicyStoreSourceType),
			"profiles":              stringListData(r.Profiles, len(r.Profiles) > 0),
			"protocol":              stringData(protocol, f.Port != nil),
			"localPorts":            stringListData(localPorts, f.Port != nil),
			"remotePorts":           stringListData(remotePorts, f.Port != nil),
			"icmpTypes":             stringListData(icmpTypes, f.Port != nil),
			"localAddresses":        stringListData(localAddresses, f.Address != nil),
			"remoteAddresses":       stringListData(remoteAddresses, f.Address != nil),
			"program":               stringData(program, f.Application != nil),
			"serviceName":           stringData(serviceName, f.Service != nil),
			"interfaceTypes":        stringListData(interfaceTypes, f.InterfaceType != nil),
			"authorizedUsers":       stringData(authorizedUsers, f.Security != nil),
			"authorizedComputers":   stringData(authorizedComputers, f.Security != nil),
		})
		if err != nil {
			return nil, err
		}

		mqlFwRules[i] = mqlFwRule
	}

	return mqlFwRules, nil
}
