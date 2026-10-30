// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- snmp.community ---

// defaultSnmpCommunityNames are the community names every scanner tries first.
var defaultSnmpCommunityNames = map[string]struct{}{
	"public":  {},
	"private": {},
}

// usesDefaultCommunityName reports whether an SNMP community carries one of the
// well-known default names, without the name itself reaching the result. It is
// nil when the device did not report a name, since an unread name is not proof
// that the community was renamed.
func usesDefaultCommunityName(name string) *bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	_, isDefault := defaultSnmpCommunityNames[strings.ToLower(name)]
	return &isDefault
}

func snmpCommunityArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id": llx.StringData(rowID("mikrotik.snmp.community/", row, row["addresses"], row["security"])),
		// the community string is a shared secret: only whether it is one of
		// the well-known defaults is reported, never the string itself
		"usesDefaultCommunityName":  llx.BoolDataPtr(usesDefaultCommunityName(row["name"])),
		"addresses":                 llx.StringData(row["addresses"]),
		"readAccess":                boolField(row, "read-access"),
		"writeAccess":               boolField(row, "write-access"),
		"security":                  llx.StringData(row["security"]),
		"authenticationProtocol":    llx.StringData(row["authentication-protocol"]),
		"encryptionProtocol":        llx.StringData(row["encryption-protocol"]),
		"hasAuthenticationPassword": presenceField(row, "authentication-password"),
		"hasEncryptionPassword":     presenceField(row, "encryption-password"),
		"default":                   boolField(row, "default"),
		"disabled":                  boolField(row, "disabled"),
	}
}

func newMikrotikSnmpCommunity(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.snmp.community", snmpCommunityArgs(row))
}

func (r *mqlMikrotik) snmpCommunities() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/snmp/community")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikSnmpCommunity)
}

// --- system.logging.action ---

func loggingActionArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData("mikrotik.system.logging.action/" + row["name"]),
		"name":             llx.StringData(row["name"]),
		"target":           llx.StringData(row["target"]),
		"remote":           llx.StringData(row["remote"]),
		"remotePort":       intField(row, "remote-port"),
		"srcAddress":       llx.StringData(row["src-address"]),
		"bsdSyslog":        boolField(row, "bsd-syslog"),
		"syslogFacility":   llx.StringData(row["syslog-facility"]),
		"syslogSeverity":   llx.StringData(row["syslog-severity"]),
		"syslogTimeFormat": llx.StringData(row["syslog-time-format"]),
		"memoryLines":      intField(row, "memory-lines"),
		"memoryStopOnFull": boolField(row, "memory-stop-on-full"),
		"diskFileName":     llx.StringData(row["disk-file-name"]),
		"diskLinesPerFile": intField(row, "disk-lines-per-file"),
		"diskFileCount":    intField(row, "disk-file-count"),
		"diskStopOnFull":   boolField(row, "disk-stop-on-full"),
	}
}

func newMikrotikLoggingAction(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.system.logging.action", loggingActionArgs(row))
}

func (r *mqlMikrotik) loggingActions() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/logging/action")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikLoggingAction)
}

// --- system.logging.rule ---

type mqlMikrotikSystemLoggingRuleInternal struct {
	cacheAction string
}

func loggingRuleArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":     llx.StringData(rowID("mikrotik.system.logging.rule/", row, row["topics"], row["action"])),
		"topics":   listField(row, "topics"),
		"prefix":   llx.StringData(row["prefix"]),
		"disabled": boolField(row, "disabled"),
		"invalid":  boolField(row, "invalid"),
	}
}

func newMikrotikLoggingRule(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.system.logging.rule", loggingRuleArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikSystemLoggingRule).cacheAction = row["action"]
	return res, nil
}

func (r *mqlMikrotik) loggingRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/logging")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikLoggingRule)
}

// action resolves the rule's action against the already-cached action
// listing, so reading where every topic ends up costs one read of
// /system/logging/action rather than one per rule.
func (r *mqlMikrotikSystemLoggingRule) action() (*mqlMikrotikSystemLoggingAction, error) {
	null := func() (*mqlMikrotikSystemLoggingAction, error) {
		r.Action.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if r.cacheAction == "" {
		return null()
	}
	rows, err := mikrotikConn(r.MqlRuntime).Print("/system/logging/action")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row["name"] == r.cacheAction {
			res, err := newMikrotikLoggingAction(r.MqlRuntime, row)
			if err != nil {
				return nil, err
			}
			return res.(*mqlMikrotikSystemLoggingAction), nil
		}
	}
	return null()
}
