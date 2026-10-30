// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (p *mqlAuditpol) list() ([]any, error) {
	entries, err := fetchAuditpolEntries(p.MqlRuntime)
	if err != nil {
		return nil, err
	}

	auditPolEntries := make([]any, len(entries))
	for i := range entries {
		entry := entries[i]
		success, failure, setting := auditpolFlagData(entry.Flags)
		o, err := CreateResource(p.MqlRuntime, "auditpol.entry", map[string]*llx.RawData{
			"machinename":      llx.StringData(entry.MachineName),
			"policytarget":     llx.StringData(entry.PolicyTarget),
			"subcategory":      llx.StringData(entry.Subcategory),
			"subcategoryguid":  llx.StringData(entry.SubcategoryGUID),
			"inclusionsetting": llx.StringData(entry.InclusionSetting),
			"exclusionsetting": llx.StringData(entry.ExclusionSetting),
			"setting":          setting,
			"success":          success,
			"failure":          failure,
		})
		if err != nil {
			return nil, err
		}
		auditPolEntries[i] = o.(*mqlAuditpolEntry)
	}

	return auditPolEntries, nil
}

func (p *mqlAuditpolEntry) id() (string, error) {
	return p.Subcategoryguid.Data, nil
}

// auditpolFlagData is a subcategory's setting as the success, failure, and
// English setting fields; all null when the setting could not be read.
func auditpolFlagData(flags *windows.AuditFlags) (success, failure, setting *llx.RawData) {
	if flags == nil {
		return llx.NilData, llx.NilData, llx.NilData
	}
	return llx.BoolData(flags.Success()), llx.BoolData(flags.Failure()), llx.StringData(flags.Setting())
}

// success and failure are set with the entry; an entry created without them
// (for example from an older recording) reads them from the inclusion setting
// if it is a text the provider knows, and is null otherwise.
func (p *mqlAuditpolEntry) success() (bool, error) {
	flags, ok := p.flagsFromInclusionSetting()
	if !ok {
		p.Success = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return flags.Success(), nil
}

func (p *mqlAuditpolEntry) failure() (bool, error) {
	flags, ok := p.flagsFromInclusionSetting()
	if !ok {
		p.Failure = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return flags.Failure(), nil
}

func (p *mqlAuditpolEntry) flagsFromInclusionSetting() (windows.AuditFlags, bool) {
	if p.Inclusionsetting.IsNull() || p.Inclusionsetting.Error != nil {
		return 0, false
	}
	return windows.AuditFlagsFromInclusionSetting(p.Inclusionsetting.Data)
}
