// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// fetchAuditpolEntries runs `auditpol /get /category:* /r` and parses its CSV
// output. Shared by the windows.auditPolicy and (deprecated) auditpol
// resources so both replay the same command.
func fetchAuditpolEntries(runtime *plugin.Runtime) ([]windows.AuditpolEntry, error) {
	o, err := CreateResource(runtime, "powershell", map[string]*llx.RawData{
		"script": llx.StringData("[Console]::OutputEncoding = [Text.Encoding]::UTF8;auditpol /get /category:* /r"),
	})
	if err != nil {
		return nil, err
	}

	cmd := o.(*mqlPowershell)
	out := cmd.GetStdout()
	if out.Error != nil {
		return nil, fmt.Errorf("could not run auditpol: %w", out.Error)
	}
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, fmt.Errorf("could not run auditpol: %w", exit.Error)
	}
	if exit.Data != 0 {
		return nil, fmt.Errorf("could not run auditpol: %s", strings.TrimSpace(cmd.Stderr.Data))
	}

	return windows.ParseAuditpol(strings.NewReader(out.Data))
}

func (p *mqlWindowsAuditPolicy) list() ([]any, error) {
	entries, err := fetchAuditpolEntries(p.MqlRuntime)
	if err != nil {
		return nil, err
	}

	subcategories := make([]any, len(entries))
	for i := range entries {
		entry := entries[i]
		known, ok := windows.LookupAuditpolSubcategory(entry.SubcategoryGUID)
		name := known.Name
		if name == "" {
			name = entry.Subcategory
		}
		// a GUID the table does not carry has no known category; report null
		// rather than an empty string, which would read as a real category and
		// silently drop the subcategory out of every category filter
		category := llx.NilData
		if ok {
			category = llx.StringData(known.Category)
		}
		flags := auditpolInclusionAudits(entry.InclusionSetting)
		o, err := CreateResource(p.MqlRuntime, "windows.auditPolicy.subcategory", map[string]*llx.RawData{
			"name":             llx.StringData(name),
			"guid":             llx.StringData(entry.SubcategoryGUID),
			"category":         category,
			"localizedName":    llx.StringData(entry.Subcategory),
			"success":          llx.BoolData(flags.success),
			"failure":          llx.BoolData(flags.failure),
			"inclusionSetting": llx.StringData(entry.InclusionSetting),
			"exclusionSetting": llx.StringData(entry.ExclusionSetting),
		})
		if err != nil {
			return nil, err
		}
		subcategories[i] = o.(*mqlWindowsAuditPolicySubcategory)
	}

	return subcategories, nil
}

func (p *mqlWindowsAuditPolicySubcategory) id() (string, error) {
	// a subcategory missing from the system has no GUID; key it by the
	// requested name instead
	if p.Guid.Data != "" {
		return "windows.auditPolicy.subcategory/" + p.Guid.Data, nil
	}
	return "windows.auditPolicy.subcategory/" + p.Name.Data, nil
}

func initWindowsAuditPolicySubcategory(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// we only look up the subcategory if it is selected by name and nothing else
	raw, ok := args["name"]
	if !ok || len(args) != 1 {
		return args, nil, nil
	}
	name, ok := raw.Value.(string)
	if !ok {
		return nil, nil, errors.New("name must be a string")
	}

	o, err := CreateResource(runtime, "windows.auditPolicy", nil)
	if err != nil {
		return nil, nil, err
	}
	policy := o.(*mqlWindowsAuditPolicy)
	list := policy.GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}

	// the key may be the English name, the localized name the system reports,
	// or a GUID with or without braces
	want := strings.ToLower(strings.TrimSpace(name))
	want = strings.TrimPrefix(want, "{")
	want = strings.TrimSuffix(want, "}")
	for i := range list.Data {
		sub := list.Data[i].(*mqlWindowsAuditPolicySubcategory)
		if strings.ToLower(sub.Name.Data) == want ||
			strings.ToLower(sub.Guid.Data) == want ||
			strings.ToLower(sub.LocalizedName.Data) == want {
			return nil, sub, nil
		}
	}

	// The subcategory is not present on the system: nothing about it is
	// audited, so success and failure are explicitly false. (Null would make
	// `subcategory(...) { success && failure }` pass, since null && null is
	// true in MQL.) The fields auditpol would have reported stay null.
	res := &mqlWindowsAuditPolicySubcategory{}
	res.MqlRuntime = runtime
	res.Name = plugin.TValue[string]{Data: name, State: plugin.StateIsSet}
	res.Success = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Failure = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Guid.State = plugin.StateIsSet | plugin.StateIsNull
	res.Category.State = plugin.StateIsSet | plugin.StateIsNull
	res.LocalizedName.State = plugin.StateIsSet | plugin.StateIsNull
	res.InclusionSetting.State = plugin.StateIsSet | plugin.StateIsNull
	res.ExclusionSetting.State = plugin.StateIsSet | plugin.StateIsNull
	res.__id, _ = res.id()
	return nil, res, nil
}
