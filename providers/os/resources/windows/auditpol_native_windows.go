// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32Audit = windows.NewLazySystemDLL("advapi32.dll")

	procAuditEnumerateSubCategories = modadvapi32Audit.NewProc("AuditEnumerateSubCategories")
	procAuditQuerySystemPolicy      = modadvapi32Audit.NewProc("AuditQuerySystemPolicy")
	procAuditLookupSubCategoryNameW = modadvapi32Audit.NewProc("AuditLookupSubCategoryNameW")
	procAuditFree                   = modadvapi32Audit.NewProc("AuditFree")
)

// auditPolicyInformation is AUDIT_POLICY_INFORMATION (ntsecapi.h).
type auditPolicyInformation struct {
	AuditSubCategoryGuid windows.GUID
	AuditingInformation  uint32
	AuditCategoryGuid    windows.GUID
}

// NativeAuditPolicy reads the system audit policy of every subcategory with
// AuditEnumerateSubCategories and AuditQuerySystemPolicy, the API auditpol
// itself uses. The entries carry what `auditpol /get /category:* /r` prints
// for them, with the setting from the POLICY_AUDIT_EVENT_* bits instead of
// the display text. The localized columns (the subcategory name, the policy
// target and the inclusion setting) are the ones auditpol prints in the
// display language of this process. For a display language whose auditpol
// texts aren't known, or a setting that isn't a documented one, it returns an
// error and the caller runs auditpol.
func NativeAuditPolicy() ([]AuditpolEntry, error) {
	texts, lang, ok := auditpolTextsForLanguage(preferredUILanguage())
	if !ok {
		return nil, fmt.Errorf("auditpol texts for display language %q are not known", lang)
	}

	machine, err := windows.ComputerName()
	if err != nil {
		return nil, fmt.Errorf("could not read the computer name: %w", err)
	}

	guids, err := auditEnumerateSubCategories()
	if err != nil {
		return nil, err
	}
	infos, err := auditQuerySystemPolicy(guids)
	if err != nil {
		return nil, err
	}

	res := make([]AuditpolEntry, 0, len(infos))
	for i := range infos {
		info := infos[i]
		guid := strings.ToUpper(strings.Trim(info.AuditSubCategoryGuid.String(), "{}"))
		name, err := auditLookupSubCategoryName(&info.AuditSubCategoryGuid)
		if err != nil {
			return nil, fmt.Errorf("could not look up the name of audit subcategory %s: %w", guid, err)
		}
		flags, ok := auditFlagsFromInformation(info.AuditingInformation)
		if !ok {
			return nil, fmt.Errorf("audit subcategory %s has the unknown setting %#x", guid, info.AuditingInformation)
		}
		res = append(res, AuditpolEntry{
			MachineName:      machine,
			PolicyTarget:     texts.PolicyTarget,
			Subcategory:      name,
			SubcategoryGUID:  guid,
			InclusionSetting: texts.setting(flags),
			Flags:            &flags,
		})
	}
	SortAuditpolEntries(res)
	return res, nil
}

// auditFlagsFromInformation reads AUDIT_POLICY_INFORMATION.AuditingInformation.
// A query reports POLICY_AUDIT_EVENT_SUCCESS and _FAILURE, or none of them
// (POLICY_AUDIT_EVENT_NONE may be set) for no auditing. Any other bit is not
// a documented query result, so the setting is unknown rather than guessed.
func auditFlagsFromInformation(v uint32) (AuditFlags, bool) {
	const policyAuditEventNone = 0x4
	if v&^uint32(AuditSuccess|AuditFailure|policyAuditEventNone) != 0 {
		return 0, false
	}
	return AuditFlags(v) & (AuditSuccess | AuditFailure), true
}

func auditEnumerateSubCategories() ([]windows.GUID, error) {
	if err := procAuditEnumerateSubCategories.Find(); err != nil {
		return nil, err
	}
	var arr *windows.GUID
	var count uint32
	// NULL category and bRetrieveAllSubCategories: every subcategory
	r, _, e := procAuditEnumerateSubCategories.Call(0, 1, uintptr(unsafe.Pointer(&arr)), uintptr(unsafe.Pointer(&count)))
	if byte(r) == 0 {
		return nil, fmt.Errorf("AuditEnumerateSubCategories: %w", e)
	}
	defer auditFree(unsafe.Pointer(arr))
	if count == 0 || arr == nil {
		return nil, errors.New("AuditEnumerateSubCategories returned no subcategories")
	}
	return append([]windows.GUID(nil), unsafe.Slice(arr, count)...), nil
}

func auditQuerySystemPolicy(guids []windows.GUID) ([]auditPolicyInformation, error) {
	if err := procAuditQuerySystemPolicy.Find(); err != nil {
		return nil, err
	}
	var arr *auditPolicyInformation
	r, _, e := procAuditQuerySystemPolicy.Call(uintptr(unsafe.Pointer(&guids[0])), uintptr(len(guids)), uintptr(unsafe.Pointer(&arr)))
	if byte(r) == 0 {
		return nil, fmt.Errorf("AuditQuerySystemPolicy: %w", e)
	}
	defer auditFree(unsafe.Pointer(arr))
	if arr == nil {
		return nil, errors.New("AuditQuerySystemPolicy returned no policy")
	}
	return append([]auditPolicyInformation(nil), unsafe.Slice(arr, len(guids))...), nil
}

func auditLookupSubCategoryName(guid *windows.GUID) (string, error) {
	if err := procAuditLookupSubCategoryNameW.Find(); err != nil {
		return "", err
	}
	var name *uint16
	r, _, e := procAuditLookupSubCategoryNameW.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&name)))
	if byte(r) == 0 {
		return "", e
	}
	defer auditFree(unsafe.Pointer(name))
	return windows.UTF16PtrToString(name), nil
}

func auditFree(p unsafe.Pointer) {
	if p != nil {
		procAuditFree.Call(uintptr(p)) //nolint:errcheck
	}
}

// preferredUILanguage is the display language MUI resolves this process's
// resources to, and so the one auditpol would print in, for example "de-DE".
func preferredUILanguage() string {
	langs, err := windows.GetThreadPreferredUILanguages(windows.MUI_LANGUAGE_NAME | windows.MUI_MERGE_USER_FALLBACK)
	if err != nil || len(langs) == 0 {
		return ""
	}
	return langs[0]
}
