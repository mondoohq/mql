// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// uacPath is the key that holds every User Account Control security option,
// plus LocalAccountTokenFilterPolicy, which governs UAC remote restrictions for
// local accounts.
const uacPath = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

func (r *mqlWindowsUac) id() (string, error) {
	return "windows.uac", nil
}

// readUacKey reads the Policies\System key and returns its values as a
// name->item map (lower-cased keys). A missing key yields an empty map rather
// than an error, so every field resolves to null (the Windows default applies).
// A genuine read failure is surfaced to the caller.
func (r *mqlWindowsUac) readUacKey() (map[string]registry.RegistryKeyItem, error) {
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(uacPath),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, nil
		}
		return nil, err
	}

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res, nil
}

// uacValues holds the UAC settings as nullable pointers: nil means the value is
// absent from the registry and the Windows default applies. On/off settings are
// bools (any non-zero DWORD is true); the two prompt behaviors are int64s and
// are passed through unmodified, including values Windows does not define.
type uacValues struct {
	EnableLua                     *bool
	ConsentPromptBehaviorAdmin    *int64
	ConsentPromptBehaviorUser     *int64
	FilterAdministratorToken      *bool
	EnableInstallerDetection      *bool
	EnableSecureUiaPaths          *bool
	EnableUiaDesktopToggle        *bool
	EnableVirtualization          *bool
	LocalAccountTokenFilterPolicy *bool
	PromptOnSecureDesktop         *bool
	ValidateAdminCodeSignatures   *bool
}

// computeUac extracts the UAC settings from the Policies\System registry
// items. Pure function for unit testing.
func computeUac(items map[string]registry.RegistryKeyItem) uacValues {
	return uacValues{
		EnableLua:                     regBoolPtr(items, "EnableLUA"),
		ConsentPromptBehaviorAdmin:    regIntPtr(items, "ConsentPromptBehaviorAdmin"),
		ConsentPromptBehaviorUser:     regIntPtr(items, "ConsentPromptBehaviorUser"),
		FilterAdministratorToken:      regBoolPtr(items, "FilterAdministratorToken"),
		EnableInstallerDetection:      regBoolPtr(items, "EnableInstallerDetection"),
		EnableSecureUiaPaths:          regBoolPtr(items, "EnableSecureUIAPaths"),
		EnableUiaDesktopToggle:        regBoolPtr(items, "EnableUIADesktopToggle"),
		EnableVirtualization:          regBoolPtr(items, "EnableVirtualization"),
		LocalAccountTokenFilterPolicy: regBoolPtr(items, "LocalAccountTokenFilterPolicy"),
		PromptOnSecureDesktop:         regBoolPtr(items, "PromptOnSecureDesktop"),
		ValidateAdminCodeSignatures:   regBoolPtr(items, "ValidateAdminCodeSignatures"),
	}
}

func (r *mqlWindowsUac) enableLua() (bool, error)                     { return false, r.populate() }
func (r *mqlWindowsUac) consentPromptBehaviorAdmin() (int64, error)   { return 0, r.populate() }
func (r *mqlWindowsUac) consentPromptBehaviorUser() (int64, error)    { return 0, r.populate() }
func (r *mqlWindowsUac) filterAdministratorToken() (bool, error)      { return false, r.populate() }
func (r *mqlWindowsUac) enableInstallerDetection() (bool, error)      { return false, r.populate() }
func (r *mqlWindowsUac) enableSecureUiaPaths() (bool, error)          { return false, r.populate() }
func (r *mqlWindowsUac) enableUiaDesktopToggle() (bool, error)        { return false, r.populate() }
func (r *mqlWindowsUac) enableVirtualization() (bool, error)          { return false, r.populate() }
func (r *mqlWindowsUac) localAccountTokenFilterPolicy() (bool, error) { return false, r.populate() }
func (r *mqlWindowsUac) promptOnSecureDesktop() (bool, error)         { return false, r.populate() }
func (r *mqlWindowsUac) validateAdminCodeSignatures() (bool, error)   { return false, r.populate() }

// populate reads the Policies\System key once and fills every field. Each
// accessor delegates here and the first call sets all fields, so the registry
// is read a single time however many fields a query touches.
func (r *mqlWindowsUac) populate() error {
	items, err := r.readUacKey()
	if err != nil {
		return err
	}
	v := computeUac(items)

	r.EnableLua = boolFieldPtr(v.EnableLua)
	r.ConsentPromptBehaviorAdmin = intFieldPtr(v.ConsentPromptBehaviorAdmin)
	r.ConsentPromptBehaviorUser = intFieldPtr(v.ConsentPromptBehaviorUser)
	r.FilterAdministratorToken = boolFieldPtr(v.FilterAdministratorToken)
	r.EnableInstallerDetection = boolFieldPtr(v.EnableInstallerDetection)
	r.EnableSecureUiaPaths = boolFieldPtr(v.EnableSecureUiaPaths)
	r.EnableUiaDesktopToggle = boolFieldPtr(v.EnableUiaDesktopToggle)
	r.EnableVirtualization = boolFieldPtr(v.EnableVirtualization)
	r.LocalAccountTokenFilterPolicy = boolFieldPtr(v.LocalAccountTokenFilterPolicy)
	r.PromptOnSecureDesktop = boolFieldPtr(v.PromptOnSecureDesktop)
	r.ValidateAdminCodeSignatures = boolFieldPtr(v.ValidateAdminCodeSignatures)
	return nil
}
