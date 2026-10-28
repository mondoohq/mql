// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// restrictionsPayloadType is the payload type of the Restrictions payload
// (https://github.com/apple/device-management, mdm/profiles/com.apple.applicationaccess.yaml).
const restrictionsPayloadType = "com.apple.applicationaccess"

// Apple Intelligence keys of the Restrictions payload that macOS supports
// (macOS 15.0 to 15.4, deprecated in 26.4). Each defaults to true.
const (
	restrictionAllowWritingTools                           = "allowWritingTools"
	restrictionAllowGenmoji                                = "allowGenmoji"
	restrictionAllowImagePlayground                        = "allowImagePlayground"
	restrictionAllowExternalIntelligenceIntegrations       = "allowExternalIntelligenceIntegrations"
	restrictionAllowExternalIntelligenceIntegrationsSignIn = "allowExternalIntelligenceIntegrationsSignIn"
	restrictionAllowMailSummary                            = "allowMailSummary"
	restrictionAllowMailSmartReplies                       = "allowMailSmartReplies"
	restrictionAllowNotesTranscription                     = "allowNotesTranscription"
	restrictionAllowNotesTranscriptionSummary              = "allowNotesTranscriptionSummary"
	restrictionAllowSafariSummary                          = "allowSafariSummary"
	restrictionAllowAppleIntelligenceReport                = "allowAppleIntelligenceReport"
)

var appleIntelligenceRestrictionKeys = []string{
	restrictionAllowWritingTools,
	restrictionAllowGenmoji,
	restrictionAllowImagePlayground,
	restrictionAllowExternalIntelligenceIntegrations,
	restrictionAllowExternalIntelligenceIntegrationsSignIn,
	restrictionAllowMailSummary,
	restrictionAllowMailSmartReplies,
	restrictionAllowNotesTranscription,
	restrictionAllowNotesTranscriptionSummary,
	restrictionAllowSafariSummary,
	restrictionAllowAppleIntelligenceReport,
}

type mqlMacosAppleIntelligenceInternal struct {
	lock      sync.Mutex
	populated bool
	err       error
}

func (m *mqlMacosAppleIntelligence) id() (string, error) {
	return "macos.appleIntelligence", nil
}

// restrictionBool reads one boolean restriction from a payload's content. The
// profiles tool reports payload booleans as plist booleans, but string
// spellings are accepted as for ProfileRemovalDisallowed. Any other type, or an
// absent key, is not a setting.
func restrictionBool(content map[string]any, key string) (bool, bool) {
	switch v := content[key].(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// combineRestrictions merges the Apple Intelligence keys of several
// Restrictions payloads. The most restrictive value wins: a key is false when
// any payload sets it false, true when payloads set it and none sets it false,
// and absent from the result when no payload sets it.
func combineRestrictions(contents []map[string]any) map[string]bool {
	res := map[string]bool{}
	for _, content := range contents {
		for _, key := range appleIntelligenceRestrictionKeys {
			v, ok := restrictionBool(content, key)
			if !ok {
				continue
			}
			if prev, seen := res[key]; seen && !prev {
				continue
			}
			res[key] = v
		}
	}
	return res
}

// setsAppleIntelligenceRestriction reports whether a Restrictions payload's
// content sets any of the Apple Intelligence keys.
func setsAppleIntelligenceRestriction(content map[string]any) bool {
	for _, key := range appleIntelligenceRestrictionKeys {
		if _, ok := restrictionBool(content, key); ok {
			return true
		}
	}
	return false
}

func restrictionField(values map[string]bool, key string) plugin.TValue[bool] {
	v, ok := values[key]
	if !ok {
		return plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[bool]{Data: v, State: plugin.StateIsSet}
}

// populate collects the Restrictions payloads of the system-scope profiles
// and sets every field.
func (m *mqlMacosAppleIntelligence) populate() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.populated {
		return m.err
	}
	m.populated = true

	contents, profiles, err := m.restrictionPayloads()
	if err != nil {
		m.err = err
		return err
	}
	values := combineRestrictions(contents)

	m.WritingToolsAllowed = restrictionField(values, restrictionAllowWritingTools)
	m.GenmojiAllowed = restrictionField(values, restrictionAllowGenmoji)
	m.ImagePlaygroundAllowed = restrictionField(values, restrictionAllowImagePlayground)
	m.ExternalIntelligenceIntegrationsAllowed = restrictionField(values, restrictionAllowExternalIntelligenceIntegrations)
	m.ExternalIntelligenceSignInAllowed = restrictionField(values, restrictionAllowExternalIntelligenceIntegrationsSignIn)
	m.MailSummaryAllowed = restrictionField(values, restrictionAllowMailSummary)
	m.MailSmartRepliesAllowed = restrictionField(values, restrictionAllowMailSmartReplies)
	m.NotesTranscriptionAllowed = restrictionField(values, restrictionAllowNotesTranscription)
	m.NotesTranscriptionSummaryAllowed = restrictionField(values, restrictionAllowNotesTranscriptionSummary)
	m.SafariSummaryAllowed = restrictionField(values, restrictionAllowSafariSummary)
	m.ReportAllowed = restrictionField(values, restrictionAllowAppleIntelligenceReport)
	m.Profiles = plugin.TValue[[]any]{Data: profiles, State: plugin.StateIsSet}
	return nil
}

// restrictionPayloads returns the content of every Restrictions payload in a
// system-scope profile, and the profiles among them that set an Apple
// Intelligence key.
func (m *mqlMacosAppleIntelligence) restrictionPayloads() ([]map[string]any, []any, error) {
	res, err := CreateResource(m.MqlRuntime, "macos.profiles", nil)
	if err != nil {
		return nil, nil, err
	}
	list := res.(*mqlMacosProfiles).GetList()
	if list.Error != nil {
		return nil, nil, list.Error
	}

	contents := []map[string]any{}
	profiles := []any{}
	for _, raw := range list.Data {
		profile, ok := raw.(*mqlMacosProfile)
		if !ok || profile.Scope.Data != "system" {
			continue
		}
		setsKey := false
		for _, p := range profile.Payloads.Data {
			payload, ok := p.(*mqlMacosProfilePayload)
			if !ok || payload.Type.Data != restrictionsPayloadType {
				continue
			}
			content, ok := payload.Content.Data.(map[string]any)
			if !ok {
				continue
			}
			contents = append(contents, content)
			if setsAppleIntelligenceRestriction(content) {
				setsKey = true
			}
		}
		if setsKey {
			profiles = append(profiles, profile)
		}
	}
	return contents, profiles, nil
}

func (m *mqlMacosAppleIntelligence) writingToolsAllowed() (bool, error) { return false, m.populate() }
func (m *mqlMacosAppleIntelligence) genmojiAllowed() (bool, error)      { return false, m.populate() }
func (m *mqlMacosAppleIntelligence) imagePlaygroundAllowed() (bool, error) {
	return false, m.populate()
}

func (m *mqlMacosAppleIntelligence) externalIntelligenceIntegrationsAllowed() (bool, error) {
	return false, m.populate()
}

func (m *mqlMacosAppleIntelligence) externalIntelligenceSignInAllowed() (bool, error) {
	return false, m.populate()
}
func (m *mqlMacosAppleIntelligence) mailSummaryAllowed() (bool, error) { return false, m.populate() }
func (m *mqlMacosAppleIntelligence) mailSmartRepliesAllowed() (bool, error) {
	return false, m.populate()
}

func (m *mqlMacosAppleIntelligence) notesTranscriptionAllowed() (bool, error) {
	return false, m.populate()
}

func (m *mqlMacosAppleIntelligence) notesTranscriptionSummaryAllowed() (bool, error) {
	return false, m.populate()
}
func (m *mqlMacosAppleIntelligence) safariSummaryAllowed() (bool, error) { return false, m.populate() }
func (m *mqlMacosAppleIntelligence) reportAllowed() (bool, error)        { return false, m.populate() }
func (m *mqlMacosAppleIntelligence) profiles() ([]any, error)            { return nil, m.populate() }
