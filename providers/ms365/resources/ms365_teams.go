// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	teamsScope = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
)

var teamsReport = `
$ErrorActionPreference = "Stop"
$graphToken= '%s'
$teamsToken = '%s'

Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force
Import-Module MicrosoftTeams
Connect-MicrosoftTeams -AccessTokens @("$graphToken", "$teamsToken")

# Fetch all the necessary policies
$CsTeamsClientConfiguration = (Get-CsTeamsClientConfiguration)
$CsTenantFederationConfiguration = (Get-CsTenantFederationConfiguration)
$CsTeamsMeetingPolicy = (Get-CsTeamsMeetingPolicy -Identity Global)
$CsTeamsMessagingPolicy = (Get-CsTeamsMessagingPolicy -Identity Global)
# Fetch the calling policy to get the cloud recording setting
$callingPolicy = (Get-CsTeamsCallingPolicy -Identity Global)
$CsTeamsMeetingPolicy | Add-Member -NotePropertyName "AllowCloudRecordingForCalls" -NotePropertyValue $callingPolicy.AllowCloudRecordingForCalls
# PreventTollBypass is a calling policy setting, not a meeting policy one
$CsTeamsMeetingPolicy | Add-Member -NotePropertyName "PreventTollBypass" -NotePropertyValue $callingPolicy.PreventTollBypass -Force

# AllowedDomains is either an AllowAllKnownDomains object (ToString
# "AllowAllKnownDomains") or an AllowList whose AllowedDomain entries carry a
# Domain property. BlockedDomains holds DomainPattern entries. Emit the raw
# tokens; the provider normalizes them.
function Get-FederationDomainTokens($value) {
  $tokens = New-Object System.Collections.Generic.List[string]
  foreach ($item in $value) {
    if ($null -eq $item) { continue }
    if ($null -ne $item.PSObject.Properties['AllowedDomain']) {
      foreach ($d in $item.AllowedDomain) {
        if ($null -ne $d.PSObject.Properties['Domain']) { $tokens.Add([string]$d.Domain) } else { $tokens.Add($d.ToString()) }
      }
    } elseif ($null -ne $item.PSObject.Properties['Domain']) {
      $tokens.Add([string]$item.Domain)
    } else {
      $tokens.Add($item.ToString())
    }
  }
  return ,$tokens
}
$CsTenantFederationConfiguration.AllowedDomains = Get-FederationDomainTokens $CsTenantFederationConfiguration.AllowedDomains
$CsTenantFederationConfiguration.BlockedDomains = Get-FederationDomainTokens $CsTenantFederationConfiguration.BlockedDomains

$msteams = New-Object PSObject
Add-Member -InputObject $msteams -MemberType NoteProperty -Name CsTeamsClientConfiguration -Value $CsTeamsClientConfiguration
Add-Member -InputObject $msteams -MemberType NoteProperty -Name CsTenantFederationConfiguration -Value $CsTenantFederationConfiguration
Add-Member -InputObject $msteams -MemberType NoteProperty -Name CsTeamsMeetingPolicy -Value $CsTeamsMeetingPolicy
Add-Member -InputObject $msteams -MemberType NoteProperty -Name CsTeamsMessagingPolicy -Value $CsTeamsMessagingPolicy

Disconnect-MicrosoftTeams -Confirm:$false
ConvertTo-Json -Depth 4 $msteams
`

type MsTeamsReport struct {
	CsTeamsClientConfiguration      any                              `json:"CsTeamsClientConfiguration"`
	CsTenantFederationConfiguration *CsTenantFederationConfiguration `json:"CsTenantFederationConfiguration"`
	CsTeamsMeetingPolicy            *CsTeamsMeetingPolicy            `json:"CsTeamsMeetingPolicy"`
	CsTeamsMessagingPolicy          *CsTeamsMessagingPolicy          `json:"CsTeamsMessagingPolicy"`
}

type CsTenantFederationConfiguration struct {
	Identity                                    string    `json:"Identity"`
	AllowFederatedUsers                         bool      `json:"AllowFederatedUsers"`
	AllowPublicUsers                            *bool     `json:"AllowPublicUsers"`
	AllowTeamsConsumer                          bool      `json:"AllowTeamsConsumer"`
	AllowTeamsConsumerInbound                   bool      `json:"AllowTeamsConsumerInbound"`
	TreatDiscoveredPartnersAsUnverified         bool      `json:"TreatDiscoveredPartnersAsUnverified"`
	SharedSipAddressSpace                       bool      `json:"SharedSipAddressSpace"`
	RestrictTeamsConsumerToExternalUserProfiles bool      `json:"RestrictTeamsConsumerToExternalUserProfiles"`
	ExternalAccessWithTrialTenants              string    `json:"ExternalAccessWithTrialTenants"`
	AllowedDomains                              []*string `json:"AllowedDomains"`
	BlockedDomains                              []*string `json:"BlockedDomains"`
}

// allowAllKnownDomainsToken is how Get-CsTenantFederationConfiguration renders
// AllowedDomains when the tenant federates with every domain not blocked.
const allowAllKnownDomainsToken = "AllowAllKnownDomains"

// normalizeFederationDomains turns the AllowedDomains or BlockedDomains tokens
// emitted by the Teams script into bare domain names. A token is a bare domain,
// a "Domain=contoso.com" pattern, a comma-joined list of such patterns (the
// AllowList string form), or AllowAllKnownDomains. Null and empty tokens are
// dropped. The bool reports whether AllowAllKnownDomains was present.
func normalizeFederationDomains(tokens []*string) ([]string, bool) {
	domains := []string{}
	allowAll := false
	for _, tok := range tokens {
		if tok == nil {
			continue
		}
		for _, part := range strings.Split(*tok, ",") {
			part = strings.TrimSpace(part)
			if strings.EqualFold(part, allowAllKnownDomainsToken) {
				allowAll = true
				continue
			}
			if k, v, ok := strings.Cut(part, "="); ok && strings.EqualFold(strings.TrimSpace(k), "Domain") {
				part = strings.TrimSpace(v)
			}
			if part == "" {
				continue
			}
			domains = append(domains, part)
		}
	}
	return domains, allowAll
}

type CsTeamsMeetingPolicy struct {
	AllowAnonymousUsersToJoinMeeting           bool   `json:"AllowAnonymousUsersToJoinMeeting"`
	AllowAnonymousUsersToStartMeeting          bool   `json:"AllowAnonymousUsersToStartMeeting"`
	AutoAdmittedUsers                          string `json:"AutoAdmittedUsers"`
	AllowPSTNUsersToBypassLobby                bool   `json:"AllowPSTNUsersToBypassLobby"`
	AllowExternalNonTrustedMeetingChat         bool   `json:"AllowExternalNonTrustedMeetingChat"`
	MeetingChatEnabledType                     string `json:"MeetingChatEnabledType"`
	DesignatedPresenterRoleMode                string `json:"DesignatedPresenterRoleMode"`
	AllowExternalParticipantGiveRequestControl bool   `json:"AllowExternalParticipantGiveRequestControl"`
	AllowSecurityEndUserReporting              *bool  `json:"AllowSecurityEndUserReporting"`
	AllowCloudRecordingForCalls                bool   `json:"AllowCloudRecordingForCalls"`
	AllowCloudRecording                        bool   `json:"AllowCloudRecording"`
	AllowRecordingStorageOutsideRegion         bool   `json:"AllowRecordingStorageOutsideRegion"`
	AllowTranscription                         bool   `json:"AllowTranscription"`
	AllowParticipantGiveRequestControl         bool   `json:"AllowParticipantGiveRequestControl"`
	PreventTollBypass                          *bool  `json:"PreventTollBypass"`
}

type CsTeamsClientConfig struct {
	AllowEmailIntoChannel            bool   `json:"AllowEmailIntoChannel"`
	AllowDropBox                     bool   `json:"AllowDropBox"`
	AllowBox                         bool   `json:"AllowBox"`
	AllowGoogleDrive                 bool   `json:"AllowGoogleDrive"`
	AllowShareFile                   bool   `json:"AllowShareFile"`
	AllowEgnyte                      bool   `json:"AllowEgnyte"`
	AllowOrganizationTab             bool   `json:"AllowOrganizationTab"`
	AllowSkypeBusinessInterop        bool   `json:"AllowSkypeBusinessInterop"`
	AllowGuestUser                   bool   `json:"AllowGuestUser"`
	ContentPin                       string `json:"ContentPin"`
	AllowResourceAccountSendMessage  bool   `json:"AllowResourceAccountSendMessage"`
	AllowScopedPeopleSearchandAccess bool   `json:"AllowScopedPeopleSearchandAccess"`
}

type CsTeamsMessagingPolicy struct {
	AllowSecurityEndUserReporting bool   `json:"AllowSecurityEndUserReporting"`
	AllowUserChat                 bool   `json:"AllowUserChat"`
	AllowUserDeleteMessage        bool   `json:"AllowUserDeleteMessage"`
	AllowOwnerDeleteMessage       bool   `json:"AllowOwnerDeleteMessage"`
	AllowUserDeleteChat           bool   `json:"AllowUserDeleteChat"`
	ReadReceiptsEnabledType       string `json:"ReadReceiptsEnabledType"`
}

type mqlMs365TeamsInternal struct {
	teamsReportLock sync.Mutex
	fetched         bool
	fetchErr        error
}

func (r *mqlMs365Teams) gatherTeamsReport() error {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)

	r.teamsReportLock.Lock()
	defer r.teamsReportLock.Unlock()

	// only fetch once
	if r.fetched {
		return r.fetchErr
	}

	errHandler := func(err error) error {
		r.fetchErr = err
		r.fetched = true
		return err
	}

	ctx := context.Background()
	token := conn.Token()
	teamsToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{teamsScope},
	})
	if err != nil {
		return errHandler(err)
	}
	graphToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{connection.DefaultMSGraphScope},
	})
	if err != nil {
		return errHandler(err)
	}

	fmtScript := fmt.Sprintf(teamsReport, graphToken.Token, teamsToken.Token)
	res, err := conn.CheckAndRunPowershellScript(fmtScript)
	if err != nil {
		return errHandler(err)
	}
	report := &MsTeamsReport{}
	if res.ExitStatus == 0 {
		data, err := io.ReadAll(res.Stdout)
		if err != nil {
			return errHandler(err)
		}
		str := string(data)
		// The Connect-MicrosoftTeams also displays a header for which there
		// are no params to hide it. To allow the JSON unmarshal to work
		// we strip away everything until the first '{' character.
		idx := strings.IndexByte(str, '{')
		if idx == -1 {
			return errHandler(errors.New("invalid JSON format"))
		}
		after := str[idx:]
		newData := []byte(after)

		logger.DebugDumpJSON("ms-teams-report", string(newData))
		err = json.Unmarshal(newData, report)
		if err != nil {
			return errHandler(err)
		}
	} else {
		data, err := io.ReadAll(res.Stderr)
		if err != nil {
			return errHandler(err)
		}

		str := string(data)
		if strings.Contains(strings.ToLower(str), "access denied") {
			return errHandler(errors.New("access denied, please ensure the credentials have the right permissions in Azure AD"))
		}

		logger.DebugDumpJSON("ms-teams-report", string(data))
		return errHandler(fmt.Errorf("failed to generate ms teams report (exit code %d): %s", res.ExitStatus, string(data)))
	}

	if report.CsTeamsClientConfiguration != nil {
		csTeamsConfiguration, csTeamsConfigurationErr := convert.JsonToDict(report.CsTeamsClientConfiguration)
		r.CsTeamsClientConfiguration = plugin.TValue[any]{Data: csTeamsConfiguration, State: plugin.StateIsSet, Error: csTeamsConfigurationErr}

		// decode the same payload into the typed client configuration resource
		clientConfig := &CsTeamsClientConfig{}
		raw, err := json.Marshal(report.CsTeamsClientConfiguration)
		if err == nil {
			err = json.Unmarshal(raw, clientConfig)
		}
		if err != nil {
			// a decode failure must surface as an error rather than reporting a
			// zero-value config (all false/"") as if it were the real client state
			r.ClientConfiguration = plugin.TValue[*mqlMs365TeamsClientConfig]{State: plugin.StateIsSet, Error: err}
		} else {
			mqlClientConfig, mqlClientConfigErr := CreateResource(r.MqlRuntime, "ms365.teams.clientConfig",
				map[string]*llx.RawData{
					"__id":                             llx.StringData("ms365.teams.clientConfig"),
					"allowEmailIntoChannel":            llx.BoolData(clientConfig.AllowEmailIntoChannel),
					"allowDropBox":                     llx.BoolData(clientConfig.AllowDropBox),
					"allowBox":                         llx.BoolData(clientConfig.AllowBox),
					"allowGoogleDrive":                 llx.BoolData(clientConfig.AllowGoogleDrive),
					"allowShareFile":                   llx.BoolData(clientConfig.AllowShareFile),
					"allowEgnyte":                      llx.BoolData(clientConfig.AllowEgnyte),
					"allowOrganizationTab":             llx.BoolData(clientConfig.AllowOrganizationTab),
					"allowSkypeBusinessInterop":        llx.BoolData(clientConfig.AllowSkypeBusinessInterop),
					"allowGuestUser":                   llx.BoolData(clientConfig.AllowGuestUser),
					"contentPin":                       llx.StringData(clientConfig.ContentPin),
					"allowResourceAccountSendMessage":  llx.BoolData(clientConfig.AllowResourceAccountSendMessage),
					"allowScopedPeopleSearchandAccess": llx.BoolData(clientConfig.AllowScopedPeopleSearchandAccess),
				})
			if mqlClientConfigErr != nil {
				r.ClientConfiguration = plugin.TValue[*mqlMs365TeamsClientConfig]{State: plugin.StateIsSet, Error: mqlClientConfigErr}
			} else {
				r.ClientConfiguration = plugin.TValue[*mqlMs365TeamsClientConfig]{Data: mqlClientConfig.(*mqlMs365TeamsClientConfig), State: plugin.StateIsSet}
			}
		}
	} else {
		r.CsTeamsClientConfiguration = plugin.TValue[any]{State: plugin.StateIsSet, Error: errors.New("CsTeamsClientConfiguration is nil")}
		r.ClientConfiguration = plugin.TValue[*mqlMs365TeamsClientConfig]{State: plugin.StateIsSet, Error: errors.New("CsTeamsClientConfiguration is nil")}
	}

	if report.CsTenantFederationConfiguration != nil {
		tenantConfig := report.CsTenantFederationConfiguration
		allowedDomains, allowAllKnownDomains := normalizeFederationDomains(tenantConfig.AllowedDomains)
		blockedDomains, _ := normalizeFederationDomains(tenantConfig.BlockedDomains)
		mqlTenantConfig, mqlTenantConfigErr := CreateResource(r.MqlRuntime, "ms365.teams.tenantFederationConfig",
			map[string]*llx.RawData{
				"identity":                                    llx.StringData(tenantConfig.Identity),
				"blockedDomains":                              llx.ArrayData(convert.SliceAnyToInterface(blockedDomains), types.String),
				"allowedDomains":                              llx.ArrayData(convert.SliceAnyToInterface(allowedDomains), types.String),
				"allowAllKnownDomains":                        llx.BoolData(allowAllKnownDomains),
				"allowFederatedUsers":                         llx.BoolData(tenantConfig.AllowFederatedUsers),
				"allowPublicUsers":                            llx.BoolDataPtr(tenantConfig.AllowPublicUsers),
				"allowTeamsConsumer":                          llx.BoolData(tenantConfig.AllowTeamsConsumer),
				"allowTeamsConsumerInbound":                   llx.BoolData(tenantConfig.AllowTeamsConsumerInbound),
				"treatDiscoveredPartnersAsUnverified":         llx.BoolData(tenantConfig.TreatDiscoveredPartnersAsUnverified),
				"sharedSipAddressSpace":                       llx.BoolData(tenantConfig.SharedSipAddressSpace),
				"restrictTeamsConsumerToExternalUserProfiles": llx.BoolData(tenantConfig.RestrictTeamsConsumerToExternalUserProfiles),
				"externalAccessWithTrialTenants":              llx.StringData(tenantConfig.ExternalAccessWithTrialTenants),
			})
		if mqlTenantConfigErr != nil {
			r.CsTenantFederationConfiguration = plugin.TValue[*mqlMs365TeamsTenantFederationConfig]{State: plugin.StateIsSet, Error: mqlTenantConfigErr}
		} else {
			r.CsTenantFederationConfiguration = plugin.TValue[*mqlMs365TeamsTenantFederationConfig]{Data: mqlTenantConfig.(*mqlMs365TeamsTenantFederationConfig), State: plugin.StateIsSet}
		}
	} else {
		r.CsTenantFederationConfiguration = plugin.TValue[*mqlMs365TeamsTenantFederationConfig]{State: plugin.StateIsSet, Error: errors.New("CsTenantFederationConfiguration is nil")}
	}

	if report.CsTeamsMeetingPolicy != nil {
		teamsPolicy := report.CsTeamsMeetingPolicy
		mqlTeamsPolicy, mqlTeamsPolicyErr := CreateResource(r.MqlRuntime, "ms365.teams.teamsMeetingPolicyConfig",
			map[string]*llx.RawData{
				"allowAnonymousUsersToJoinMeeting":           llx.BoolData(teamsPolicy.AllowAnonymousUsersToJoinMeeting),
				"allowAnonymousUsersToStartMeeting":          llx.BoolData(teamsPolicy.AllowAnonymousUsersToStartMeeting),
				"allowExternalNonTrustedMeetingChat":         llx.BoolData(teamsPolicy.AllowExternalNonTrustedMeetingChat),
				"autoAdmittedUsers":                          llx.StringData(teamsPolicy.AutoAdmittedUsers),
				"allowPSTNUsersToBypassLobby":                llx.BoolData(teamsPolicy.AllowPSTNUsersToBypassLobby),
				"meetingChatEnabledType":                     llx.StringData(teamsPolicy.MeetingChatEnabledType),
				"designatedPresenterRoleMode":                llx.StringData(teamsPolicy.DesignatedPresenterRoleMode),
				"allowExternalParticipantGiveRequestControl": llx.BoolData(teamsPolicy.AllowExternalParticipantGiveRequestControl),
				"allowSecurityEndUserReporting":              llx.BoolDataPtr(teamsPolicy.AllowSecurityEndUserReporting),
				"allowCloudRecordingForCalls":                llx.BoolData(teamsPolicy.AllowCloudRecordingForCalls),
				"allowCloudRecording":                        llx.BoolData(teamsPolicy.AllowCloudRecording),
				"allowRecordingStorageOutsideRegion":         llx.BoolData(teamsPolicy.AllowRecordingStorageOutsideRegion),
				"allowTranscription":                         llx.BoolData(teamsPolicy.AllowTranscription),
				"allowParticipantGiveRequestControl":         llx.BoolData(teamsPolicy.AllowParticipantGiveRequestControl),
				"preventTollBypass":                          llx.BoolDataPtr(teamsPolicy.PreventTollBypass),
			})
		if mqlTeamsPolicyErr != nil {
			r.CsTeamsMeetingPolicy = plugin.TValue[*mqlMs365TeamsTeamsMeetingPolicyConfig]{State: plugin.StateIsSet, Error: mqlTeamsPolicyErr}
		} else {
			r.CsTeamsMeetingPolicy = plugin.TValue[*mqlMs365TeamsTeamsMeetingPolicyConfig]{Data: mqlTeamsPolicy.(*mqlMs365TeamsTeamsMeetingPolicyConfig), State: plugin.StateIsSet}
		}
	} else {
		r.CsTeamsMeetingPolicy = plugin.TValue[*mqlMs365TeamsTeamsMeetingPolicyConfig]{State: plugin.StateIsSet, Error: errors.New("CsTeamsMeetingPolicy is nil")}
	}

	if report.CsTeamsMessagingPolicy != nil {
		teamsMessagePolicy := report.CsTeamsMessagingPolicy
		mqlTeamsMessagePolicy, mqlTeamsMessagePolicyErr := CreateResource(r.MqlRuntime, "ms365.teams.teamsMessagingPolicyConfig",
			map[string]*llx.RawData{
				"allowSecurityEndUserReporting": llx.BoolData(teamsMessagePolicy.AllowSecurityEndUserReporting),
				"allowUserChat":                 llx.BoolData(teamsMessagePolicy.AllowUserChat),
				"allowUserDeleteMessage":        llx.BoolData(teamsMessagePolicy.AllowUserDeleteMessage),
				"allowOwnerDeleteMessage":       llx.BoolData(teamsMessagePolicy.AllowOwnerDeleteMessage),
				"allowUserDeleteChat":           llx.BoolData(teamsMessagePolicy.AllowUserDeleteChat),
				"readReceiptsEnabledType":       llx.StringData(teamsMessagePolicy.ReadReceiptsEnabledType),
			})
		if mqlTeamsMessagePolicyErr != nil {
			r.CsTeamsMessagingPolicy = plugin.TValue[*mqlMs365TeamsTeamsMessagingPolicyConfig]{State: plugin.StateIsSet, Error: mqlTeamsMessagePolicyErr}
		} else {
			r.CsTeamsMessagingPolicy = plugin.TValue[*mqlMs365TeamsTeamsMessagingPolicyConfig]{Data: mqlTeamsMessagePolicy.(*mqlMs365TeamsTeamsMessagingPolicyConfig), State: plugin.StateIsSet}
		}
	} else {
		r.CsTeamsMessagingPolicy = plugin.TValue[*mqlMs365TeamsTeamsMessagingPolicyConfig]{State: plugin.StateIsSet, Error: errors.New("CsTeamsMessagingPolicy is nil")}
	}

	r.fetched = true
	return nil
}

func (r *mqlMs365Teams) csTeamsClientConfiguration() (any, error) {
	return nil, r.gatherTeamsReport()
}

func (r *mqlMs365Teams) clientConfiguration() (*mqlMs365TeamsClientConfig, error) {
	return nil, r.gatherTeamsReport()
}

func (r *mqlMs365Teams) csTenantFederationConfiguration() (*mqlMs365TeamsTenantFederationConfig, error) {
	return nil, r.gatherTeamsReport()
}

func (r *mqlMs365Teams) csTeamsMeetingPolicy() (*mqlMs365TeamsTeamsMeetingPolicyConfig, error) {
	return nil, r.gatherTeamsReport()
}

func (r *mqlMs365Teams) csTeamsMessagingPolicy() (*mqlMs365TeamsTeamsMessagingPolicyConfig, error) {
	return nil, r.gatherTeamsReport()
}
