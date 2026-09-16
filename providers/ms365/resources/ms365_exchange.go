// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	outlookScope    = "https://outlook.office.com/.default"
	complianceScope = "https://ps.compliance.protection.outlook.com/.default"
)

var securityAndComplianceReport = `
$appId = '%s'
$organization = '%s'
$tenantId = '%s'
$complianceToken = '%s'

Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Import-Module ExchangeOnlineManagement
Connect-IPPSSession -AccessToken $complianceToken -AppID $appId -Organization $organization -ShowBanner:$false
$DlpCompliancePolicy = @(Get-DlpCompliancePolicy)
$DlpComplianceRule = @(Get-DlpComplianceRule)
# a cmdlet that fails non-terminating still yields @(), which serializes to []
# and would report "this tenant publishes no label policies" as fact; $null
# serializes to null and the field reads null instead
$LabelPolicy = $null
try { $LabelPolicy = @(Get-LabelPolicy -ErrorAction Stop) } catch { $LabelPolicy = $null }
$securityAndCompliance = @{ DlpCompliancePolicy = $DlpCompliancePolicy; DlpComplianceRule = $DlpComplianceRule; LabelPolicy = $LabelPolicy }

ConvertTo-Json -Depth 6 $securityAndCompliance
`

var exchangeReport = `
$appId = '%s'
$organization = '%s'
$tenantId = '%s'
$outlookToken= '%s'

Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AccessToken $outlookToken -AppID $appId -Organization $organization -ShowBanner:$false -ShowProgress:$false
$MailboxAuditBypassAssociation = (Get-MailboxAuditBypassAssociation -ResultSize Unlimited)

$MalwareFilterPolicy = (Get-MalwareFilterPolicy)
$HostedOutboundSpamFilterPolicy = (Get-HostedOutboundSpamFilterPolicy)
$HostedContentFilterPolicy = (Get-HostedContentFilterPolicy)
$TransportRule = (Get-TransportRule)
$RemoteDomain = (Get-RemoteDomain Default)
$SafeLinksPolicy = (Get-SafeLinksPolicy)
$SafeAttachmentPolicy = (Get-SafeAttachmentPolicy)
$OrganizationConfig = (Get-OrganizationConfig)
$AuthenticationPolicy = (Get-AuthenticationPolicy)
$AntiPhishPolicy = (Get-AntiPhishPolicy)
$DkimSigningConfig = (Get-DkimSigningConfig)
$OwaMailboxPolicy = (Get-OwaMailboxPolicy)
$AdminAuditLogConfig = (Get-AdminAuditLogConfig)
$PhishFilterPolicy = (Get-PhishFilterPolicy)
$QuarantinePolicy = (Get-QuarantinePolicy)
$JournalRule = (Get-JournalRule)
$MailboxPlan = (Get-MailboxPlan)
$RetentionPolicy = (Get-RetentionPolicy)
$Mailbox = (Get-Mailbox -ResultSize Unlimited | Select-Object Identity, DisplayName, PrimarySmtpAddress, RecipientTypeDetails, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner, AuditLogAgeLimit)
$AtpPolicyForO365 = (Get-AtpPolicyForO365)
$SharingPolicy = (Get-SharingPolicy)
$RoleAssignmentPolicy = (Get-RoleAssignmentPolicy)
$ExternalInOutlook = (Get-ExternalInOutlook)
$ExoMailbox = (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox | Select-Object Identity, ExternalDirectoryObjectId)
$TeamsProtectionPolicy = (Get-TeamsProtectionPolicy)
$ReportSubmissionPolicy = (Get-ReportSubmissionPolicy)
$TransportConfig = (Get-TransportConfig)
# see the note on $LabelPolicy: these three answer questions that turn on the
# result being empty, so a failed cmdlet has to read null rather than empty
$EmailTenantSettings = $null
try { $EmailTenantSettings = (Get-EmailTenantSettings -ErrorAction Stop) } catch { $EmailTenantSettings = $null }
$EOPProtectionPolicyRule = $null
try { $EOPProtectionPolicyRule = @(Get-EOPProtectionPolicyRule -ErrorAction Stop) } catch { $EOPProtectionPolicyRule = $null }
$ATPProtectionPolicyRule = $null
try { $ATPProtectionPolicyRule = @(Get-ATPProtectionPolicyRule -ErrorAction Stop) } catch { $ATPProtectionPolicyRule = $null }

$exchangeOnline = New-Object PSObject
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name MalwareFilterPolicy -Value @($MalwareFilterPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name HostedOutboundSpamFilterPolicy -Value @($HostedOutboundSpamFilterPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name HostedContentFilterPolicy -Value @($HostedContentFilterPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name TransportRule -Value @($TransportRule)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name RemoteDomain -Value  @($RemoteDomain)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name SafeLinksPolicy -Value @($SafeLinksPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name SafeAttachmentPolicy -Value @($SafeAttachmentPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name OrganizationConfig -Value $OrganizationConfig
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name AuthenticationPolicy -Value @($AuthenticationPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name AntiPhishPolicy -Value @($AntiPhishPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name DkimSigningConfig -Value @($DkimSigningConfig)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name OwaMailboxPolicy -Value @($OwaMailboxPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name AdminAuditLogConfig -Value $AdminAuditLogConfig
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name PhishFilterPolicy -Value @($PhishFilterPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name QuarantinePolicy -Value @($QuarantinePolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name JournalRule -Value @($JournalRule)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name MailboxPlan -Value @($MailboxPlan)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name RetentionPolicy -Value @($RetentionPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name Mailbox -Value @($Mailbox)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name AtpPolicyForO365 -Value @($AtpPolicyForO365)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name SharingPolicy -Value @($SharingPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name RoleAssignmentPolicy -Value @($RoleAssignmentPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name ExternalInOutlook -Value @($ExternalInOutlook)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name ExoMailbox -Value @($ExoMailbox)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name TeamsProtectionPolicy -Value @($TeamsProtectionPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name ReportSubmissionPolicy -Value @($ReportSubmissionPolicy)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name TransportConfig -Value $TransportConfig
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name MailboxAuditBypassAssociation -Value @($MailboxAuditBypassAssociation)
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name EmailTenantSettings -Value $EmailTenantSettings
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name EOPProtectionPolicyRule -Value $EOPProtectionPolicyRule
Add-Member -InputObject $exchangeOnline -MemberType NoteProperty -Name ATPProtectionPolicyRule -Value $ATPProtectionPolicyRule

Disconnect-ExchangeOnline -Confirm:$false

ConvertTo-Json -Depth 4 $exchangeOnline
`

type ExchangeOnlineReport struct {
	MalwareFilterPolicy            []any             `json:"MalwareFilterPolicy"`
	HostedOutboundSpamFilterPolicy []any             `json:"HostedOutboundSpamFilterPolicy"`
	HostedContentFilterPolicy      []any             `json:"HostedContentFilterPolicy"`
	TransportRule                  []any             `json:"TransportRule"`
	RemoteDomain                   []any             `json:"RemoteDomain"`
	SafeLinksPolicy                []any             `json:"SafeLinksPolicy"`
	SafeAttachmentPolicy           []any             `json:"SafeAttachmentPolicy"`
	OrganizationConfig             any               `json:"OrganizationConfig"`
	AuthenticationPolicy           any               `json:"AuthenticationPolicy"`
	AntiPhishPolicy                []any             `json:"AntiPhishPolicy"`
	DkimSigningConfig              any               `json:"DkimSigningConfig"`
	OwaMailboxPolicy               any               `json:"OwaMailboxPolicy"`
	AdminAuditLogConfig            any               `json:"AdminAuditLogConfig"`
	PhishFilterPolicy              []any             `json:"PhishFilterPolicy"`
	QuarantinePolicy               []any             `json:"QuarantinePolicy"`
	JournalRules                   []JournalRule     `json:"JournalRule"`
	MailboxPlans                   []MailboxPlan     `json:"MailboxPlan"`
	RetentionPolicies              []RetentionPolicy `json:"RetentionPolicy"`
	AtpPolicyForO365               []any             `json:"AtpPolicyForO365"`
	SharingPolicy                  []any             `json:"SharingPolicy"`
	RoleAssignmentPolicy           []any             `json:"RoleAssignmentPolicy"`
	ExternalInOutlook              []*ExternalSender `json:"ExternalInOutlook"`
	// note: this only contains shared mailboxes
	ExoMailbox             []*ExoMailbox             `json:"ExoMailbox"`
	TeamsProtectionPolicy  []*TeamsProtectionPolicy  `json:"TeamsProtectionPolicy"`
	ReportSubmissionPolicy []*ReportSubmissionPolicy `json:"ReportSubmissionPolicy"`
	TransportConfig        *TransportConfig          `json:"TransportConfig"`
	Mailbox                []MailboxWithAudit        `json:"Mailbox"`

	MailboxAuditBypassAssociation []MailboxAuditBypassAssociation `json:"MailboxAuditBypassAssociation"`

	EmailTenantSettings     any   `json:"EmailTenantSettings"`
	EOPProtectionPolicyRule []any `json:"EOPProtectionPolicyRule"`
	ATPProtectionPolicyRule []any `json:"ATPProtectionPolicyRule"`
}

type MailboxAuditBypassAssociation struct {
	Name               string `json:"Name"`
	AuditBypassEnabled bool   `json:"AuditBypassEnabled"`
}

type SecurityAndComplianceReport struct {
	DlpCompliancePolicy []any `json:"DlpCompliancePolicy"`
	DlpComplianceRule   []any `json:"DlpComplianceRule"`
	LabelPolicy         []any `json:"LabelPolicy"`
}

type MailboxWithAudit struct {
	Identity             string   `json:"Identity"`
	DisplayName          string   `json:"DisplayName"`
	PrimarySmtpAddress   string   `json:"PrimarySmtpAddress"`
	RecipientTypeDetails string   `json:"RecipientTypeDetails"`
	AuditEnabled         bool     `json:"AuditEnabled"`
	AuditAdmin           []string `json:"AuditAdmin"`
	AuditDelegate        []string `json:"AuditDelegate"`
	AuditOwner           []string `json:"AuditOwner"`
	AuditLogAgeLimit     string   `json:"AuditLogAgeLimit"`
}

type ExternalSender struct {
	Identity  string   `json:"Identity"`
	Enabled   bool     `json:"Enabled"`
	AllowList []string `json:"AllowList"`
}

type ExoMailbox struct {
	ExternalDirectoryObjectId string   `json:"ExternalDirectoryObjectId"`
	UserPrincipalName         string   `json:"UserPrincipalName"`
	Alias                     string   `json:"Alias"`
	DisplayName               string   `json:"DisplayName"`
	EmailAddresses            []string `json:"EmailAddresses"`
	PrimarySmtpAddress        string   `json:"PrimarySmtpAddress"`
	RecipientType             string   `json:"RecipientType"`
	RecipientTypeDetails      string   `json:"RecipientTypeDetails"`
	Identity                  string   `json:"Identity"`
	Id                        string   `json:"Id"`
	ExchangeVersion           string   `json:"ExchangeVersion"`
	Name                      string   `json:"Name"`
	DistinguishedName         string   `json:"DistinguishedName"`
	OrganizationId            string   `json:"OrganizationId"`
	Guid                      string   `json:"Guid"`
}

type TeamsProtectionPolicy struct {
	Identity   string `json:"Identity"`
	ZapEnabled bool   `json:"ZapEnabled"`
	IsValid    bool   `json:"IsValid"`
}

type ReportSubmissionPolicy struct {
	Identity                                    string   `json:"Identity"`
	ReportJunkToCustomizedAddress               bool     `json:"ReportJunkToCustomizedAddress"`
	ReportNotJunkToCustomizedAddress            bool     `json:"ReportNotJunkToCustomizedAddress"`
	ReportPhishToCustomizedAddress              bool     `json:"ReportPhishToCustomizedAddress"`
	ReportJunkAddresses                         []string `json:"ReportJunkAddresses"`
	ReportNotJunkAddresses                      []string `json:"ReportNotJunkAddresses"`
	ReportPhishAddresses                        []string `json:"ReportPhishAddresses"`
	ReportChatMessageEnabled                    bool     `json:"ReportChatMessageEnabled"`
	ReportChatMessageToCustomizedAddressEnabled bool     `json:"ReportChatMessageToCustomizedAddressEnabled"`
	EnableReportToMicrosoft                     bool     `json:"EnableReportToMicrosoft"`
	PreSubmitMessageEnabled                     bool     `json:"PreSubmitMessageEnabled"`
	PostSubmitMessageEnabled                    bool     `json:"PostSubmitMessageEnabled"`
	EnableThirdPartyAddress                     bool     `json:"EnableThirdPartyAddress"`
	PhishingReviewResultMessage                 string   `json:"PhishingReviewResultMessage"`
	NotificationFooterMessage                   string   `json:"NotificationFooterMessage"`
	JunkReviewResultMessage                     string   `json:"JunkReviewResultMessage"`
	NotJunkReviewResultMessage                  string   `json:"NotJunkReviewResultMessage"`
	NotificationSenderAddress                   []string `json:"NotificationSenderAddress"`
	EnableCustomNotificationSender              bool     `json:"EnableCustomNotificationSender"`
	EnableOrganizationBranding                  bool     `json:"EnableOrganizationBranding"`
	DisableQuarantineReportingOption            bool     `json:"DisableQuarantineReportingOption"`
}

type JournalRule struct {
	Name                string `json:"Name"`
	JournalEmailAddress string `json:"JournalEmailAddress"`
	Scope               string `json:"Scope"`
	Enabled             bool   `json:"Enabled"`
}

type MailboxPlan struct {
	Name              string `json:"Name"`
	Alias             string `json:"Alias"`
	ProhibitSendQuota string `json:"ProhibitSendQuota"`
	MaxSendSize       string `json:"MaxSendSize"`
	MaxReceiveSize    string `json:"MaxReceiveSize"`
}

type RetentionPolicy struct {
	Name                    string   `json:"Name"`
	RetentionPolicyTagLinks []string `json:"RetentionPolicyTagLinks"`
	RetentionId             string   `json:"RetentionId"`
}

type TransportConfig struct {
	SmtpClientAuthenticationDisabled bool `json:"SmtpClientAuthenticationDisabled"`
}

type mqlMs365ExchangeonlineInternal struct {
	exchangeReportLock sync.Mutex
	fetched            bool
	fetchErr           error
	org                string
}

func (r *mqlMs365Exchangeonline) getOrg() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)
	microsoft, err := CreateResource(r.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return "", err
	}
	mqlMicrosoft := microsoft.(*mqlMicrosoft)
	// we prefer the explicitly passed in org, if there is one
	org := conn.Organization()
	if org == "" {
		tenantDomainName := mqlMicrosoft.GetTenantDomainName()
		if tenantDomainName.Error != nil {
			// note: we don't want to err here. maybe the app registration has no perms to get the organization
			// in that case we try and get the report by using the explicitly passed in exchange organization
			log.Debug().Err(tenantDomainName.Error).Msg("unable to get tenant domain name")
		} else {
			org = tenantDomainName.Data
		}
	}
	return org, nil
}

// exchangeEntryID builds the cache key for one row of an Exchange cmdlet
// result. Exchange objects carry an Identity, which is what every other policy
// resource in this package keys on, but a cmdlet shape that omits it must still
// produce a distinct key per row: CreateResource is first-wins on
// resourceName+"\x00"+__id, so rows sharing a key collapse into the first one
// and the rest of the collection is silently discarded. Fall back to the row's
// position so that can never happen. Both forms are synthetic and stay hidden --
// none of these resources declares a public `id` field.
func exchangeEntryID(prefix, identity string, index int) string {
	if identity != "" {
		return prefix + "-" + identity
	}
	return fmt.Sprintf("%s-#%d", prefix, index)
}

// Related to TeamsProtectionPolicy as a separate function
func convertTeamsProtectionPolicy(r *mqlMs365Exchangeonline, data []*TeamsProtectionPolicy) ([]any, error) {
	var result []any
	for i, t := range data {
		if t == nil {
			continue
		}
		policy, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.teamsProtectionPolicy",
			map[string]*llx.RawData{
				"__id":       llx.StringData(exchangeEntryID("teamsProtectionPolicy", t.Identity, i)),
				"zapEnabled": llx.BoolData(t.ZapEnabled),
				"isValid":    llx.BoolData(t.IsValid),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, policy)
	}
	return result, nil
}

// Related to ReportSubmissionPolicy as a separate function
func convertReportSubmissionPolicy(r *mqlMs365Exchangeonline, data []*ReportSubmissionPolicy) ([]any, error) {
	var result []any
	for i, t := range data {
		if t == nil {
			continue
		}
		policy, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.reportSubmissionPolicy",
			map[string]*llx.RawData{
				"__id":                                        llx.StringData(exchangeEntryID("reportSubmissionPolicy", t.Identity, i)),
				"reportJunkToCustomizedAddress":               llx.BoolData(t.ReportJunkToCustomizedAddress),
				"reportNotJunkToCustomizedAddress":            llx.BoolData(t.ReportNotJunkToCustomizedAddress),
				"reportPhishToCustomizedAddress":              llx.BoolData(t.ReportPhishToCustomizedAddress),
				"reportJunkAddresses":                         llx.ArrayData(llx.TArr2Raw(t.ReportJunkAddresses), types.Any),
				"reportNotJunkAddresses":                      llx.ArrayData(llx.TArr2Raw(t.ReportNotJunkAddresses), types.Any),
				"reportPhishAddresses":                        llx.ArrayData(llx.TArr2Raw(t.ReportPhishAddresses), types.Any),
				"reportChatMessageEnabled":                    llx.BoolData(t.ReportChatMessageEnabled),
				"reportChatMessageToCustomizedAddressEnabled": llx.BoolData(t.ReportChatMessageToCustomizedAddressEnabled),
				"enableReportToMicrosoft":                     llx.BoolData(t.EnableReportToMicrosoft),
				"preSubmitMessageEnabled":                     llx.BoolData(t.PreSubmitMessageEnabled),
				"postSubmitMessageEnabled":                    llx.BoolData(t.PostSubmitMessageEnabled),
				"enableThirdPartyAddress":                     llx.BoolData(t.EnableThirdPartyAddress),
				"phishingReviewResultMessage":                 llx.StringData(t.PhishingReviewResultMessage),
				"notificationFooterMessage":                   llx.StringData(t.NotificationFooterMessage),
				"junkReviewResultMessage":                     llx.StringData(t.JunkReviewResultMessage),
				"notJunkReviewResultMessage":                  llx.StringData(t.NotJunkReviewResultMessage),
				"notificationSenderAddresses":                 llx.ArrayData(llx.TArr2Raw(t.NotificationSenderAddress), types.String),
				"enableCustomNotificationSender":              llx.BoolData(t.EnableCustomNotificationSender),
				"enableOrganizationBranding":                  llx.BoolData(t.EnableOrganizationBranding),
				"disableQuarantineReportingOption":            llx.BoolData(t.DisableQuarantineReportingOption),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, policy)
	}
	return result, nil
}

func convertJournalRules(r *mqlMs365Exchangeonline, data []JournalRule) ([]any, error) {
	var result []any
	for _, jr := range data {
		mql, err := CreateResource(r.MqlRuntime, ResourceMs365ExchangeonlineJournalRule,
			map[string]*llx.RawData{
				"__id":                llx.StringData("journalRule-" + jr.Name),
				"name":                llx.StringData(jr.Name),
				"journalEmailAddress": llx.StringData(jr.JournalEmailAddress),
				"scope":               llx.StringData(jr.Scope),
				"enabled":             llx.BoolData(jr.Enabled),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

func convertMailboxPlans(r *mqlMs365Exchangeonline, data []MailboxPlan) ([]any, error) {
	var result []any
	for _, mp := range data {
		mql, err := CreateResource(r.MqlRuntime, ResourceMs365ExchangeonlineMailboxPlan,
			map[string]*llx.RawData{
				"__id":              llx.StringData("mailboxPlan-" + mp.Name),
				"name":              llx.StringData(mp.Name),
				"alias":             llx.StringData(mp.Alias),
				"prohibitSendQuota": llx.StringData(mp.ProhibitSendQuota),
				"maxSendSize":       llx.StringData(mp.MaxSendSize),
				"maxReceiveSize":    llx.StringData(mp.MaxReceiveSize),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

func convertRetentionPolicies(r *mqlMs365Exchangeonline, data []RetentionPolicy) ([]any, error) {
	var result []any
	for _, rp := range data {
		mql, err := CreateResource(r.MqlRuntime, ResourceMs365ExchangeonlineRetentionPolicy,
			map[string]*llx.RawData{
				"__id":                    llx.StringData("retentionPolicy-" + rp.Name),
				"name":                    llx.StringData(rp.Name),
				"retentionPolicyTagLinks": llx.ArrayData(llx.TArr2Raw(rp.RetentionPolicyTagLinks), types.String),
				"retentionId":             llx.StringData(rp.RetentionId),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// fetchExchangeReport prefers the Exchange admin endpoint and falls back to the
// PowerShell module when that endpoint cannot serve the tenant, so a scan that
// works today keeps working. Both paths produce the same report: the module is
// a client for the same endpoint, so the cmdlet objects and their property
// names are identical either way.
func (r *mqlMs365Exchangeonline) fetchExchangeReport(ctx context.Context, conn *connection.Ms365Connection, organization string, token string) (*ExchangeOnlineReport, error) {
	client := newExchangeRestClient(exchangeAdminApiHost, conn.TenantId(), organization, token)

	report, failures, err := fetchExchangeReportViaRest(ctx, client)
	if err == nil {
		// a cmdlet that failed leaves its field null, which is what the
		// PowerShell report did with a cmdlet that errored mid-script
		for name, failure := range failures {
			log.Warn().Err(failure).Str("section", name).
				Msg("unable to collect exchange online section, the matching field will be null")
		}
		return report, nil
	}

	// PowerShell is a client for this same endpoint, so a throttle or an outage
	// would only repeat itself over a slower transport and be reported as a
	// PowerShell failure. Surface the real cause instead.
	if exchangeErrorIsTransient(err) {
		return nil, err
	}

	log.Warn().Err(err).Msg("exchange online admin endpoint unavailable, falling back to powershell")
	return r.fetchExchangeReportViaPowershell(conn, organization, token)
}

func (r *mqlMs365Exchangeonline) fetchExchangeReportViaPowershell(conn *connection.Ms365Connection, organization string, token string) (*ExchangeOnlineReport, error) {
	fmtScript := fmt.Sprintf(exchangeReport, conn.ClientId(), organization, conn.TenantId(), token)
	res, err := conn.CheckAndRunPowershellScript(fmtScript)
	if err != nil {
		return nil, err
	}

	if res.ExitStatus != 0 {
		data, err := io.ReadAll(res.Stderr)
		if err != nil {
			return nil, err
		}

		if strings.Contains(strings.ToLower(string(data)), "unauthorized") {
			return nil, errors.New("access denied, please ensure the credentials have the right permissions in Azure AD")
		}

		logger.DebugDumpJSON("exchange-online-report", data)
		return nil, fmt.Errorf("failed to generate exchange online report (exit code %d): %s", res.ExitStatus, string(data))
	}

	data, err := io.ReadAll(res.Stdout)
	if err != nil {
		return nil, err
	}
	logger.DebugDumpJSON("exchange-online-report", data)

	report := &ExchangeOnlineReport{}
	if err := json.Unmarshal(data, report); err != nil {
		return nil, err
	}
	return report, nil
}

// isAbsentSection reports whether an Exchange report section was never
// populated, i.e. its cmdlet did not run or failed.
//
// fetchExchangeReport only errors when EVERY section fails, so a report with
// one denied cmdlet is returned successfully with that one field left nil. The
// distinction matters because a section that ran and matched nothing decodes to
// a non-nil empty slice: absent means "not collected", empty means "collected,
// none found".
//
// Sections declared as `any` are assigned from a []any, so a failed one can
// hold a TYPED nil, which does not compare equal to nil. Check reflectively so
// both shapes read as absent.
func isAbsentSection(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Interface, reflect.Func:
		return rv.IsNil()
	}
	return false
}

// exchangeNullableList builds the value for a list field sourced from one
// report section. An absent section reads null rather than as an empty list.
//
// convert.JsonToDictSlice(nil) returns (nil, nil) -- no error -- and assigning
// that with StateIsSet but no StateIsNull makes ToDataRes take the non-null
// path, so the field renders as [] rather than null. That reports "this tenant
// has none of these" as fact for data that was never collected.
func exchangeNullableList(isAbsent bool, data []any, err error) plugin.TValue[[]any] {
	if isAbsent {
		return plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet, Error: err}
}

// exchangeNullableDict is exchangeNullableList for a scalar dict field.
// convert.JsonToDict(nil) behaves the same way, rendering as {} rather than
// null.
func exchangeNullableDict(isAbsent bool, data any, err error) plugin.TValue[any] {
	if isAbsent {
		return plugin.TValue[any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[any]{Data: data, State: plugin.StateIsSet, Error: err}
}

// exchangeNullableBool is exchangeNullableList for a bool derived from a
// section. A derived false is indistinguishable from a real one, so an absent
// section must read null instead.
func exchangeNullableBool(isAbsent bool, data bool, err error) plugin.TValue[bool] {
	if isAbsent {
		return plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[bool]{Data: data, State: plugin.StateIsSet, Error: err}
}

func (r *mqlMs365Exchangeonline) getExchangeReport() error {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)

	r.exchangeReportLock.Lock()
	defer r.exchangeReportLock.Unlock()

	// only fetch once
	if r.fetched {
		return r.fetchErr
	}

	errHandler := func(err error) error {
		r.fetchErr = err
		r.fetched = true
		return err
	}

	organization, err := r.getOrg()
	if organization == "" || err != nil {
		return errHandler(errors.New("no organization provided, unable to fetch exchange online report"))
	}

	ctx := context.Background()
	token := conn.Token()
	outlookToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{outlookScope},
	})
	if err != nil {
		return errHandler(err)
	}

	report, err := r.fetchExchangeReport(ctx, conn, organization, outlookToken.Token)
	if err != nil {
		return errHandler(err)
	}

	// Process enhanced mailbox data
	mailboxesWithAudit := []any{}
	var mailboxesWithAuditErr error
	for _, m := range report.Mailbox {
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.mailboxWithAudit",
			map[string]*llx.RawData{
				"__id":                 llx.StringData(m.Identity),
				"identity":             llx.StringData(m.Identity),
				"displayName":          llx.StringData(m.DisplayName),
				"primarySmtpAddress":   llx.StringData(m.PrimarySmtpAddress),
				"recipientTypeDetails": llx.StringData(m.RecipientTypeDetails),
				"auditEnabled":         llx.BoolData(m.AuditEnabled),
				"auditAdmin":           llx.ArrayData(llx.TArr2Raw(m.AuditAdmin), types.String),
				"auditDelegate":        llx.ArrayData(llx.TArr2Raw(m.AuditDelegate), types.String),
				"auditOwner":           llx.ArrayData(llx.TArr2Raw(m.AuditOwner), types.String),
				"auditLogAgeLimit":     llx.StringData(m.AuditLogAgeLimit),
			})
		if err != nil {
			mailboxesWithAuditErr = err
			break
		}
		mailboxesWithAudit = append(mailboxesWithAudit, mql)
	}
	r.MailboxesWithAudit = exchangeNullableList(isAbsentSection(report.Mailbox), mailboxesWithAudit, mailboxesWithAuditErr)

	malwareFilterPolicy, malwareFilterPolicyErr := convert.JsonToDictSlice(report.MalwareFilterPolicy)
	r.MalwareFilterPolicy = exchangeNullableList(isAbsentSection(report.MalwareFilterPolicy), malwareFilterPolicy, malwareFilterPolicyErr)

	hostedOutboundSpamFilterPolicy, hostedOutboundSpamFilterPolicyErr := convert.JsonToDictSlice(report.HostedOutboundSpamFilterPolicy)
	r.HostedOutboundSpamFilterPolicy = exchangeNullableList(isAbsentSection(report.HostedOutboundSpamFilterPolicy), hostedOutboundSpamFilterPolicy, hostedOutboundSpamFilterPolicyErr)

	transportRule, transportRuleErr := convert.JsonToDictSlice(report.TransportRule)
	r.TransportRule = exchangeNullableList(isAbsentSection(report.TransportRule), transportRule, transportRuleErr)

	safeLinksPolicy, safeLinksPolicyErr := convert.JsonToDictSlice(report.SafeLinksPolicy)
	r.SafeLinksPolicy = exchangeNullableList(isAbsentSection(report.SafeLinksPolicy), safeLinksPolicy, safeLinksPolicyErr)

	safeAttachmentPolicy, safeAttachmentPolicyErr := convert.JsonToDictSlice(report.SafeAttachmentPolicy)
	r.SafeAttachmentPolicy = exchangeNullableList(isAbsentSection(report.SafeAttachmentPolicy), safeAttachmentPolicy, safeAttachmentPolicyErr)

	organizationConfig, organizationConfigErr := convert.JsonToDict(report.OrganizationConfig)
	r.OrganizationConfig = exchangeNullableDict(isAbsentSection(report.OrganizationConfig), organizationConfig, organizationConfigErr)

	antiPhishPolicy, antiPhishPolicyErr := convert.JsonToDictSlice(report.AntiPhishPolicy)
	r.AntiPhishPolicy = exchangeNullableList(isAbsentSection(report.AntiPhishPolicy), antiPhishPolicy, antiPhishPolicyErr)

	dkimSigningConfig, dkimSigningConfigErr := convert.JsonToDictSlice(report.DkimSigningConfig)
	r.DkimSigningConfig = exchangeNullableList(isAbsentSection(report.DkimSigningConfig), dkimSigningConfig, dkimSigningConfigErr)

	owaMailboxPolicy, owaMailboxPolicyErr := convert.JsonToDictSlice(report.OwaMailboxPolicy)
	r.OwaMailboxPolicy = exchangeNullableList(isAbsentSection(report.OwaMailboxPolicy), owaMailboxPolicy, owaMailboxPolicyErr)

	adminAuditLogConfig, adminAuditLogConfigErr := convert.JsonToDict(report.AdminAuditLogConfig)
	r.AdminAuditLogConfig = exchangeNullableDict(isAbsentSection(report.AdminAuditLogConfig), adminAuditLogConfig, adminAuditLogConfigErr)
	r.UnifiedAuditLogIngestionEnabled = exchangeNullableBool(isAbsentSection(report.AdminAuditLogConfig), dictBoolValue(adminAuditLogConfig, "unifiedAuditLogIngestionEnabled"), adminAuditLogConfigErr)

	phishFilterPolicy, phishFilterPolicyErr := convert.JsonToDictSlice(report.PhishFilterPolicy)
	r.PhishFilterPolicy = exchangeNullableList(isAbsentSection(report.PhishFilterPolicy), phishFilterPolicy, phishFilterPolicyErr)

	mailbox, mailboxErr := convert.JsonToDictSlice(report.Mailbox)
	r.Mailbox = exchangeNullableList(isAbsentSection(report.Mailbox), mailbox, mailboxErr)

	atpPolicyForO365, atpPolicyForO365Err := convert.JsonToDictSlice(report.AtpPolicyForO365)
	r.AtpPolicyForO365 = exchangeNullableList(isAbsentSection(report.AtpPolicyForO365), atpPolicyForO365, atpPolicyForO365Err)

	sharingPolicy, sharingPolicyErr := convert.JsonToDictSlice(report.SharingPolicy)
	r.SharingPolicy = exchangeNullableList(isAbsentSection(report.SharingPolicy), sharingPolicy, sharingPolicyErr)

	roleAssignmentPolicy, roleAssignmentPolicyErr := convert.JsonToDictSlice(report.RoleAssignmentPolicy)
	r.RoleAssignmentPolicy = exchangeNullableList(isAbsentSection(report.RoleAssignmentPolicy), roleAssignmentPolicy, roleAssignmentPolicyErr)

	externalInOutlook := []any{}
	var externalInOutlookErr error
	for i, e := range report.ExternalInOutlook {
		if e == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.externalSender",
			map[string]*llx.RawData{
				"__id":      llx.StringData(exchangeEntryID("externalSender", e.Identity, i)),
				"identity":  llx.StringData(e.Identity),
				"enabled":   llx.BoolData(e.Enabled),
				"allowList": llx.ArrayData(llx.TArr2Raw(e.AllowList), types.Any),
			})
		if err != nil {
			externalInOutlookErr = err
			break
		}

		externalInOutlook = append(externalInOutlook, mql)
	}
	r.ExternalInOutlook = exchangeNullableList(isAbsentSection(report.ExternalInOutlook), externalInOutlook, externalInOutlookErr)

	sharedMailboxes := []any{}
	var sharedMailboxesErr error
	for i, m := range report.ExoMailbox {
		if m == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.exoMailbox",
			map[string]*llx.RawData{
				"__id":                      llx.StringData(exchangeEntryID("exoMailbox", m.Identity, i)),
				"identity":                  llx.StringData(m.Identity),
				"externalDirectoryObjectId": llx.StringData(m.ExternalDirectoryObjectId),
			})
		if err != nil {
			sharedMailboxesErr = err
			break
		}

		sharedMailboxes = append(sharedMailboxes, mql)
	}
	r.SharedMailboxes = exchangeNullableList(isAbsentSection(report.ExoMailbox), sharedMailboxes, sharedMailboxesErr)

	// Related to TeamsProtectionPolicy
	if report.TeamsProtectionPolicy != nil {
		teamsProtectionPolicies, teamsProtectionPolicyErr := convertTeamsProtectionPolicy(r, report.TeamsProtectionPolicy)
		r.TeamsProtectionPolicies = plugin.TValue[[]any]{Data: teamsProtectionPolicies, State: plugin.StateIsSet, Error: teamsProtectionPolicyErr}
	} else {
		r.TeamsProtectionPolicies = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Journal Rules
	if report.JournalRules != nil {
		journalRules, journalRulesErr := convertJournalRules(r, report.JournalRules)
		r.JournalRules = plugin.TValue[[]any]{Data: journalRules, State: plugin.StateIsSet, Error: journalRulesErr}
	} else {
		r.JournalRules = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Mailbox Plans
	if report.MailboxPlans != nil {
		mailboxPlans, mailboxPlansErr := convertMailboxPlans(r, report.MailboxPlans)
		r.MailboxPlans = plugin.TValue[[]any]{Data: mailboxPlans, State: plugin.StateIsSet, Error: mailboxPlansErr}
	} else {
		r.MailboxPlans = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Retention Policies
	if report.RetentionPolicies != nil {
		retentionPolicies, retentionPoliciesErr := convertRetentionPolicies(r, report.RetentionPolicies)
		r.RetentionPolicies = plugin.TValue[[]any]{Data: retentionPolicies, State: plugin.StateIsSet, Error: retentionPoliciesErr}
	} else {
		r.RetentionPolicies = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Related to ReportSubmissionPolicy
	if report.ReportSubmissionPolicy != nil {
		reportSubmissionPolicies, reportSubmissionPolicyErr := convertReportSubmissionPolicy(r, report.ReportSubmissionPolicy)
		r.ReportSubmissionPolicies = plugin.TValue[[]any]{Data: reportSubmissionPolicies, State: plugin.StateIsSet, Error: reportSubmissionPolicyErr}
	} else {
		r.ReportSubmissionPolicies = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	transportConfig, transportConfigErr := convert.JsonToDict(report.TransportConfig)
	r.TransportConfig = exchangeNullableDict(isAbsentSection(report.TransportConfig), transportConfig, transportConfigErr)

	mailboxAuditBypassAssociations := []any{}
	var mailboxAuditBypassAssociationErr error
	for i, assoc := range report.MailboxAuditBypassAssociation {
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonlineMailboxAuditBypassAssociation",
			map[string]*llx.RawData{
				"__id":               llx.StringData(exchangeEntryID("mailboxAuditBypassAssociation", assoc.Name, i)),
				"name":               llx.StringData(assoc.Name),
				"auditBypassEnabled": llx.BoolData(assoc.AuditBypassEnabled),
			})
		if err != nil {
			mailboxAuditBypassAssociationErr = err
			break
		}
		mailboxAuditBypassAssociations = append(mailboxAuditBypassAssociations, mql)
	}
	r.MailboxAuditBypassAssociation = exchangeNullableList(isAbsentSection(report.MailboxAuditBypassAssociation), mailboxAuditBypassAssociations, mailboxAuditBypassAssociationErr)

	// resource views of the policies above, decoded from the same payload (see
	// ms365_exchange_policies.go). The deprecated []dict accessors keep
	// returning every property; these expose the security-relevant subset.
	// They go through exchangeNullableList for the same absent-vs-empty
	// distinction as the raw dict fields above.

	transportRules, transportRulesErr := convertTransportRules(r, report.TransportRule)
	r.TransportRules = exchangeNullableList(isAbsentSection(report.TransportRule), transportRules, transportRulesErr)

	antiPhishPolicies, antiPhishPoliciesErr := convertAntiPhishPolicies(r, report.AntiPhishPolicy)
	r.AntiPhishPolicies = exchangeNullableList(isAbsentSection(report.AntiPhishPolicy), antiPhishPolicies, antiPhishPoliciesErr)

	safeLinksPolicies, safeLinksPoliciesErr := convertSafeLinksPolicies(r, report.SafeLinksPolicy)
	r.SafeLinksPolicies = exchangeNullableList(isAbsentSection(report.SafeLinksPolicy), safeLinksPolicies, safeLinksPoliciesErr)

	safeAttachmentPolicies, safeAttachmentPoliciesErr := convertSafeAttachmentPolicies(r, report.SafeAttachmentPolicy)
	r.SafeAttachmentPolicies = exchangeNullableList(isAbsentSection(report.SafeAttachmentPolicy), safeAttachmentPolicies, safeAttachmentPoliciesErr)

	malwareFilterPolicies, malwareFilterPoliciesErr := convertMalwareFilterPolicies(r, report.MalwareFilterPolicy)
	r.MalwareFilterPolicies = exchangeNullableList(isAbsentSection(report.MalwareFilterPolicy), malwareFilterPolicies, malwareFilterPoliciesErr)

	hostedContentFilterPolicies, hostedContentFilterPoliciesErr := convertHostedContentFilterPolicies(r, report.HostedContentFilterPolicy)
	r.HostedContentFilterPolicies = exchangeNullableList(isAbsentSection(report.HostedContentFilterPolicy), hostedContentFilterPolicies, hostedContentFilterPoliciesErr)

	hostedOutboundSpamFilterPolicies, hostedOutboundSpamFilterPoliciesErr := convertHostedOutboundSpamFilterPolicies(r, report.HostedOutboundSpamFilterPolicy)
	r.HostedOutboundSpamFilterPolicies = exchangeNullableList(isAbsentSection(report.HostedOutboundSpamFilterPolicy), hostedOutboundSpamFilterPolicies, hostedOutboundSpamFilterPoliciesErr)

	dkimSigningConfigs, dkimSigningConfigsErr := convertDkimSigningConfigs(r, report.DkimSigningConfig)
	r.DkimSigningConfigs = exchangeNullableList(isAbsentSection(report.DkimSigningConfig), dkimSigningConfigs, dkimSigningConfigsErr)

	authenticationPolicies, authenticationPoliciesErr := convertAuthenticationPolicies(r, report.AuthenticationPolicy)
	r.AuthenticationPolicies = exchangeNullableList(isAbsentSection(report.AuthenticationPolicy), authenticationPolicies, authenticationPoliciesErr)

	owaMailboxPolicies, owaMailboxPoliciesErr := convertOwaMailboxPolicies(r, report.OwaMailboxPolicy)
	r.OwaMailboxPolicies = exchangeNullableList(isAbsentSection(report.OwaMailboxPolicy), owaMailboxPolicies, owaMailboxPoliciesErr)

	remoteDomains, remoteDomainsErr := convertRemoteDomains(r, report.RemoteDomain)
	r.RemoteDomains = exchangeNullableList(isAbsentSection(report.RemoteDomain), remoteDomains, remoteDomainsErr)

	quarantinePolicies, quarantinePoliciesErr := convertQuarantinePolicies(r, report.QuarantinePolicy)
	r.QuarantinePolicies = exchangeNullableList(isAbsentSection(report.QuarantinePolicy), quarantinePolicies, quarantinePoliciesErr)

	atpPoliciesForO365, atpPoliciesForO365Err := convertAtpPoliciesForO365(r, report.AtpPolicyForO365)
	r.AtpPoliciesForO365 = exchangeNullableList(isAbsentSection(report.AtpPolicyForO365), atpPoliciesForO365, atpPoliciesForO365Err)

	sharingPolicies, sharingPoliciesErr := convertSharingPolicies(r, report.SharingPolicy)
	r.SharingPolicies = exchangeNullableList(isAbsentSection(report.SharingPolicy), sharingPolicies, sharingPoliciesErr)

	roleAssignmentPolicies, roleAssignmentPoliciesErr := convertRoleAssignmentPolicies(r, report.RoleAssignmentPolicy)
	r.RoleAssignmentPolicies = exchangeNullableList(isAbsentSection(report.RoleAssignmentPolicy), roleAssignmentPolicies, roleAssignmentPoliciesErr)

	emailTenantSettings, emailTenantSettingsErr := convert.JsonToDict(report.EmailTenantSettings)
	r.PriorityAccountProtectionEnabled = exchangeNullableBool(isAbsentSection(report.EmailTenantSettings),
		dictBoolValue(emailTenantSettings, "enablePriorityAccountProtection"), emailTenantSettingsErr)

	// a preset is turned on by one rule of each kind, so a partial answer cannot
	// support "the preset is not in use" -- if either cmdlet did not run, the
	// whole list reads null rather than a list missing half its rows
	protectionPolicyRules, protectionPolicyRulesErr := convertProtectionPolicyRules(r, report.EOPProtectionPolicyRule, report.ATPProtectionPolicyRule)
	r.ProtectionPolicyRules = exchangeNullableList(
		isAbsentSection(report.EOPProtectionPolicyRule) || isAbsentSection(report.ATPProtectionPolicyRule),
		protectionPolicyRules, protectionPolicyRulesErr)

	r.fetched = true
	return nil
}

func (r *mqlMs365Exchangeonline) malwareFilterPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) hostedOutboundSpamFilterPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) hostedContentFilterPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) transportRule() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) remoteDomain() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) quarantinePolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) journalRules() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) mailboxPlans() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) retentionPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) safeLinksPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) safeAttachmentPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) organizationConfig() (any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) authenticationPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) antiPhishPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) dkimSigningConfig() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) owaMailboxPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) adminAuditLogConfig() (any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) unifiedAuditLogIngestionEnabled() (bool, error) {
	return false, r.getExchangeReport()
}

// dictBoolValue does a case-insensitive lookup of key in a JsonToDict result
// and returns its bool value, or false when the key is absent or not a bool.
func dictBoolValue(d any, key string) bool {
	m, ok := d.(map[string]any)
	if !ok {
		return false
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			b, _ := v.(bool)
			return b
		}
	}
	return false
}

func (r *mqlMs365Exchangeonline) phishFilterPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) mailbox() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) atpPolicyForO365() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) sharingPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) roleAssignmentPolicy() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) externalInOutlook() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365ExchangeonlineExternalSender) id() (string, error) {
	return r.Identity.Data, nil
}

func (r *mqlMs365Exchangeonline) sharedMailboxes() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (m *mqlMs365ExchangeonlineExoMailbox) id() (string, error) {
	return m.Identity.Data, nil
}

func (r *mqlMs365Exchangeonline) teamsProtectionPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) reportSubmissionPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (m *mqlMs365ExchangeonlineExoMailbox) user() (*mqlMicrosoftUser, error) {
	externalId := m.ExternalDirectoryObjectId.Data
	if externalId == "" {
		return nil, errors.New("no externalDirectoryObjectId provided, cannot find user for mailbox")
	}
	microsoft, err := m.MqlRuntime.CreateResource(m.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlMicrosoft := microsoft.(*mqlMicrosoft)
	users := mqlMicrosoft.GetUsers()
	if users.Error != nil {
		return nil, users.Error
	}
	for _, u := range users.Data.List.Data {
		mqlUser := u.(*mqlMicrosoftUser)
		if mqlUser.Id.Data == externalId {
			return mqlUser, nil
		}
	}
	return nil, errors.New("cannot find user for exchange mailbox")
}

func (r *mqlMs365Exchangeonline) mailboxesWithAudit() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) transportConfig() (any, error) {
	return nil, r.getExchangeReport()
}

type mqlMs365ExchangeonlineSecurityAndComplianceInternal struct {
	scReportLock sync.Mutex
	fetched      bool
	fetchErr     error
	report       *SecurityAndComplianceReport
}

func (r *mqlMs365ExchangeonlineSecurityAndCompliance) getSecurityAndComplianceReport() (*SecurityAndComplianceReport, error) {
	r.scReportLock.Lock()
	defer r.scReportLock.Unlock()

	if r.fetched {
		return r.report, r.fetchErr
	}

	r.fetched = true

	errHandler := func(err error) (*SecurityAndComplianceReport, error) {
		r.fetchErr = err
		return nil, err
	}

	parent, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline", nil)
	if err != nil {
		return errHandler(err)
	}
	exchangeOnline := parent.(*mqlMs365Exchangeonline)
	conn := exchangeOnline.MqlRuntime.Connection.(*connection.Ms365Connection)

	organization, err := exchangeOnline.getOrg()
	if organization == "" || err != nil {
		return errHandler(errors.New("no organization provided, unable to fetch security and compliance report"))
	}

	ctx := context.Background()
	token := conn.Token()
	complianceToken, err := token.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{complianceScope},
	})
	if err != nil {
		return errHandler(err)
	}

	fmtScript := fmt.Sprintf(securityAndComplianceReport, conn.ClientId(), organization, conn.TenantId(), complianceToken.Token)
	res, err := conn.CheckAndRunPowershellScript(fmtScript)
	if err != nil {
		return errHandler(err)
	}

	report := &SecurityAndComplianceReport{}
	if res.ExitStatus != 0 {
		data, _ := io.ReadAll(res.Stderr)
		return errHandler(fmt.Errorf("failed to generate security and compliance report (exit code %d): %s", res.ExitStatus, string(data)))
	}

	data, err := io.ReadAll(res.Stdout)
	if err != nil {
		return errHandler(err)
	}
	logger.DebugDumpJSON("security-and-compliance-report", data)

	if err := json.Unmarshal(data, report); err != nil {
		return errHandler(err)
	}

	r.report = report
	return r.report, nil
}

func (r *mqlMs365Exchangeonline) securityAndCompliance() (*mqlMs365ExchangeonlineSecurityAndCompliance, error) {
	resource, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.securityAndCompliance", nil)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMs365ExchangeonlineSecurityAndCompliance), nil
}

func (r *mqlMs365Exchangeonline) mailboxAuditBypassAssociation() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) priorityAccountProtectionEnabled() (bool, error) {
	return false, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) protectionPolicyRules() ([]any, error) {
	return nil, r.getExchangeReport()
}
