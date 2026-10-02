// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// decodeExchangeList re-decodes the raw cmdlet payload (already unmarshalled
// into []any by the report parser) into a struct slice. The full object is
// serialized in the report, so the decoded view is a faithful subset of the
// same data with no additional API call.
func decodeExchangeList[T any](raw any) ([]*T, error) {
	if raw == nil {
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var out []*T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// exchangeDomainList decodes Exchange domain collections whose elements are
// MultiValuedProperty<...> values (e.g. SmtpDomainWithSubdomains on hosted
// content filter policies, SharingPolicyDomain on sharing policies).
//
// Depending on the cmdlet and PowerShell's ConvertTo-Json serialization, each
// element is rendered either as a bare domain string ("contoso.com") or as an
// object carrying a "Domain" field ({"Domain":"contoso.com",...}); a
// single-element collection may additionally be emitted as a scalar instead of
// an array. Decoding such objects into a plain []string fails with
// "cannot unmarshal object into Go struct field ... of type string", which
// aborts the whole resource. Normalizing every shape to a []string of domains
// keeps decoding resilient for tenants that have any of these domains set.
type exchangeDomainList []string

func (d *exchangeDomainList) UnmarshalJSON(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*d = flattenExchangeDomains(raw)
	return nil
}

func flattenExchangeDomains(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, flattenExchangeDomains(e)...)
		}
		return out
	case map[string]any:
		if domain := exchangeDomainFromObject(t); domain != "" {
			return []string{domain}
		}
		return nil
	default:
		return nil
	}
}

func exchangeDomainFromObject(obj map[string]any) string {
	// Preferred, explicitly-named keys first.
	for _, key := range []string{"Domain", "SmtpDomain", "DomainName", "Name", "Address"} {
		if s, ok := obj[key].(string); ok && s != "" {
			return s
		}
	}
	// Fallback: any string-valued key that looks like a domain.
	for key, val := range obj {
		if s, ok := val.(string); ok && s != "" && strings.Contains(strings.ToLower(key), "domain") {
			return s
		}
	}
	return ""
}

// --- Transport rules ---

type ExchangeTransportRule struct {
	Identity                       string   `json:"Identity"`
	Name                           string   `json:"Name"`
	Priority                       int64    `json:"Priority"`
	State                          string   `json:"State"`
	Mode                           string   `json:"Mode"`
	RouteMessageOutboundRequireTls bool     `json:"RouteMessageOutboundRequireTls"`
	Comments                       string   `json:"Comments"`
	SenderDomainIs                 []string `json:"SenderDomainIs"`
}

func convertTransportRules(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	rules, err := decodeExchangeList[ExchangeTransportRule](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, t := range rules {
		if t == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.transportRuleEntry",
			map[string]*llx.RawData{
				"__id":                           llx.StringData("transportRule-" + t.Identity),
				"identity":                       llx.StringData(t.Identity),
				"name":                           llx.StringData(t.Name),
				"priority":                       llx.IntData(t.Priority),
				"state":                          llx.StringData(t.State),
				"mode":                           llx.StringData(t.Mode),
				"routeMessageOutboundRequireTls": llx.BoolData(t.RouteMessageOutboundRequireTls),
				"comments":                       llx.StringData(t.Comments),
				"senderDomainIs":                 llx.ArrayData(llx.TArr2Raw(t.SenderDomainIs), types.String),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Anti-phishing policies ---

type ExchangeAntiPhishPolicy struct {
	Identity                            string `json:"Identity"`
	Name                                string `json:"Name"`
	Enabled                             bool   `json:"Enabled"`
	PhishThresholdLevel                 int64  `json:"PhishThresholdLevel"`
	EnableMailboxIntelligence           bool   `json:"EnableMailboxIntelligence"`
	EnableMailboxIntelligenceProtection bool   `json:"EnableMailboxIntelligenceProtection"`
	EnableSpoofIntelligence             bool   `json:"EnableSpoofIntelligence"`
	EnableFirstContactSafetyTips        bool   `json:"EnableFirstContactSafetyTips"`
	EnableTargetedUserProtection        bool   `json:"EnableTargetedUserProtection"`
	EnableTargetedDomainsProtection     bool   `json:"EnableTargetedDomainsProtection"`
	EnableOrganizationDomainsProtection bool   `json:"EnableOrganizationDomainsProtection"`
	TargetedUserProtectionAction        string `json:"TargetedUserProtectionAction"`
	TargetedDomainProtectionAction      string `json:"TargetedDomainProtectionAction"`
	AuthenticationFailAction            string `json:"AuthenticationFailAction"`
	DmarcQuarantineAction               string `json:"DmarcQuarantineAction"`
	DmarcRejectAction                   string `json:"DmarcRejectAction"`
	EnableSimilarDomainsSafetyTips      bool   `json:"EnableSimilarDomainsSafetyTips"`
	EnableSimilarUsersSafetyTips        bool   `json:"EnableSimilarUsersSafetyTips"`
	EnableSuspiciousSafetyTip           bool   `json:"EnableSuspiciousSafetyTip"`
	EnableUnauthenticatedSender         bool   `json:"EnableUnauthenticatedSender"`
	EnableUnusualCharactersSafetyTips   bool   `json:"EnableUnusualCharactersSafetyTips"`
	EnableViaTag                        bool   `json:"EnableViaTag"`
	HonorDmarcPolicy                    bool   `json:"HonorDmarcPolicy"`
	ImpersonationProtectionState        string `json:"ImpersonationProtectionState"`
	MailboxIntelligenceProtectionAction string `json:"MailboxIntelligenceProtectionAction"`
}

func convertAntiPhishPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeAntiPhishPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.antiPhishPolicyEntry",
			map[string]*llx.RawData{
				"__id":                                llx.StringData("antiPhishPolicy-" + p.Identity),
				"identity":                            llx.StringData(p.Identity),
				"name":                                llx.StringData(p.Name),
				"enabled":                             llx.BoolData(p.Enabled),
				"phishThresholdLevel":                 llx.IntData(p.PhishThresholdLevel),
				"enableMailboxIntelligence":           llx.BoolData(p.EnableMailboxIntelligence),
				"enableMailboxIntelligenceProtection": llx.BoolData(p.EnableMailboxIntelligenceProtection),
				"enableSpoofIntelligence":             llx.BoolData(p.EnableSpoofIntelligence),
				"enableFirstContactSafetyTips":        llx.BoolData(p.EnableFirstContactSafetyTips),
				"enableTargetedUserProtection":        llx.BoolData(p.EnableTargetedUserProtection),
				"enableTargetedDomainsProtection":     llx.BoolData(p.EnableTargetedDomainsProtection),
				"enableOrganizationDomainsProtection": llx.BoolData(p.EnableOrganizationDomainsProtection),
				"targetedUserProtectionAction":        llx.StringData(p.TargetedUserProtectionAction),
				"targetedDomainProtectionAction":      llx.StringData(p.TargetedDomainProtectionAction),
				"authenticationFailAction":            llx.StringData(p.AuthenticationFailAction),
				"dmarcQuarantineAction":               llx.StringData(p.DmarcQuarantineAction),
				"dmarcRejectAction":                   llx.StringData(p.DmarcRejectAction),
				"enableSimilarDomainsSafetyTips":      llx.BoolData(p.EnableSimilarDomainsSafetyTips),
				"enableSimilarUsersSafetyTips":        llx.BoolData(p.EnableSimilarUsersSafetyTips),
				"enableSuspiciousSafetyTip":           llx.BoolData(p.EnableSuspiciousSafetyTip),
				"enableUnauthenticatedSender":         llx.BoolData(p.EnableUnauthenticatedSender),
				"enableUnusualCharactersSafetyTips":   llx.BoolData(p.EnableUnusualCharactersSafetyTips),
				"enableViaTag":                        llx.BoolData(p.EnableViaTag),
				"honorDmarcPolicy":                    llx.BoolData(p.HonorDmarcPolicy),
				"impersonationProtectionState":        llx.StringData(p.ImpersonationProtectionState),
				"mailboxIntelligenceProtectionAction": llx.StringData(p.MailboxIntelligenceProtectionAction),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Safe Links policies ---

type ExchangeSafeLinksPolicy struct {
	Identity                 string `json:"Identity"`
	Name                     string `json:"Name"`
	EnableSafeLinksForEmail  bool   `json:"EnableSafeLinksForEmail"`
	EnableSafeLinksForTeams  bool   `json:"EnableSafeLinksForTeams"`
	EnableSafeLinksForOffice bool   `json:"EnableSafeLinksForOffice"`
	TrackClicks              bool   `json:"TrackClicks"`
	AllowClickThrough        bool   `json:"AllowClickThrough"`
	ScanUrls                 bool   `json:"ScanUrls"`
	EnableForInternalSenders bool   `json:"EnableForInternalSenders"`
	DeliverMessageAfterScan  bool   `json:"DeliverMessageAfterScan"`
	DisableUrlRewrite        bool   `json:"DisableUrlRewrite"`
}

func convertSafeLinksPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeSafeLinksPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.safeLinksPolicyEntry",
			map[string]*llx.RawData{
				"__id":                     llx.StringData("safeLinksPolicy-" + p.Identity),
				"identity":                 llx.StringData(p.Identity),
				"name":                     llx.StringData(p.Name),
				"enableSafeLinksForEmail":  llx.BoolData(p.EnableSafeLinksForEmail),
				"enableSafeLinksForTeams":  llx.BoolData(p.EnableSafeLinksForTeams),
				"enableSafeLinksForOffice": llx.BoolData(p.EnableSafeLinksForOffice),
				"trackClicks":              llx.BoolData(p.TrackClicks),
				"allowClickThrough":        llx.BoolData(p.AllowClickThrough),
				"scanUrls":                 llx.BoolData(p.ScanUrls),
				"enableForInternalSenders": llx.BoolData(p.EnableForInternalSenders),
				"deliverMessageAfterScan":  llx.BoolData(p.DeliverMessageAfterScan),
				"disableUrlRewrite":        llx.BoolData(p.DisableUrlRewrite),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Safe Attachment policies ---

type ExchangeSafeAttachmentPolicy struct {
	Identity        string `json:"Identity"`
	Name            string `json:"Name"`
	Enable          bool   `json:"Enable"`
	Action          string `json:"Action"`
	Redirect        bool   `json:"Redirect"`
	RedirectAddress string `json:"RedirectAddress"`
	QuarantineTag   string `json:"QuarantineTag"`
}

func convertSafeAttachmentPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeSafeAttachmentPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.safeAttachmentPolicyEntry",
			map[string]*llx.RawData{
				"__id":            llx.StringData("safeAttachmentPolicy-" + p.Identity),
				"identity":        llx.StringData(p.Identity),
				"name":            llx.StringData(p.Name),
				"enable":          llx.BoolData(p.Enable),
				"action":          llx.StringData(p.Action),
				"redirect":        llx.BoolData(p.Redirect),
				"redirectAddress": llx.StringData(p.RedirectAddress),
				"quarantineTag":   llx.StringData(p.QuarantineTag),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Malware filter policies ---

type ExchangeMalwareFilterPolicy struct {
	Identity                               string   `json:"Identity"`
	Name                                   string   `json:"Name"`
	EnableFileFilter                       bool     `json:"EnableFileFilter"`
	ZapEnabled                             bool     `json:"ZapEnabled"`
	EnableInternalSenderAdminNotifications bool     `json:"EnableInternalSenderAdminNotifications"`
	EnableExternalSenderAdminNotifications bool     `json:"EnableExternalSenderAdminNotifications"`
	FileTypes                              []string `json:"FileTypes"`
	CustomNotifications                    bool     `json:"CustomNotifications"`
	ExternalSenderAdminAddress             string   `json:"ExternalSenderAdminAddress"`
	FileTypeAction                         string   `json:"FileTypeAction"`
	InternalSenderAdminAddress             string   `json:"InternalSenderAdminAddress"`
	QuarantineTag                          string   `json:"QuarantineTag"`
}

func convertMalwareFilterPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeMalwareFilterPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.malwareFilterPolicyEntry",
			map[string]*llx.RawData{
				"__id":                                   llx.StringData("malwareFilterPolicy-" + p.Identity),
				"identity":                               llx.StringData(p.Identity),
				"name":                                   llx.StringData(p.Name),
				"enableFileFilter":                       llx.BoolData(p.EnableFileFilter),
				"zapEnabled":                             llx.BoolData(p.ZapEnabled),
				"enableInternalSenderAdminNotifications": llx.BoolData(p.EnableInternalSenderAdminNotifications),
				"enableExternalSenderAdminNotifications": llx.BoolData(p.EnableExternalSenderAdminNotifications),
				"fileTypes":                              llx.ArrayData(llx.TArr2Raw(p.FileTypes), types.String),
				"customNotifications":                    llx.BoolData(p.CustomNotifications),
				"externalSenderAdminAddress":             llx.StringData(p.ExternalSenderAdminAddress),
				"fileTypeAction":                         llx.StringData(p.FileTypeAction),
				"internalSenderAdminAddress":             llx.StringData(p.InternalSenderAdminAddress),
				"quarantineTag":                          llx.StringData(p.QuarantineTag),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Hosted content (spam) filter policies ---

type ExchangeHostedContentFilterPolicy struct {
	Identity                       string             `json:"Identity"`
	Name                           string             `json:"Name"`
	SpamAction                     string             `json:"SpamAction"`
	HighConfidenceSpamAction       string             `json:"HighConfidenceSpamAction"`
	PhishSpamAction                string             `json:"PhishSpamAction"`
	HighConfidencePhishAction      string             `json:"HighConfidencePhishAction"`
	BulkSpamAction                 string             `json:"BulkSpamAction"`
	BulkThreshold                  int64              `json:"BulkThreshold"`
	EnableEndUserSpamNotifications bool               `json:"EnableEndUserSpamNotifications"`
	AllowedSenderDomains           exchangeDomainList `json:"AllowedSenderDomains"`
	BlockedSenderDomains           exchangeDomainList `json:"BlockedSenderDomains"`
}

func convertHostedContentFilterPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeHostedContentFilterPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.hostedContentFilterPolicyEntry",
			map[string]*llx.RawData{
				"__id":                           llx.StringData("hostedContentFilterPolicy-" + p.Identity),
				"identity":                       llx.StringData(p.Identity),
				"name":                           llx.StringData(p.Name),
				"spamAction":                     llx.StringData(p.SpamAction),
				"highConfidenceSpamAction":       llx.StringData(p.HighConfidenceSpamAction),
				"phishSpamAction":                llx.StringData(p.PhishSpamAction),
				"highConfidencePhishAction":      llx.StringData(p.HighConfidencePhishAction),
				"bulkSpamAction":                 llx.StringData(p.BulkSpamAction),
				"bulkThreshold":                  llx.IntData(p.BulkThreshold),
				"enableEndUserSpamNotifications": llx.BoolData(p.EnableEndUserSpamNotifications),
				"allowedSenderDomains":           llx.ArrayData(llx.TArr2Raw([]string(p.AllowedSenderDomains)), types.String),
				"blockedSenderDomains":           llx.ArrayData(llx.TArr2Raw([]string(p.BlockedSenderDomains)), types.String),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Hosted outbound spam filter policies ---

type ExchangeHostedOutboundSpamFilterPolicy struct {
	Identity                                  string   `json:"Identity"`
	Name                                      string   `json:"Name"`
	RecipientLimitExternalPerHour             int64    `json:"RecipientLimitExternalPerHour"`
	RecipientLimitInternalPerHour             int64    `json:"RecipientLimitInternalPerHour"`
	RecipientLimitPerDay                      int64    `json:"RecipientLimitPerDay"`
	ActionWhenThresholdReached                string   `json:"ActionWhenThresholdReached"`
	AutoForwardingMode                        string   `json:"AutoForwardingMode"`
	BccSuspiciousOutboundMail                 bool     `json:"BccSuspiciousOutboundMail"`
	NotifyOutboundSpam                        bool     `json:"NotifyOutboundSpam"`
	Enabled                                   bool     `json:"Enabled"`
	BccSuspiciousOutboundAdditionalRecipients []string `json:"BccSuspiciousOutboundAdditionalRecipients"`
	NotifyOutboundSpamRecipients              []string `json:"NotifyOutboundSpamRecipients"`
}

func convertHostedOutboundSpamFilterPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeHostedOutboundSpamFilterPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.hostedOutboundSpamFilterPolicyEntry",
			map[string]*llx.RawData{
				"__id":                          llx.StringData("hostedOutboundSpamFilterPolicy-" + p.Identity),
				"identity":                      llx.StringData(p.Identity),
				"name":                          llx.StringData(p.Name),
				"recipientLimitExternalPerHour": llx.IntData(p.RecipientLimitExternalPerHour),
				"recipientLimitInternalPerHour": llx.IntData(p.RecipientLimitInternalPerHour),
				"recipientLimitPerDay":          llx.IntData(p.RecipientLimitPerDay),
				"actionWhenThresholdReached":    llx.StringData(p.ActionWhenThresholdReached),
				"autoForwardingMode":            llx.StringData(p.AutoForwardingMode),
				"bccSuspiciousOutboundMail":     llx.BoolData(p.BccSuspiciousOutboundMail),
				"notifyOutboundSpam":            llx.BoolData(p.NotifyOutboundSpam),
				"enabled":                       llx.BoolData(p.Enabled),
				"bccSuspiciousOutboundAdditionalRecipients": llx.ArrayData(llx.TArr2Raw(p.BccSuspiciousOutboundAdditionalRecipients), types.String),
				"notifyOutboundSpamRecipients":              llx.ArrayData(llx.TArr2Raw(p.NotifyOutboundSpamRecipients), types.String),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- DKIM signing configurations ---

type ExchangeDkimSigningConfig struct {
	Identity string `json:"Identity"`
	Domain   string `json:"Domain"`
	Enabled  bool   `json:"Enabled"`
	Status   string `json:"Status"`
}

func convertDkimSigningConfigs(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	configs, err := decodeExchangeList[ExchangeDkimSigningConfig](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, c := range configs {
		if c == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.dkimSigningConfigEntry",
			map[string]*llx.RawData{
				"__id":     llx.StringData("dkimSigningConfig-" + c.Identity),
				"identity": llx.StringData(c.Identity),
				"domain":   llx.StringData(c.Domain),
				"enabled":  llx.BoolData(c.Enabled),
				"status":   llx.StringData(c.Status),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Authentication policies ---

type ExchangeAuthenticationPolicy struct {
	Identity                           string `json:"Identity"`
	Name                               string `json:"Name"`
	AllowBasicAuthActiveSync           bool   `json:"AllowBasicAuthActiveSync"`
	AllowBasicAuthAutodiscover         bool   `json:"AllowBasicAuthAutodiscover"`
	AllowBasicAuthImap                 bool   `json:"AllowBasicAuthImap"`
	AllowBasicAuthMapi                 bool   `json:"AllowBasicAuthMapi"`
	AllowBasicAuthOfflineAddressBook   bool   `json:"AllowBasicAuthOfflineAddressBook"`
	AllowBasicAuthOutlookService       bool   `json:"AllowBasicAuthOutlookService"`
	AllowBasicAuthPop                  bool   `json:"AllowBasicAuthPop"`
	AllowBasicAuthPowershell           bool   `json:"AllowBasicAuthPowershell"`
	AllowBasicAuthReportingWebServices bool   `json:"AllowBasicAuthReportingWebServices"`
	AllowBasicAuthRpc                  bool   `json:"AllowBasicAuthRpc"`
	AllowBasicAuthSmtp                 bool   `json:"AllowBasicAuthSmtp"`
	AllowBasicAuthWebServices          bool   `json:"AllowBasicAuthWebServices"`
}

func convertAuthenticationPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeAuthenticationPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.authenticationPolicyEntry",
			map[string]*llx.RawData{
				"__id":                               llx.StringData("authenticationPolicy-" + p.Identity),
				"identity":                           llx.StringData(p.Identity),
				"name":                               llx.StringData(p.Name),
				"allowBasicAuthActiveSync":           llx.BoolData(p.AllowBasicAuthActiveSync),
				"allowBasicAuthAutodiscover":         llx.BoolData(p.AllowBasicAuthAutodiscover),
				"allowBasicAuthImap":                 llx.BoolData(p.AllowBasicAuthImap),
				"allowBasicAuthMapi":                 llx.BoolData(p.AllowBasicAuthMapi),
				"allowBasicAuthOfflineAddressBook":   llx.BoolData(p.AllowBasicAuthOfflineAddressBook),
				"allowBasicAuthOutlookService":       llx.BoolData(p.AllowBasicAuthOutlookService),
				"allowBasicAuthPop":                  llx.BoolData(p.AllowBasicAuthPop),
				"allowBasicAuthPowershell":           llx.BoolData(p.AllowBasicAuthPowershell),
				"allowBasicAuthReportingWebServices": llx.BoolData(p.AllowBasicAuthReportingWebServices),
				"allowBasicAuthRpc":                  llx.BoolData(p.AllowBasicAuthRpc),
				"allowBasicAuthSmtp":                 llx.BoolData(p.AllowBasicAuthSmtp),
				"allowBasicAuthWebServices":          llx.BoolData(p.AllowBasicAuthWebServices),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- OWA mailbox policies ---

type ExchangeOwaMailboxPolicy struct {
	Identity                                  string   `json:"Identity"`
	Name                                      string   `json:"Name"`
	AdditionalStorageProvidersAvailable       bool     `json:"AdditionalStorageProvidersAvailable"`
	DirectFileAccessOnPublicComputersEnabled  bool     `json:"DirectFileAccessOnPublicComputersEnabled"`
	DirectFileAccessOnPrivateComputersEnabled bool     `json:"DirectFileAccessOnPrivateComputersEnabled"`
	ForceSaveAttachmentFilteringEnabled       bool     `json:"ForceSaveAttachmentFilteringEnabled"`
	AllowedFileTypes                          []string `json:"AllowedFileTypes"`
	BlockedFileTypes                          []string `json:"BlockedFileTypes"`
	ActiveSyncIntegrationEnabled              bool     `json:"ActiveSyncIntegrationEnabled"`
	AllAddressListsEnabled                    bool     `json:"AllAddressListsEnabled"`
	AllowCopyContactsToDeviceAddressBook      bool     `json:"AllowCopyContactsToDeviceAddressBook"`
	BookingsEnabled                           bool     `json:"BookingsEnabled"`
	BookingsMailboxCreationEnabled            bool     `json:"BookingsMailboxCreationEnabled"`
	CalendarEnabled                           bool     `json:"CalendarEnabled"`
	ChangePasswordEnabled                     bool     `json:"ChangePasswordEnabled"`
	ContactsEnabled                           bool     `json:"ContactsEnabled"`
	FacebookEnabled                           bool     `json:"FacebookEnabled"`
	GroupCreationEnabled                      bool     `json:"GroupCreationEnabled"`
	InstantMessagingEnabled                   bool     `json:"InstantMessagingEnabled"`
	InterestingCalendarsEnabled               bool     `json:"InterestingCalendarsEnabled"`
	JournalEnabled                            bool     `json:"JournalEnabled"`
	LinkedInEnabled                           bool     `json:"LinkedInEnabled"`
	LocalEventsEnabled                        bool     `json:"LocalEventsEnabled"`
	NotesEnabled                              bool     `json:"NotesEnabled"`
	OfflineEnabledWeb                         bool     `json:"OfflineEnabledWeb"`
	OfflineEnabledWin                         bool     `json:"OfflineEnabledWin"`
	OneWinNativeOutlookEnabled                bool     `json:"OneWinNativeOutlookEnabled"`
	PlacesEnabled                             bool     `json:"PlacesEnabled"`
	PremiumClientEnabled                      bool     `json:"PremiumClientEnabled"`
	RecoverDeletedItemsEnabled                bool     `json:"RecoverDeletedItemsEnabled"`
	RemindersAndNotificationsEnabled          bool     `json:"RemindersAndNotificationsEnabled"`
	SignaturesEnabled                         bool     `json:"SignaturesEnabled"`
	TasksEnabled                              bool     `json:"TasksEnabled"`
	TextMessagingEnabled                      bool     `json:"TextMessagingEnabled"`
	ThemeSelectionEnabled                     bool     `json:"ThemeSelectionEnabled"`
	WSSAccessOnPrivateComputersEnabled        bool     `json:"WSSAccessOnPrivateComputersEnabled"`
	WSSAccessOnPublicComputersEnabled         bool     `json:"WSSAccessOnPublicComputersEnabled"`
	WeatherEnabled                            bool     `json:"WeatherEnabled"`
	// pointers: the cmdlet leaves these unset on a policy that never configured
	// them, and a plain bool would report an unconfigured policy as one that
	// disallows personal accounts
	PersonalAccountsEnabled         *bool `json:"PersonalAccountsEnabled"`
	PersonalAccountCalendarsEnabled *bool `json:"PersonalAccountCalendarsEnabled"`
}

func convertOwaMailboxPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeOwaMailboxPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.owaMailboxPolicyEntry",
			map[string]*llx.RawData{
				"__id":                                llx.StringData("owaMailboxPolicy-" + p.Identity),
				"identity":                            llx.StringData(p.Identity),
				"name":                                llx.StringData(p.Name),
				"additionalStorageProvidersAvailable": llx.BoolData(p.AdditionalStorageProvidersAvailable),
				"directFileAccessOnPublicComputersEnabled":  llx.BoolData(p.DirectFileAccessOnPublicComputersEnabled),
				"directFileAccessOnPrivateComputersEnabled": llx.BoolData(p.DirectFileAccessOnPrivateComputersEnabled),
				"forceSaveAttachmentFilteringEnabled":       llx.BoolData(p.ForceSaveAttachmentFilteringEnabled),
				"allowedFileTypes":                          llx.ArrayData(llx.TArr2Raw(p.AllowedFileTypes), types.String),
				"blockedFileTypes":                          llx.ArrayData(llx.TArr2Raw(p.BlockedFileTypes), types.String),
				"activeSyncIntegrationEnabled":              llx.BoolData(p.ActiveSyncIntegrationEnabled),
				"allAddressListsEnabled":                    llx.BoolData(p.AllAddressListsEnabled),
				"allowCopyContactsToDeviceAddressBook":      llx.BoolData(p.AllowCopyContactsToDeviceAddressBook),
				"bookingsEnabled":                           llx.BoolData(p.BookingsEnabled),
				"bookingsMailboxCreationEnabled":            llx.BoolData(p.BookingsMailboxCreationEnabled),
				"calendarEnabled":                           llx.BoolData(p.CalendarEnabled),
				"changePasswordEnabled":                     llx.BoolData(p.ChangePasswordEnabled),
				"contactsEnabled":                           llx.BoolData(p.ContactsEnabled),
				"facebookEnabled":                           llx.BoolData(p.FacebookEnabled),
				"groupCreationEnabled":                      llx.BoolData(p.GroupCreationEnabled),
				"instantMessagingEnabled":                   llx.BoolData(p.InstantMessagingEnabled),
				"interestingCalendarsEnabled":               llx.BoolData(p.InterestingCalendarsEnabled),
				"journalEnabled":                            llx.BoolData(p.JournalEnabled),
				"linkedInEnabled":                           llx.BoolData(p.LinkedInEnabled),
				"localEventsEnabled":                        llx.BoolData(p.LocalEventsEnabled),
				"notesEnabled":                              llx.BoolData(p.NotesEnabled),
				"offlineEnabledWeb":                         llx.BoolData(p.OfflineEnabledWeb),
				"offlineEnabledWin":                         llx.BoolData(p.OfflineEnabledWin),
				"oneWinNativeOutlookEnabled":                llx.BoolData(p.OneWinNativeOutlookEnabled),
				"placesEnabled":                             llx.BoolData(p.PlacesEnabled),
				"premiumClientEnabled":                      llx.BoolData(p.PremiumClientEnabled),
				"recoverDeletedItemsEnabled":                llx.BoolData(p.RecoverDeletedItemsEnabled),
				"remindersAndNotificationsEnabled":          llx.BoolData(p.RemindersAndNotificationsEnabled),
				"signaturesEnabled":                         llx.BoolData(p.SignaturesEnabled),
				"tasksEnabled":                              llx.BoolData(p.TasksEnabled),
				"textMessagingEnabled":                      llx.BoolData(p.TextMessagingEnabled),
				"themeSelectionEnabled":                     llx.BoolData(p.ThemeSelectionEnabled),
				"wssAccessOnPrivateComputersEnabled":        llx.BoolData(p.WSSAccessOnPrivateComputersEnabled),
				"wssAccessOnPublicComputersEnabled":         llx.BoolData(p.WSSAccessOnPublicComputersEnabled),
				"weatherEnabled":                            llx.BoolData(p.WeatherEnabled),
				"personalAccountsEnabled":                   llx.BoolDataPtr(p.PersonalAccountsEnabled),
				"personalAccountCalendarsEnabled":           llx.BoolDataPtr(p.PersonalAccountCalendarsEnabled),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Remote domains ---

type ExchangeRemoteDomain struct {
	Identity              string `json:"Identity"`
	Name                  string `json:"Name"`
	DomainName            string `json:"DomainName"`
	AllowedOOFType        string `json:"AllowedOOFType"`
	AutoReplyEnabled      bool   `json:"AutoReplyEnabled"`
	AutoForwardEnabled    bool   `json:"AutoForwardEnabled"`
	DeliveryReportEnabled bool   `json:"DeliveryReportEnabled"`
	NDREnabled            bool   `json:"NDREnabled"`
	IsInternal            bool   `json:"IsInternal"`
	ContentType           string `json:"ContentType"`

	MeetingForwardNotificationEnabled bool `json:"MeetingForwardNotificationEnabled"`
}

func convertRemoteDomains(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	domains, err := decodeExchangeList[ExchangeRemoteDomain](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, d := range domains {
		if d == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.remoteDomainEntry",
			map[string]*llx.RawData{
				"__id":                              llx.StringData("remoteDomain-" + d.Identity),
				"identity":                          llx.StringData(d.Identity),
				"name":                              llx.StringData(d.Name),
				"domainName":                        llx.StringData(d.DomainName),
				"allowedOOFType":                    llx.StringData(d.AllowedOOFType),
				"autoReplyEnabled":                  llx.BoolData(d.AutoReplyEnabled),
				"autoForwardEnabled":                llx.BoolData(d.AutoForwardEnabled),
				"deliveryReportEnabled":             llx.BoolData(d.DeliveryReportEnabled),
				"ndrEnabled":                        llx.BoolData(d.NDREnabled),
				"isInternal":                        llx.BoolData(d.IsInternal),
				"contentType":                       llx.StringData(d.ContentType),
				"meetingForwardNotificationEnabled": llx.BoolData(d.MeetingForwardNotificationEnabled),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Quarantine policies ---

type ExchangeQuarantinePolicy struct {
	Identity string `json:"Identity"`
	Name     string `json:"Name"`
	// EndUserQuarantinePermissionsValue is no longer returned by
	// Get-QuarantinePolicy; EndUserQuarantinePermissions carries the same data.
	EndUserQuarantinePermissionsValue *int64 `json:"EndUserQuarantinePermissionsValue"`
	// EndUserQuarantinePermissions is a string such as
	// "[PermissionToBlockSender: False\r\nPermissionToDelete: True\r\n...]".
	EndUserQuarantinePermissions string `json:"EndUserQuarantinePermissions"`
	ESNEnabled                   bool   `json:"ESNEnabled"`
}

// quarantinePermissionBits maps each end-user quarantine permission to its bit
// in EndUserQuarantinePermissionsValue, as documented for
// New-QuarantinePolicy -EndUserQuarantinePermissionsValue.
var quarantinePermissionBits = []struct {
	name  string // permission name in EndUserQuarantinePermissions
	field string // MQL field
	bit   int64
}{
	{"PermissionToViewHeader", "permissionToViewHeader", 128},
	{"PermissionToDownload", "permissionToDownload", 64},
	{"PermissionToAllowSender", "permissionToAllowSender", 32},
	{"PermissionToBlockSender", "permissionToBlockSender", 16},
	{"PermissionToRequestRelease", "permissionToRequestRelease", 8},
	{"PermissionToRelease", "permissionToRelease", 4},
	{"PermissionToPreview", "permissionToPreview", 2},
	{"PermissionToDelete", "permissionToDelete", 1},
}

// parseQuarantinePermissions parses the EndUserQuarantinePermissions string
// into permission name -> granted. Unknown or malformed lines are skipped.
func parseQuarantinePermissions(s string) map[string]bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	out := map[string]bool{}
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\r' || r == '\n' || r == ',' || r == ';' }) {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		b, err := strconv.ParseBool(strings.TrimSpace(val))
		if err != nil {
			continue
		}
		out[strings.TrimSpace(key)] = b
	}
	return out
}

// quarantinePolicyPermissions returns the bitmask and per-permission flags of a
// quarantine policy. The bitmask comes from EndUserQuarantinePermissionsValue
// when present, otherwise it is computed from EndUserQuarantinePermissions.
// Each flag comes from EndUserQuarantinePermissions when it names the
// permission, otherwise from the bitmask. With neither source, the bitmask
// and flags are null.
func quarantinePolicyPermissions(p *ExchangeQuarantinePolicy) (*int64, map[string]*bool) {
	parsed := parseQuarantinePermissions(p.EndUserQuarantinePermissions)
	flags := make(map[string]*bool, len(quarantinePermissionBits))

	mask := p.EndUserQuarantinePermissionsValue
	if mask == nil {
		var computed int64
		known := false
		for _, perm := range quarantinePermissionBits {
			granted, ok := parsed[perm.name]
			if !ok {
				continue
			}
			known = true
			if granted {
				computed |= perm.bit
			}
		}
		if known {
			mask = &computed
		}
	}

	for _, perm := range quarantinePermissionBits {
		if granted, ok := parsed[perm.name]; ok {
			flags[perm.field] = &granted
		} else if mask != nil {
			granted := *mask&perm.bit != 0
			flags[perm.field] = &granted
		} else {
			flags[perm.field] = nil
		}
	}
	return mask, flags
}

func convertQuarantinePolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeQuarantinePolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mask, flags := quarantinePolicyPermissions(p)
		args := map[string]*llx.RawData{
			"__id":                              llx.StringData("quarantinePolicy-" + p.Identity),
			"identity":                          llx.StringData(p.Identity),
			"name":                              llx.StringData(p.Name),
			"endUserQuarantinePermissionsValue": llx.IntDataPtr(mask),
			"esnEnabled":                        llx.BoolData(p.ESNEnabled),
		}
		for field, v := range flags {
			args[field] = llx.BoolDataPtr(v)
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.quarantinePolicyEntry", args)
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- ATP policy for Office 365 ---

type ExchangeAtpPolicyForO365 struct {
	Identity                string `json:"Identity"`
	Name                    string `json:"Name"`
	EnableSafeDocs          bool   `json:"EnableSafeDocs"`
	AllowSafeDocsOpen       bool   `json:"AllowSafeDocsOpen"`
	EnableATPForSPOTeamsODB bool   `json:"EnableATPForSPOTeamsODB"`
}

func convertAtpPoliciesForO365(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeAtpPolicyForO365](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.atpPolicyForO365Entry",
			map[string]*llx.RawData{
				"__id":                    llx.StringData("atpPolicyForO365-" + p.Identity),
				"identity":                llx.StringData(p.Identity),
				"name":                    llx.StringData(p.Name),
				"enableSafeDocs":          llx.BoolData(p.EnableSafeDocs),
				"allowSafeDocsOpen":       llx.BoolData(p.AllowSafeDocsOpen),
				"enableATPForSPOTeamsODB": llx.BoolData(p.EnableATPForSPOTeamsODB),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Sharing policies ---

type ExchangeSharingPolicy struct {
	Identity string             `json:"Identity"`
	Name     string             `json:"Name"`
	Enabled  bool               `json:"Enabled"`
	Default  bool               `json:"Default"`
	Domains  exchangeDomainList `json:"Domains"`
}

func convertSharingPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeSharingPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.sharingPolicyEntry",
			map[string]*llx.RawData{
				"__id":      llx.StringData("sharingPolicy-" + p.Identity),
				"identity":  llx.StringData(p.Identity),
				"name":      llx.StringData(p.Name),
				"enabled":   llx.BoolData(p.Enabled),
				"isDefault": llx.BoolData(p.Default),
				"domains":   llx.ArrayData(llx.TArr2Raw([]string(p.Domains)), types.String),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Role assignment policies ---

type ExchangeRoleAssignmentPolicy struct {
	Identity      string   `json:"Identity"`
	Name          string   `json:"Name"`
	IsDefault     bool     `json:"IsDefault"`
	Description   string   `json:"Description"`
	AssignedRoles []string `json:"AssignedRoles"`
}

func convertRoleAssignmentPolicies(r *mqlMs365Exchangeonline, raw any) ([]any, error) {
	policies, err := decodeExchangeList[ExchangeRoleAssignmentPolicy](raw)
	if err != nil {
		return nil, err
	}
	result := []any{}
	for _, p := range policies {
		if p == nil {
			continue
		}
		mql, err := CreateResource(r.MqlRuntime, "ms365.exchangeonline.roleAssignmentPolicyEntry",
			map[string]*llx.RawData{
				"__id":          llx.StringData("roleAssignmentPolicy-" + p.Identity),
				"identity":      llx.StringData(p.Identity),
				"name":          llx.StringData(p.Name),
				"isDefault":     llx.BoolData(p.IsDefault),
				"description":   llx.StringData(p.Description),
				"assignedRoles": llx.ArrayData(llx.TArr2Raw(p.AssignedRoles), types.String),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mql)
	}
	return result, nil
}

// --- Resource accessors (plural field name, singular element resource) ---

func (r *mqlMs365Exchangeonline) transportRules() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) antiPhishPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) safeLinksPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) safeAttachmentPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) malwareFilterPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) hostedContentFilterPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) hostedOutboundSpamFilterPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) dkimSigningConfigs() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) authenticationPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) owaMailboxPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) remoteDomains() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) quarantinePolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) atpPoliciesForO365() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) sharingPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

func (r *mqlMs365Exchangeonline) roleAssignmentPolicies() ([]any, error) {
	return nil, r.getExchangeReport()
}

// --- Preset security policy rules ---

// protectionPolicyRuleKinds maps a report section to the kind reported on each
// rule it produced. A preset security policy is turned on by one Exchange
// Online Protection rule and one Defender for Office 365 rule, and the two come
// from different cmdlets, so the kind is what tells them apart once they are
// merged into a single list.
type protectionPolicyRuleSection struct {
	kind string
	rows []any
}

// convertProtectionPolicyRules renders the rules that apply the built-in
// Standard and Strict preset security policies.
//
// The rows are read defensively rather than struct-decoded, the same way the
// DLP policies are: these cmdlets are served both by the admin REST endpoint
// and by the PowerShell module, and the two do not agree on how an enum or an
// empty multi-valued property serializes.
func convertProtectionPolicyRules(r *mqlMs365Exchangeonline, eopRows []any, atpRows []any) ([]any, error) {
	result := []any{}

	for _, section := range []protectionPolicyRuleSection{
		{kind: "eop", rows: eopRows},
		{kind: "atp", rows: atpRows},
	} {
		for _, item := range section.rows {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}

			identity := dlpString(m, "Identity")
			id := identity
			if id == "" {
				id = dlpString(m, "Name")
			}

			mql, err := CreateResource(r.MqlRuntime, ResourceMs365ExchangeonlineProtectionPolicyRule,
				protectionPolicyRuleFields(m, section.kind, id, identity))
			if err != nil {
				return nil, err
			}
			result = append(result, mql)
		}
	}

	return result, nil
}

// protectionPolicyRuleFields maps one rule row onto the resource's fields.
func protectionPolicyRuleFields(m map[string]any, kind string, id string, identity string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                      llx.StringData("protectionPolicyRule-" + kind + "-" + id),
		"identity":                  llx.StringData(identity),
		"name":                      llx.StringData(dlpString(m, "Name")),
		"kind":                      llx.StringData(kind),
		"state":                     llx.StringData(dlpString(m, "State")),
		"priority":                  llx.IntData(dlpInt(m, "Priority")),
		"eopProtectionPolicy":       llx.StringData(dlpString(m, "EOPProtectionPolicy")),
		"safeAttachmentPolicy":      llx.StringData(dlpString(m, "SafeAttachmentPolicy")),
		"safeLinksPolicy":           llx.StringData(dlpString(m, "SafeLinksPolicy")),
		"sentTo":                    llx.ArrayData(dlpStringSlice(m, "SentTo"), types.String),
		"sentToMemberOf":            llx.ArrayData(dlpStringSlice(m, "SentToMemberOf"), types.String),
		"recipientDomainIs":         llx.ArrayData(dlpStringSlice(m, "RecipientDomainIs"), types.String),
		"exceptIfSentTo":            llx.ArrayData(dlpStringSlice(m, "ExceptIfSentTo"), types.String),
		"exceptIfSentToMemberOf":    llx.ArrayData(dlpStringSlice(m, "ExceptIfSentToMemberOf"), types.String),
		"exceptIfRecipientDomainIs": llx.ArrayData(dlpStringSlice(m, "ExceptIfRecipientDomainIs"), types.String),
		"comment":                   llx.StringData(dlpString(m, "Comment")),
		"whenChanged":               llx.TimeDataPtr(dlpTime(m, "WhenChanged")),
	}
}
