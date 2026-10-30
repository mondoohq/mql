// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// exchangeAdminApiHost serves Exchange Online cmdlets. It is the host the
	// ExchangeOnlineManagement module connects to, and it accepts the token this
	// provider already acquires for outlookScope.
	//
	// Security & Compliance cmdlets are deliberately not served from here. That
	// workload sits behind a per-tenant regional host that has to be discovered
	// through a redirect before any cmdlet can run, so it stays on PowerShell.
	exchangeAdminApiHost = "https://outlook.office365.com"

	// exchangeSystemMailboxGuid is the organization system mailbox. The value is
	// the same in every organization and is the routing key app-only callers use
	// for operations that do not target a specific mailbox.
	exchangeSystemMailboxGuid = "bb558c35-97f1-4cb9-8ff7-d53741dc928c"

	// exchangeHTTPTimeout bounds a single cmdlet request. exchangeMaxPages caps
	// how many requests a walk makes but says nothing about how long one may
	// hang, and these requests do not go through an SDK pipeline that would
	// impose a deadline of its own. Sections run concurrently, so a stalled
	// connection to the admin host would otherwise hold the whole collection
	// rather than just its own section. Generous because some cmdlets are slow
	// on large tenants.
	exchangeHTTPTimeout = 2 * time.Minute

	// exchangeMaxPages bounds nextLink following so a service that keeps
	// handing back a continuation cannot spin forever.
	exchangeMaxPages = 512
)

// exchangeRestClient runs Exchange Online and Security & Compliance cmdlets
// over HTTPS instead of through a PowerShell session. Since EXO V3 every cmdlet
// is served by this endpoint and the module is only a client for it, so the
// rows returned here are the same objects the cmdlets emit, with their property
// names unchanged.
type exchangeRestClient struct {
	host         string
	tenantId     string
	organization string
	token        string
	httpClient   *http.Client
}

func newExchangeRestClient(host string, tenantId string, organization string, token string) *exchangeRestClient {
	return &exchangeRestClient{
		host:         host,
		tenantId:     tenantId,
		organization: organization,
		token:        token,
		httpClient:   &http.Client{Timeout: exchangeHTTPTimeout},
	}
}

// exchangeHTTPError is a non-2xx response from the admin endpoint, carrying the
// status so a caller can tell why the request failed rather than only that it
// did.
type exchangeHTTPError struct {
	StatusCode int
	msg        string
}

func (e *exchangeHTTPError) Error() string { return e.msg }

// exchangeErrorIsTransient reports whether err is the service asking to be
// tried again later rather than saying it cannot serve this caller at all.
//
// It decides whether the PowerShell fallback is worth taking. The
// ExchangeOnlineManagement module is a client for this same endpoint, so
// falling back on a throttle or an outage does not route around anything: it
// reissues the same request over a slower transport, gets throttled again, and
// reports it as a PowerShell failure with the original status lost. Falling
// back is only meaningful when the endpoint or the credential cannot serve the
// request at all, which is what the remaining statuses mean.
func exchangeErrorIsTransient(err error) bool {
	if httpErr, ok := errors.AsType[*exchangeHTTPError](err); ok {
		return httpErr.StatusCode == http.StatusRequestTimeout ||
			httpErr.StatusCode == http.StatusTooManyRequests ||
			httpErr.StatusCode >= 500
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

type exchangeCmdletInput struct {
	CmdletName string         `json:"CmdletName"`
	Parameters map[string]any `json:"Parameters,omitempty"`
}

type exchangeCmdletRequest struct {
	CmdletInput exchangeCmdletInput `json:"CmdletInput"`
}

type exchangeCmdletResponse struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// anchorMailbox is the routing hint the service uses to reach the right backend.
// App-only callers with no specific mailbox target address the organization
// system mailbox.
func (c *exchangeRestClient) anchorMailbox() string {
	return fmt.Sprintf("APP:SystemMailbox{%s}@%s", exchangeSystemMailboxGuid, c.organization)
}

func (c *exchangeRestClient) invokeUrl(selects []string) string {
	u := fmt.Sprintf("%s/adminapi/beta/%s/InvokeCommand", c.host, c.tenantId)
	if len(selects) > 0 {
		u += "?$select=" + url.QueryEscape(strings.Join(selects, ","))
	}
	return u
}

// invoke runs one cmdlet and returns every row it produced. Results that arrive
// in pages are followed through @odata.nextLink so a large collection is never
// silently truncated at the service page limit.
func (c *exchangeRestClient) invoke(ctx context.Context, cmdlet string, params map[string]any, selects ...string) ([]json.RawMessage, error) {
	body, err := json.Marshal(exchangeCmdletRequest{
		CmdletInput: exchangeCmdletInput{CmdletName: cmdlet, Parameters: params},
	})
	if err != nil {
		return nil, err
	}

	rows := []json.RawMessage{}
	next := c.invokeUrl(selects)
	seen := map[string]struct{}{}

	for page := 0; next != ""; page++ {
		if page >= exchangeMaxPages {
			return nil, fmt.Errorf("%s returned more than %d pages", cmdlet, exchangeMaxPages)
		}
		// a service that echoes the same continuation would otherwise loop
		if _, repeated := seen[next]; repeated {
			return nil, fmt.Errorf("%s repeated the same continuation link", cmdlet)
		}
		seen[next] = struct{}{}

		resp, err := c.post(ctx, next, body, cmdlet)
		if err != nil {
			return nil, err
		}
		rows = append(rows, resp.Value...)
		next = resp.NextLink
	}

	return rows, nil
}

func (c *exchangeRestClient) post(ctx context.Context, url string, body []byte, cmdlet string) (*exchangeCmdletResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-AnchorMailbox", c.anchorMailbox())
	// ask for the largest page the service serves, so a big collection costs
	// fewer round trips
	req.Header.Set("Prefer", "odata.maxpagesize=1000")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &exchangeHTTPError{
				StatusCode: resp.StatusCode,
				msg:        fmt.Sprintf("access denied running %s, please ensure the credentials have the right permissions and Exchange RBAC roles (status %d)", cmdlet, resp.StatusCode),
			}
		}
		return nil, &exchangeHTTPError{
			StatusCode: resp.StatusCode,
			msg:        fmt.Sprintf("%s failed with status %d: %s", cmdlet, resp.StatusCode, string(raw)),
		}
	}

	out := &exchangeCmdletResponse{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("cannot decode %s response: %w", cmdlet, err)
	}
	return out, nil
}

// decodeRows decodes cmdlet rows into a typed slice. An empty result decodes to
// an empty (non-nil) slice, which is how a cmdlet that ran but matched nothing
// is represented.
func decodeRows[T any](rows []json.RawMessage) ([]T, error) {
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		var item T
		if err := json.Unmarshal(row, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// decodeSingle decodes the first row of a cmdlet that describes one object.
// Get-OrganizationConfig and friends are single-object cmdlets whose value the
// PowerShell report stored unwrapped, so the same unwrapping happens here to
// keep the field shape identical.
func decodeSingle(rows []json.RawMessage) (any, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	var item any
	if err := json.Unmarshal(rows[0], &item); err != nil {
		return nil, err
	}
	return item, nil
}

// exchangeSection is one cmdlet call and the report field it fills.
type exchangeSection struct {
	// name identifies the section in error messages
	name string
	// cmdlet is the Exchange cmdlet to run
	cmdlet string
	// params are the cmdlet parameters, matching what the PowerShell report passed
	params map[string]any
	// selects restricts the returned properties, standing in for Select-Object
	selects []string
	// assign decodes the rows into the report
	assign func(rows []json.RawMessage, report *ExchangeOnlineReport) error
}

// exchangeReportSections mirrors the cmdlets the PowerShell report ran, in the
// same order, with the same parameters.
//
// Get-EXOMailbox is the one substitution: it is implemented by the
// ExchangeOnlineManagement module rather than by the service, so the shared
// mailbox list comes from Get-Mailbox with the same filter. Both cmdlets return
// Identity and ExternalDirectoryObjectId, which are the only properties the
// report consumes.
func exchangeReportSections() []exchangeSection {
	unlimited := map[string]any{"ResultSize": "Unlimited"}

	return []exchangeSection{
		{
			name: "MailboxAuditBypassAssociation", cmdlet: "Get-MailboxAuditBypassAssociation", params: unlimited,
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[MailboxAuditBypassAssociation](rows)
				r.MailboxAuditBypassAssociation = out
				return err
			},
		},
		{
			name: "MalwareFilterPolicy", cmdlet: "Get-MalwareFilterPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.MalwareFilterPolicy = out
				return err
			},
		},
		{
			name: "HostedOutboundSpamFilterPolicy", cmdlet: "Get-HostedOutboundSpamFilterPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.HostedOutboundSpamFilterPolicy = out
				return err
			},
		},
		{
			name: "HostedContentFilterPolicy", cmdlet: "Get-HostedContentFilterPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.HostedContentFilterPolicy = out
				return err
			},
		},
		{
			name: "TransportRule", cmdlet: "Get-TransportRule",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.TransportRule = out
				return err
			},
		},
		{
			// the PowerShell report asked for the Default remote domain only
			name: "RemoteDomain", cmdlet: "Get-RemoteDomain", params: map[string]any{"Identity": "Default"},
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.RemoteDomain = out
				return err
			},
		},
		{
			name: "SafeLinksPolicy", cmdlet: "Get-SafeLinksPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.SafeLinksPolicy = out
				return err
			},
		},
		{
			name: "SafeAttachmentPolicy", cmdlet: "Get-SafeAttachmentPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.SafeAttachmentPolicy = out
				return err
			},
		},
		{
			name: "OrganizationConfig", cmdlet: "Get-OrganizationConfig",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeSingle(rows)
				r.OrganizationConfig = out
				return err
			},
		},
		{
			name: "AuthenticationPolicy", cmdlet: "Get-AuthenticationPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.AuthenticationPolicy = out
				return err
			},
		},
		{
			name: "AntiPhishPolicy", cmdlet: "Get-AntiPhishPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.AntiPhishPolicy = out
				return err
			},
		},
		{
			name: "DkimSigningConfig", cmdlet: "Get-DkimSigningConfig",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.DkimSigningConfig = out
				return err
			},
		},
		{
			name: "OwaMailboxPolicy", cmdlet: "Get-OwaMailboxPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.OwaMailboxPolicy = out
				return err
			},
		},
		{
			name: "AdminAuditLogConfig", cmdlet: "Get-AdminAuditLogConfig",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeSingle(rows)
				r.AdminAuditLogConfig = out
				return err
			},
		},
		{
			name: "PhishFilterPolicy", cmdlet: "Get-PhishFilterPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.PhishFilterPolicy = out
				return err
			},
		},
		{
			name: "QuarantinePolicy", cmdlet: "Get-QuarantinePolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.QuarantinePolicy = out
				return err
			},
		},
		{
			name: "JournalRule", cmdlet: "Get-JournalRule",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[JournalRule](rows)
				r.JournalRules = out
				return err
			},
		},
		{
			name: "MailboxPlan", cmdlet: "Get-MailboxPlan",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[MailboxPlan](rows)
				r.MailboxPlans = out
				return err
			},
		},
		{
			name: "RetentionPolicy", cmdlet: "Get-RetentionPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[RetentionPolicy](rows)
				r.RetentionPolicies = out
				return err
			},
		},
		{
			name: "Mailbox", cmdlet: "Get-Mailbox", params: unlimited,
			selects: []string{
				"Identity", "DisplayName", "PrimarySmtpAddress", "RecipientTypeDetails",
				"AuditEnabled", "AuditAdmin", "AuditDelegate", "AuditOwner", "AuditLogAgeLimit",
			},
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[MailboxWithAudit](rows)
				r.Mailbox = out
				return err
			},
		},
		{
			name: "AtpPolicyForO365", cmdlet: "Get-AtpPolicyForO365",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.AtpPolicyForO365 = out
				return err
			},
		},
		{
			name: "SharingPolicy", cmdlet: "Get-SharingPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.SharingPolicy = out
				return err
			},
		},
		{
			name: "RoleAssignmentPolicy", cmdlet: "Get-RoleAssignmentPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.RoleAssignmentPolicy = out
				return err
			},
		},
		{
			name: "ExternalInOutlook", cmdlet: "Get-ExternalInOutlook",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[*ExternalSender](rows)
				r.ExternalInOutlook = out
				return err
			},
		},
		{
			name:    "ExoMailbox",
			cmdlet:  "Get-Mailbox",
			params:  map[string]any{"ResultSize": "Unlimited", "RecipientTypeDetails": "SharedMailbox"},
			selects: []string{"Identity", "ExternalDirectoryObjectId"},
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[*ExoMailbox](rows)
				r.ExoMailbox = out
				return err
			},
		},
		{
			name: "TeamsProtectionPolicy", cmdlet: "Get-TeamsProtectionPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[*TeamsProtectionPolicy](rows)
				r.TeamsProtectionPolicy = out
				return err
			},
		},
		{
			name: "ReportSubmissionPolicy", cmdlet: "Get-ReportSubmissionPolicy",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[*ReportSubmissionPolicy](rows)
				r.ReportSubmissionPolicy = out
				return err
			},
		},
		{
			name: "EmailTenantSettings", cmdlet: "Get-EmailTenantSettings",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeSingle(rows)
				r.EmailTenantSettings = out
				return err
			},
		},
		{
			name: "EOPProtectionPolicyRule", cmdlet: "Get-EOPProtectionPolicyRule",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.EOPProtectionPolicyRule = out
				return err
			},
		},
		{
			name: "ATPProtectionPolicyRule", cmdlet: "Get-ATPProtectionPolicyRule",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				out, err := decodeRows[any](rows)
				r.ATPProtectionPolicyRule = out
				return err
			},
		},
		{
			name: "TransportConfig", cmdlet: "Get-TransportConfig",
			assign: func(rows []json.RawMessage, r *ExchangeOnlineReport) error {
				if len(rows) == 0 {
					return nil
				}
				out := &TransportConfig{}
				if err := json.Unmarshal(rows[0], out); err != nil {
					return err
				}
				r.TransportConfig = out
				return nil
			},
		},
	}
}

// exchangeSectionConcurrency bounds how many cmdlets run at once. The single
// PowerShell session ran them one after another; a small pool keeps the
// wall-clock cost down without hammering the service into throttling.
const exchangeSectionConcurrency = 6

// runExchangeSections executes every section and returns the sections that
// failed keyed by name. A cmdlet failure leaves its report field unset, which
// matches the PowerShell report: it did not stop on error, so a cmdlet that
// failed left its variable null and the corresponding MQL field null.
func runExchangeSections(ctx context.Context, client *exchangeRestClient, sections []exchangeSection, report *ExchangeOnlineReport) map[string]error {
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		failures = map[string]error{}
		sem      = make(chan struct{}, exchangeSectionConcurrency)
	)

	for i := range sections {
		section := sections[i]
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()

			rows, err := client.invoke(ctx, section.cmdlet, section.params, section.selects...)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[section.name] = err
				return
			}
			if err := section.assign(rows, report); err != nil {
				failures[section.name] = err
			}
		})
	}
	wg.Wait()

	return failures
}

// fetchExchangeReportViaRest builds the Exchange Online report from the admin
// endpoint. It fails only when no section succeeded, which is the signal that
// the endpoint or the credential is unusable and the PowerShell path should be
// tried instead. A partial result is returned as-is so one unavailable cmdlet
// does not cost the whole report.
func fetchExchangeReportViaRest(ctx context.Context, client *exchangeRestClient) (*ExchangeOnlineReport, map[string]error, error) {
	report := &ExchangeOnlineReport{}
	sections := exchangeReportSections()
	failures := runExchangeSections(ctx, client, sections, report)

	if len(failures) == len(sections) {
		return nil, failures, fmt.Errorf("every exchange cmdlet failed, first error: %w", anyError(failures))
	}
	return report, failures, nil
}

// fetchHostedConnectionFilterPolicyViaRest reads the default connection filter
// policy, the IP allow and block lists used for mail flow.
func fetchHostedConnectionFilterPolicyViaRest(ctx context.Context, client *exchangeRestClient) (*HostedConnectionFilterPolicyReport, error) {
	rows, err := client.invoke(ctx, "Get-HostedConnectionFilterPolicy", map[string]any{"Identity": "Default"})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no hosted connection filter policy returned")
	}

	policy := &HostedConnectionFilterPolicyData{}
	if err := json.Unmarshal(rows[0], policy); err != nil {
		return nil, err
	}
	return &HostedConnectionFilterPolicyReport{HostedConnectionFilterPolicy: policy}, nil
}

// anyError returns one error from the map so a caller can report a cause. Map
// iteration order is unspecified, so the name is included to keep the message
// self-explanatory.
func anyError(failures map[string]error) error {
	for name, err := range failures {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}
