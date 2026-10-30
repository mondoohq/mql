// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testClient(host string) *exchangeRestClient {
	return newExchangeRestClient(host, "tenant-guid", "contoso.onmicrosoft.com", "tok-123")
}

func TestExchangeAnchorMailbox(t *testing.T) {
	// app-only callers with no specific mailbox target address the organization
	// system mailbox, whose guid is the same in every organization
	c := testClient("https://outlook.office365.com")
	assert.Equal(t,
		"APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@contoso.onmicrosoft.com",
		c.anchorMailbox())
}

func TestExchangeInvokeUrl(t *testing.T) {
	c := testClient("https://outlook.office365.com")

	assert.Equal(t,
		"https://outlook.office365.com/adminapi/beta/tenant-guid/InvokeCommand",
		c.invokeUrl(nil))

	assert.Equal(t,
		"https://outlook.office365.com/adminapi/beta/tenant-guid/InvokeCommand?$select=Identity%2CDisplayName",
		c.invokeUrl([]string{"Identity", "DisplayName"}))
}

func TestExchangeInvokeRequestShape(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotQuery  string
		gotHeader http.Header
		gotBody   exchangeCmdletRequest
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotHeader = r.Header.Clone()
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		fmt.Fprint(w, `{"value":[]}`)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).invoke(context.Background(), "Get-Mailbox",
		map[string]any{"ResultSize": "Unlimited"}, "Identity")
	require.NoError(t, err)

	// every cmdlet, including Get-*, is a POST
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/adminapi/beta/tenant-guid/InvokeCommand", gotPath)
	assert.Contains(t, gotQuery, "select=Identity")

	assert.Equal(t, "Bearer tok-123", gotHeader.Get("Authorization"))
	assert.Equal(t, "application/json", gotHeader.Get("Content-Type"))
	// routing hint is mandatory; without it the service can fail the request
	assert.Contains(t, gotHeader.Get("X-AnchorMailbox"), "APP:SystemMailbox{")
	assert.Equal(t, "odata.maxpagesize=1000", gotHeader.Get("Prefer"))

	assert.Equal(t, "Get-Mailbox", gotBody.CmdletInput.CmdletName)
	assert.Equal(t, "Unlimited", gotBody.CmdletInput.Parameters["ResultSize"])
}

func TestExchangeInvokeSinglePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"value":[{"Name":"a"},{"Name":"b"}]}`)
	}))
	defer srv.Close()

	rows, err := testClient(srv.URL).invoke(context.Background(), "Get-JournalRule", nil)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.JSONEq(t, `{"Name":"a"}`, string(rows[0]))
}

func TestExchangeInvokeFollowsNextLink(t *testing.T) {
	// Get-Mailbox on a large tenant pages; dropping the continuation would
	// silently report a truncated mailbox list as the whole tenant
	var srv *httptest.Server
	var calls atomic.Int32
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch n {
		case 1:
			fmt.Fprintf(w, `{"value":[{"Identity":"m1"}],"@odata.nextLink":%q}`, srv.URL+"/page2")
		case 2:
			fmt.Fprintf(w, `{"value":[{"Identity":"m2"}],"@odata.nextLink":%q}`, srv.URL+"/page3")
		default:
			fmt.Fprint(w, `{"value":[{"Identity":"m3"}]}`)
		}
	}))
	defer srv.Close()

	rows, err := testClient(srv.URL).invoke(context.Background(), "Get-Mailbox", nil)
	require.NoError(t, err)

	got, err := decodeRows[MailboxWithAudit](rows)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "m1", got[0].Identity)
	assert.Equal(t, "m3", got[2].Identity)
	assert.Equal(t, int32(3), calls.Load())
}

func TestExchangeInvokeRejectsRepeatedContinuation(t *testing.T) {
	// a service that echoes the same continuation would otherwise spin forever
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"value":[{"Name":"a"}],"@odata.nextLink":%q}`, srv.URL+"/same")
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).invoke(context.Background(), "Get-TransportRule", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "same continuation")
}

func TestExchangeInvokeErrors(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprintf("access denied on %d", status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()

			_, err := testClient(srv.URL).invoke(context.Background(), "Get-OrganizationConfig", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "access denied")
			assert.Contains(t, err.Error(), "Get-OrganizationConfig")
		})
	}

	t.Run("other status carries cmdlet, code and body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "unsupported parameter")
		}))
		defer srv.Close()

		_, err := testClient(srv.URL).invoke(context.Background(), "Get-RemoteDomain", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Get-RemoteDomain")
		assert.Contains(t, err.Error(), "400")
		assert.Contains(t, err.Error(), "unsupported parameter")
	})

	t.Run("malformed body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"value":`)
		}))
		defer srv.Close()

		_, err := testClient(srv.URL).invoke(context.Background(), "Get-TransportConfig", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot decode")
	})
}

func TestDecodeRows(t *testing.T) {
	t.Run("empty is non-nil", func(t *testing.T) {
		// a cmdlet that ran but matched nothing must produce an empty list, not
		// a null one: the report distinguishes the two
		out, err := decodeRows[JournalRule](nil)
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Empty(t, out)
	})

	t.Run("typed decode keeps cmdlet property names", func(t *testing.T) {
		rows := []json.RawMessage{
			json.RawMessage(`{"Name":"jr1","JournalEmailAddress":"j@contoso.com","Scope":"Global","Enabled":true}`),
		}
		out, err := decodeRows[JournalRule](rows)
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "jr1", out[0].Name)
		assert.Equal(t, "j@contoso.com", out[0].JournalEmailAddress)
		assert.True(t, out[0].Enabled)
	})

	t.Run("decode failure surfaces", func(t *testing.T) {
		_, err := decodeRows[JournalRule]([]json.RawMessage{json.RawMessage(`{"Name":`)})
		require.Error(t, err)
	})
}

func TestDecodeSingle(t *testing.T) {
	t.Run("no rows is nil", func(t *testing.T) {
		out, err := decodeSingle(nil)
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("unwraps the first row", func(t *testing.T) {
		// Get-OrganizationConfig is a single-object cmdlet; the report stored it
		// unwrapped, so an array here would change the field shape
		out, err := decodeSingle([]json.RawMessage{json.RawMessage(`{"Name":"contoso"}`)})
		require.NoError(t, err)
		obj, ok := out.(map[string]any)
		require.True(t, ok, "expected a bare object, not a list")
		assert.Equal(t, "contoso", obj["Name"])
	})
}

func TestExchangeReportSectionsSpec(t *testing.T) {
	sections := map[string]exchangeSection{}
	for _, s := range exchangeReportSections() {
		require.NotContains(t, sections, s.name, "duplicate section name")
		sections[s.name] = s
	}

	t.Run("remote domain asks for the default domain", func(t *testing.T) {
		assert.Equal(t, "Default", sections["RemoteDomain"].params["Identity"])
	})

	t.Run("mailbox is unlimited and selects the audit properties", func(t *testing.T) {
		s := sections["Mailbox"]
		assert.Equal(t, "Unlimited", s.params["ResultSize"])
		assert.ElementsMatch(t, []string{
			"Identity", "DisplayName", "PrimarySmtpAddress", "RecipientTypeDetails",
			"AuditEnabled", "AuditAdmin", "AuditDelegate", "AuditOwner", "AuditLogAgeLimit",
		}, s.selects)
	})

	t.Run("shared mailboxes come from Get-Mailbox with the same filter", func(t *testing.T) {
		// Get-EXOMailbox is a module cmdlet rather than a service one, so the
		// shared mailbox list is filtered server side instead
		s := sections["ExoMailbox"]
		assert.Equal(t, "Get-Mailbox", s.cmdlet)
		assert.Equal(t, "SharedMailbox", s.params["RecipientTypeDetails"])
		assert.Equal(t, "Unlimited", s.params["ResultSize"])
		assert.ElementsMatch(t, []string{"Identity", "ExternalDirectoryObjectId"}, s.selects)
	})

	t.Run("audit bypass association is unlimited", func(t *testing.T) {
		assert.Equal(t, "Unlimited", sections["MailboxAuditBypassAssociation"].params["ResultSize"])
	})

	t.Run("covers every cmdlet the powershell report ran", func(t *testing.T) {
		for _, name := range []string{
			"MalwareFilterPolicy", "HostedOutboundSpamFilterPolicy", "HostedContentFilterPolicy",
			"TransportRule", "RemoteDomain", "SafeLinksPolicy", "SafeAttachmentPolicy",
			"OrganizationConfig", "AuthenticationPolicy", "AntiPhishPolicy", "DkimSigningConfig",
			"OwaMailboxPolicy", "AdminAuditLogConfig", "PhishFilterPolicy", "QuarantinePolicy",
			"JournalRule", "MailboxPlan", "RetentionPolicy", "Mailbox", "AtpPolicyForO365",
			"SharingPolicy", "RoleAssignmentPolicy", "ExternalInOutlook", "ExoMailbox",
			"TeamsProtectionPolicy", "ReportSubmissionPolicy", "TransportConfig",
			"MailboxAuditBypassAssociation",
		} {
			assert.Contains(t, sections, name)
		}
	})
}

// exchangeRowServer answers every InvokeCommand with the rows registered for
// the requested cmdlet, and fails the cmdlets listed in broken.
func exchangeRowServer(t *testing.T, rows map[string]string, broken map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req exchangeCmdletRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))

		if broken[req.CmdletInput.CmdletName] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if body, ok := rows[req.CmdletInput.CmdletName]; ok {
			fmt.Fprintf(w, `{"value":%s}`, body)
			return
		}
		fmt.Fprint(w, `{"value":[]}`)
	}))
}

func TestFetchExchangeReportViaRest(t *testing.T) {
	t.Run("builds the report and keeps single objects unwrapped", func(t *testing.T) {
		srv := exchangeRowServer(t, map[string]string{
			"Get-OrganizationConfig": `[{"Name":"contoso","MailTipsAllTipsEnabled":true}]`,
			"Get-TransportConfig":    `[{"SmtpClientAuthenticationDisabled":true}]`,
			"Get-JournalRule":        `[{"Name":"jr1","Enabled":true}]`,
			"Get-TransportRule":      `[{"Name":"tr1"},{"Name":"tr2"}]`,
		}, nil)
		defer srv.Close()

		report, failures, err := fetchExchangeReportViaRest(context.Background(), testClient(srv.URL))
		require.NoError(t, err)
		assert.Empty(t, failures)

		// single-object cmdlets stay bare, matching the powershell report
		orgConfig, ok := report.OrganizationConfig.(map[string]any)
		require.True(t, ok, "OrganizationConfig must be an object, not a list")
		assert.Equal(t, "contoso", orgConfig["Name"])

		require.NotNil(t, report.TransportConfig)
		assert.True(t, report.TransportConfig.SmtpClientAuthenticationDisabled)

		require.Len(t, report.JournalRules, 1)
		assert.Equal(t, "jr1", report.JournalRules[0].Name)
		assert.Len(t, report.TransportRule, 2)
	})

	t.Run("a failing cmdlet leaves its field null and spares the others", func(t *testing.T) {
		// the powershell report did not stop on error either: a cmdlet that
		// failed left its variable null and the matching field null
		srv := exchangeRowServer(t,
			map[string]string{"Get-TransportRule": `[{"Name":"tr1"}]`},
			map[string]bool{"Get-AntiPhishPolicy": true})
		defer srv.Close()

		report, failures, err := fetchExchangeReportViaRest(context.Background(), testClient(srv.URL))
		require.NoError(t, err)

		require.Contains(t, failures, "AntiPhishPolicy")
		assert.Nil(t, report.AntiPhishPolicy)
		assert.Len(t, report.TransportRule, 1)
	})

	t.Run("every cmdlet failing is a report failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		_, _, err := fetchExchangeReportViaRest(context.Background(), testClient(srv.URL))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "every exchange cmdlet failed")
	})

	t.Run("a cmdlet that matched nothing yields an empty, non-null list", func(t *testing.T) {
		srv := exchangeRowServer(t, nil, nil)
		defer srv.Close()

		report, _, err := fetchExchangeReportViaRest(context.Background(), testClient(srv.URL))
		require.NoError(t, err)
		require.NotNil(t, report.TransportRule)
		assert.Empty(t, report.TransportRule)
	})
}

func TestFetchHostedConnectionFilterPolicyViaRest(t *testing.T) {
	t.Run("reads the default policy", func(t *testing.T) {
		var got exchangeCmdletRequest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
			fmt.Fprint(w, `{"value":[{"Identity":"Default","EnableSafeList":true,
			  "IPAllowList":["1.2.3.4"],"IPBlockList":["5.6.7.8"]}]}`)
		}))
		defer srv.Close()

		report, err := fetchHostedConnectionFilterPolicyViaRest(context.Background(), testClient(srv.URL))
		require.NoError(t, err)

		assert.Equal(t, "Get-HostedConnectionFilterPolicy", got.CmdletInput.CmdletName)
		assert.Equal(t, "Default", got.CmdletInput.Parameters["Identity"])

		policy := report.HostedConnectionFilterPolicy
		require.NotNil(t, policy)
		assert.Equal(t, "Default", policy.Identity)
		assert.True(t, policy.EnableSafeList)
		assert.Equal(t, []string{"1.2.3.4"}, policy.IPAllowList)
		assert.Equal(t, []string{"5.6.7.8"}, policy.IPBlockList)
	})

	t.Run("no policy is an error rather than a blank policy", func(t *testing.T) {
		// a zero-value policy would report an empty IP allow list as fact
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"value":[]}`)
		}))
		defer srv.Close()

		_, err := fetchHostedConnectionFilterPolicyViaRest(context.Background(), testClient(srv.URL))
		require.Error(t, err)
	})
}

// The REST rows and the PowerShell JSON must land in the same report shape, or
// a policy reading these dict fields would see different data depending on
// which transport served the scan.
func TestRestAndPowershellReportsAgree(t *testing.T) {
	powershellJson := `{
	  "OrganizationConfig": {"Name":"contoso","MailTipsAllTipsEnabled":true},
	  "TransportRule": [{"Name":"tr1","State":"Enabled"}],
	  "JournalRule": [{"Name":"jr1","Enabled":true,"Scope":"Global"}],
	  "TransportConfig": {"SmtpClientAuthenticationDisabled":true}
	}`

	fromPowershell := &ExchangeOnlineReport{}
	require.NoError(t, json.Unmarshal([]byte(powershellJson), fromPowershell))

	srv := exchangeRowServer(t, map[string]string{
		"Get-OrganizationConfig": `[{"Name":"contoso","MailTipsAllTipsEnabled":true}]`,
		"Get-TransportRule":      `[{"Name":"tr1","State":"Enabled"}]`,
		"Get-JournalRule":        `[{"Name":"jr1","Enabled":true,"Scope":"Global"}]`,
		"Get-TransportConfig":    `[{"SmtpClientAuthenticationDisabled":true}]`,
	}, nil)
	defer srv.Close()

	fromRest, _, err := fetchExchangeReportViaRest(context.Background(), testClient(srv.URL))
	require.NoError(t, err)

	assert.Equal(t, fromPowershell.OrganizationConfig, fromRest.OrganizationConfig)
	assert.Equal(t, fromPowershell.TransportRule, fromRest.TransportRule)
	assert.Equal(t, fromPowershell.JournalRules, fromRest.JournalRules)
	assert.Equal(t, fromPowershell.TransportConfig, fromRest.TransportConfig)
}

// TestExchangeErrorIsTransient pins which failures take the PowerShell
// fallback. PowerShell reaches the same endpoint, so falling back on a
// throttle repeats the throttle over a slower transport and reports it as a
// PowerShell failure; the fallback is only worth taking when the endpoint or
// the credential cannot serve the request at all.
func TestExchangeErrorIsTransient(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"throttled", &exchangeHTTPError{StatusCode: http.StatusTooManyRequests}, true},
		{"request timeout", &exchangeHTTPError{StatusCode: http.StatusRequestTimeout}, true},
		{"internal server error", &exchangeHTTPError{StatusCode: http.StatusInternalServerError}, true},
		{"bad gateway", &exchangeHTTPError{StatusCode: http.StatusBadGateway}, true},
		{"service unavailable", &exchangeHTTPError{StatusCode: http.StatusServiceUnavailable}, true},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("get org config: %w", context.DeadlineExceeded), true},

		{"unauthorized", &exchangeHTTPError{StatusCode: http.StatusUnauthorized}, false},
		{"forbidden", &exchangeHTTPError{StatusCode: http.StatusForbidden}, false},
		{"not found", &exchangeHTTPError{StatusCode: http.StatusNotFound}, false},
		{"bad request", &exchangeHTTPError{StatusCode: http.StatusBadRequest}, false},
		{"wrapped forbidden", fmt.Errorf("run cmdlet: %w", &exchangeHTTPError{StatusCode: http.StatusForbidden}), false},
		{"a plain error is not assumed transient", errors.New("boom"), false},
		{"no error", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, exchangeErrorIsTransient(tc.err))
		})
	}
}

// A non-2xx response has to carry its status out of post, or the caller cannot
// tell a throttle from a permission problem and falls back on both.
func TestPostReturnsATypedStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"throttled"}`)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).invoke(context.Background(), "Get-OrganizationConfig", nil)
	require.Error(t, err)

	var httpErr *exchangeHTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusTooManyRequests, httpErr.StatusCode)
	assert.True(t, exchangeErrorIsTransient(err), "a 429 must not take the powershell fallback")
}
