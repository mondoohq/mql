// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---------------------------------------------------------------------------
// Conditional Access references
// ---------------------------------------------------------------------------

type fakeRefResource struct{ id string }

func (f *fakeRefResource) MqlID() string   { return f.id }
func (f *fakeRefResource) MqlName() string { return "fake" }

const (
	liveObjectID    = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	deletedObjectID = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
	deniedObjectID  = "1b2c3d4e-5f6a-4b7c-9d8e-9f0a1b2c3d4e"
)

func TestTransformErrorKeepsGraphErrorCode(t *testing.T) {
	// every resource init passes Graph errors through transformError, so the
	// not-found classifier has to keep working on its output
	assert.True(t, isResourceNotFound(transformError(odataErrWithCode("Request_ResourceNotFound"))))
	assert.True(t, isResourceNotFound(transformError(betaODataErrWithCode("Request_ResourceNotFound"))))
	assert.False(t, isResourceNotFound(transformError(odataErrWithCode("Authorization_RequestDenied"))))

	// the readable message is unchanged
	assert.Equal(t, "error while performing request. Code: Request_ResourceNotFound, Message: ",
		transformError(odataErrWithCode("Request_ResourceNotFound")).Error())
}

func TestResolveDirectoryRefsSkipsOnlyDeletedObjects(t *testing.T) {
	lookup := func(id string) (plugin.Resource, error) {
		switch id {
		case liveObjectID:
			return &fakeRefResource{id: id}, nil
		case deletedObjectID:
			// what initMicrosoftUser / initMicrosoftGroup return for a deleted object
			return nil, transformError(odataErrWithCode("Request_ResourceNotFound"))
		case deniedObjectID:
			return nil, transformError(odataErrWithCode("Authorization_RequestDenied"))
		}
		t.Fatalf("unexpected lookup of %q", id)
		return nil, nil
	}

	t.Run("a deleted object is skipped, special tokens are not looked up", func(t *testing.T) {
		res, err := resolveDirectoryRefsWith("microsoft.group",
			[]any{"All", "GuestsOrExternalUsers", liveObjectID, deletedObjectID}, lookup)
		require.NoError(t, err)
		require.Len(t, res, 1)
		assert.Equal(t, liveObjectID, res[0].(*fakeRefResource).id)
	})

	t.Run("a denied lookup fails the list instead of reading empty", func(t *testing.T) {
		res, err := resolveDirectoryRefsWith("microsoft.group", []any{liveObjectID, deniedObjectID}, lookup)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "Authorization_RequestDenied")
	})

	t.Run("a transport error fails the list", func(t *testing.T) {
		res, err := resolveDirectoryRefsWith("microsoft.user", []any{liveObjectID}, func(string) (plugin.Resource, error) {
			return nil, &net.DNSError{Err: "no such host", Name: "graph.microsoft.com"}
		})
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("a service principal missing from the tenant list is skipped", func(t *testing.T) {
		res, err := resolveDirectoryRefsWith("microsoft.serviceprincipal", []any{deletedObjectID}, func(string) (plugin.Resource, error) {
			return nil, errServicePrincipalNotFound
		})
		require.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("a failed service principal listing is not a deleted object", func(t *testing.T) {
		assert.False(t, isDeletedDirectoryObject(errors.New("service principal not found")),
			"only the sentinel counts, not a lookalike message")
	})
}

// ---------------------------------------------------------------------------
// Role definition assignments
// ---------------------------------------------------------------------------

const resourceNotFoundBody = `{"error":{"code":"Request_ResourceNotFound","message":"Resource does not exist or one of its queried reference-property objects are not present."}}`

const twoAssignmentsBody = `{
  "value": [
    {"id": "assign-live", "principalId": "` + liveObjectID + `", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10"},
    {"id": "assign-dangling", "principalId": "` + deletedObjectID + `", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10"}
  ]
}`

const getByIdsBody = `{
  "value": [
    {"@odata.type": "#microsoft.graph.user", "id": "` + liveObjectID + `", "displayName": "Ada Admin"}
  ]
}`

type graphRoute struct {
	status int
	body   string
}

// newTestGraphClient serves Graph requests from routes keyed by
// "<METHOD> <path>[ expand]", where " expand" is appended when the request
// carries $expand.
func newTestGraphClient(t *testing.T, routes map[string]graphRoute) (*msgraphsdkgo.GraphServiceClient, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/v1.0")
		if r.URL.Query().Get("$expand") != "" {
			key += " expand"
		}
		if r.Method == http.MethodPost {
			var reader io.Reader = r.Body
			if r.Header.Get("Content-Encoding") == "gzip" {
				gz, err := gzip.NewReader(r.Body)
				require.NoError(t, err)
				reader = gz
			}
			body, _ := io.ReadAll(reader)
			key += " " + string(body)
		}
		seen = append(seen, key)
		for k, route := range routes {
			if strings.HasPrefix(key, k) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(route.status)
				_, _ = w.Write([]byte(route.body))
				return
			}
		}
		t.Errorf("unexpected request %q", key)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(srv.URL + "/v1.0")
	return msgraphsdkgo.NewGraphServiceClient(adapter), &seen
}

func TestFetchRoleDefinitionAssignments(t *testing.T) {
	const assignmentsPath = "GET /roleManagement/directory/roleAssignments"

	t.Run("one deleted principal does not hide the live assignments", func(t *testing.T) {
		client, seen := newTestGraphClient(t, map[string]graphRoute{
			assignmentsPath + " expand":       {http.StatusNotFound, resourceNotFoundBody},
			assignmentsPath:                   {http.StatusOK, twoAssignmentsBody},
			"POST /directoryObjects/getByIds": {http.StatusOK, getByIdsBody},
		})

		rows, err := fetchRoleDefinitionAssignments(context.Background(), client, "62e90394-69f5-4237-9190-012177145e10")
		require.NoError(t, err)
		require.Len(t, rows, 2)

		assert.Equal(t, "assign-live", *rows[0].assignment.GetId())
		require.NotNil(t, rows[0].principal, "the live principal is resolved")
		principalType, principalName := directoryPrincipalInfo(rows[0].principal)
		assert.Equal(t, "user", principalType)
		assert.Equal(t, "Ada Admin", principalName)

		assert.Equal(t, "assign-dangling", *rows[1].assignment.GetId())
		assert.Nil(t, rows[1].principal, "the deleted principal stays nil")

		require.Len(t, *seen, 3)
		assert.Contains(t, (*seen)[2], liveObjectID)
		assert.Contains(t, (*seen)[2], deletedObjectID)
	})

	t.Run("a role with no directory role behind it has no assignments", func(t *testing.T) {
		client, _ := newTestGraphClient(t, map[string]graphRoute{
			assignmentsPath + " expand": {http.StatusNotFound, resourceNotFoundBody},
			assignmentsPath:             {http.StatusNotFound, resourceNotFoundBody},
		})

		rows, err := fetchRoleDefinitionAssignments(context.Background(), client, "a0b1b346-4d3e-4e8b-98f8-753987be4970")
		require.NoError(t, err)
		assert.NotNil(t, rows)
		assert.Empty(t, rows)
	})

	t.Run("a denied request is an error, not an empty list", func(t *testing.T) {
		client, _ := newTestGraphClient(t, map[string]graphRoute{
			assignmentsPath + " expand": {http.StatusForbidden, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`},
		})

		rows, err := fetchRoleDefinitionAssignments(context.Background(), client, "62e90394-69f5-4237-9190-012177145e10")
		require.Error(t, err)
		assert.Nil(t, rows)
	})

	t.Run("expanded principals are used directly", func(t *testing.T) {
		client, seen := newTestGraphClient(t, map[string]graphRoute{
			assignmentsPath + " expand": {http.StatusOK, `{"value":[{"id":"a1","principalId":"` + liveObjectID + `","principal":{"@odata.type":"#microsoft.graph.group","id":"` + liveObjectID + `","displayName":"Admins"}}]}`},
		})

		rows, err := fetchRoleDefinitionAssignments(context.Background(), client, "62e90394-69f5-4237-9190-012177145e10")
		require.NoError(t, err)
		require.Len(t, rows, 1)
		principalType, principalName := directoryPrincipalInfo(rows[0].principal)
		assert.Equal(t, "group", principalType)
		assert.Equal(t, "Admins", principalName)
		assert.Len(t, *seen, 1)
	})
}

// ---------------------------------------------------------------------------
// Tenant settings
// ---------------------------------------------------------------------------

func TestTenantSettingsWithoutSettingsReadNull(t *testing.T) {
	for _, payload := range []string{
		`{"@odata.type":"#microsoft.graph.adminAppsAndServices"}`,
		`{"@odata.type":"#microsoft.graph.adminAppsAndServices","settings":null}`,
	} {
		node, err := kjson.NewJsonParseNode([]byte(payload))
		require.NoError(t, err)
		parsed, err := node.GetObjectValue(betamodels.CreateAdminAppsAndServicesFromDiscriminatorValue)
		require.NoError(t, err)
		cfg := parsed.(betamodels.AdminAppsAndServicesable)

		tenant := &mqlMicrosoftTenant{}
		res, err := tenant.settingsFrom(cfg)
		require.NoError(t, err)
		assert.Nil(t, res)
		assert.True(t, tenant.Settings.State&plugin.StateIsNull != 0, "settings must read null, not both switches off")
		assert.True(t, tenant.Settings.State&plugin.StateIsSet != 0)
	}

	tenant := &mqlMicrosoftTenant{}
	res, err := tenant.settingsFrom(nil)
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.True(t, tenant.Settings.State&plugin.StateIsNull != 0)
}

func TestTenantFormsSettingsWithoutSettingsReadNull(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(`{"@odata.type":"#microsoft.graph.adminForms"}`))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateAdminFormsFromDiscriminatorValue)
	require.NoError(t, err)

	tenant := &mqlMicrosoftTenant{}
	res, err := tenant.formsSettingsFrom(parsed.(betamodels.AdminFormsable))
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.True(t, tenant.FormsSettings.State&plugin.StateIsNull != 0)
	assert.True(t, tenant.FormsSettings.State&plugin.StateIsSet != 0)
}

// ---------------------------------------------------------------------------
// PowerShell reports
// ---------------------------------------------------------------------------

// cmdletCall matches a cmdlet invocation in a report script.
var cmdletCall = regexp.MustCompile(`\b(Get-[A-Za-z0-9]+)\b`)

// Every section has to turn a failed cmdlet into null. A section that ran the
// cmdlet bare, or with @(...) around a value that can be null, reports a
// failure as an empty list.
func TestPowershellReportSectionsFailToNull(t *testing.T) {
	for name, script := range map[string]string{
		"exchange":                exchangeReport,
		"security and compliance": securityAndComplianceReport,
	} {
		t.Run(name, func(t *testing.T) {
			sections := 0
			for _, line := range strings.Split(script, "\n") {
				if !cmdletCall.MatchString(line) {
					continue
				}
				sections++
				assert.True(t, strings.HasPrefix(strings.TrimSpace(line), "try {"), "cmdlet outside try/catch: %s", line)
				assert.Contains(t, line, "-ErrorAction Stop", "cmdlet without -ErrorAction Stop: %s", line)
				assert.Regexp(t, `catch \{ \$[A-Za-z0-9]+ = \$null \}$`, strings.TrimSpace(line), "section does not fall back to null: %s", line)
			}
			assert.NotZero(t, sections)
			assert.NotContains(t, script, "-Value @(", "@($null) serializes as [null], not null")
		})
	}
}

// A failed Connect-* makes every following cmdlet fail; the script must stop
// with a non-zero exit code so the caller reports an error.
func TestPowershellReportConnectFailureExits(t *testing.T) {
	connect := regexp.MustCompile(`(?s)try \{\s*Connect-[A-Za-z]+ [^\n]*-ErrorAction Stop\s*\} catch \{[^}]*exit 1\s*\}`)
	assert.Regexp(t, connect, exchangeReport)
	assert.Regexp(t, connect, securityAndComplianceReport)
}

// A section the script reported as null must decode to an absent section, and
// one that ran and found nothing must not.
func TestExchangeReportNullSectionsDecodeAbsent(t *testing.T) {
	rt := reflect.TypeOf(ExchangeOnlineReport{})
	nulls := map[string]any{}
	empties := map[string]any{}
	for i := 0; i < rt.NumField(); i++ {
		tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		require.NotEmpty(t, tag)
		nulls[tag] = nil
		if rt.Field(i).Type.Kind() == reflect.Slice || rt.Field(i).Type.Kind() == reflect.Interface {
			empties[tag] = []any{}
		}
	}

	decode := func(m map[string]any) ExchangeOnlineReport {
		data, err := json.Marshal(m)
		require.NoError(t, err)
		var report ExchangeOnlineReport
		require.NoError(t, json.Unmarshal(data, &report))
		return report
	}

	nullReport := reflect.ValueOf(decode(nulls))
	emptyReport := reflect.ValueOf(decode(empties))
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		assert.True(t, isAbsentSection(nullReport.Field(i).Interface()), "null section %s must decode absent", name)
		if _, ok := empties[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]]; ok {
			assert.False(t, isAbsentSection(emptyReport.Field(i).Interface()), "empty section %s must not decode absent", name)
		}
	}
}

func TestDlpListsReadNullForAbsentSection(t *testing.T) {
	var report SecurityAndComplianceReport
	require.NoError(t, json.Unmarshal([]byte(`{"DlpCompliancePolicy":null,"DlpComplianceRule":null,"LabelPolicy":[]}`), &report))

	sc := &mqlMs365ExchangeonlineSecurityAndCompliance{}
	sc.fetched = true
	sc.report = &report

	policies, err := sc.dlpPolicies()
	require.NoError(t, err)
	assert.Nil(t, policies)
	assert.True(t, sc.DlpPolicies.State&plugin.StateIsNull != 0, "dlpPolicies must read null when the cmdlet failed")

	rules, err := sc.dlpRules()
	require.NoError(t, err)
	assert.Nil(t, rules)
	assert.True(t, sc.DlpRules.State&plugin.StateIsNull != 0, "dlpRules must read null when the cmdlet failed")

	// a cmdlet that ran and found nothing is still an empty list
	require.NoError(t, json.Unmarshal([]byte(`{"DlpCompliancePolicy":[],"DlpComplianceRule":[]}`), &report))
	sc2 := &mqlMs365ExchangeonlineSecurityAndCompliance{}
	sc2.fetched = true
	sc2.report = &report
	policies, err = sc2.dlpPolicies()
	require.NoError(t, err)
	assert.NotNil(t, policies)
	assert.Empty(t, policies)
	assert.True(t, sc2.DlpPolicies.State&plugin.StateIsNull == 0)
}
