// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

func testApiClient(t *testing.T, srv *httptest.Server, unstable ...string) (*datadog.APIClient, context.Context) {
	t.Helper()
	cfg := datadog.NewConfiguration()
	for _, op := range unstable {
		if !cfg.SetUnstableOperationEnabled(op, true) {
			t.Fatalf("%s is not an unstable operation in this SDK version", op)
		}
	}
	cfg.Servers = datadog.ServerConfigurations{{URL: srv.URL}}
	ctx := context.WithValue(context.Background(), datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: "api"},
		"appKeyAuth": {Key: "app"},
	})
	return datadog.NewAPIClient(cfg), ctx
}

// --- Workflows ---

// workflowPage renders n workflows whose IDs start at offset, with the
// reported filtered total. Every attribute the API requires is present so the
// SDK decodes each record rather than discarding it.
func workflowPage(offset, n int, total int) string {
	records := make([]string, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, fmt.Sprintf(`{"id":"wf-%d","type":"workflows","attributes":{"name":"w%d"}}`, offset+i, offset+i))
	}
	meta := ""
	if total > 0 {
		meta = fmt.Sprintf(`,"meta":{"page":{"totalCount":%d,"totalFilteredCount":%d}}`, total+1000, total)
	}
	return fmt.Sprintf(`{"data":[%s]%s}`, strings.Join(records, ","), meta)
}

func TestListWorkflowsPaginatesAndIncludesDrafts(t *testing.T) {
	size := int(workflowPageSize)
	total := 2*size + 7

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drafts are left out unless asked for, and a draft that runs as its
		// owner is as much a grant as a published workflow.
		if got := r.URL.Query().Get("filter[includeUnpublished]"); got != "true" {
			t.Errorf("expected filter[includeUnpublished]=true, got %q", got)
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start := page * size
		n := total - start
		if n > size {
			n = size
		}
		if n < 0 {
			n = 0
		}
		fmt.Fprint(w, workflowPage(start, n, total))
	}))
	defer srv.Close()

	client, ctx := testApiClient(t, srv)
	items, _, err := listWorkflows(ctx, datadogV2.NewWorkflowAutomationApi(client))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != total {
		t.Fatalf("expected %d workflows, got %d", total, len(items))
	}
}

func TestListWorkflowsSurvivesServerSidePageCap(t *testing.T) {
	// The server hands back fewer records per page than were asked for. A walk
	// that stopped on the first short page would report 20 of 45 workflows.
	const capped, total = 20, 45
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start := page * capped
		n := total - start
		if n > capped {
			n = capped
		}
		if n < 0 {
			n = 0
		}
		fmt.Fprint(w, workflowPage(start, n, total))
	}))
	defer srv.Close()

	client, ctx := testApiClient(t, srv)
	items, _, err := listWorkflows(ctx, datadogV2.NewWorkflowAutomationApi(client))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != total {
		t.Fatalf("expected %d workflows, got %d", total, len(items))
	}
}

func TestListWorkflowsStopsWhenPageIsIgnored(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		// Always the first page, and a total that is never reached.
		fmt.Fprint(w, workflowPage(0, int(workflowPageSize), 10*int(workflowPageSize)))
	}))
	defer srv.Close()

	client, ctx := testApiClient(t, srv)
	items, _, err := listWorkflows(ctx, datadogV2.NewWorkflowAutomationApi(client))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != int(workflowPageSize) {
		t.Fatalf("expected one page of workflows without repeats, got %d", len(items))
	}
	if requests != 2 {
		t.Fatalf("expected the walk to stop on the first repeated page, made %d requests", requests)
	}
}

func TestListWorkflowsReturnsForbiddenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errors":["Forbidden"]}`)
	}))
	defer srv.Close()

	client, ctx := testApiClient(t, srv)
	_, httpResp, err := listWorkflows(ctx, datadogV2.NewWorkflowAutomationApi(client))
	if err == nil {
		t.Fatal("expected an error on a 403 response")
	}
	// The caller classifies the refusal through isForbidden, which only works
	// if the response travels back with the error.
	if !isForbidden(httpResp) {
		t.Fatalf("expected the 403 response to be returned with the error, got %v", httpResp)
	}
}

const workflowPayload = `{
  "id": "wf-1",
  "type": "workflows",
  "attributes": {
    "name": "Rotate keys",
    "description": "Rotates keys nightly",
    "published": true,
    "sensitivePrivileges": true,
    "runAsUserMode": "service_account",
    "tags": ["team:sec"],
    "createdAt": "2026-01-02T03:04:05Z",
    "updatedAt": "2026-02-03T04:05:06Z"
  },
  "relationships": {
    "owner":   {"data": {"id": "user-owner",   "type": "users"}},
    "creator": {"data": {"id": "user-creator", "type": "users"}},
    "runAs":   {"data": {"id": "user-sa",      "type": "users"}}
  }
}`

func decodeWorkflow(t *testing.T, payload string) datadogV2.WorkflowListItem {
	t.Helper()
	var w datadogV2.WorkflowListItem
	if err := json.Unmarshal([]byte(payload), &w); err != nil {
		t.Fatalf("could not decode workflow: %v", err)
	}
	if w.UnparsedObject != nil {
		t.Fatalf("SDK could not decode workflow fixture: %v", w.UnparsedObject)
	}
	return w
}

func TestWorkflowArgs(t *testing.T) {
	args := workflowArgs(decodeWorkflow(t, workflowPayload))

	if got := args["runAsUserMode"].Value; got != "service_account" {
		t.Fatalf("expected runAsUserMode service_account, got %v", got)
	}
	if got := args["sensitivePrivileges"].Value; got != true {
		t.Fatalf("expected sensitivePrivileges true, got %v", got)
	}
	if got := args["published"].Value; got != true {
		t.Fatalf("expected published true, got %v", got)
	}
	if got := args["description"].Value; got != "Rotates keys nightly" {
		t.Fatalf("unexpected description %v", got)
	}
	created, ok := args["createdAt"].Value.(*time.Time)
	if !ok || created == nil || !created.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("unexpected createdAt %v", args["createdAt"].Value)
	}
}

func TestWorkflowArgsAbsentValuesAreNull(t *testing.T) {
	// A workflow listed without these attributes must read null rather than a
	// fabricated false: an unknown sensitivePrivileges reported as false would
	// pass a check that no workflow holds sensitive privileges.
	args := workflowArgs(decodeWorkflow(t, `{"id":"wf-2","type":"workflows","attributes":{"name":"bare"}}`))
	for _, field := range []string{"sensitivePrivileges", "published", "runAsUserMode", "description", "createdAt", "updatedAt"} {
		if v := args[field].Value; v != nil {
			if tp, ok := v.(*time.Time); ok && tp == nil {
				continue
			}
			t.Errorf("expected %s to be null, got %v", field, v)
		}
	}
}

func TestWorkflowUserRefs(t *testing.T) {
	owner, creator, runAs := workflowUserRefs(decodeWorkflow(t, workflowPayload))
	if owner != "user-owner" || creator != "user-creator" || runAs != "user-sa" {
		t.Fatalf("expected owner/creator/runAs user-owner/user-creator/user-sa, got %q/%q/%q", owner, creator, runAs)
	}

	owner, creator, runAs = workflowUserRefs(decodeWorkflow(t, `{"id":"wf-3","type":"workflows","attributes":{"name":"x"}}`))
	if owner != "" || creator != "" || runAs != "" {
		t.Fatalf("expected no user references without relationships, got %q/%q/%q", owner, creator, runAs)
	}
}

// --- Security Inbox rules ---

const inboxRuleAttrs = `"action":{"description":"%s"},"created_at":1767323045000,` +
	`"created_by":{"id":"%s","name":"n","type":"%s"},"enabled":%t,` +
	`"modified_at":0,"modified_by":{"id":"sys","name":"Datadog","type":"system"},` +
	`"name":"%s","rule":{"finding_types":["secret","attack_path"]%s}`

func customRuleJSON(i int) string {
	return fmt.Sprintf(`{"id":"00000000-0000-4000-8000-%012d","type":"inbox_rules","attributes":{`+inboxRuleAttrs+`}}`,
		i+1, "custom", "user-1", "user", true, fmt.Sprintf("custom-%d", i), `,"query":"env:prod"`)
}

func TestListSecurityInboxRules(t *testing.T) {
	const pageSize = int(securityInboxRulePageSize)
	const total = pageSize + 3

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/security/findings/automation/default_inbox_rules":
			fmt.Fprintf(w, `{"data":[{"id":"secret_default_rule","type":"default_inbox_rules","attributes":{`+inboxRuleAttrs+`}}]}`,
				"Secrets", "system-id", "system", false, "Secrets", "")
		case "/api/v2/security/findings/automation/inbox_rules":
			page, _ := strconv.Atoi(r.URL.Query().Get("page[number]"))
			start := page * pageSize
			var records []string
			for i := start; i < total && i < start+pageSize; i++ {
				records = append(records, customRuleJSON(i))
			}
			fmt.Fprintf(w, `{"data":[%s],"links":{"first":"f","last":"l"},"meta":{"page":{"total_filtered_count":%d}}}`,
				strings.Join(records, ","), total)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, ctx := testApiClient(t, srv,
		"v2.ListSecurityFindingsAutomationInboxRules",
		"v2.ListSecurityFindingsAutomationDefaultInboxRules")
	rules, _, err := listSecurityInboxRules(ctx, datadogV2.NewSecurityMonitoringApi(client))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != total+1 {
		t.Fatalf("expected %d rules, got %d", total+1, len(rules))
	}

	def := rules[0]
	if !def.isDefault || def.id != "secret_default_rule" || def.enabled {
		t.Fatalf("expected a disabled default rule secret_default_rule, got %+v", def)
	}
	// Datadog created the default rule, so there is no user to resolve.
	if def.createdBy != "" || def.modifiedBy != "" {
		t.Fatalf("expected system actors to carry no user reference, got %q/%q", def.createdBy, def.modifiedBy)
	}
	if def.query != nil {
		t.Fatalf("expected a rule without a query to read null, got %q", *def.query)
	}

	custom := rules[1]
	if custom.isDefault || !custom.enabled || custom.id != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("unexpected custom rule %+v", custom)
	}
	if custom.createdBy != "user-1" {
		t.Fatalf("expected the creating user to be user-1, got %q", custom.createdBy)
	}
	if custom.query == nil || *custom.query != "env:prod" {
		t.Fatalf("expected query env:prod, got %v", custom.query)
	}
	if len(custom.findingTypes) != 2 || custom.findingTypes[0] != "secret" || custom.findingTypes[1] != "attack_path" {
		t.Fatalf("unexpected finding types %v", custom.findingTypes)
	}
	if custom.description == nil || *custom.description != "custom" {
		t.Fatalf("unexpected description %v", custom.description)
	}
}

func TestListSecurityInboxRulesRequiresUnstableEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the SDK must refuse the call before it reaches the server")
	}))
	defer srv.Close()

	client, ctx := testApiClient(t, srv)
	_, _, err := listSecurityInboxRules(ctx, datadogV2.NewSecurityMonitoringApi(client))
	if err == nil || !strings.Contains(err.Error(), "v2.ListSecurityFindingsAutomationDefaultInboxRules") {
		t.Fatalf("expected the disabled unstable operation to be named, got %v", err)
	}
}

func TestUnixMillis(t *testing.T) {
	if got := unixMillis(0); got != nil {
		t.Fatalf("expected an absent timestamp to read null, got %v", got)
	}
	got := unixMillis(1767323045000)
	if got == nil || !got.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("expected 2026-01-02T03:04:05Z, got %v", got)
	}
}

func TestInboxRuleActor(t *testing.T) {
	if got := inboxRuleActor(datadogV2.AUTOMATIONRULEACTORTYPE_USER, "u-1"); got != "u-1" {
		t.Fatalf("expected a user actor to keep its ID, got %q", got)
	}
	if got := inboxRuleActor(datadogV2.AUTOMATIONRULEACTORTYPE_SYSTEM, "u-1"); got != "" {
		t.Fatalf("expected a system actor to carry no user reference, got %q", got)
	}
}
