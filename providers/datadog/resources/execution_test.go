// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

// decodeScope parses a scope payload the way the SDK does when it reads an API
// response, so the struct tags are exercised rather than bypassed by building
// the struct in Go.
func decodeScope(t *testing.T, payload string) *datadogV2.ExecutionPolicyScope {
	t.Helper()
	var scope datadogV2.ExecutionPolicyScope
	if err := json.Unmarshal([]byte(payload), &scope); err != nil {
		t.Fatalf("could not decode scope %s: %v", payload, err)
	}
	return &scope
}

func TestExecutionScopeType(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "kubernetes",
			payload: `{"kubernetes":{"rules":[{"target_namespaces":["prod"]}]}}`,
			want:    executionScopeKubernetes,
		},
		{
			name:    "scripts",
			payload: `{"scripts":{"rules":[{"target_script_names":["restart"]}]}}`,
			want:    executionScopeScripts,
		},
		{
			name:    "remote shell",
			payload: `{"remote_action_rshell":{"rules":[{"access":"read_write","target_paths":["/"]}]}}`,
			want:    executionScopeRemoteActionRshell,
		},
		{
			// Datadog documents an empty object as "no scope restriction", so
			// this has to read as none and not as unknown.
			name:    "empty object",
			payload: `{}`,
			want:    executionScopeNone,
		},
		{
			// A member the SDK does not model lands in AdditionalProperties.
			// Reporting none here would present a restricted policy as
			// unrestricted, which is the failure that matters.
			name:    "unmodeled member",
			payload: `{"ssh":{"rules":[{"target_hosts":["db-1"]}]}}`,
			want:    executionScopeUnknown,
		},
		{
			// The API documents at most one member. Two means the record does
			// not mean what the schema says it means.
			name:    "two members at once",
			payload: `{"kubernetes":{"rules":[{"target_namespaces":["prod"]}]},"scripts":{"rules":[{"target_script_names":["restart"]}]}}`,
			want:    executionScopeUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := executionScopeType(decodeScope(t, tc.payload)); got != tc.want {
				t.Fatalf("expected scope type %q, got %q", tc.want, got)
			}
		})
	}
}

func TestExecutionScopeTypeNilScope(t *testing.T) {
	// A policy with no scope at all is the widest one there is, so it must read
	// as none rather than crash or report unknown.
	if got := executionScopeType(nil); got != executionScopeNone {
		t.Fatalf("expected scope type %q for an absent scope, got %q", executionScopeNone, got)
	}
}

func TestExecutionScopeKubernetesNamespaces(t *testing.T) {
	scope := decodeScope(t, `{"kubernetes":{"rules":[
		{"target_namespaces":["prod","prod-db"]},
		{"target_namespaces":["staging"]}
	]}}`)

	got := executionScopeKubernetesNamespaces(scope)
	want := []string{"prod", "prod-db", "staging"}
	if len(got) != len(want) {
		t.Fatalf("expected %d namespaces across both rules, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected namespace %q at %d, got %q", want[i], i, got[i])
		}
	}
}

func TestExecutionScopeKubernetesNamespacesOtherMember(t *testing.T) {
	// A scripts scope must not leak values into the Kubernetes list.
	scope := decodeScope(t, `{"scripts":{"rules":[{"target_script_names":["restart"]}]}}`)
	if got := executionScopeKubernetesNamespaces(scope); len(got) != 0 {
		t.Fatalf("expected no namespaces on a scripts scope, got %v", got)
	}
	if got := executionScopeKubernetesNamespaces(nil); len(got) != 0 {
		t.Fatalf("expected no namespaces on an absent scope, got %v", got)
	}
}

func TestExecutionScopeScriptNames(t *testing.T) {
	scope := decodeScope(t, `{"scripts":{"rules":[
		{"target_script_names":["restart-web"]},
		{"target_script_names":["rotate-keys","drain-node"]}
	]}}`)

	got := executionScopeScriptNames(scope)
	want := []string{"restart-web", "rotate-keys", "drain-node"}
	if len(got) != len(want) {
		t.Fatalf("expected %d script names across both rules, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected script name %q at %d, got %q", want[i], i, got[i])
		}
	}
}

func TestExecutionScopeRemoteShellRuleDecode(t *testing.T) {
	scope := decodeScope(t, `{"remote_action_rshell":{"rules":[
		{"access":"read_write","target_paths":["/etc","/var/lib"]},
		{"access":"read_only","target_paths":["/opt"]}
	]}}`)

	rules := scope.RemoteActionRshell.GetRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 remote shell rules, got %d", len(rules))
	}
	// read_write is the strongest grant a policy can carry, so the access field
	// reading as an empty string (a mistyped json tag) would hide it entirely.
	if got := string(rules[0].GetAccess()); got != string(datadogV2.EXECUTIONPOLICYREMOTEACTIONRSHELLACCESS_READ_WRITE) {
		t.Fatalf("expected the first rule to grant read_write, got %q", got)
	}
	if got := rules[0].GetTargetPaths(); len(got) != 2 || got[0] != "/etc" || got[1] != "/var/lib" {
		t.Fatalf("expected target paths [/etc /var/lib], got %v", got)
	}
	if got := string(rules[1].GetAccess()); got != string(datadogV2.EXECUTIONPOLICYREMOTEACTIONRSHELLACCESS_READ_ONLY) {
		t.Fatalf("expected the second rule to grant read_only, got %q", got)
	}
}

// policyPayload is one execution policy record shaped like the documented API
// response. Every field the resource reads comes through here, so a mistyped
// struct tag shows up as a zero value in the assertions below.
const policyPayload = `{
	"id": "1c9e5b46-0000-0000-0000-000000000000",
	"type": "execution_policy",
	"attributes": {
		"name": "prod remote shell",
		"effect": "deny",
		"version": 7,
		"created_at": "2026-03-04T10:11:12Z",
		"updated_at": "2026-05-06T13:14:15Z",
		"created_by": "user-created",
		"updated_by": "user-updated",
		"action_pattern": {
			"integration": "INTEGRATION_REMOTE_ACTION",
			"action_fqns": ["com.datadoghq.remote_action.rshell"]
		},
		"targets": [
			{"name": "production", "agent_tags": ["env:prod", "team:core"]},
			{"agent_tags": ["env:staging"]}
		],
		"scope": {"remote_action_rshell":{"rules":[{"access":"read_write","target_paths":["/"]}]}}
	}
}`

func decodePolicy(t *testing.T, payload string) *datadogV2.ExecutionPolicyResponseData {
	t.Helper()
	var data datadogV2.ExecutionPolicyResponseData
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		t.Fatalf("could not decode policy: %v", err)
	}
	return &data
}

func TestExecutionPolicyDecode(t *testing.T) {
	policy := decodePolicy(t, policyPayload)
	if got := policy.GetId(); got != "1c9e5b46-0000-0000-0000-000000000000" {
		t.Fatalf("expected the policy id, got %q", got)
	}

	attrs := policy.GetAttributes()
	if got := attrs.GetName(); got != "prod remote shell" {
		t.Fatalf("expected name, got %q", got)
	}
	if got := string(attrs.GetEffect()); got != string(datadogV2.EXECUTIONPOLICYEFFECT_DENY) {
		t.Fatalf("expected effect deny, got %q", got)
	}
	if got := attrs.GetVersion(); got != 7 {
		t.Fatalf("expected version 7, got %d", got)
	}
	if got := attrs.GetCreatedAt().UTC().Format("2006-01-02"); got != "2026-03-04" {
		t.Fatalf("expected created_at 2026-03-04, got %s", got)
	}
	// created_by and updated_by are the join keys for the user references, so
	// they must decode to distinct IDs rather than to one another.
	if got := attrs.GetCreatedBy(); got != "user-created" {
		t.Fatalf("expected created_by user-created, got %q", got)
	}
	if got := attrs.GetUpdatedBy(); got != "user-updated" {
		t.Fatalf("expected updated_by user-updated, got %q", got)
	}

	pattern := attrs.GetActionPattern()
	if got := string(pattern.GetIntegration()); got != string(datadogV2.EXECUTIONPOLICYINTEGRATION_INTEGRATION_REMOTE_ACTION) {
		t.Fatalf("expected the remote action integration, got %q", got)
	}
	if got := pattern.GetActionFqns(); len(got) != 1 || got[0] != "com.datadoghq.remote_action.rshell" {
		t.Fatalf("expected one action fqn, got %v", got)
	}

	if got := executionScopeType(attrs.Scope); got != executionScopeRemoteActionRshell {
		t.Fatalf("expected a remote shell scope, got %q", got)
	}
}

func TestExecutionPolicyTargetDecode(t *testing.T) {
	attrs := decodePolicy(t, policyPayload).GetAttributes()
	targets := attrs.GetTargets()
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if got := targets[0].GetAgentTags(); len(got) != 2 || got[0] != "env:prod" || got[1] != "team:core" {
		t.Fatalf("expected agent tags [env:prod team:core], got %v", got)
	}
	if name := targets[0].Name.Get(); name == nil || *name != "production" {
		t.Fatalf("expected the first target to be named production, got %v", name)
	}
	// A target with no name must read as null. Reporting an empty string would
	// present an unnamed target as one labeled with the empty string.
	if name := targets[1].Name.Get(); name != nil {
		t.Fatalf("expected an unnamed target to read as null, got %q", *name)
	}
}

// --- Pagination ---

func testExecutionPolicyApi(t *testing.T, srv *httptest.Server) (*datadogV2.ExecutionPolicyApi, context.Context) {
	t.Helper()
	cfg := datadog.NewConfiguration()
	if !cfg.SetUnstableOperationEnabled("v2.ListExecutionPolicies", true) {
		t.Fatal("v2.ListExecutionPolicies is not an unstable operation in this SDK version")
	}
	cfg.Servers = datadog.ServerConfigurations{{URL: srv.URL}}

	ctx := context.WithValue(context.Background(), datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: "api"},
		"appKeyAuth": {Key: "app"},
	})
	return datadogV2.NewExecutionPolicyApi(datadog.NewAPIClient(cfg)), ctx
}

// pageOf renders a response page holding n policies whose IDs start at offset.
// Every attribute the API documents as required is present: the SDK discards a
// record that is missing one, leaving it with an empty ID, so a short fixture
// would exercise the undecodable path instead of the paging path.
func pageOf(offset, n, total int) string {
	records := make([]string, 0, n)
	for i := range n {
		records = append(records, fmt.Sprintf(
			`{"id":"policy-%d","type":"execution_policy","attributes":{`+
				`"name":"p%d","effect":"allow","version":1,`+
				`"created_at":"2026-01-02T03:04:05Z","updated_at":"2026-01-02T03:04:05Z",`+
				`"created_by":"u","updated_by":"u",`+
				`"action_pattern":{"integration":"INTEGRATION_SCRIPT","action_fqns":["*"]},`+
				`"targets":[]}}`,
			offset+i, offset+i))
	}
	return fmt.Sprintf(`{"data":[%s],"meta":{"page":{"total":%d}}}`, strings.Join(records, ","), total)
}

func TestListExecutionPoliciesPaginates(t *testing.T) {
	size := int(executionPolicyPageSize)
	total := 2*size + 3

	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page[number]")
		requested = append(requested, page)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "0":
			fmt.Fprint(w, pageOf(0, size, total))
		case "1":
			fmt.Fprint(w, pageOf(size, size, total))
		default:
			fmt.Fprint(w, pageOf(2*size, 3, total))
		}
	}))
	defer srv.Close()

	api, ctx := testExecutionPolicyApi(t, srv)
	got, _, err := listExecutionPolicies(ctx, api)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != total {
		t.Fatalf("expected %d policies across three pages, got %d", total, len(got))
	}
	if got[0].GetId() != "policy-0" || got[total-1].GetId() != fmt.Sprintf("policy-%d", total-1) {
		t.Fatalf("expected policies in page order, got %q first and %q last", got[0].GetId(), got[total-1].GetId())
	}
	if len(requested) != 3 {
		t.Fatalf("expected three requests, got %d (%v)", len(requested), requested)
	}
	if requested[0] != "0" || requested[1] != "1" || requested[2] != "2" {
		t.Fatalf("expected page numbers 0,1,2, got %v", requested)
	}
}

func TestListExecutionPoliciesStopsOnRepeatedPage(t *testing.T) {
	size := int(executionPolicyPageSize)

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An endpoint that ignores page[number] hands back the first page over
		// and over. Without the repeat guard the walk would run to the page cap
		// and report the same policies a hundred times.
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, pageOf(0, size, 10_000))
	}))
	defer srv.Close()

	api, ctx := testExecutionPolicyApi(t, srv)
	got, _, err := listExecutionPolicies(ctx, api)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != size {
		t.Fatalf("expected the walk to stop with %d policies, got %d", size, len(got))
	}
	if calls != 2 {
		t.Fatalf("expected the walk to stop after the first repeated page (2 calls), got %d", calls)
	}
}

func TestListExecutionPoliciesStopsOnEmptyPage(t *testing.T) {
	size := int(executionPolicyPageSize)

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page[number]") == "0" {
			// A total larger than what the endpoint will actually serve. The
			// walk has to end on the empty page rather than chase the total.
			fmt.Fprint(w, pageOf(0, size, 10_000))
			return
		}
		fmt.Fprint(w, `{"data":[],"meta":{"page":{"total":10000}}}`)
	}))
	defer srv.Close()

	api, ctx := testExecutionPolicyApi(t, srv)
	got, _, err := listExecutionPolicies(ctx, api)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != size {
		t.Fatalf("expected %d policies, got %d", size, len(got))
	}
	if calls != 2 {
		t.Fatalf("expected the walk to stop on the empty page (2 calls), got %d", calls)
	}
}

func TestListExecutionPoliciesSkipsUndecodableRecords(t *testing.T) {
	// The SDK drops a record that is missing a required attribute, leaving it
	// with an empty ID. Every such record looks identical, so keeping them
	// would both report policies with no readable field and collapse the whole
	// page to one entry under the repeat guard.
	size := int(executionPolicyPageSize)
	broken := `{"id":"policy-broken","type":"execution_policy","attributes":{"name":"no version"}}`

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page[number]") == "0" {
			full := pageOf(0, size, size+1)
			// Splice the unreadable record in alongside a full page of good
			// ones, so the walk has to continue past it.
			fmt.Fprint(w, strings.Replace(full, `"data":[`, `"data":[`+broken+`,`, 1))
			return
		}
		fmt.Fprint(w, `{"data":[],"meta":{"page":{"total":101}}}`)
	}))
	defer srv.Close()

	api, ctx := testExecutionPolicyApi(t, srv)
	got, _, err := listExecutionPolicies(ctx, api)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != size {
		t.Fatalf("expected the %d readable policies and none of the broken one, got %d", size, len(got))
	}
	for _, policy := range got {
		if policy.GetId() == "" {
			t.Fatal("an undecodable policy reached the result")
		}
	}
	if calls != 2 {
		t.Fatalf("expected the walk to continue past the unreadable record, got %d calls", calls)
	}
}

func TestListExecutionPoliciesReturnsResponseOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"errors":["Forbidden"]}`)
	}))
	defer srv.Close()

	api, ctx := testExecutionPolicyApi(t, srv)
	_, httpResp, err := listExecutionPolicies(ctx, api)
	if err == nil {
		t.Fatal("expected an error on a 403 response")
	}
	// The caller degrades a 403 to "feature not licensed" through isForbidden,
	// which can only fire if the walk hands the response back alongside the
	// error. Dropping it turns a permission gap into a failed scan.
	if !isForbidden(httpResp) {
		t.Fatalf("expected the 403 response to be returned with the error, got %v", httpResp)
	}
}

func TestListExecutionPoliciesRequiresUnstableEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the SDK must refuse the call before it reaches the server")
	}))
	defer srv.Close()

	// This is why the connection turns the operation on. Without it the client
	// refuses locally and every organization reports an error rather than data.
	cfg := datadog.NewConfiguration()
	cfg.Servers = datadog.ServerConfigurations{{URL: srv.URL}}
	api := datadogV2.NewExecutionPolicyApi(datadog.NewAPIClient(cfg))

	_, _, err := listExecutionPolicies(context.Background(), api)
	if err == nil {
		t.Fatal("expected the call to be refused while the unstable operation is disabled")
	}
	if !strings.Contains(err.Error(), "v2.ListExecutionPolicies") {
		t.Fatalf("expected the error to name the disabled operation, got %v", err)
	}
}

// --- User references ---

func TestExecutionPolicyCreatorResolvesThroughUserIndex(t *testing.T) {
	// created_by and updated_by carry user IDs, which is what the shared index
	// is keyed on. Joining on the wrong attribute would miss here.
	attrs := decodePolicy(t, policyPayload).GetAttributes()
	idx := newUserIndex([]datadogV2.User{
		testUser("user-created", "author", "author@example.com"),
		testUser("user-updated", "editor", "editor@example.com"),
	})

	creator, ok := idx.lookup(attrs.GetCreatedBy())
	if !ok || creator.GetId() != "user-created" {
		t.Fatalf("expected the creator to resolve to user-created, got %q (found %v)", creator.GetId(), ok)
	}
	editor, ok := idx.lookup(attrs.GetUpdatedBy())
	if !ok || editor.GetId() != "user-updated" {
		t.Fatalf("expected the last editor to resolve to user-updated, got %q (found %v)", editor.GetId(), ok)
	}
}

func TestExecutionPolicyCreatorRemovedFromOrg(t *testing.T) {
	// A policy outlives the account that wrote it. The reference has to report
	// a miss so the field reads null, rather than resolving to a wrong user.
	attrs := decodePolicy(t, policyPayload).GetAttributes()
	idx := newUserIndex([]datadogV2.User{testUser("someone-else", "other", "other@example.com")})

	if _, ok := idx.lookup(attrs.GetCreatedBy()); ok {
		t.Fatal("expected a creator who has left the organization to report a miss")
	}
}
