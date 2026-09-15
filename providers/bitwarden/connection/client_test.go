// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"go.mondoo.com/mql/providers/bitwarden/connection/bwapi"
)

func TestFlexEnumUnmarshalJSON(t *testing.T) {
	t.Run("integer ordinal", func(t *testing.T) {
		var f flexEnum
		if err := json.Unmarshal([]byte("2"), &f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.asInt == nil || *f.asInt != 2 {
			t.Fatalf("asInt = %v, want 2", f.asInt)
		}
		if f.asString != nil {
			t.Fatalf("asString = %v, want nil", f.asString)
		}
	})

	t.Run("string name", func(t *testing.T) {
		var f flexEnum
		if err := json.Unmarshal([]byte(`"Owner"`), &f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.asString == nil || *f.asString != "Owner" {
			t.Fatalf("asString = %v, want Owner", f.asString)
		}
		if f.asInt != nil {
			t.Fatalf("asInt = %v, want nil", f.asInt)
		}
	})

	t.Run("null leaves both unset", func(t *testing.T) {
		var f flexEnum
		if err := json.Unmarshal([]byte("null"), &f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.asInt != nil || f.asString != nil {
			t.Fatalf("expected both nil, got asInt=%v asString=%v", f.asInt, f.asString)
		}
	})

	t.Run("invalid input errors", func(t *testing.T) {
		var f flexEnum
		if err := json.Unmarshal([]byte("{}"), &f); err == nil {
			t.Fatal("expected error decoding an object into flexEnum, got nil")
		}
	})

	t.Run("negative ordinal decodes", func(t *testing.T) {
		var f flexEnum
		if err := json.Unmarshal([]byte("-1"), &f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.asInt == nil || *f.asInt != -1 {
			t.Fatalf("asInt = %v, want -1", f.asInt)
		}
	})
}

// intEnum / strEnum build a flexEnum in the wire form the API would send.
func intEnum(i int) flexEnum    { return flexEnum{asInt: &i} }
func strEnum(s string) flexEnum { return flexEnum{asString: &s} }

func TestPolicyTypeName(t *testing.T) {
	tests := []struct {
		name string
		in   flexEnum
		want string
	}{
		{"ordinal 0", intEnum(0), "twoFactorAuthentication"},
		{"ordinal 8", intEnum(8), "resetPassword"},
		{"last ordinal", intEnum(len(policyTypeNames) - 1), policyTypeNames[len(policyTypeNames)-1]},
		{"out-of-range ordinal", intEnum(len(policyTypeNames)), "unknown(" + strconv.Itoa(len(policyTypeNames)) + ")"},
		{"negative ordinal", intEnum(-5), "unknown(-5)"},
		{"pascalcase string", strEnum("MasterPassword"), "masterPassword"},
		{"already camel string", strEnum("passwordGenerator"), "passwordGenerator"},
		{"empty string", strEnum(""), ""},
		{"unset", flexEnum{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PolicyTypeName(tc.in); got != tc.want {
				t.Fatalf("PolicyTypeName(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMemberRoleName(t *testing.T) {
	tests := []struct {
		name string
		in   flexEnum
		want string
	}{
		{"owner", intEnum(0), "owner"},
		{"admin", intEnum(1), "admin"},
		{"user", intEnum(2), "user"},
		{"manager", intEnum(3), "manager"},
		{"custom", intEnum(4), "custom"},
		{"out-of-range", intEnum(5), "unknown(5)"},
		{"string owner", strEnum("Owner"), "owner"},
		{"string custom", strEnum("Custom"), "custom"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MemberRoleName(tc.in); got != tc.want {
				t.Fatalf("MemberRoleName(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMemberStatusName(t *testing.T) {
	tests := []struct {
		name string
		in   flexEnum
		want string
	}{
		{"revoked (-1)", intEnum(-1), "revoked"},
		{"invited", intEnum(0), "invited"},
		{"accepted", intEnum(1), "accepted"},
		{"confirmed", intEnum(2), "confirmed"},
		{"staged", intEnum(3), "staged"},
		{"out-of-range", intEnum(4), "unknown(4)"},
		{"string confirmed", strEnum("Confirmed"), "confirmed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MemberStatusName(tc.in); got != tc.want {
				t.Fatalf("MemberStatusName(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestResolveEnumStringBranch pins the expected wire format for string-valued
// enums. The API sends PascalCase names, and lowercasing only the first rune
// turns them into the camelCase names the .lr schema documents, including
// multi-word names like "TwoFactorAuthentication" -> "twoFactorAuthentication".
// A blanket strings.ToLower would flatten those multi-word names incorrectly
// ("twofactorauthentication"), which is why the first-rune transform is used.
// This test fails if that behavior regresses, and documents that an all-caps
// wire value ("OWNER") is NOT normalized, so any future API change to all-caps
// values is caught here rather than silently mislabeled.
func TestResolveEnumStringBranch(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"TwoFactorAuthentication", "twoFactorAuthentication"},
		{"MasterPassword", "masterPassword"},
		{"Owner", "owner"},
		{"passwordGenerator", "passwordGenerator"},
		{"", ""},
		// documented limitation: all-caps is not folded to lower-case
		{"OWNER", "oWNER"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			if got := resolveEnum(strEnum(tc.in), memberRoleNames); got != tc.want {
				t.Fatalf("resolveEnum(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMemberDecode(t *testing.T) {
	payload := `{
		"id": "member-1",
		"userId": "user-1",
		"name": "Jane Doe",
		"email": "jane@example.com",
		"type": 0,
		"status": 2,
		"twoFactorEnabled": true,
		"resetPasswordEnrolled": false,
		"externalId": null,
		"collections": [
			{"id": "col-1", "readOnly": true, "hidePasswords": false, "manage": false}
		]
	}`
	var m Member
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Id != "member-1" {
		t.Fatalf("Id = %q, want member-1", m.Id)
	}
	if m.UserId == nil || *m.UserId != "user-1" {
		t.Fatalf("UserId = %v, want user-1", m.UserId)
	}
	if m.ExternalId != nil {
		t.Fatalf("ExternalId = %v, want nil", m.ExternalId)
	}
	if !m.TwoFactorEnabled {
		t.Fatal("TwoFactorEnabled = false, want true")
	}
	if got := MemberRoleName(m.Type); got != "owner" {
		t.Fatalf("role = %q, want owner", got)
	}
	if got := MemberStatusName(m.Status); got != "confirmed" {
		t.Fatalf("status = %q, want confirmed", got)
	}
	if len(m.Collections) != 1 || m.Collections[0].Id != "col-1" || !m.Collections[0].ReadOnly {
		t.Fatalf("collections decode mismatch: %+v", m.Collections)
	}
}

func TestPolicyDecode(t *testing.T) {
	payload := `{
		"id": "policy-1",
		"type": 0,
		"enabled": true,
		"data": {"minComplexity": 3}
	}`
	var p Policy
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Id != "policy-1" || !p.Enabled {
		t.Fatalf("policy scalar decode mismatch: %+v", p)
	}
	if got := PolicyTypeName(p.Type); got != "twoFactorAuthentication" {
		t.Fatalf("policy type = %q, want twoFactorAuthentication", got)
	}
	if p.Data["minComplexity"] != float64(3) {
		t.Fatalf("Data = %v, want minComplexity=3", p.Data)
	}
}

func TestGroupAndCollectionDecode(t *testing.T) {
	groupPayload := `{
		"id": "group-1",
		"name": "Engineering",
		"externalId": "ext-1",
		"collections": [{"id": "col-1", "readOnly": false, "hidePasswords": true, "manage": true}]
	}`
	var g Group
	if err := json.Unmarshal([]byte(groupPayload), &g); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Name != "Engineering" || g.ExternalId == nil || *g.ExternalId != "ext-1" {
		t.Fatalf("group decode mismatch: %+v", g)
	}
	if len(g.Collections) != 1 || !g.Collections[0].HidePasswords || !g.Collections[0].Manage {
		t.Fatalf("group collection grants mismatch: %+v", g.Collections)
	}

	collectionPayload := `{
		"id": "col-1",
		"name": "Shared",
		"externalId": null,
		"groups": [{"id": "group-1", "readOnly": true, "hidePasswords": false, "manage": false}]
	}`
	var c Collection
	if err := json.Unmarshal([]byte(collectionPayload), &c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Name != "Shared" || c.ExternalId != nil {
		t.Fatalf("collection decode mismatch: %+v", c)
	}
	if len(c.Groups) != 1 || c.Groups[0].Id != "group-1" || !c.Groups[0].ReadOnly {
		t.Fatalf("collection group grants mismatch: %+v", c.Groups)
	}
}

func TestListResponseDecode(t *testing.T) {
	payload := `{"object":"list","data":[{"id":"p1","type":1,"enabled":false,"data":null}],"continuationToken":null}`
	var out listResponse[Policy]
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Object != "list" || len(out.Data) != 1 || out.Data[0].Id != "p1" {
		t.Fatalf("list envelope decode mismatch: %+v", out)
	}
	if out.ContinuationToken != nil {
		t.Fatalf("ContinuationToken = %v, want nil", out.ContinuationToken)
	}
}

// pagedHandler serves a list endpoint in pages of the given size, using the
// index of the next record as the continuation cursor, the way the Public API
// documents the field: a cursor on a partial page, null on the last one.
func pagedHandler(t *testing.T, ids []string, pageSize int, requests *[]string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		*requests = append(*requests, r.URL.RequestURI())

		start := 0
		if tok := r.URL.Query().Get("continuationToken"); tok != "" {
			var err error
			start, err = strconv.Atoi(tok)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		end := start + pageSize
		if end > len(ids) {
			end = len(ids)
		}

		body := map[string]any{"object": "list"}
		data := make([]map[string]any, 0, end-start)
		for _, id := range ids[start:end] {
			data = append(data, map[string]any{"id": id, "name": id, "externalId": nil, "groups": nil})
		}
		body["data"] = data
		if end < len(ids) {
			body["continuationToken"] = strconv.Itoa(end)
		} else {
			body["continuationToken"] = nil
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func TestListAllFollowsContinuationToken(t *testing.T) {
	ids := []string{"c1", "c2", "c3", "c4", "c5"}
	var requests []string
	srv := httptest.NewServer(pagedHandler(t, ids, 3, &requests))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	got, err := c.ListCollections(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(ids) {
		t.Fatalf("got %d collections, want %d (short enumeration)", len(got), len(ids))
	}
	for i, want := range ids {
		if got[i].Id != want {
			t.Fatalf("collection %d = %q, want %q", i, got[i].Id, want)
		}
	}

	wantRequests := []string{"/collections", "/collections?continuationToken=3"}
	if len(requests) != len(wantRequests) {
		t.Fatalf("requests = %v, want %v", requests, wantRequests)
	}
	for i, want := range wantRequests {
		if requests[i] != want {
			t.Fatalf("request %d = %q, want %q", i, requests[i], want)
		}
	}
}

func TestListAllSinglePageIssuesOneRequest(t *testing.T) {
	ids := []string{"m1", "m2"}
	var requests []string
	srv := httptest.NewServer(pagedHandler(t, ids, 10, &requests))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	got, err := c.ListMembers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d members, want 2", len(got))
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %v, want a single request when the cursor is null", requests)
	}
}

// TestListAllStuckTokenTerminates covers a server that keeps echoing the same
// cursor. Without the repeat guard the walk would re-fetch the same page for
// the length of the scan.
func TestListAllStuckTokenTerminates(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":            "list",
			"data":              []map[string]any{{"id": "g1", "name": "g1"}},
			"continuationToken": "stuck",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.ListGroups(context.Background())
	if err == nil {
		t.Fatal("expected an error for a server that never advances its cursor")
	}
	if !strings.Contains(err.Error(), "same continuation token twice") {
		t.Fatalf("error = %v, want the repeated-cursor error", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 (the guard must fire on the first repeat)", requests)
	}
}

// TestListAllPageCapTerminates covers a server that mints a fresh cursor on
// every response, which the repeat guard cannot catch.
func TestListAllPageCapTerminates(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object":            "list",
			"data":              []map[string]any{{"id": strconv.Itoa(requests), "type": 1, "enabled": false}},
			"continuationToken": strconv.Itoa(requests),
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	_, err := c.ListPolicies(context.Background())
	if err == nil {
		t.Fatal("expected an error for a server that paginates forever")
	}
	if !strings.Contains(err.Error(), "did not stop paginating") {
		t.Fatalf("error = %v, want the page-cap error", err)
	}
	if requests != maxListPages {
		t.Fatalf("requests = %d, want the walk to stop at maxListPages (%d)", requests, maxListPages)
	}
}

// fieldSet returns the exported field names of a struct type.
func fieldSet(t reflect.Type) map[string]struct{} {
	m := make(map[string]struct{}, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		m[t.Field(i).Name] = struct{}{}
	}
	return m
}

// TestOpenAPIGeneratedModelsDecodeRealShape proves the vendored, spec-generated
// bwapi models (providers/bitwarden/connection/bwapi/models.gen.go) decode a
// real, spec-shaped Public API response for the fields the spec covers. It
// validates the generated type layer end to end even though the provider does
// not decode into it (see TestOpenAPISpecGaps for why).
func TestOpenAPIGeneratedModelsDecodeRealShape(t *testing.T) {
	payload := `{
		"object": "list",
		"data": [{
			"object": "member",
			"id": "539a36c5-e0d2-4cf9-979e-51ecf5cf6593",
			"userId": "48b47ee1-493e-4c67-aef7-014996c40eca",
			"name": "John Smith",
			"email": "jsmith@example.com",
			"twoFactorEnabled": true,
			"status": 2,
			"type": 0,
			"accessAll": false,
			"externalId": null,
			"collections": [{"id": "bfbc8338-e329-4dc0-b0c9-317c2ebf1a09", "readOnly": true}]
		}],
		"continuationToken": null
	}`
	var out bwapi.MemberResponseModelListResponseModel
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		t.Fatalf("generated member-list model failed to decode a spec-shaped payload: %v", err)
	}
	if len(out.Data) != 1 || out.Data[0].Email != "jsmith@example.com" {
		t.Fatalf("generated model decode mismatch: %+v", out)
	}
	if out.Data[0].Type != bwapi.OrganizationUserTypeN0 {
		t.Fatalf("generated enum decode = %v, want ordinal 0 (owner)", out.Data[0].Type)
	}
	if out.Data[0].Status != bwapi.OrganizationUserStatusTypeN2 {
		t.Fatalf("generated status enum decode = %v, want ordinal 2 (confirmed)", out.Data[0].Status)
	}
}

// TestOpenAPISpecGaps pins the ways Bitwarden's vendored Public API spec
// diverges from what this provider actually reads. These gaps are the reason
// the response decoding in client.go stays hand-written rather than switching
// to the generated bwapi models. Each assertion is a tripwire: if a future
// re-vendor of the spec closes a gap, its sub-check fails, signaling that the
// generated type can then replace the corresponding hand-written struct.
func TestOpenAPISpecGaps(t *testing.T) {
	// The permission-grant model (our SelectionReadOnly) omits hidePasswords
	// and manage. The provider exposes both on collectionAccess/groupAccess/
	// memberAccess, so adopting the generated model would silently report every
	// grant as hidePasswords=false, manage=false.
	assoc := fieldSet(reflect.TypeOf(bwapi.AssociationWithPermissionsResponseModel{}))
	for _, f := range []string{"HidePasswords", "Manage"} {
		if _, ok := assoc[f]; ok {
			t.Errorf("spec now models AssociationWithPermissionsResponseModel.%s; SelectionReadOnly can adopt the generated model", f)
		}
	}

	// The member model omits resetPasswordEnrolled, which the provider exposes.
	if _, ok := fieldSet(reflect.TypeOf(bwapi.MemberResponseModel{}))["ResetPasswordEnrolled"]; ok {
		t.Error("spec now models MemberResponseModel.ResetPasswordEnrolled; revisit the hand-written Member")
	}

	// The collection model omits name, which the provider exposes.
	if _, ok := fieldSet(reflect.TypeOf(bwapi.CollectionResponseModel{}))["Name"]; ok {
		t.Error("spec now models CollectionResponseModel.Name; revisit the hand-written Collection")
	}

	// Policy data is typed as a nested map[string]map[string]interface{}, which
	// cannot decode the flat data objects the API actually returns.
	var p bwapi.PolicyResponseModel
	if err := json.Unmarshal([]byte(`{"id":"539a36c5-e0d2-4cf9-979e-51ecf5cf6593","type":1,"enabled":true,"data":{"minComplexity":3}}`), &p); err == nil {
		t.Error("spec's PolicyResponseModel.Data now decodes flat policy data; revisit the hand-written Policy")
	}

	// Ids are typed as UUIDs, rejecting the non-UUID ids the hand-written
	// structs tolerate, and enum fields are plain integers that cannot decode
	// the string wire form flexEnum handles.
	var g bwapi.GroupResponseModel
	if err := json.Unmarshal([]byte(`{"id":"group-1","name":"Eng"}`), &g); err == nil {
		t.Error("spec's GroupResponseModel.Id now tolerates non-UUID ids; the UUID friction is gone")
	}
}
