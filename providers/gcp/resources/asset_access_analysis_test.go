// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"cloud.google.com/go/iam/apiv1/iampb"
	"go.mondoo.com/mql/llx"
	expr "google.golang.org/genproto/googleapis/type/expr"
)

const testBucket = "//storage.googleapis.com/projects/_/buckets/my-bucket"

// analysisResult builds one AnalyzeIamPolicy result. attached is the resource the
// binding hangs off, which is what distinguishes an inherited grant from a
// direct one.
func analysisResult(attached, role string, members []string, condition *expr.Expr, expanded ...string) *assetpb.IamPolicyAnalysisResult {
	r := &assetpb.IamPolicyAnalysisResult{
		AttachedResourceFullName: attached,
		IamBinding: &iampb.Binding{
			Role:      role,
			Members:   members,
			Condition: condition,
		},
	}
	if len(expanded) > 0 {
		identities := make([]*assetpb.IamPolicyAnalysisResult_Identity, 0, len(expanded))
		for _, e := range expanded {
			identities = append(identities, &assetpb.IamPolicyAnalysisResult_Identity{Name: e})
		}
		r.IdentityList = &assetpb.IamPolicyAnalysisResult_IdentityList{Identities: identities}
	}
	return r
}

func response(fullyExplored bool, results ...*assetpb.IamPolicyAnalysisResult) *assetpb.AnalyzeIamPolicyResponse {
	return &assetpb.AnalyzeIamPolicyResponse{
		FullyExplored: fullyExplored,
		MainAnalysis: &assetpb.AnalyzeIamPolicyResponse_IamPolicyAnalysis{
			AnalysisResults: results,
		},
	}
}

func asStrings(t *testing.T, in []any) []string {
	t.Helper()
	out := make([]string, 0, len(in))
	for _, v := range in {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("expected string element, got %T", v)
		}
		out = append(out, s)
	}
	return out
}

func assertStrings(t *testing.T, label string, got []any, want []string) {
	t.Helper()
	gotStrings := asStrings(t, got)
	if len(gotStrings) != len(want) {
		t.Errorf("%s = %v, want %v", label, gotStrings, want)
		return
	}
	for i := range want {
		if gotStrings[i] != want[i] {
			t.Errorf("%s = %v, want %v", label, gotStrings, want)
			return
		}
	}
}

func TestSummarizeAccessAnalysisDirectGrant(t *testing.T) {
	resp := response(true, analysisResult(testBucket, "roles/storage.objectViewer",
		[]string{"user:alice@example.com"}, nil))

	got := summarizeAccessAnalysis(resp, testBucket)

	assertStrings(t, "principals", got.principals, []string{"user:alice@example.com"})
	assertStrings(t, "inheritedPrincipals", got.inheritedPrincipals, nil)
	assertStrings(t, "conditionalPrincipals", got.conditionalPrincipals, nil)
	assertStrings(t, "roles", got.roles, []string{"roles/storage.objectViewer"})
	if !got.fullyExplored {
		t.Error("fullyExplored = false, want true")
	}
}

// A binding attached above the resource is the case a per-resource iamPolicy read
// cannot see, so it must be reported as inherited.
func TestSummarizeAccessAnalysisInheritedGrant(t *testing.T) {
	resp := response(true, analysisResult(
		"//cloudresourcemanager.googleapis.com/projects/my-project",
		"roles/storage.admin", []string{"group:platform@example.com"}, nil,
		"user:bob@example.com", "user:carol@example.com"))

	got := summarizeAccessAnalysis(resp, testBucket)

	// The expanded members replace the group, since the group itself cannot
	// authenticate.
	assertStrings(t, "principals", got.principals,
		[]string{"user:bob@example.com", "user:carol@example.com"})
	assertStrings(t, "inheritedPrincipals", got.inheritedPrincipals,
		[]string{"user:bob@example.com", "user:carol@example.com"})
}

// A condition-gated grant applies only when the condition evaluates true, so it
// must not read as unconditional access.
func TestSummarizeAccessAnalysisConditionalGrant(t *testing.T) {
	resp := response(true, analysisResult(testBucket, "roles/storage.objectViewer",
		[]string{"user:dave@example.com"},
		&expr.Expr{Expression: `request.time < timestamp("2030-01-01T00:00:00Z")`}))

	got := summarizeAccessAnalysis(resp, testBucket)

	assertStrings(t, "principals", got.principals, []string{"user:dave@example.com"})
	assertStrings(t, "conditionalPrincipals", got.conditionalPrincipals,
		[]string{"user:dave@example.com"})
	assertStrings(t, "inheritedPrincipals", got.inheritedPrincipals, nil)
}

// IdentityList is empty when the binding held no expandable member. Falling back
// to the binding's own members is required, or direct user grants vanish.
func TestSummarizeAccessAnalysisFallsBackToBindingMembers(t *testing.T) {
	resp := response(true, analysisResult(testBucket, "roles/storage.objectViewer",
		[]string{"allUsers"}, nil))

	got := summarizeAccessAnalysis(resp, testBucket)

	assertStrings(t, "principals", got.principals, []string{"allUsers"})
}

// The same principal reached through several bindings is one principal, and the
// output order must be stable across runs.
func TestSummarizeAccessAnalysisDedupesAndSorts(t *testing.T) {
	resp := response(true,
		analysisResult(testBucket, "roles/storage.objectViewer",
			[]string{"user:zoe@example.com"}, nil),
		analysisResult(testBucket, "roles/storage.admin",
			[]string{"user:adam@example.com", "user:zoe@example.com"}, nil),
	)

	got := summarizeAccessAnalysis(resp, testBucket)

	assertStrings(t, "principals", got.principals,
		[]string{"user:adam@example.com", "user:zoe@example.com"})
	assertStrings(t, "roles", got.roles,
		[]string{"roles/storage.admin", "roles/storage.objectViewer"})
}

// A principal granted directly on the resource and again on an ancestor appears
// in both lists, and inheritance must not be inferred from the direct binding.
func TestSummarizeAccessAnalysisMixedDirectAndInherited(t *testing.T) {
	resp := response(true,
		analysisResult(testBucket, "roles/storage.objectViewer",
			[]string{"user:erin@example.com"}, nil),
		analysisResult("//cloudresourcemanager.googleapis.com/folders/123",
			"roles/storage.admin", []string{"user:erin@example.com"}, nil),
	)

	got := summarizeAccessAnalysis(resp, testBucket)

	assertStrings(t, "principals", got.principals, []string{"user:erin@example.com"})
	assertStrings(t, "inheritedPrincipals", got.inheritedPrincipals,
		[]string{"user:erin@example.com"})
}

// An incomplete analysis must not present as an empty-but-authoritative answer.
func TestSummarizeAccessAnalysisNotFullyExplored(t *testing.T) {
	got := summarizeAccessAnalysis(response(false), testBucket)

	if got.fullyExplored {
		t.Error("fullyExplored = true, want false")
	}
	assertStrings(t, "principals", got.principals, nil)
}

func TestSummarizeAccessAnalysisSkipsEmptyMembers(t *testing.T) {
	resp := response(true, analysisResult(testBucket, "",
		[]string{"", "user:frank@example.com"}, nil))

	got := summarizeAccessAnalysis(resp, testBucket)

	assertStrings(t, "principals", got.principals, []string{"user:frank@example.com"})
	assertStrings(t, "roles", got.roles, nil)
}

func TestRawDataString(t *testing.T) {
	tests := []struct {
		name string
		in   *llx.RawData
		want string
	}{
		{"nil RawData", nil, ""},
		{"nil value", llx.NilData, ""},
		{"string value", llx.StringData("storage.objects.get"), "storage.objects.get"},
		{"empty string", llx.StringData(""), ""},
		{"non-string value", llx.IntData(42), ""},
		{"bool value", llx.BoolData(true), ""},
	}
	for _, tt := range tests {
		if got := rawDataString(tt.in); got != tt.want {
			t.Errorf("%s: rawDataString() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestSortedAnySet(t *testing.T) {
	got := sortedAnySet(map[string]struct{}{"c": {}, "a": {}, "b": {}})
	assertStrings(t, "sortedAnySet", got, []string{"a", "b", "c"})

	if got := sortedAnySet(map[string]struct{}{}); len(got) != 0 {
		t.Errorf("sortedAnySet(empty) = %v, want empty", got)
	}
}

func TestServiceAccountFullResourceName(t *testing.T) {
	want := "//iam.googleapis.com/projects/my-project/serviceAccounts/sa@my-project.iam.gserviceaccount.com"
	got := serviceAccountFullResourceName("my-project", "sa@my-project.iam.gserviceaccount.com")
	if got != want {
		t.Errorf("serviceAccountFullResourceName() = %q, want %q", got, want)
	}
}
