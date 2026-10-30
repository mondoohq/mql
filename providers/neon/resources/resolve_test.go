// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// The cross-resource accessors resolve a parent without an API call whenever
// the runtime already holds it. These tests pin that resolution: which lookups
// answer from what the query already fetched, and which fall through to a read.
// A regression here is silent, because a lookup that finds nothing reports the
// reference as null rather than failing.

func testRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// seedRoot puts a root resource with already-resolved lists in the runtime, so
// getNeon hands it back instead of building one that would call the API.
func seedRoot(runtime *plugin.Runtime, projects, organizations []any) *mqlNeon {
	root := &mqlNeon{MqlRuntime: runtime, __id: "neon"}
	root.Projects = plugin.TValue[[]any]{Data: projects, State: plugin.StateIsSet}
	root.Organizations = plugin.TValue[[]any]{Data: organizations, State: plugin.StateIsSet}
	runtime.Resources.Set("neon\x00neon", root)
	return root
}

func testProject(runtime *plugin.Runtime, id string) *mqlNeonProject {
	return &mqlNeonProject{
		MqlRuntime: runtime,
		__id:       id,
		Id:         plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
	}
}

func testOrganization(runtime *plugin.Runtime, id string) *mqlNeonOrganization {
	return &mqlNeonOrganization{
		MqlRuntime: runtime,
		__id:       id,
		Id:         plugin.TValue[string]{Data: id, State: plugin.StateIsSet},
	}
}

func TestProjectByIDResolvesFromTheProjectList(t *testing.T) {
	runtime := testRuntime()
	want := testProject(runtime, "proj-2")
	seedRoot(runtime, []any{testProject(runtime, "proj-1"), want}, nil)

	got, err := projectByID(runtime, "proj-2")
	if err != nil {
		t.Fatalf("projectByID: %v", err)
	}
	if got != want {
		t.Fatalf("expected the project from the list, got %v", got)
	}
}

// A personal project belongs to no organization, so it is not in the list the
// root collects per organization. It is still reachable, and a branch or
// endpoint of it must report its project rather than null.
func TestProjectByIDResolvesAProjectMissingFromTheList(t *testing.T) {
	runtime := testRuntime()
	seedRoot(runtime, []any{testProject(runtime, "proj-1")}, nil)

	personal := testProject(runtime, "proj-personal")
	runtime.Resources.Set("neon.project\x00proj-personal", personal)

	got, err := projectByID(runtime, "proj-personal")
	if err != nil {
		t.Fatalf("projectByID: %v", err)
	}
	if got != personal {
		t.Fatalf("expected the project the runtime already holds, got %v", got)
	}
}

func TestProjectByIDWithoutAnIDResolvesToNothing(t *testing.T) {
	runtime := testRuntime()
	seedRoot(runtime, nil, nil)

	got, err := projectByID(runtime, "")
	if err != nil {
		t.Fatalf("projectByID: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no project, got %v", got)
	}
}

func TestOrganizationByIDResolvesFromTheOrganizationList(t *testing.T) {
	runtime := testRuntime()
	want := testOrganization(runtime, "org-2")
	seedRoot(runtime, nil, []any{testOrganization(runtime, "org-1"), want})

	got, err := organizationByID(runtime, "org-2")
	if err != nil {
		t.Fatalf("organizationByID: %v", err)
	}
	if got != want {
		t.Fatalf("expected the organization from the list, got %v", got)
	}
}

func TestOrganizationByIDResolvesOneMissingFromTheList(t *testing.T) {
	runtime := testRuntime()
	seedRoot(runtime, nil, []any{testOrganization(runtime, "org-1")})

	other := testOrganization(runtime, "org-other")
	runtime.Resources.Set("neon.organization\x00org-other", other)

	got, err := organizationByID(runtime, "org-other")
	if err != nil {
		t.Fatalf("organizationByID: %v", err)
	}
	if got != other {
		t.Fatalf("expected the organization the runtime already holds, got %v", got)
	}
}

// An organization neither listed nor already held resolves to nothing, which is
// the signal for the caller to read it directly.
func TestOrganizationByIDResolvesToNothingWhenUnknown(t *testing.T) {
	runtime := testRuntime()
	seedRoot(runtime, nil, []any{testOrganization(runtime, "org-1")})

	got, err := organizationByID(runtime, "org-unknown")
	if err != nil {
		t.Fatalf("organizationByID: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no organization, got %v", got)
	}
}

// An organization list the key cannot read is not an answer about any one
// organization, so the lookup reports nothing rather than the list's error.
func TestOrganizationByIDIgnoresAnUnreadableList(t *testing.T) {
	runtime := testRuntime()
	root := seedRoot(runtime, nil, nil)
	root.Organizations = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}

	got, err := organizationByID(runtime, "org-1")
	if err != nil {
		t.Fatalf("organizationByID: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no organization, got %v", got)
	}
}

func TestNewNeonProjectSeedsTheOwnerFromThePayload(t *testing.T) {
	runtime := testRuntime()
	orgID := "org-1"
	rec := projectRecord{
		ID:    "proj-1",
		Name:  "production",
		OrgID: &orgID,
		Owner: &projectOwnerRecord{Email: "ada@example.com"},
	}

	project, err := newNeonProject(runtime, &rec)
	if err != nil {
		t.Fatalf("newNeonProject: %v", err)
	}
	if project.cacheOrgID != "org-1" {
		t.Errorf("organization linkage not cached: %q", project.cacheOrgID)
	}

	owner, err := project.ownerEmail()
	if err != nil {
		t.Fatalf("ownerEmail: %v", err)
	}
	if owner != "ada@example.com" {
		t.Errorf("expected the owner from the payload, got %q", owner)
	}
}

// The list endpoint omits the owner, so a project already built from the
// project endpoint must keep the owner it has when the same project comes back
// through a list.
func TestNewNeonProjectKeepsAKnownOwner(t *testing.T) {
	runtime := testRuntime()

	first, err := newNeonProject(runtime, &projectRecord{
		ID:    "proj-1",
		Owner: &projectOwnerRecord{Email: "ada@example.com"},
	})
	if err != nil {
		t.Fatalf("newNeonProject: %v", err)
	}

	second, err := newNeonProject(runtime, &projectRecord{ID: "proj-1"})
	if err != nil {
		t.Fatalf("newNeonProject: %v", err)
	}
	if second != first {
		t.Fatal("expected the project the runtime already holds")
	}

	owner, err := second.ownerEmail()
	if err != nil {
		t.Fatalf("ownerEmail: %v", err)
	}
	if owner != "ada@example.com" {
		t.Errorf("owner was lost on the second read: %q", owner)
	}
}

// A denied owner read is memoized as an answer, and a later payload must not
// quietly replace it, or the field would flip between reads of the same project.
func TestSeedOwnerEmailDoesNotOverwriteAnAnsweredRead(t *testing.T) {
	project := &mqlNeonProject{}
	project.ownerFetched.Store(true)

	project.seedOwnerEmail("ada@example.com")

	if project.ownerEmail_ != "" {
		t.Errorf("expected the answered read to stand, got %q", project.ownerEmail_)
	}
}

// CreateResource hands back an instance it already holds, so two queries can
// seed the same project at once. Run with -race, this pins that the seed is
// synchronized with the read it memoizes for.
func TestSeedOwnerEmailIsSafeUnderConcurrency(t *testing.T) {
	project := &mqlNeonProject{}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			project.seedOwnerEmail("ada@example.com")
		})
	}
	for range 16 {
		wg.Go(func() {
			if project.ownerFetched.Load() && project.ownerEmail_ != "ada@example.com" {
				t.Error("a seeded project reported an owner it was never given")
			}
		})
	}
	wg.Wait()

	if project.ownerEmail_ != "ada@example.com" {
		t.Errorf("expected the seeded owner, got %q", project.ownerEmail_)
	}
}

// --- cache keys -----------------------------------------------------------

// The __id is what the runtime caches a resource under, so a key that repeats
// across the dimension a resource repeats in makes the second reading resolve
// to the first. These tests pin the dimensions each key carries.

func TestOrganizationMemberIDCarriesTheOrganization(t *testing.T) {
	const memberID = "11111111-2222-3333-4444-555555555555"

	first := organizationMemberID("org-one", memberID)
	second := organizationMemberID("org-two", memberID)
	if first == second {
		t.Fatalf("two organizations sharing a membership id produced one key: %q", first)
	}

	if again := organizationMemberID("org-one", memberID); again != first {
		t.Fatalf("the same reading produced two keys: %q and %q", first, again)
	}

	// A member is unique within one organization, so the membership id has to
	// keep two roster entries of one organization apart.
	other := organizationMemberID("org-one", "66666666-7777-8888-9999-000000000000")
	if other == first {
		t.Fatalf("two members of one organization produced one key: %q", first)
	}
}

func TestAdvisorIssueKeyPrefersTheCacheKey(t *testing.T) {
	rec := advisorIssueRecord{
		Name:     "rls_disabled_in_public",
		Detail:   "Table `public.orders` is public, but RLS has not been enabled.",
		CacheKey: "rls_disabled_in_public:public.orders",
	}
	if got := advisorIssueKey(&rec, 0); got != rec.CacheKey {
		t.Fatalf("expected the cache key %q, got %q", rec.CacheKey, got)
	}
	// The index must not reach a key the API answered for.
	if got := advisorIssueKey(&rec, 7); got != rec.CacheKey {
		t.Fatalf("the index changed a key the API answered for: %q", got)
	}
}

func TestAdvisorIssueKeyWithoutACacheKeySeparatesFindingsOfOneType(t *testing.T) {
	// The issue name is the type of the check, so two findings of one type
	// against different objects carry the same name. Keying on the name alone
	// would drop the second as a duplicate of the first.
	first := advisorIssueRecord{
		Name:   "rls_disabled_in_public",
		Detail: "Table `public.orders` is public, but RLS has not been enabled.",
	}
	second := advisorIssueRecord{
		Name:   "rls_disabled_in_public",
		Detail: "Table `public.customers` is public, but RLS has not been enabled.",
	}

	firstKey := advisorIssueKey(&first, 0)
	secondKey := advisorIssueKey(&second, 1)
	if firstKey == secondKey {
		t.Fatalf("two findings of one type produced one key: %q", firstKey)
	}
	if firstKey == first.Name || secondKey == second.Name {
		t.Fatalf("a key fell back to the bare issue name: %q and %q", firstKey, secondKey)
	}

	// The detail is what separates them, so the key does not move when the
	// findings come back in a different order.
	if again := advisorIssueKey(&first, 5); again != firstKey {
		t.Fatalf("the key moved with the position in the response: %q and %q", firstKey, again)
	}
}

func TestAdvisorIssueKeyWithoutACacheKeyOrDetailStaysDistinct(t *testing.T) {
	first := advisorIssueRecord{Name: "rls_disabled_in_public"}
	second := advisorIssueRecord{Name: "rls_disabled_in_public"}

	firstKey := advisorIssueKey(&first, 0)
	secondKey := advisorIssueKey(&second, 1)
	if firstKey == secondKey {
		t.Fatalf("two findings with nothing to tell them apart produced one key: %q", firstKey)
	}
	if firstKey == first.Name {
		t.Fatalf("a key fell back to the bare issue name: %q", firstKey)
	}
}

// --- failed reads ---------------------------------------------------------

// A lookup that finds nothing reports the reference as null, which is the same
// shape a read that failed would take if the error were dropped. Null on an
// access field reads as an account holding nothing, and `null && null` is true
// in MQL, so an assertion over dropped errors passes without having checked
// anything. These tests pin that a failed read stays an error.

var errRead = errors.New("neon API: 500 internal_error")

func failedProjectMember(runtime *plugin.Runtime, project *mqlNeonProject, userID string) *mqlNeonProjectMember {
	member := &mqlNeonProjectMember{MqlRuntime: runtime, __id: project.Id.Data + "/member/m-1"}
	member.cacheProjectID = project.Id.Data
	member.cacheUserID = userID
	return member
}

func TestOrganizationMemberByUserIDReportsAFailedOrganizationRead(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	project.Organization = plugin.TValue[*mqlNeonOrganization]{
		Error: errRead, State: plugin.StateIsSet | plugin.StateIsNull,
	}

	got, err := organizationMemberByUserID(runtime, project, "user-1")
	if !errors.Is(err, errRead) {
		t.Fatalf("expected the read error, got %v (member %v)", err, got)
	}
}

func TestOrganizationMemberByUserIDReportsAFailedRosterRead(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	org := testOrganization(runtime, "org-1")
	org.Members = plugin.TValue[[]any]{Error: errRead, State: plugin.StateIsSet | plugin.StateIsNull}
	project.Organization = plugin.TValue[*mqlNeonOrganization]{Data: org, State: plugin.StateIsSet}

	got, err := organizationMemberByUserID(runtime, project, "user-1")
	if !errors.Is(err, errRead) {
		t.Fatalf("expected the read error, got %v (member %v)", err, got)
	}
}

func TestOrganizationMemberByUserIDResolvesFromTheRoster(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	org := testOrganization(runtime, "org-1")

	want := &mqlNeonOrganizationMember{MqlRuntime: runtime, __id: "org-1/member/m-2"}
	want.cacheUserID = "user-2"
	other := &mqlNeonOrganizationMember{MqlRuntime: runtime, __id: "org-1/member/m-1"}
	other.cacheUserID = "user-1"

	org.Members = plugin.TValue[[]any]{Data: []any{other, want}, State: plugin.StateIsSet}
	project.Organization = plugin.TValue[*mqlNeonOrganization]{Data: org, State: plugin.StateIsSet}

	got, err := organizationMemberByUserID(runtime, project, "user-2")
	if err != nil {
		t.Fatalf("organizationMemberByUserID: %v", err)
	}
	if got != want {
		t.Fatalf("expected the roster entry of user-2, got %v", got)
	}
}

// A project with no organization behind it, and an account that has left the
// organization, are both genuine absences and stay null.
func TestOrganizationMemberByUserIDReportsAGenuineAbsence(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	project.Organization = plugin.TValue[*mqlNeonOrganization]{State: plugin.StateIsSet | plugin.StateIsNull}

	got, err := organizationMemberByUserID(runtime, project, "user-1")
	if err != nil || got != nil {
		t.Fatalf("expected no organization and no error, got %v and %v", got, err)
	}

	org := testOrganization(runtime, "org-1")
	org.Members = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	project.Organization = plugin.TValue[*mqlNeonOrganization]{Data: org, State: plugin.StateIsSet}

	got, err = organizationMemberByUserID(runtime, project, "user-1")
	if err != nil || got != nil {
		t.Fatalf("expected an account off the roster to report as absent, got %v and %v", got, err)
	}
}

func testOperation(runtime *plugin.Runtime, projectID, endpointID string) *mqlNeonProjectOperation {
	operation := &mqlNeonProjectOperation{MqlRuntime: runtime, __id: projectID + "/operation/op-1"}
	operation.cacheProjectID = projectID
	operation.cacheEndpointID = endpointID
	return operation
}

func TestOperationEndpointReportsAFailedEndpointRead(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	project.Endpoints = plugin.TValue[[]any]{Error: errRead, State: plugin.StateIsSet | plugin.StateIsNull}
	seedRoot(runtime, []any{project}, nil)

	operation := testOperation(runtime, "proj-1", "ep-1")
	got, err := operation.endpoint()
	if !errors.Is(err, errRead) {
		t.Fatalf("expected the read error, got %v (endpoint %v)", err, got)
	}
}

func TestOperationEndpointResolvesFromTheEndpointList(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	want := &mqlNeonEndpoint{
		MqlRuntime: runtime,
		__id:       "ep-1",
		Id:         plugin.TValue[string]{Data: "ep-1", State: plugin.StateIsSet},
	}
	project.Endpoints = plugin.TValue[[]any]{Data: []any{want}, State: plugin.StateIsSet}
	seedRoot(runtime, []any{project}, nil)

	operation := testOperation(runtime, "proj-1", "ep-1")
	got, err := operation.endpoint()
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	if got != want {
		t.Fatalf("expected the endpoint from the list, got %v", got)
	}
}

// An operation may name a compute endpoint that has since been deleted, which
// is a genuine absence rather than a failed read.
func TestOperationEndpointReportsADeletedEndpointAsAbsent(t *testing.T) {
	runtime := testRuntime()
	project := testProject(runtime, "proj-1")
	project.Endpoints = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
	seedRoot(runtime, []any{project}, nil)

	operation := testOperation(runtime, "proj-1", "ep-gone")
	got, err := operation.endpoint()
	if err != nil || got != nil {
		t.Fatalf("expected a deleted endpoint to report as absent, got %v and %v", got, err)
	}
	if !operation.Endpoint.IsNull() {
		t.Fatal("expected the endpoint field to be marked null")
	}
}
