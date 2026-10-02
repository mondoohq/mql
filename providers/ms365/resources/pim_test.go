// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/authentication"
	kjson "github.com/microsoft/kiota-serialization-json-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Shapes taken from the Microsoft Graph v1.0 reference responses for
// roleManagement/directory/roleAssignmentScheduleInstances and
// identityGovernance/privilegedAccess/group/{assignment,eligibility}ScheduleInstances.
const roleAssignmentScheduleInstanceJSON = `{
  "@odata.type": "#microsoft.graph.unifiedRoleAssignmentScheduleInstance",
  "id": "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1-e",
  "principalId": "3fbd929d-8c56-4462-851e-0eb9a7b3a2a5",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/",
  "appScopeId": null,
  "startDateTime": "2022-04-12T14:44:50.287Z",
  "endDateTime": null,
  "assignmentType": "Assigned",
  "memberType": "Direct",
  "roleAssignmentOriginId": "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1",
  "roleAssignmentScheduleId": "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1-e"
}`

const groupAssignmentScheduleInstanceJSON = `{
  "@odata.type": "#microsoft.graph.privilegedAccessGroupAssignmentScheduleInstance",
  "id": "2b5ed229-4072-478d-9504-a047ebd4b07d_owner_3cce9d87-3986-4f19-8335-7ed075408ca2",
  "startDateTime": "2023-02-06T19:36:37.073Z",
  "endDateTime": "2023-02-07T03:36:37.073Z",
  "accessId": "owner",
  "principalId": "3cce9d87-3986-4f19-8335-7ed075408ca2",
  "groupId": "2b5ed229-4072-478d-9504-a047ebd4b07d",
  "memberType": "group",
  "assignmentType": "activated",
  "assignmentScheduleId": "2b5ed229-4072-478d-9504-a047ebd4b07d_owner_3cce9d87-3986-4f19-8335-7ed075408ca2"
}`

const groupEligibilityScheduleInstanceJSON = `{
  "@odata.type": "#microsoft.graph.privilegedAccessGroupEligibilityScheduleInstance",
  "id": "2b5ed229-4072-478d-9504-a047ebd4b07d_member_3cce9d87-3986-4f19-8335-7ed075408ca2",
  "startDateTime": "2023-02-06T19:36:37.073Z",
  "accessId": "member",
  "principalId": "3cce9d87-3986-4f19-8335-7ed075408ca2",
  "groupId": "2b5ed229-4072-478d-9504-a047ebd4b07d",
  "memberType": "direct",
  "eligibilityScheduleId": "2b5ed229-4072-478d-9504-a047ebd4b07d_member_3cce9d87-3986-4f19-8335-7ed075408ca2"
}`

func TestRoleAssignmentInstanceArgs(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(roleAssignmentScheduleInstanceJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateUnifiedRoleAssignmentScheduleInstanceFromDiscriminatorValue)
	require.NoError(t, err)
	inst := parsed.(models.UnifiedRoleAssignmentScheduleInstanceable)

	args := roleAssignmentInstanceArgs(inst, map[string]string{
		"3fbd929d-8c56-4462-851e-0eb9a7b3a2a5": "servicePrincipal",
	})
	assert.Equal(t, "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1-e", args["__id"].Value)
	assert.Equal(t, "3fbd929d-8c56-4462-851e-0eb9a7b3a2a5", args["principalId"].Value)
	assert.Equal(t, "servicePrincipal", args["principalType"].Value)
	assert.Equal(t, "/", args["directoryScopeId"].Value)
	assert.Equal(t, "Assigned", args["assignmentType"].Value)
	assert.Equal(t, "Direct", args["memberType"].Value)
	assert.Equal(t, "lAPpYvVpN0KRkAEhdxReEJC2sEqbR_9Hr48lds9SGHI-1", args["roleAssignmentOriginId"].Value)
	assert.Equal(t, time.Date(2022, 4, 12, 14, 44, 50, 287000000, time.UTC), args["startDateTime"].Value.(*time.Time).UTC())

	// a permanent assignment has no end, and no app scope: both stay null
	// rather than reading as a zero time or an empty string
	assert.Nil(t, args["endDateTime"].Value)
	assert.Nil(t, args["appScopeId"].Value)

	// the role definition is not a field; it backs the roleDefinition accessor
	assert.NotContains(t, args, "roleDefinitionId")
}

func TestRoleAssignmentInstanceArgs_DeletedPrincipal(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(roleAssignmentScheduleInstanceJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateUnifiedRoleAssignmentScheduleInstanceFromDiscriminatorValue)
	require.NoError(t, err)

	// a principal that getByIds no longer returns has no type
	args := roleAssignmentInstanceArgs(parsed.(models.UnifiedRoleAssignmentScheduleInstanceable), map[string]string{})
	assert.Equal(t, "", args["principalType"].Value)
}

func TestGroupAssignmentInstanceArgs(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(groupAssignmentScheduleInstanceJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreatePrivilegedAccessGroupAssignmentScheduleInstanceFromDiscriminatorValue)
	require.NoError(t, err)
	inst := parsed.(models.PrivilegedAccessGroupAssignmentScheduleInstanceable)

	args := groupAssignmentInstanceArgs(inst, map[string]string{
		"3cce9d87-3986-4f19-8335-7ed075408ca2": "group",
	})
	assert.Equal(t, "owner", args["accessId"].Value)
	assert.Equal(t, "activated", args["assignmentType"].Value)
	assert.Equal(t, "group", args["memberType"].Value)
	assert.Equal(t, "group", args["principalType"].Value)
	assert.Equal(t, time.Date(2023, 2, 7, 3, 36, 37, 73000000, time.UTC), args["endDateTime"].Value.(*time.Time).UTC())
	assert.Equal(t, "2b5ed229-4072-478d-9504-a047ebd4b07d_owner_3cce9d87-3986-4f19-8335-7ed075408ca2", args["assignmentScheduleId"].Value)
	assert.NotContains(t, args, "groupId")
}

func TestGroupEligibilityInstanceArgs(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(groupEligibilityScheduleInstanceJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreatePrivilegedAccessGroupEligibilityScheduleInstanceFromDiscriminatorValue)
	require.NoError(t, err)
	inst := parsed.(models.PrivilegedAccessGroupEligibilityScheduleInstanceable)

	args := groupEligibilityInstanceArgs(inst, map[string]string{
		"3cce9d87-3986-4f19-8335-7ed075408ca2": "user",
	})
	assert.Equal(t, "member", args["accessId"].Value)
	assert.Equal(t, "direct", args["memberType"].Value)
	assert.Equal(t, "user", args["principalType"].Value)
	// endDateTime is absent from the payload: an eligibility that never expires
	assert.Nil(t, args["endDateTime"].Value)
	assert.NotNil(t, args["startDateTime"].Value)
}

func TestGroupEligibilityInstanceArgs_AbsentEnum(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(`{"@odata.type":"#microsoft.graph.privilegedAccessGroupEligibilityScheduleInstance","id":"x"}`))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreatePrivilegedAccessGroupEligibilityScheduleInstanceFromDiscriminatorValue)
	require.NoError(t, err)

	args := groupEligibilityInstanceArgs(parsed.(models.PrivilegedAccessGroupEligibilityScheduleInstanceable), nil)
	// an absent enum stays null instead of rendering the enum's zero value
	// (owner for accessId, direct for memberType)
	assert.Nil(t, args["accessId"].Value)
	assert.Nil(t, args["memberType"].Value)
}

func odataErrWithStatus(code string, status int) error {
	err := odataErrWithCode(code)
	err.ResponseStatusCode = status
	return err
}

func TestClassifyPimError(t *testing.T) {
	assert.NoError(t, classifyPimError(nil, permRoleAssignmentScheduleRead))

	notLicensed := classifyPimError(odataErrWithStatus("AadPremiumLicenseRequired", 400), permRoleAssignmentScheduleRead)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(notLicensed))

	denied := classifyPimError(odataErrWithStatus("Authorization_RequestDenied", 403), permRoleAssignmentScheduleRead)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(denied))
	var e *llx.Error
	require.True(t, errors.As(denied, &e))
	assert.Equal(t, []string{permRoleAssignmentScheduleRead}, e.Permissions)

	// a license refusal answered with 403 is still not applicable, not a
	// missing permission
	licensed403 := classifyPimError(odataErrWithStatus("AadPremiumLicenseRequired", 403), permRoleAssignmentScheduleRead)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(licensed403))

	// a malformed request and a transport failure claim nothing
	missingFilter := classifyPimError(odataErrWithStatus("MissingParameters", 400), permPrivilegedAssignmentGroup)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(missingFilter))
	assert.Contains(t, missingFilter.Error(), "MissingParameters")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyPimError(errors.New("connection reset"), permPrivilegedAssignmentGroup)))
}

// pimGroupGraph serves the PIM for Groups assignment collection, keyed by the
// groupId named in $filter, both through $batch and as a plain GET. A route
// keyed by a full path (without query) serves follow-up pages.
type pimGroupGraph struct {
	t      *testing.T
	srv    *httptest.Server
	routes map[string]fakeRoute
	// onBatch, when set, runs at the start of every $batch call; the func it
	// returns runs when that call has been answered
	onBatch func() func()

	mu     sync.Mutex
	direct []string
}

func newPimGroupGraph(t *testing.T, routes map[string]fakeRoute) *pimGroupGraph {
	g := &pimGroupGraph{t: t, routes: routes}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *pimGroupGraph) base() string { return g.srv.URL + "/v1.0" }

func (g *pimGroupGraph) client() *msgraphsdkgo.GraphServiceClient {
	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(g.t, err)
	adapter.SetBaseUrl(g.base())
	return msgraphsdkgo.NewGraphServiceClient(adapter)
}

func (g *pimGroupGraph) lookup(rawURL string) (int, json.RawMessage) {
	u, err := url.Parse(rawURL)
	require.NoError(g.t, err)
	key := strings.TrimPrefix(u.Path, "/v1.0")
	if filter := u.Query().Get("$filter"); filter != "" {
		key = filter
	}
	route, ok := g.routes[key]
	if !ok {
		return http.StatusNotFound, json.RawMessage(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`)
	}
	return route.status, json.RawMessage(strings.ReplaceAll(route.body, "{{base}}", g.base()))
}

func (g *pimGroupGraph) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/$batch") {
		if g.onBatch != nil {
			defer g.onBatch()()
		}
		var req struct {
			Requests []struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			} `json:"requests"`
		}
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			require.NoError(g.t, err)
			body = gz
		}
		require.NoError(g.t, json.NewDecoder(body).Decode(&req))
		type sub struct {
			ID      string            `json:"id"`
			Status  int               `json:"status"`
			Headers map[string]string `json:"headers"`
			Body    json.RawMessage   `json:"body"`
		}
		out := struct {
			Responses []sub `json:"responses"`
		}{}
		for _, step := range req.Requests {
			status, b := g.lookup(step.URL)
			out.Responses = append(out.Responses, sub{ID: step.ID, Status: status, Headers: map[string]string{"Content-Type": "application/json"}, Body: b})
		}
		require.NoError(g.t, json.NewEncoder(w).Encode(out))
		return
	}
	// record the direct per-group retries; follow-up pages carry no filter
	if r.URL.Query().Get("$filter") != "" {
		g.mu.Lock()
		g.direct = append(g.direct, r.URL.String())
		g.mu.Unlock()
	}
	status, b := g.lookup(r.URL.String())
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func listGroupAssignmentsFrom(g *pimGroupGraph, groupIDs []string) ([]models.PrivilegedAccessGroupAssignmentScheduleInstanceable, error) {
	ctx := context.Background()
	client := g.client()
	builder := client.IdentityGovernance().PrivilegedAccess().Group().AssignmentScheduleInstances()
	config := func(groupID string) *identitygovernance.PrivilegedAccessGroupAssignmentScheduleInstancesRequestBuilderGetRequestConfiguration {
		filter := odataEqFilter("groupId", groupID)
		return &identitygovernance.PrivilegedAccessGroupAssignmentScheduleInstancesRequestBuilderGetRequestConfiguration{
			QueryParameters: &identitygovernance.PrivilegedAccessGroupAssignmentScheduleInstancesRequestBuilderGetQueryParameters{Filter: &filter},
		}
	}
	return listPerGroup[*models.PrivilegedAccessGroupAssignmentScheduleInstanceCollectionResponse, models.PrivilegedAccessGroupAssignmentScheduleInstanceable](
		ctx, client, groupIDs,
		func(groupID string) (*abstractions.RequestInformation, error) {
			return builder.ToGetRequestInformation(ctx, config(groupID))
		},
		func(groupID string) (any, error) {
			return builder.Get(ctx, config(groupID))
		},
		models.CreatePrivilegedAccessGroupAssignmentScheduleInstanceCollectionResponseFromDiscriminatorValue,
		permPrivilegedAssignmentGroup,
	)
}

// Each group is asked for with its own groupId filter, and a group's later
// pages are followed: a $batch sub-response carries only the first page.
func TestListPerGroup_FiltersAndPages(t *testing.T) {
	g := newPimGroupGraph(t, map[string]fakeRoute{
		"groupId eq 'g-1'": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/identityGovernance/privilegedAccess/group/assignmentScheduleInstances/page2",
			"value": [{"id": "g-1_member_u-1", "groupId": "g-1", "accessId": "member"}]}`},
		"/identityGovernance/privilegedAccess/group/assignmentScheduleInstances/page2": {status: 200, body: `{
			"value": [{"id": "g-1_owner_u-2", "groupId": "g-1", "accessId": "owner"}]}`},
		"groupId eq 'g-2'": {status: 200, body: `{"value": [{"id": "g-2_member_u-3", "groupId": "g-2", "accessId": "member"}]}`},
		"groupId eq 'g-3'": {status: 200, body: `{"value": []}`},
	})

	got, err := listGroupAssignmentsFrom(g, []string{"g-1", "g-2", "g-3"})
	require.NoError(t, err)
	ids := []string{}
	for _, inst := range got {
		ids = append(ids, *inst.GetId())
	}
	assert.Equal(t, []string{"g-1_member_u-1", "g-1_owner_u-2", "g-2_member_u-3"}, ids)
	assert.Empty(t, g.direct, "no group failed, so nothing is asked again outside the batch")
}

// A $batch sub-response keeps only the status of a failure. The failed group
// is asked again directly so the Graph error code decides the kind: a missing
// license is not applicable, a 403 names the permission.
func TestListPerGroup_FailureIsClassifiedFromDirectRetry(t *testing.T) {
	t.Run("license", func(t *testing.T) {
		g := newPimGroupGraph(t, map[string]fakeRoute{
			"groupId eq 'g-1'": {status: 200, body: `{"value": []}`},
			"groupId eq 'g-2'": {status: 400, body: `{"error":{"code":"AadPremiumLicenseRequired","message":"The tenant needs an AAD Premium 2 license."}}`},
		})
		_, err := listGroupAssignmentsFrom(g, []string{"g-1", "g-2"})
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
		require.Len(t, g.direct, 1)
		assert.Contains(t, g.direct[0], "g-2")
	})

	t.Run("forbidden", func(t *testing.T) {
		g := newPimGroupGraph(t, map[string]fakeRoute{
			"groupId eq 'g-1'": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`},
		})
		_, err := listGroupAssignmentsFrom(g, []string{"g-1"})
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
		var e *llx.Error
		require.True(t, errors.As(err, &e))
		assert.Equal(t, []string{permPrivilegedAssignmentGroup}, e.Permissions)
	})
}

// A group deleted during the scan (404), or one PIM cannot manage (400), is
// skipped; the other groups' instances are still returned.
func TestListPerGroup_GroupLocalFailureIsSkipped(t *testing.T) {
	for name, route := range map[string]fakeRoute{
		"not found":   {status: 404, body: `{"error":{"code":"Request_ResourceNotFound","message":"Resource 'g-2' does not exist."}}`},
		"bad request": {status: 400, body: `{"error":{"code":"BadRequest","message":"The group is not onboarded to PIM."}}`},
	} {
		t.Run(name, func(t *testing.T) {
			g := newPimGroupGraph(t, map[string]fakeRoute{
				"groupId eq 'g-1'": {status: 200, body: `{"value": [{"id": "g-1_member_u-1", "groupId": "g-1"}]}`},
				"groupId eq 'g-2'": route,
				"groupId eq 'g-3'": {status: 200, body: `{"value": [{"id": "g-3_owner_u-2", "groupId": "g-3"}]}`},
			})
			got, err := listGroupAssignmentsFrom(g, []string{"g-1", "g-2", "g-3"})
			require.NoError(t, err)
			ids := []string{}
			for _, inst := range got {
				ids = append(ids, *inst.GetId())
			}
			assert.Equal(t, []string{"g-1_member_u-1", "g-3_owner_u-2"}, ids)
			require.Len(t, g.direct, 1)
			assert.Contains(t, g.direct[0], "g-2")
		})
	}
}

// When every group fails, the failure is not about one group, so the field
// reports it instead of an empty list.
func TestListPerGroup_EveryGroupFailingIsAnError(t *testing.T) {
	g := newPimGroupGraph(t, map[string]fakeRoute{
		"groupId eq 'g-1'": {status: 400, body: `{"error":{"code":"MissingParameters","message":"GroupId or PrincipalId"}}`},
		"groupId eq 'g-2'": {status: 400, body: `{"error":{"code":"MissingParameters","message":"GroupId or PrincipalId"}}`},
	})
	_, err := listGroupAssignmentsFrom(g, []string{"g-1", "g-2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MissingParameters")
}

// A permission refusal on one group holds for the tenant, so it fails the
// field even when other groups were read.
func TestListPerGroup_ForbiddenAmongGoodGroupsFailsTheField(t *testing.T) {
	g := newPimGroupGraph(t, map[string]fakeRoute{
		"groupId eq 'g-1'": {status: 200, body: `{"value": [{"id": "g-1_member_u-1", "groupId": "g-1"}]}`},
		"groupId eq 'g-2'": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`},
	})
	_, err := listGroupAssignmentsFrom(g, []string{"g-1", "g-2"})
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}

// Groups are read in several $batch calls at once, and the instances still
// come back in group order.
func TestListPerGroup_ChunksRunConcurrentlyInOrder(t *testing.T) {
	routes := map[string]fakeRoute{}
	groupIDs := []string{}
	want := []string{}
	for i := 0; i < pimGroupChunkSize*pimGroupConcurrency+5; i++ {
		id := fmt.Sprintf("g-%03d", i)
		groupIDs = append(groupIDs, id)
		want = append(want, id+"_member_u")
		routes["groupId eq '"+id+"'"] = fakeRoute{status: 200, body: `{"value": [{"id": "` + id + `_member_u", "groupId": "` + id + `"}]}`}
	}
	g := newPimGroupGraph(t, routes)

	// hold every $batch call until two are in flight; sequential chunks never
	// get there and time out
	var inFlight atomic.Int32
	overlap := make(chan struct{})
	var once sync.Once
	g.onBatch = func() func() {
		if inFlight.Add(1) >= 2 {
			once.Do(func() { close(overlap) })
		}
		select {
		case <-overlap:
		case <-time.After(2 * time.Second):
		}
		return func() { inFlight.Add(-1) }
	}

	got, err := listGroupAssignmentsFrom(g, groupIDs)
	require.NoError(t, err)
	select {
	case <-overlap:
	default:
		t.Fatal("no two $batch calls were in flight at once")
	}
	ids := []string{}
	for _, inst := range got {
		ids = append(ids, *inst.GetId())
	}
	assert.Equal(t, want, ids)
}

func TestChunkBatchRequests(t *testing.T) {
	reqs := make([]batchItemRequest, 5)
	for i := range reqs {
		reqs[i].key = fmt.Sprint(i)
	}
	chunks := chunkBatchRequests(reqs, 2)
	require.Len(t, chunks, 3)
	assert.Equal(t, "4", chunks[2][0].key)
	assert.Len(t, chunks[2], 1)
	assert.Empty(t, chunkBatchRequests(nil, 2))
}

func TestIsGroupLocalPimError(t *testing.T) {
	assert.True(t, isGroupLocalPimError(odataErrWithStatus("Request_ResourceNotFound", 404)))
	assert.True(t, isGroupLocalPimError(odataErrWithStatus("BadRequest", 400)))
	assert.False(t, isGroupLocalPimError(odataErrWithStatus("AadPremiumLicenseRequired", 400)))
	assert.False(t, isGroupLocalPimError(odataErrWithStatus("Authorization_RequestDenied", 403)))
	assert.False(t, isGroupLocalPimError(odataErrWithStatus("InvalidAuthenticationToken", 401)))
	assert.False(t, isGroupLocalPimError(odataErrWithStatus("TooManyRequests", 429)))
	assert.False(t, isGroupLocalPimError(odataErrWithStatus("ServiceUnavailable", 503)))
	assert.False(t, isGroupLocalPimError(errors.New("connection reset")))
}

func TestUniqueNonEmpty(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, uniqueNonEmpty([]string{"a", "", "b", "a", ""}))
	assert.Empty(t, uniqueNonEmpty(nil))
}
