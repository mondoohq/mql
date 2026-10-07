// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fakeado

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const base = "/" + Org

// get sends one request with the given Authorization header and returns the
// answer with its body read.
func get(t *testing.T, srv *Server, path, authorization string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, string(body)
}

func basic(pat string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(":"+pat))
}

func TestAnUnauthenticatedRequestGetsTheSignInPage(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/_apis/connectionData", "")

	assert.Equal(t, http.StatusNonAuthoritativeInfo, res.StatusCode)
	assert.Contains(t, body, "Sign in")
}

func TestAWrongTokenGetsTheSignInPage(t *testing.T) {
	srv := New(t)

	res, _ := get(t, srv, base+"/_apis/connectionData", basic("some-other-token"))

	assert.Equal(t, http.StatusNonAuthoritativeInfo, res.StatusCode)
}

func TestARejectedCredentialOnAVersionedRouteGetsTheSignInPage(t *testing.T) {
	// The credential is checked before anything else, so a versioned route
	// answers a rejected or missing credential the same way connectionData does.
	srv := New(t)

	routes := []string{
		base + "/_apis/projects?api-version=" + APIVersion,
		base + "/scan-test/_apis/git/repositories?api-version=" + APIVersion,
	}
	credentials := map[string]string{
		"a wrong bearer token": "Bearer not-the-" + BearerToken,
		"no credential":        "",
	}
	for _, route := range routes {
		for name, header := range credentials {
			res, body := get(t, srv, route, header)
			assert.Equal(t, http.StatusNonAuthoritativeInfo, res.StatusCode, "%s on %s", name, route)
			assert.Contains(t, body, "Sign in", "%s on %s", name, route)
			assert.NotContains(t, body, `"value"`, "%s on %s leaks no data", name, route)
		}
	}
}

func TestBothCredentialsAreAccepted(t *testing.T) {
	srv := New(t)

	for name, header := range map[string]string{"bearer": "Bearer " + BearerToken, "basic": basic(PAT)} {
		res, body := get(t, srv, base+"/_apis/connectionData", header)
		assert.Equal(t, http.StatusOK, res.StatusCode, name)
		assert.Contains(t, body, `"deploymentType"`, name)
	}
}

func TestVersionedCallsNeedTheAPIVersion(t *testing.T) {
	srv := New(t)

	res, _ := get(t, srv, base+"/_apis/projects", basic(PAT))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)

	res, _ = get(t, srv, base+"/_apis/projects?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestProjectsComeInTwoPages(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/_apis/projects?api-version=7.1", basic(PAT))
	assert.Equal(t, "2", res.Header.Get("x-ms-continuationtoken"))
	assert.Equal(t, []string{"scan-test", "scan test"}, projectNames(t, body))

	res, body = get(t, srv, base+"/_apis/projects?api-version=7.1&continuationToken=2", basic(PAT))
	assert.Empty(t, res.Header.Get("x-ms-continuationtoken"), "the last page names no next page")
	assert.Equal(t, []string{"locked-down", "legacy-apps"}, projectNames(t, body))
}

func projectNames(t *testing.T, body string) []string {
	t.Helper()
	var list struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &list))
	var names []string
	for _, p := range list.Value {
		names = append(names, p.Name)
	}
	return names
}

func TestRepositoriesOfAProjectWithASpace(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/scan%20test/_apis/git/repositories?api-version=7.1", basic(PAT))

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, body, RepoIacSpace)
	assert.NotContains(t, body, RepoIacID, "the repository of the other project with the same name is not listed")
}

func TestAnUnreadableProjectAnswers403(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/locked-down/_apis/git/repositories?api-version=7.1", basic(PAT))

	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Contains(t, body, "TF401019")
}

func TestHideRepositoriesAnswers404ForThatListOnly(t *testing.T) {
	srv := New(t)
	srv.HideRepositories("legacy-apps")

	res, body := get(t, srv, base+"/legacy-apps/_apis/git/repositories?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Contains(t, body, "TF401019")

	res, _ = get(t, srv, base+"/scan-test/_apis/git/repositories?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode, "another project still lists its repositories")

	res, body = get(t, srv, base+"/legacy-apps/_apis/git/repositories/"+RepoDocsID+"?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode, "only the list is hidden, not the repository")
	assert.Contains(t, body, RepoDocsID)
}

func TestOneRepositoryIsFoundByNameOrID(t *testing.T) {
	srv := New(t)

	_, byName := get(t, srv, base+"/scan-test/_apis/git/repositories/ado-scan-test-app?api-version=7.1", basic(PAT))
	_, byID := get(t, srv, base+"/scan-test/_apis/git/repositories/"+RepoAppID+"?api-version=7.1", basic(PAT))

	assert.JSONEq(t, byName, byID)
	assert.Contains(t, byName, RepoAppID)
}

func TestItemsOfAnEmptyRepositoryAnswer404(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/scan-test/_apis/git/repositories/"+RepoEmptyID+"/items?scopePath=/&recursionLevel=Full&api-version=7.1", basic(PAT))

	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Contains(t, body, "VS403403")
}

func TestDenyItemsAnswers403ForThatRepositoryOnly(t *testing.T) {
	srv := New(t)
	srv.DenyItems(RepoIacID)

	res, _ := get(t, srv, base+"/scan-test/_apis/git/repositories/"+RepoIacID+"/items?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusForbidden, res.StatusCode)

	res, _ = get(t, srv, base+"/scan-test/_apis/git/repositories/"+RepoAppID+"/items?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestThrottleNextAnswers429AndThenRecovers(t *testing.T) {
	srv := New(t)
	srv.ThrottleNext("/_apis/projects", 2, "1")

	for i := 0; i < 2; i++ {
		res, _ := get(t, srv, base+"/_apis/projects?api-version=7.1", basic(PAT))
		assert.Equal(t, http.StatusTooManyRequests, res.StatusCode, "request %d", i)
		assert.Equal(t, "1", res.Header.Get("Retry-After"))
	}
	res, _ := get(t, srv, base+"/_apis/projects?api-version=7.1", basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestRequestsAreRecordedInOrder(t *testing.T) {
	srv := New(t)

	get(t, srv, base+"/_apis/connectionData", basic(PAT))
	get(t, srv, base+"/_apis/projects?api-version=7.1", basic(PAT))

	assert.Equal(t, []string{
		"/" + Org + "/_apis/connectionData?",
		"/" + Org + "/_apis/projects?api-version=7.1",
	}, srv.Requests())
}

func TestEveryFixtureIsValidJSON(t *testing.T) {
	entries, err := fixtures.ReadDir("testdata")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, e := range entries {
		data, err := fixtures.ReadFile("testdata/" + e.Name())
		require.NoError(t, err)
		assert.True(t, json.Valid(data), "%s is not valid JSON", e.Name())
	}
}

func TestEachServiceAnswersOnlyItsOwnAPIVersion(t *testing.T) {
	srv := New(t)

	cases := []struct {
		path    string
		version string
	}{
		{path: "/advsec" + base + "/_apis/no-such-route", version: AdvSecAPIVersion},
		{path: "/vssps" + base + "/_apis/no-such-route", version: APIVersion},
		{path: base + "/scan-test/_apis/distributedtask/no-such-route", version: PreviewAPIVersion},
		{path: base + "/scan-test/_apis/pipelines/no-such-route", version: PreviewAPIVersion},
	}
	for _, tc := range cases {
		for _, v := range []string{APIVersion, AdvSecAPIVersion, PreviewAPIVersion} {
			res, _ := get(t, srv, tc.path+"?api-version="+v, basic(PAT))
			if v == tc.version {
				assert.Equal(t, http.StatusNotFound, res.StatusCode, "%s with %s reaches the router", tc.path, v)
			} else {
				assert.Equal(t, http.StatusBadRequest, res.StatusCode, "%s refuses %s", tc.path, v)
			}
		}
	}
}

func TestConnectionDataIsServedOnlyByTheMainHost(t *testing.T) {
	srv := New(t)

	res, _ := get(t, srv, "/vssps"+base+"/_apis/connectionData", basic(PAT))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode, "an unversioned call to another host is refused")
}

func TestRefsKeepOnlyTheFilteredKind(t *testing.T) {
	srv := New(t)
	refs := base + "/scan-test/_apis/git/repositories/" + RepoIacID + "/refs"

	type list struct {
		Value []struct {
			Name string `json:"name"`
		} `json:"value"`
	}
	res, body := get(t, srv, refs+"?filter=heads/&api-version="+APIVersion, basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	var heads list
	require.NoError(t, json.Unmarshal([]byte(body), &heads))
	require.Len(t, heads.Value, 2)
	for _, r := range heads.Value {
		assert.True(t, strings.HasPrefix(r.Name, "refs/heads/"), r.Name)
	}

	_, body = get(t, srv, refs+"?api-version="+APIVersion, basic(PAT))
	var all list
	require.NoError(t, json.Unmarshal([]byte(body), &all))
	assert.Len(t, all.Value, 3, "without a filter the tag is listed too")
}

func TestDenyAnswersForbiddenOnlyForTheMatchingPath(t *testing.T) {
	srv := New(t)
	srv.Deny("/refs")
	repo := base + "/scan-test/_apis/git/repositories/" + RepoIacID

	res, _ := get(t, srv, repo+"/refs?api-version="+APIVersion, basic(PAT))
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	res, _ = get(t, srv, repo+"/items?api-version="+APIVersion, basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestAccessControlListsAnswerOnlyTheAskedToken(t *testing.T) {
	srv := New(t)
	acls := base + "/_apis/accesscontrollists/" + gitNamespace + "?api-version=" + APIVersion + "&token="

	type list struct {
		Value []struct {
			Token string `json:"token"`
		} `json:"value"`
	}
	read := func(query string) list {
		t.Helper()
		res, body := get(t, srv, acls+query, basic(PAT))
		require.Equal(t, http.StatusOK, res.StatusCode)
		var l list
		require.NoError(t, json.Unmarshal([]byte(body), &l))
		return l
	}

	project := "repoV2/" + ProjectScanTestID
	one := read(url.QueryEscape(project) + "&recurse=false")
	require.Len(t, one.Value, 1)
	assert.Equal(t, project, one.Value[0].Token)

	assert.Len(t, read(url.QueryEscape(project)+"&recurse=true").Value, 3, "recurse adds the repository lists")
	assert.Empty(t, read(url.QueryEscape("repoV2/"+ProjectLegacyAppsID)+"&recurse=false").Value, "a token with no list")
}

func TestIdentitiesFindAGroupByItsName(t *testing.T) {
	srv := New(t)
	search := "/vssps" + base + "/_apis/identities?api-version=" + APIVersion + "&searchFilter=General&queryMembership=None&filterValue="

	type list struct {
		Value []struct {
			Descriptor string `json:"descriptor"`
		} `json:"value"`
	}
	res, body := get(t, srv, search+url.QueryEscape(`[scan-test]\contributors`), basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	var found list
	require.NoError(t, json.Unmarshal([]byte(body), &found))
	require.Len(t, found.Value, 1)
	assert.Equal(t, ContributorsDescriptor, found.Value[0].Descriptor)

	_, body = get(t, srv, search+url.QueryEscape(`[legacy-apps]\Contributors`), basic(PAT))
	var none list
	require.NoError(t, json.Unmarshal([]byte(body), &none))
	assert.Empty(t, none.Value)
}

func TestDropAccessControlListAnswersNoListForThatTokenOnly(t *testing.T) {
	srv := New(t)
	project := "repoV2/" + ProjectScanTestID
	srv.DropAccessControlList(project)
	acls := base + "/_apis/accesscontrollists/" + gitNamespace + "?api-version=" + APIVersion + "&recurse=false&token="

	_, body := get(t, srv, acls+url.QueryEscape(project), basic(PAT))
	assert.JSONEq(t, `{"count":0,"value":[]}`, body)

	_, body = get(t, srv, acls+url.QueryEscape(project+"/"+RepoIacID), basic(PAT))
	assert.Contains(t, body, project+"/"+RepoIacID, "the repository list is still served")
}

func TestAdvancedSecurityIsOffUntilEnabled(t *testing.T) {
	srv := New(t)
	repo := "/advsec" + base + "/scan-test/_apis/"
	enablement := repo + "management/repositories/" + RepoAppID + "/enablement?api-version=" + AdvSecAPIVersion
	alerts := repo + "alert/repositories/" + RepoAppID + "/alerts?api-version=" + AdvSecAPIVersion

	res, body := get(t, srv, enablement, basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, body, `"advSecEnabled":false`)
	res, body = get(t, srv, alerts, basic(PAT))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, body, "VS2150009")

	srv.EnableAdvancedSecurity(RepoAppID)
	_, body = get(t, srv, enablement, basic(PAT))
	assert.Contains(t, body, `"advSecEnabled":true`)
	res, body = get(t, srv, alerts, basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, body, `"alertType": "secret"`)
}

func TestHideItemAnswers404ByPathAndKeepsTheEntryInTheTree(t *testing.T) {
	srv := New(t)
	srv.HideItem(RepoAppID, "/azure-pipelines.yml")
	items := base + "/scan-test/_apis/git/repositories/" + RepoAppID + "/items?api-version=" + APIVersion

	res, body := get(t, srv, items+"&path=%2Fazure-pipelines.yml", basic(PAT))
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Contains(t, body, "TF401174")
	res, _ = get(t, srv, items+"&path=%2FSECURITY.md", basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode, "another file is still read")
	_, body = get(t, srv, items, basic(PAT))
	assert.Contains(t, body, "/azure-pipelines.yml", "the tree still lists the hidden file")
}

func TestAnswerAdvancedSecurityOffRefusesOnlyTheMatchingPath(t *testing.T) {
	srv := New(t)
	srv.EnableAdvancedSecurity(RepoAppID)
	srv.AnswerAdvancedSecurityOff("/enablement")
	repo := "/advsec" + base + "/scan-test/_apis/"
	enablement := repo + "management/repositories/" + RepoAppID + "/enablement?api-version=" + AdvSecAPIVersion
	alerts := repo + "alert/repositories/" + RepoAppID + "/alerts?api-version=" + AdvSecAPIVersion

	res, body := get(t, srv, enablement, basic(PAT))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, body, "VS2150009")
	res, _ = get(t, srv, alerts, basic(PAT))
	assert.Equal(t, http.StatusOK, res.StatusCode, "the alert route is not matched")
}

func TestServiceHooksListEverySubscriptionOfTheOrganization(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/_apis/hooks/subscriptions?api-version="+APIVersion, basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, body, `"count": 7`)
}

func TestEnvironmentChecksCarrySettingsOnlyWhenAsked(t *testing.T) {
	srv := New(t)
	checks := base + "/legacy-apps/_apis/pipelines/checks/configurations?api-version=" + PreviewAPIVersion + "&resourceType=environment&resourceId=1"

	res, body := get(t, srv, checks, basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, body, `"Approval"`)
	assert.NotContains(t, body, "requesterCannotBeApprover")

	_, body = get(t, srv, checks+"&%24expand=settings", basic(PAT))
	assert.Contains(t, body, `"requesterCannotBeApprover":false`)

	res, _ = get(t, srv, base+"/legacy-apps/_apis/pipelines/checks/configurations?api-version="+PreviewAPIVersion, basic(PAT))
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestEnvironmentsOfAProjectWithNoneAreEmpty(t *testing.T) {
	srv := New(t)

	res, body := get(t, srv, base+"/scan-test/_apis/distributedtask/environments?api-version="+PreviewAPIVersion, basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, body, `"count":0`)
	_, body = get(t, srv, base+"/legacy-apps/_apis/distributedtask/environments?api-version="+PreviewAPIVersion, basic(PAT))
	assert.Contains(t, body, `"production"`)
}

func TestOneItemComesWithItsContentOnlyWhenAsked(t *testing.T) {
	srv := New(t)
	items := base + "/scan-test/_apis/git/repositories/" + RepoAppID + "/items?api-version=7.1&$format=json&path="

	res, body := get(t, srv, items+"/Azure-Pipelines.yml&includeContent=true", basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	var item map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &item))
	assert.Equal(t, "/azure-pipelines.yml", item["path"])
	assert.Contains(t, item["content"], "AdvancedSecurity-Dependency-Scanning@1")

	res, body = get(t, srv, items+"/azure-pipelines.yml", basic(PAT))
	require.Equal(t, http.StatusOK, res.StatusCode)
	assert.NotContains(t, body, `"content"`)

	res, body = get(t, srv, items+"/missing.txt&includeContent=true", basic(PAT))
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
	assert.Contains(t, body, "TF401174")
}
