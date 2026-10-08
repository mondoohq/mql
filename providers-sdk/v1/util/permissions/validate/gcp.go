// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// A GCP permission is real when Google's IAM API lists it for the resource it
// is granted on: queryTestablePermissions, asked for a project and for an
// organization, is the same list `gcloud iam roles create` validates a custom
// role against. For each permission the API also says whether it may go in a
// custom role at all (customRolesSupportLevel), whether it is deprecated
// (stage), and whether it is an alias of another name (primaryPermission), so
// a rejected entry can be told apart: not a permission, a permission of the
// other scope, an alias of the name to use, or real but only grantable through
// a predefined role. Matching is exact; permission names are case-sensitive
// and several services spell theirs all lowercase.
//
// The API needs a Google identity that can see the project and the
// organization: an access token in GCP_ACCESS_TOKEN (what
// google-github-actions/auth emits with token_format: access_token), or
// failing that the local gcloud login.
const gcpQueryTestablePermissionsURL = "https://iam.googleapis.com/v1/permissions:queryTestablePermissions"

// gcpPermission is one permission as the IAM API describes it. Scopes names
// the resource kinds it was testable on ("project", "organization"); a
// permission testable on both is granted at either level.
type gcpPermission struct {
	Name    string
	Scopes  []string
	Stage   string // GA, BETA, DEPRECATED, ...
	Support string // SUPPORTED, TESTING or NOT_SUPPORTED in custom roles
	Primary string // the primary permission this name is an alias of, if any
}

func (p gcpPermission) hasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// gcpScopes are the two resource kinds the manifest distinguishes, in the
// order their results are merged.
var gcpScopes = []string{"project", "organization"}

func loadGCPCatalog(f *fetcher, project, organization string) (*catalog, error) {
	if project == "" || organization == "" {
		return nil, errors.New("gcp: -gcp-project and -gcp-organization (or GCP_PROJECT and GCP_ORGANIZATION) are required")
	}
	token, err := gcpAccessToken()
	if err != nil {
		return nil, err
	}
	resources := map[string]string{
		"project":      "//cloudresourcemanager.googleapis.com/projects/" + project,
		"organization": "//cloudresourcemanager.googleapis.com/organizations/" + organization,
	}
	byScope := map[string][]gcpTestablePermission{}
	for _, scope := range gcpScopes {
		fmt.Fprintf(f.log, "  querying testable permissions for the %s\n", scope)
		perms, err := queryTestablePermissions(f.client, token, resources[scope])
		if err != nil {
			return nil, fmt.Errorf("gcp %s: %w", scope, err)
		}
		byScope[scope] = perms
	}
	c := newCatalog()
	addGCPPermissions(c, byScope)
	return c, nil
}

// addGCPPermissions merges the per-scope API results into the catalog: one
// entry per permission name, with the scopes it was testable on.
func addGCPPermissions(into *catalog, byScope map[string][]gcpTestablePermission) {
	for _, scope := range gcpScopes {
		for _, p := range byScope[scope] {
			e, ok := into.gcp[p.Name]
			if !ok {
				e = gcpPermission{Name: p.Name, Stage: p.Stage, Support: p.CustomRolesSupportLevel, Primary: p.PrimaryPermission}
				if e.Primary == e.Name {
					e.Primary = ""
				}
				into.add(p.Name)
			}
			if !e.hasScope(scope) {
				e.Scopes = append(e.Scopes, scope)
			}
			into.gcp[p.Name] = e
		}
	}
}

// gcpTestablePermission is the API's own shape, as far as the validator reads.
type gcpTestablePermission struct {
	Name                    string `json:"name"`
	Stage                   string `json:"stage"`
	CustomRolesSupportLevel string `json:"customRolesSupportLevel"`
	PrimaryPermission       string `json:"primaryPermission"`
}

func queryTestablePermissions(client *http.Client, token, resource string) ([]gcpTestablePermission, error) {
	var out []gcpTestablePermission
	pageToken := ""
	for page := 0; page < 100; page++ {
		body, _ := json.Marshal(map[string]any{
			"fullResourceName": resource,
			"pageSize":         1000,
			"pageToken":        pageToken,
		})
		req, err := http.NewRequest(http.MethodPost, gcpQueryTestablePermissionsURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("queryTestablePermissions: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
		}
		var res struct {
			Permissions   []gcpTestablePermission `json:"permissions"`
			NextPageToken string                  `json:"nextPageToken"`
		}
		if err := json.Unmarshal(data, &res); err != nil {
			return nil, err
		}
		out = append(out, res.Permissions...)
		if res.NextPageToken == "" {
			if len(out) == 0 {
				return nil, errors.New("queryTestablePermissions: no permissions returned")
			}
			return out, nil
		}
		pageToken = res.NextPageToken
	}
	return nil, errors.New("queryTestablePermissions: too many pages")
}

func gcpAccessToken() (string, error) {
	if t := os.Getenv("GCP_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	out, err := exec.Command("gcloud", "auth", "print-access-token").Output()
	if err != nil {
		return "", fmt.Errorf("gcp: no GCP_ACCESS_TOKEN and `gcloud auth print-access-token` failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
