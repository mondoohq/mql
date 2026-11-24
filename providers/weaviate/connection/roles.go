// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"

	"github.com/weaviate/weaviate-go-client/v5/weaviate/except"
	"github.com/weaviate/weaviate/entities/models"
)

// Role is a role the server defines and every grant it holds, exactly as the
// server reports them. The Go client's own role type regroups grants by domain
// and keeps only the qualifiers it knows: a tenant-scoped grant comes back as a
// collection-wide or global one, a grant over named users comes back as a grant
// over every user, and a grant in a domain the client does not know is dropped.
// Reading the server's own models keeps all of them.
type Role struct {
	Name        string        `json:"name"`
	Permissions []*Permission `json:"permissions"`
}

// Permission is one grant: an action and, under the key naming its domain, the
// qualifiers that limit it.
type Permission struct {
	models.Permission

	// QualifierKeys lists, sorted, the key of every qualifier object the server
	// sent beside the action, including keys this build has no model for. A
	// grant in a domain added to the server after this build still says which
	// domain it belongs to.
	QualifierKeys []string `json:"-"`
}

func (p *Permission) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &p.Permission); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.QualifierKeys = nil
	for key, value := range raw {
		if key == "action" || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			continue
		}
		p.QualifierKeys = append(p.QualifierKeys, key)
	}
	sort.Strings(p.QualifierKeys)
	return nil
}

// ActionName returns the granted action, or an empty string when the server sent
// none.
func (p *Permission) ActionName() string {
	if p == nil || p.Action == nil {
		return ""
	}
	return *p.Action
}

// GroupRoles returns the roles granted to one group, each with its permissions.
func (c *WeaviateConnection) GroupRoles(ctx context.Context, groupType, groupID string) ([]*Role, error) {
	path := "/v1/authz/groups/" + url.PathEscape(groupID) + "/roles/" + url.PathEscape(groupType) +
		"?includeFullRoles=true"
	var roles []*Role
	if err := c.getJSON(ctx, path, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// getJSON reads one endpoint of the server's REST API with this connection's
// credentials and decodes the response. Failures carry the same error type the
// Go client returns, so callers classify a refusal the same way whichever of
// the two read it.
func (c *WeaviateConnection) getJSON(ctx context.Context, path string, out any) error {
	client, err := c.httpClient()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ServerID()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return except.NewDerivedWeaviateClientError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return except.NewDerivedWeaviateClientError(err)
	}
	if resp.StatusCode != http.StatusOK {
		return except.NewWeaviateClientError(resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}
