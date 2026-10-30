// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"encoding/json"
	"strconv"
)

// LibraryItem is one entry in the Iru library catalog. The API has no
// unified library-items endpoint; the catalog is split by type across
// several /library/<type> endpoints. We aggregate the ones that exist into
// a single shape: the common id/name/active/timestamps are lifted out and
// the remaining, kind-specific fields are carried in Payload.
type LibraryItem struct {
	ID        string
	Name      string
	Kind      string
	Active    bool
	CreatedAt string
	UpdatedAt string
	// Payload holds the kind-specific fields (everything the endpoint
	// returns beyond the common ones). Values are JSON-native so it maps
	// straight onto an MQL dict.
	Payload map[string]any
}

// libraryEndpoints maps each existing /library/<type> listing endpoint to
// the `kind` we report for the items it returns. There is deliberately no
// "app-store-app" / "vpp-app" entry: those listing endpoints return 404 on
// the API, so the catalog we can enumerate is the custom-* set.
var libraryEndpoints = []struct {
	path string
	kind string
}{
	{"/api/v1/library/custom-apps", "custom-app"},
	{"/api/v1/library/custom-profiles", "custom-profile"},
	{"/api/v1/library/custom-scripts", "custom-script"},
}

// ListLibraryItems fetches every existing /library/<type> endpoint and
// merges the results into one catalog. An endpoint the token is not
// permitted to read (401/403) is skipped rather than failing the whole
// listing; any other error aborts.
func (c *Client) ListLibraryItems() ([]LibraryItem, error) {
	var all []LibraryItem
	for _, ep := range libraryEndpoints {
		kind := ep.kind
		err := c.paginateEnvelope(ep.path, func(results json.RawMessage) error {
			var rows []map[string]any
			if err := json.Unmarshal(results, &rows); err != nil {
				return err
			}
			for _, row := range rows {
				all = append(all, newLibraryItem(row, kind))
			}
			return nil
		})
		if err != nil {
			if IsAccessDenied(err) {
				continue
			}
			return nil, err
		}
	}
	return all, nil
}

// newLibraryItem lifts the common fields out of a raw library row and keeps
// everything else as the kind-specific payload.
func newLibraryItem(row map[string]any, kind string) LibraryItem {
	li := LibraryItem{
		Kind:      kind,
		ID:        asString(row["id"]),
		Name:      asString(row["name"]),
		CreatedAt: asString(row["created_at"]),
		UpdatedAt: asString(row["updated_at"]),
	}
	if b, ok := row["active"].(bool); ok {
		li.Active = b
	}
	payload := make(map[string]any, len(row))
	for k, v := range row {
		switch k {
		case "id", "name", "active", "created_at", "updated_at":
			// lifted into typed fields
		default:
			payload[k] = v
		}
	}
	li.Payload = payload
	return li
}

// asString coerces a JSON scalar to a string, tolerating the id field
// arriving as either a JSON string or a JSON number.
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return jsonNumberString(t)
	default:
		return ""
	}
}

// jsonNumberString renders a float64 that originated as a JSON integer
// without a decimal point or exponent.
func jsonNumberString(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	b, _ := json.Marshal(f)
	return string(b)
}
