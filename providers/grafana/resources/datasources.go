// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// grafanaDatasourceJSON mirrors one element of the /api/datasources response.
// SecureJSONFields is a map of secret-field name -> bool indicating whether the
// value is set; the secret values themselves are never returned by the API.
type grafanaDatasourceJSON struct {
	ID                int             `json:"id"`
	UID               string          `json:"uid"`
	OrgID             int             `json:"orgId"`
	Name              string          `json:"name"`
	Type              string          `json:"type"`
	Access            string          `json:"access"`
	URL               string          `json:"url"`
	IsDefault         bool            `json:"isDefault"`
	ReadOnly          bool            `json:"readOnly"`
	BasicAuth         bool            `json:"basicAuth"`
	BasicAuthUser     string          `json:"basicAuthUser"`
	User              string          `json:"user"`
	Database          string          `json:"database"`
	WithCredentials   bool            `json:"withCredentials"`
	Password          string          `json:"password"`
	BasicAuthPassword string          `json:"basicAuthPassword"`
	SecureJSONFields  map[string]bool `json:"secureJsonFields"`
	JSONData          json.RawMessage `json:"jsonData"`
}

func (g *mqlGrafana) datasources() ([]any, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/datasources")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/datasources returned status %d", resp.StatusCode)
	}

	var raw []grafanaDatasourceJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/datasources response: %w", err)
	}

	list := make([]any, 0, len(raw))
	for _, ds := range raw {
		var jsonDataDict any
		if len(ds.JSONData) > 0 && string(ds.JSONData) != "null" {
			var parsed any
			if err := json.Unmarshal(ds.JSONData, &parsed); err != nil {
				return nil, fmt.Errorf("grafana: parsing jsonData for datasource %s: %w", ds.UID, err)
			}
			jsonDataDict, err = convert.JsonToDict(parsed)
			if err != nil {
				return nil, fmt.Errorf("grafana: converting jsonData for datasource %s: %w", ds.UID, err)
			}
		}

		// Inline plaintext password fields are deprecated in Grafana but may
		// linger on legacy datasources. Surface their presence as booleans —
		// the actual values are never exposed.
		hasPassword := ds.Password != ""
		hasBasicAuthPassword := ds.BasicAuthPassword != ""

		// Promote secret-field names to a sorted []string for stable output.
		// secureJsonFields is server-managed: a key is present (with value true)
		// when a secret is stored, regardless of value.
		secureFieldNames := make([]string, 0, len(ds.SecureJSONFields))
		for k, v := range ds.SecureJSONFields {
			if v {
				secureFieldNames = append(secureFieldNames, k)
			}
		}
		slices.Sort(secureFieldNames)
		secureFields := make([]any, len(secureFieldNames))
		for i, s := range secureFieldNames {
			secureFields[i] = s
		}

		res, err := CreateResource(g.MqlRuntime, "grafana.datasource", map[string]*llx.RawData{
			"id":                   llx.IntData(int64(ds.ID)),
			"uid":                  llx.StringData(ds.UID),
			"orgId":                llx.IntData(int64(ds.OrgID)),
			"name":                 llx.StringData(ds.Name),
			"type":                 llx.StringData(ds.Type),
			"access":               llx.StringData(ds.Access),
			"url":                  llx.StringData(ds.URL),
			"isDefault":            llx.BoolData(ds.IsDefault),
			"readOnly":             llx.BoolData(ds.ReadOnly),
			"basicAuth":            llx.BoolData(ds.BasicAuth),
			"basicAuthUser":        llx.StringData(ds.BasicAuthUser),
			"user":                 llx.StringData(ds.User),
			"database":             llx.StringData(ds.Database),
			"hasPassword":          llx.BoolData(hasPassword),
			"hasBasicAuthPassword": llx.BoolData(hasBasicAuthPassword),
			"withCredentials":      llx.BoolData(ds.WithCredentials),
			"secureJsonFields":     llx.ArrayData(secureFields, types.String),
			"jsonData":             llx.DictData(jsonDataDict),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (d *mqlGrafanaDatasource) id() (string, error) {
	return "grafana-ds/" + d.Uid.Data, nil
}

// jsonDataMap returns the datasource's jsonData as a map[string]any, or nil if
// the data is missing or not an object. Used by the TLS / OAuth helpers below.
func (d *mqlGrafanaDatasource) jsonDataMap() map[string]any {
	v := d.JsonData
	if v.Error != nil || v.Data == nil {
		return nil
	}
	m, ok := v.Data.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

// boolFromJsonData looks up a boolean key in jsonData. Grafana sometimes stores
// booleans as actual bools and sometimes as strings — accept both.
func boolFromJsonData(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

func (d *mqlGrafanaDatasource) isHttps() (bool, error) {
	return strings.HasPrefix(strings.ToLower(d.Url.Data), "https://"), nil
}

func (d *mqlGrafanaDatasource) tlsSkipVerify() (bool, error) {
	return boolFromJsonData(d.jsonDataMap(), "tlsSkipVerify"), nil
}

// datasourceTLSClientAuth is true if the datasource is configured for mutual
// TLS, either via the tlsAuth flag in jsonData or by having a stored
// tlsClientCert / tlsClientKey secret listed in secureJsonFields.
func datasourceTLSClientAuth(jsonData map[string]any, secureFields []any) bool {
	if boolFromJsonData(jsonData, "tlsAuth") {
		return true
	}
	for _, f := range secureFields {
		if s, ok := f.(string); ok && (s == "tlsClientCert" || s == "tlsClientKey") {
			return true
		}
	}
	return false
}

func (d *mqlGrafanaDatasource) tlsClientAuth() (bool, error) {
	return datasourceTLSClientAuth(d.jsonDataMap(), d.SecureJsonFields.Data), nil
}

func (d *mqlGrafanaDatasource) oauthPassThru() (bool, error) {
	return boolFromJsonData(d.jsonDataMap(), "oauthPassThru"), nil
}
