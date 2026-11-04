// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
)

// plugins lists every plugin installed on the Jenkins controller in a single
// deep fetch against the plugin manager. hasUpdate is returned pre-computed
// by Jenkins against the configured update center, no per-plugin fetch
// needed.
//
// The booleans are pointers because a Jenkins tree query omits a field it
// cannot export rather than failing, so a value type would turn "the
// controller did not report this" into a confident false. For hasUpdate
// that false is the direction that makes a patch-currency audit pass.
func (r *mqlJenkins) plugins() ([]any, error) {
	conn := r.conn()

	var resp struct {
		Plugins []struct {
			ShortName           string `json:"shortName"`
			LongName            string `json:"longName"`
			Version             string `json:"version"`
			Enabled             *bool  `json:"enabled"`
			Active              *bool  `json:"active"`
			HasUpdate           *bool  `json:"hasUpdate"`
			URL                 string `json:"url"`
			RequiredCoreVersion string `json:"requiredCoreVersion"`
		} `json:"plugins"`
	}

	_, err := conn.Client().Requester.GetJSON(context.Background(), "/pluginManager", &resp, map[string]string{
		"tree": "plugins[shortName,longName,version,enabled,active,hasUpdate,url,requiredCoreVersion]",
	})
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(resp.Plugins))
	for _, p := range resp.Plugins {
		res, err := CreateResource(r.MqlRuntime, "jenkins.plugin", map[string]*llx.RawData{
			"__id":                llx.StringData(conn.BaseUrl() + "/plugin/" + p.ShortName),
			"shortName":           llx.StringData(p.ShortName),
			"longName":            llx.StringData(p.LongName),
			"version":             llx.StringData(p.Version),
			"enabled":             llx.BoolDataPtr(p.Enabled),
			"active":              llx.BoolDataPtr(p.Active),
			"hasUpdate":           llx.BoolDataPtr(p.HasUpdate),
			"url":                 llx.StringData(p.URL),
			"requiredCoreVersion": llx.StringData(p.RequiredCoreVersion),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
