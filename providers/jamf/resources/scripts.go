// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jamf/connection"
	"go.mondoo.com/mql/types"
)

// scriptParameters collects the non-empty labeled parameters (parameter4
// through parameter11) into a map keyed by parameter slot.
func scriptParameters(s jamfpro.ResourceScript) map[string]any {
	slots := map[string]string{
		"parameter4":  s.Parameter4,
		"parameter5":  s.Parameter5,
		"parameter6":  s.Parameter6,
		"parameter7":  s.Parameter7,
		"parameter8":  s.Parameter8,
		"parameter9":  s.Parameter9,
		"parameter10": s.Parameter10,
		"parameter11": s.Parameter11,
	}
	out := map[string]any{}
	for k, v := range slots {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// scriptToArgs maps a Jamf Pro script into the MQL resource fields. It is
// shared by the list creator and the by-id init function so both paths
// populate the resource identically.
func scriptToArgs(s jamfpro.ResourceScript) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":             llx.StringData(s.ID),
		"name":           llx.StringData(s.Name),
		"categoryId":     llx.StringData(s.CategoryId),
		"categoryName":   llx.StringData(s.CategoryName),
		"info":           llx.StringData(s.Info),
		"notes":          llx.StringData(s.Notes),
		"osRequirements": llx.StringData(s.OSRequirements),
		"priority":       llx.StringData(s.Priority),
		"scriptContents": llx.StringData(s.ScriptContents),
		"parameters":     llx.MapData(scriptParameters(s), types.String),
	}
}

func (r *mqlJamf) scripts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	// GetScripts paginates through every page internally, so a single call
	// returns the full set of scripts with their contents.
	scripts, err := client.GetScripts(url.Values{})
	if err != nil {
		return nil, err
	}

	var res []any
	for _, s := range scripts.Results {
		item, err := CreateResource(r.MqlRuntime, "jamf.script", scriptToArgs(s))
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}

	return res, nil
}

// initJamfScript resolves a script referenced only by id (e.g. via a policy
// script traversal or a direct jamf.script(id:) query) by fetching its full
// definition. When the resource already carries its fields (the list path),
// the args are returned unchanged.
func initJamfScript(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.JamfConnection)
	script, err := conn.Client.GetScriptByID(id)
	if err != nil {
		return nil, nil, err
	}

	return scriptToArgs(*script), nil, nil
}

func (s *mqlJamfScript) id() (string, error) {
	return "jamf.script/" + s.Id.Data, nil
}
