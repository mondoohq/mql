// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/aimodel"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAi) id() (string, error) {
	return "ai", nil
}

func (a *mqlAi) models() ([]any, error) {
	home, err := targetHomeDir(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	conn := a.MqlRuntime.Connection.(shared.Connection)
	afs := connectionAfs(a.MqlRuntime)
	osFamily := targetOSFamily(conn)

	var all []any
	for _, m := range aimodel.DetectAll(afs, home, osFamily, ollamaModelDirs(a.MqlRuntime)) {
		res, err := newAiModelResource(a.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func targetOSFamily(conn shared.Connection) string {
	asset := conn.Asset()
	if asset == nil {
		return ""
	}
	if pf := asset.Platform; pf != nil {
		switch {
		case pf.IsFamily("darwin"):
			return "darwin"
		case pf.IsFamily("linux"):
			return "linux"
		case pf.IsFamily("windows"):
			return "windows"
		}
	}
	return ""
}

func newAiModelResource(rt *plugin.Runtime, m aimodel.ModelInfo) (*mqlAiModel, error) {
	var tagsAny []interface{}
	if len(m.Tags) > 0 {
		tagsAny = make([]interface{}, 0, len(m.Tags))
		for _, t := range m.Tags {
			tagsAny = append(tagsAny, t)
		}
	}

	res, err := NewResource(rt, "ai.model", map[string]*llx.RawData{
		"__id":          llx.StringData("ai.model/" + m.Source + "/" + m.Name),
		"name":          llx.StringData(m.Name),
		"source":        llx.StringData(m.Source),
		"vendor":        llx.StringData(m.Vendor),
		"family":        llx.StringData(m.Family),
		"path":          llx.StringData(m.Path),
		"size":          llx.IntData(m.Size),
		"modifiedAt":    llx.TimeData(m.ModifiedAt),
		"format":        llx.StringData(m.Format),
		"version":       llx.StringData(m.Version),
		"quantization":  llx.StringData(m.Quantization),
		"parameterSize": llx.StringData(m.ParameterSize),
		"architecture":  llx.StringData(m.Architecture),
		"license":       llx.StringData(m.License),
		"tags":          llx.ArrayData(tagsAny, types.String),
		"description":   llx.StringData(m.Description),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAiModel), nil
}

func (a *mqlAiModel) id() (string, error) {
	return "ai.model/" + a.Source.Data + "/" + a.Name.Data, nil
}
