// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/bitwarden/connection"
)

// newMqlBitwardenPolicy maps a single Public API policy to its MQL resource.
func newMqlBitwardenPolicy(runtime *plugin.Runtime, p connection.Policy) (plugin.Resource, error) {
	data, err := convert.JsonToDict(p.Data)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "bitwarden.policy", map[string]*llx.RawData{
		"__id":       llx.StringData(p.Id),
		"id":         llx.StringData(p.Id),
		"policyType": llx.StringData(connection.PolicyTypeName(p.Type)),
		"enabled":    llx.BoolData(p.Enabled),
		"data":       llx.DictData(data),
	})
}
