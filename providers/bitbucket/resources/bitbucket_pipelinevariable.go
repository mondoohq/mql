// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
)

// newMqlBitbucketPipelineVariable maps a single API Pipelines variable to its
// MQL resource. scope is a parent-qualifying prefix (the repository full name,
// workspace slug, or deployment environment UUID) that keeps variable UUIDs,
// which are only unique within their own scope, from colliding in the cache.
// A secured variable never returns its value, so value stays empty for it.
func newMqlBitbucketPipelineVariable(runtime *plugin.Runtime, scope string, v *connection.PipelineVariable) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.pipelineVariable", map[string]*llx.RawData{
		"__id":    llx.StringData(scope + "/variables/" + v.UUID),
		"id":      llx.StringData(v.UUID),
		"key":     llx.StringData(v.Key),
		"secured": llx.BoolData(v.Secured),
		"value":   llx.StringData(v.Value),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
