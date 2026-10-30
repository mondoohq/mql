// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"go.mondoo.com/mql/types"
)

// cleanupSearchCriteria selects what a policy deletes.
type cleanupSearchCriteria struct {
	PackageTypes                 []string `json:"packageTypes"`
	Repos                        []string `json:"repos"`
	ExcludedRepos                []string `json:"excludedRepos"`
	CreatedBeforeInMonths        *int64   `json:"createdBeforeInMonths"`
	LastDownloadedBeforeInMonths *int64   `json:"lastDownloadedBeforeInMonths"`
	KeepLastNVersions            *int64   `json:"keepLastNVersions"`
}

type cleanupPolicyRecord struct {
	Key               string                `json:"key"`
	Description       string                `json:"description"`
	CronExp           string                `json:"cronExp"`
	DurationInMinutes *int64                `json:"durationInMinutes"`
	Enabled           bool                  `json:"enabled"`
	SkipTrashcan      bool                  `json:"skipTrashcan"`
	SearchCriteria    cleanupSearchCriteria `json:"searchCriteria"`
}

type mqlArtifactoryCleanupPolicyInternal struct {
	repositories []string
}

// cleanupPolicies reads the package cleanup policies of the instance.
//
// The endpoint is served by newer product versions only. An older instance
// answers 404, which is reported as an error naming the endpoint rather than
// as an empty list: a policy audit that silently reports "no policies" on an
// instance that never served them would pass for the wrong reason.
func (a *mqlArtifactory) cleanupPolicies() ([]any, error) {
	conn := artifactoryConn(a.MqlRuntime)
	requestURL := conn.ArtifactoryURL("/api/cleanup/packages/policies")

	body, err := conn.GetRaw(context.Background(), requestURL)
	if err != nil {
		if connection.IsNotFound(err) {
			return nil, fmt.Errorf("this Artifactory instance does not serve the package cleanup policies endpoint (%s): %w", requestURL, err)
		}
		return nil, err
	}

	records, err := decodeCleanupPolicies(body)
	if err != nil {
		return nil, fmt.Errorf("artifactory API %s: %w", requestURL, err)
	}

	res := make([]any, 0, len(records))
	for i := range records {
		policy, err := newArtifactoryCleanupPolicy(a.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, policy)
	}
	return res, nil
}

// decodeCleanupPolicies reads both shapes the endpoint answers with: a bare
// array of policies, and an object holding them under a policies key.
func decodeCleanupPolicies(body []byte) ([]cleanupPolicyRecord, error) {
	var list []cleanupPolicyRecord
	if err := json.Unmarshal(body, &list); err == nil {
		return list, nil
	}

	var wrapped struct {
		Policies []cleanupPolicyRecord `json:"policies"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return wrapped.Policies, nil
}

func newArtifactoryCleanupPolicy(runtime *plugin.Runtime, rec *cleanupPolicyRecord) (*mqlArtifactoryCleanupPolicy, error) {
	criteria := rec.SearchCriteria

	res, err := CreateResource(runtime, "artifactory.cleanupPolicy", map[string]*llx.RawData{
		"key":                          llx.StringData(rec.Key),
		"description":                  optionalString(rec.Description),
		"enabled":                      llx.BoolData(rec.Enabled),
		"cronExpression":               llx.StringData(rec.CronExp),
		"durationInMinutes":            optionalInt(rec.DurationInMinutes),
		"skipTrashcan":                 llx.BoolData(rec.SkipTrashcan),
		"repositories":                 llx.ArrayData(strSliceToAny(criteria.Repos), types.String),
		"excludedRepositories":         llx.ArrayData(strSliceToAny(criteria.ExcludedRepos), types.String),
		"packageTypes":                 llx.ArrayData(strSliceToAny(criteria.PackageTypes), types.String),
		"createdBeforeInMonths":        optionalInt(criteria.CreatedBeforeInMonths),
		"lastDownloadedBeforeInMonths": optionalInt(criteria.LastDownloadedBeforeInMonths),
		"keepLastNVersions":            optionalInt(criteria.KeepLastNVersions),
	})
	if err != nil {
		return nil, err
	}

	policy := res.(*mqlArtifactoryCleanupPolicy)
	policy.repositories = criteria.Repos
	return policy, nil
}

func (p *mqlArtifactoryCleanupPolicy) id() (string, error) {
	return "artifactory.cleanupPolicy/" + p.Key.Data, p.Key.Error
}

func (p *mqlArtifactoryCleanupPolicy) repositoryRefs() ([]any, error) {
	return resolveRepositories(p.MqlRuntime, p.repositories)
}

// optionalInt reports a threshold the policy does not set as null, so a policy
// that never deletes by age is distinguishable from one that deletes at zero
// months.
func optionalInt(v *int64) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(*v)
}
