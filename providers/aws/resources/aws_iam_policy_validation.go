// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// unusedAccessAge returns the unused-access window of an analyzer, or nil for
// analyzers that are not unused-access analyzers.
func unusedAccessAge(cfg aatypes.AnalyzerConfiguration) *int32 {
	unused, ok := cfg.(*aatypes.AnalyzerConfigurationMemberUnusedAccess)
	if !ok {
		return nil
	}
	return unused.Value.UnusedAccessAge
}

// unusedAccessExclusions renders the exclusion rules of an unused-access
// analyzer with the keys the schema documents. Other analyzers exclude
// nothing.
func unusedAccessExclusions(cfg aatypes.AnalyzerConfiguration) []any {
	res := []any{}
	unused, ok := cfg.(*aatypes.AnalyzerConfigurationMemberUnusedAccess)
	if !ok || unused.Value.AnalysisRule == nil {
		return res
	}
	for _, rule := range unused.Value.AnalysisRule.Exclusions {
		accountIDs := make([]any, 0, len(rule.AccountIds))
		for _, id := range rule.AccountIds {
			accountIDs = append(accountIDs, id)
		}
		resourceTags := make([]any, 0, len(rule.ResourceTags))
		for _, tags := range rule.ResourceTags {
			m := make(map[string]any, len(tags))
			for k, v := range tags {
				m[k] = v
			}
			resourceTags = append(resourceTags, m)
		}
		res = append(res, map[string]any{
			"accountIds":   accountIDs,
			"resourceTags": resourceTags,
		})
	}
	return res
}

// policyDocumentText returns the policy document as JSON text. IAM returns
// managed policy versions URL-encoded; the text is passed on as is otherwise,
// so the positions in validation findings point into the document IAM stores.
func policyDocumentText(raw string) (string, error) {
	if json.Valid([]byte(raw)) {
		return raw, nil
	}
	return url.QueryUnescape(raw)
}

func validatePolicyPosition(p *aatypes.Position) any {
	if p == nil {
		return nil
	}
	return map[string]any{
		"line":   int64(convert.ToValue(p.Line)),
		"column": int64(convert.ToValue(p.Column)),
		"offset": int64(convert.ToValue(p.Offset)),
	}
}

func validatePolicyPathElement(el aatypes.PathElement) any {
	switch v := el.(type) {
	case *aatypes.PathElementMemberIndex:
		return int64(v.Value)
	case *aatypes.PathElementMemberKey:
		return v.Value
	case *aatypes.PathElementMemberValue:
		return v.Value
	case *aatypes.PathElementMemberSubstring:
		return map[string]any{
			"start":  int64(convert.ToValue(v.Value.Start)),
			"length": int64(convert.ToValue(v.Value.Length)),
		}
	default:
		return nil
	}
}

// validatePolicyFindingsToDicts renders Access Analyzer validation findings
// with the keys the schema documents.
func validatePolicyFindingsToDicts(findings []aatypes.ValidatePolicyFinding) []any {
	res := make([]any, 0, len(findings))
	for _, f := range findings {
		locations := make([]any, 0, len(f.Locations))
		for _, loc := range f.Locations {
			path := make([]any, 0, len(loc.Path))
			for _, el := range loc.Path {
				path = append(path, validatePolicyPathElement(el))
			}
			var span any
			if loc.Span != nil {
				span = map[string]any{
					"start": validatePolicyPosition(loc.Span.Start),
					"end":   validatePolicyPosition(loc.Span.End),
				}
			}
			locations = append(locations, map[string]any{
				"path": path,
				"span": span,
			})
		}
		res = append(res, map[string]any{
			"findingType":    string(f.FindingType),
			"issueCode":      convert.ToValue(f.IssueCode),
			"findingDetails": convert.ToValue(f.FindingDetails),
			"learnMoreLink":  convert.ToValue(f.LearnMoreLink),
			"locations":      locations,
		})
	}
	return res
}

func (a *mqlAwsIamPolicy) validationFindings() ([]any, error) {
	defaultVersion, err := a.defaultVersion()
	if err != nil {
		return nil, err
	}
	raw, err := defaultVersion.rawDocument()
	if err != nil {
		return nil, err
	}
	doc, err := policyDocumentText(raw)
	if err != nil {
		return nil, err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AccessAnalyzer("")
	ctx := context.Background()
	findings := []aatypes.ValidatePolicyFinding{}
	paginator := accessanalyzer.NewValidatePolicyPaginator(svc, &accessanalyzer.ValidatePolicyInput{
		PolicyDocument: &doc,
		PolicyType:     aatypes.PolicyTypeIdentityPolicy,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					a.ValidationFindings.State = plugin.StateIsSet | plugin.StateIsNull
					return nil, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("access-analyzer:ValidatePolicy"))
			}
			return nil, err
		}
		findings = append(findings, page.Findings...)
	}
	return validatePolicyFindingsToDicts(findings), nil
}
