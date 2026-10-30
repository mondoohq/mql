// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// accessAnalyzerFindingsForArn returns the IAM Access Analyzer findings whose
// resource is the given ARN — AWS's own determination that a resource is
// externally or publicly accessible. The account-wide findings list is cached
// after first use, so this is an in-memory scan per resource. Returns an empty
// list when Access Analyzer is not enabled (no findings).
func accessAnalyzerFindingsForArn(runtime *plugin.Runtime, arn string) ([]any, error) {
	if arn == "" {
		return []any{}, nil
	}
	obj, err := CreateResource(runtime, ResourceAwsIamAccessAnalyzer, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	findings := obj.(*mqlAwsIamAccessAnalyzer).GetFindings()
	if findings.Error != nil {
		return nil, findings.Error
	}
	res := []any{}
	for _, f := range findings.Data {
		finding, ok := f.(*mqlAwsIamAccessAnalyzerFinding)
		if !ok {
			continue
		}
		resourceArn := finding.GetResourceArn()
		if resourceArn.Error != nil {
			return nil, resourceArn.Error
		}
		if resourceArn.Data == arn {
			res = append(res, finding)
		}
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) externalAccessFindings() ([]any, error) {
	return accessAnalyzerFindingsForArn(a.MqlRuntime, a.Arn.Data)
}

func (a *mqlAwsIamRole) externalAccessFindings() ([]any, error) {
	return accessAnalyzerFindingsForArn(a.MqlRuntime, a.Arn.Data)
}

func (a *mqlAwsKmsKey) externalAccessFindings() ([]any, error) {
	return accessAnalyzerFindingsForArn(a.MqlRuntime, a.Arn.Data)
}

func (a *mqlAwsSnsTopic) externalAccessFindings() ([]any, error) {
	return accessAnalyzerFindingsForArn(a.MqlRuntime, a.Arn.Data)
}
