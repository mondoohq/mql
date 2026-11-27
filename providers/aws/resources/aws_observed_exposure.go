// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// externalAccessFindingsForArn returns the IAM Access Analyzer external-access
// findings whose resource is the given ARN: AWS's own determination that a
// resource is reachable from outside the zone of trust. The account-wide list is
// cached after first use, so this is an in-memory scan per resource.
//
// region is the resource's region, or "" for a global resource (any region's
// analyzer covers it). With strict, a region without an active external-access
// analyzer is NotApplicable, so "no analyzer here" is not read as "nothing is
// reachable". Without strict, the edge answers an empty list in that case and
// when the list is refused, as it did before structured errors.
func externalAccessFindingsForArn(runtime *plugin.Runtime, arn, region string, strict bool) ([]any, error) {
	if arn == "" {
		return []any{}, nil
	}
	root, err := accessAnalyzerRoot(runtime)
	if err != nil {
		return nil, err
	}

	if strict {
		regions, err := root.externalAccessRegions()
		if err != nil {
			return nil, err
		}
		covered := len(regions) > 0
		if region != "" {
			covered = regions[region]
		}
		if !covered {
			if region == "" {
				return nil, llx.NotApplicable(errNoExternalAccessAnalyzer)
			}
			return nil, llx.NotApplicable(fmt.Errorf("no external-access analyzer is active in region %s", region))
		}
	}

	findings := root.GetExternalAccessFindings()
	if findings.Error != nil {
		if !strict && (errors.Is(findings.Error, llx.ErrNotApplicable) || errors.Is(findings.Error, llx.ErrForbidden)) {
			return []any{}, nil
		}
		return nil, findings.Error
	}
	res := []any{}
	for _, f := range findings.Data {
		finding, ok := f.(*mqlAwsIamAccessAnalyzerFinding)
		if !ok {
			continue
		}
		if finding.ResourceArn.Data == arn {
			res = append(res, finding)
		}
	}
	return res, nil
}

func (a *mqlAwsS3Bucket) externalAccessFindings() ([]any, error) {
	if !plugin.StructuredErrors() {
		return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, "", false)
	}
	region, ok, err := a.bucketRegion()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, llx.NotApplicable(errors.New("the bucket's region cannot be read from this account"))
	}
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, region, true)
}

func (a *mqlAwsIamRole) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, "", plugin.StructuredErrors())
}

func (a *mqlAwsKmsKey) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, a.Region.Data, plugin.StructuredErrors())
}

func (a *mqlAwsSnsTopic) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, a.Region.Data, plugin.StructuredErrors())
}

func (a *mqlAwsDynamodbTable) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, a.Region.Data, true)
}

func (a *mqlAwsRdsSnapshot) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, a.Region.Data, true)
}

func (a *mqlAwsEfsFilesystem) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, a.Region.Data, true)
}

func (a *mqlAwsEc2Snapshot) externalAccessFindings() ([]any, error) {
	return externalAccessFindingsForArn(a.MqlRuntime, a.Arn.Data, a.Region.Data, true)
}
