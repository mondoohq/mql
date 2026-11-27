// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
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
	// A region whose listing was refused has findings we could not read:
	// "none" would be a false negative.
	if strict && region != "" {
		if refused := root.externalRefusedRegion(region); refused != nil {
			return nil, llx.Forbidden(refused, llx.WithPermissions(permListFindings))
		}
	}
	res := []any{}
	for _, f := range findings.Data {
		finding, ok := f.(*mqlAwsIamAccessAnalyzerFinding)
		if !ok {
			continue
		}
		if sameResourceArn(finding.ResourceArn.Data, arn) {
			res = append(res, finding)
		}
	}
	if region == "" {
		res = oneRegionsFindings(res)
	}
	return res, nil
}

// sameResourceArn reports whether a finding's resource ARN names the same
// resource as the ARN mql built for it. The partition is ignored: some ARNs
// are built with "aws", which in GovCloud or China Access Analyzer reports as
// "aws-us-gov" or "aws-cn". An empty account on either side matches any:
// EC2 snapshot ARNs are canonically written without one.
func sameResourceArn(findingArn, resourceArn string) bool {
	if findingArn == resourceArn {
		return true
	}
	f, err := arn.Parse(findingArn)
	if err != nil {
		return false
	}
	r, err := arn.Parse(resourceArn)
	if err != nil {
		return false
	}
	return f.Service == r.Service && f.Region == r.Region && f.Resource == r.Resource &&
		(f.AccountID == r.AccountID || f.AccountID == "" || r.AccountID == "")
}

// oneRegionsFindings keeps, for a global resource, only the findings of one
// region. Access Analyzer reports a global resource such as an IAM role in
// every region with an analyzer, so without this one grant came back once per
// region. The alphabetically first region is kept, so the answer is stable.
func oneRegionsFindings(list []any) []any {
	first := ""
	for _, x := range list {
		if r := x.(*mqlAwsIamAccessAnalyzerFinding).Region.Data; first == "" || r < first {
			first = r
		}
	}
	res := make([]any, 0, len(list))
	for _, x := range list {
		if x.(*mqlAwsIamAccessAnalyzerFinding).Region.Data == first {
			res = append(res, x)
		}
	}
	return res
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
