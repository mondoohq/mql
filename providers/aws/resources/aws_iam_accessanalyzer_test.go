// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	testAnalyzerArn  = "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/account"
	testAnalyzer2Arn = "arn:aws:access-analyzer:us-east-1:111122223333:analyzer/organization"
)

// enableStructuredErrors turns structured errors on for one test.
func enableStructuredErrors(t *testing.T) {
	t.Helper()
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
}

// accessAnalyzerStub answers ListFindings and GetFindingV2 from fixed values and
// counts the calls per operation.
type accessAnalyzerStub struct {
	mu          sync.Mutex
	listCalls   map[string]int // analyzer ARN -> ListFindings pages served
	getCalls    int
	summaries   map[string][]aatypes.FindingSummary // analyzer ARN -> findings
	getDetails  []aatypes.FindingDetails
	listErr     error
	getErr      error
	unexpected  []string
	pageOfFirst int // when > 0, ListFindings serves the first summaries in a page of this size
}

func (s *accessAnalyzerStub) answer(params any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch in := params.(type) {
	case *accessanalyzer.ListFindingsInput:
		if s.listCalls == nil {
			s.listCalls = map[string]int{}
		}
		s.listCalls[aws.ToString(in.AnalyzerArn)]++
		if s.listErr != nil {
			return nil, s.listErr
		}
		all := s.summaries[aws.ToString(in.AnalyzerArn)]
		if s.pageOfFirst > 0 && in.NextToken == nil && len(all) > s.pageOfFirst {
			return &accessanalyzer.ListFindingsOutput{Findings: all[:s.pageOfFirst], NextToken: aws.String("page2")}, nil
		}
		if s.pageOfFirst > 0 && in.NextToken != nil {
			return &accessanalyzer.ListFindingsOutput{Findings: all[s.pageOfFirst:]}, nil
		}
		return &accessanalyzer.ListFindingsOutput{Findings: all}, nil
	case *accessanalyzer.GetFindingV2Input:
		s.getCalls++
		if s.getErr != nil {
			return nil, s.getErr
		}
		return &accessanalyzer.GetFindingV2Output{FindingDetails: s.getDetails}, nil
	default:
		s.unexpected = append(s.unexpected, fmt.Sprintf("%T", params))
		return nil, fmt.Errorf("unexpected operation %T", params)
	}
}

func (s *accessAnalyzerStub) runtime(t *testing.T) *plugin.Runtime {
	rt := testRuntime()
	rt.Connection = stubAwsConn(t, s.answer)
	return rt
}

func testFinding(rt *plugin.Runtime, id, findingType, analyzerArn string) *mqlAwsIamAccessAnalyzerFinding {
	return &mqlAwsIamAccessAnalyzerFinding{
		MqlRuntime:  rt,
		Id:          setString(id),
		Type:        setString(findingType),
		Region:      setString("us-east-1"),
		AnalyzerArn: setString(analyzerArn),
	}
}

func accessAnalyzerDenied(action string) error {
	return awsAPIErr(403, "AccessDeniedException", "User is not authorized to perform: "+action)
}

// Synthetic: the shapes of the ExternalAccess member of a finding that the
// AWS IAM Access Analyzer documentation describes; no target showed these.
// The account and principal values are documentation placeholders.
func TestDecodeFindingSummaryV1(t *testing.T) {
	t.Run("account principal with one action", func(t *testing.T) {
		got := decodeFindingSummaryV1(aatypes.FindingSummary{
			Id:                               aws.String("f-account"),
			Principal:                        map[string]string{"AWS": "arn:aws:iam::444455556666:root"},
			Action:                           []string{"s3:GetObject"},
			Condition:                        map[string]string{},
			IsPublic:                         aws.Bool(false),
			Sources:                          []aatypes.FindingSource{{Type: aatypes.FindingSourceTypePolicy}},
			ResourceControlPolicyRestriction: aatypes.ResourceControlPolicyRestrictionNotApplicable,
		})
		assert.Equal(t, map[string]any{"AWS": "arn:aws:iam::444455556666:root"}, got.principal)
		assert.Equal(t, []any{"s3:GetObject"}, got.actions)
		assert.Equal(t, map[string]any{}, got.condition)
		require.NotNil(t, got.isPublic)
		assert.False(t, *got.isPublic)
		assert.Equal(t, []any{map[string]any{"type": "POLICY"}}, got.sources)
		assert.Equal(t, "NOT_APPLICABLE", got.rcpRestrict)
	})

	t.Run("public principal", func(t *testing.T) {
		got := decodeFindingSummaryV1(aatypes.FindingSummary{
			Principal: map[string]string{"AWS": "*"},
			Action:    []string{"s3:GetObject", "s3:ListBucket"},
			IsPublic:  aws.Bool(true),
		})
		assert.Equal(t, map[string]any{"AWS": "*"}, got.principal)
		assert.Equal(t, []any{"s3:GetObject", "s3:ListBucket"}, got.actions)
		require.NotNil(t, got.isPublic)
		assert.True(t, *got.isPublic)
	})

	t.Run("condition that limits the access", func(t *testing.T) {
		got := decodeFindingSummaryV1(aatypes.FindingSummary{
			Principal: map[string]string{"AWS": "*"},
			Condition: map[string]string{"aws:SourceVpce": "vpce-1a2b3c4d"},
			IsPublic:  aws.Bool(false),
		})
		assert.Equal(t, map[string]any{"aws:SourceVpce": "vpce-1a2b3c4d"}, got.condition)
	})

	t.Run("access point source", func(t *testing.T) {
		got := decodeFindingSummaryV1(aatypes.FindingSummary{
			Sources: []aatypes.FindingSource{{
				Type: aatypes.FindingSourceTypeS3AccessPoint,
				Detail: &aatypes.FindingSourceDetail{
					AccessPointArn:     aws.String("arn:aws:s3:us-east-1:444455556666:accesspoint/shared"),
					AccessPointAccount: aws.String("444455556666"),
				},
			}},
		})
		assert.Equal(t, []any{map[string]any{
			"type":               "S3_ACCESS_POINT",
			"accessPointArn":     "arn:aws:s3:us-east-1:444455556666:accesspoint/shared",
			"accessPointAccount": "444455556666",
		}}, got.sources)
	})

	t.Run("absent public flag stays absent", func(t *testing.T) {
		got := decodeFindingSummaryV1(aatypes.FindingSummary{})
		assert.Nil(t, got.isPublic)
		assert.Equal(t, []any{}, got.actions)
		assert.Equal(t, []any{}, got.sources)
		assert.Equal(t, "", got.rcpRestrict)
	})
}

// Synthetic: the GetFindingV2 external-access member carrying the same values as
// a v1 summary decodes to the same detail; no target showed this.
func TestDecodeExternalAccessDetailsV2(t *testing.T) {
	principal := map[string]string{"AWS": "arn:aws:iam::444455556666:root"}
	condition := map[string]string{"aws:SourceVpce": "vpce-1a2b3c4d"}
	sources := []aatypes.FindingSource{{Type: aatypes.FindingSourceTypeBucketAcl}}

	v1 := decodeFindingSummaryV1(aatypes.FindingSummary{
		Principal: principal, Action: []string{"s3:PutObject"}, Condition: condition,
		IsPublic: aws.Bool(false), Sources: sources,
		ResourceControlPolicyRestriction: aatypes.ResourceControlPolicyRestrictionApplicable,
	})
	v2, ok := decodeExternalAccessDetails([]aatypes.FindingDetails{
		&aatypes.FindingDetailsMemberExternalAccessDetails{Value: aatypes.ExternalAccessDetails{
			Principal: principal, Action: []string{"s3:PutObject"}, Condition: condition,
			IsPublic: aws.Bool(false), Sources: sources,
			ResourceControlPolicyRestriction: aatypes.ResourceControlPolicyRestrictionApplicable,
		}},
	})
	require.True(t, ok)
	assert.Equal(t, v1, v2)

	_, ok = decodeExternalAccessDetails([]aatypes.FindingDetails{
		&aatypes.FindingDetailsMemberUnusedIamRoleDetails{Value: aatypes.UnusedIamRoleDetails{}},
	})
	assert.False(t, ok, "an unused-access member carries no external-access detail")
}

// Synthetic: an unused-access finding reads its external-access fields as null
// or empty without any API call.
func TestExternalFieldsNullOnUnusedFinding(t *testing.T) {
	stub := &accessAnalyzerStub{}
	rt := stub.runtime(t)
	finding := testFinding(rt, "f-unused", string(aatypes.FindingTypeUnusedIamRole), testAnalyzerArn)

	p := finding.GetPrincipal()
	require.NoError(t, p.Error)
	assert.True(t, p.IsNull())
	pub := finding.GetIsPublic()
	require.NoError(t, pub.Error)
	assert.True(t, pub.IsNull())
	c := finding.GetCondition()
	require.NoError(t, c.Error)
	assert.True(t, c.IsNull())
	rcp := finding.GetResourceControlPolicyRestriction()
	require.NoError(t, rcp.Error)
	assert.True(t, rcp.IsNull())

	acts := finding.GetActions()
	require.NoError(t, acts.Error)
	assert.Equal(t, []any{}, acts.Data)
	srcs := finding.GetSources()
	require.NoError(t, srcs.Error)
	assert.Equal(t, []any{}, srcs.Data)

	assert.Empty(t, stub.listCalls)
	assert.Zero(t, stub.getCalls)
	assert.Empty(t, stub.unexpected)
}

// Synthetic: two findings of one analyzer share one ListFindings pass; a second
// analyzer adds one pass of its own.
func TestOneListFindingsPassPerAnalyzer(t *testing.T) {
	stub := &accessAnalyzerStub{
		pageOfFirst: 1,
		summaries: map[string][]aatypes.FindingSummary{
			testAnalyzerArn: {
				{Id: aws.String("f-1"), Principal: map[string]string{"AWS": "arn:aws:iam::444455556666:root"}},
				{Id: aws.String("f-2"), Principal: map[string]string{"AWS": "*"}, IsPublic: aws.Bool(true)},
			},
			testAnalyzer2Arn: {
				{Id: aws.String("f-3"), Principal: map[string]string{"Service": "cloudfront.amazonaws.com"}},
			},
		},
	}
	rt := stub.runtime(t)
	ext := string(aatypes.FindingTypeExternalAccess)
	f1 := testFinding(rt, "f-1", ext, testAnalyzerArn)
	f2 := testFinding(rt, "f-2", ext, testAnalyzerArn)
	f3 := testFinding(rt, "f-3", ext, testAnalyzer2Arn)

	p1 := f1.GetPrincipal()
	require.NoError(t, p1.Error)
	assert.Equal(t, map[string]any{"AWS": "arn:aws:iam::444455556666:root"}, p1.Data)
	pub2 := f2.GetIsPublic()
	require.NoError(t, pub2.Error)
	assert.True(t, pub2.Data)
	// both pages of the first analyzer, read once
	assert.Equal(t, map[string]int{testAnalyzerArn: 2}, stub.listCalls)

	p3 := f3.GetPrincipal()
	require.NoError(t, p3.Error)
	assert.Equal(t, map[string]any{"Service": "cloudfront.amazonaws.com"}, p3.Data)
	assert.Equal(t, map[string]int{testAnalyzerArn: 2, testAnalyzer2Arn: 1}, stub.listCalls)
	assert.Zero(t, stub.getCalls)

	// a public flag the summary leaves out reads null, not false
	pub1 := f1.GetIsPublic()
	require.NoError(t, pub1.Error)
	assert.True(t, pub1.IsNull())
}

// Synthetic: a finding the memo does not hold reads its detail with GetFindingV2,
// once for all of its fields.
func TestDetailFallbackForMissingID(t *testing.T) {
	stub := &accessAnalyzerStub{
		summaries: map[string][]aatypes.FindingSummary{testAnalyzerArn: {{Id: aws.String("f-old")}}},
		getDetails: []aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberExternalAccessDetails{Value: aatypes.ExternalAccessDetails{
				Principal: map[string]string{"AWS": "*"},
				Action:    []string{"kms:Decrypt"},
				IsPublic:  aws.Bool(true),
			}},
		},
	}
	rt := stub.runtime(t)
	finding := testFinding(rt, "f-new", string(aatypes.FindingTypeExternalAccess), testAnalyzerArn)

	acts := finding.GetActions()
	require.NoError(t, acts.Error)
	assert.Equal(t, []any{"kms:Decrypt"}, acts.Data)
	pub := finding.GetIsPublic()
	require.NoError(t, pub.Error)
	assert.True(t, pub.Data)
	assert.Equal(t, 1, stub.getCalls)
	assert.Equal(t, map[string]int{testAnalyzerArn: 1}, stub.listCalls)
}

// Synthetic: refusals of the memo and of the fallback are Forbidden, naming the
// action that was refused.
func TestDetailRefusalIsForbidden(t *testing.T) {
	t.Run("memo refused", func(t *testing.T) {
		stub := &accessAnalyzerStub{listErr: accessAnalyzerDenied("access-analyzer:ListFindings")}
		rt := stub.runtime(t)
		finding := testFinding(rt, "f-1", string(aatypes.FindingTypeExternalAccess), testAnalyzerArn)

		for name, err := range map[string]error{
			"principal": finding.GetPrincipal().Error,
			"isPublic":  finding.GetIsPublic().Error,
			"actions":   finding.GetActions().Error,
			"condition": finding.GetCondition().Error,
			"sources":   finding.GetSources().Error,
			"rcp":       finding.GetResourceControlPolicyRestriction().Error,
		} {
			require.Error(t, err, name)
			assert.ErrorIs(t, err, llx.ErrForbidden, name)
			e, ok := err.(*llx.Error)
			require.True(t, ok, name)
			assert.Equal(t, []string{"access-analyzer:ListFindings"}, e.Permissions, name)
		}
		assert.Equal(t, map[string]int{testAnalyzerArn: 1}, stub.listCalls, "the refusal is cached")
	})

	t.Run("fallback refused", func(t *testing.T) {
		stub := &accessAnalyzerStub{getErr: accessAnalyzerDenied("access-analyzer:GetFinding")}
		rt := stub.runtime(t)
		finding := testFinding(rt, "f-1", string(aatypes.FindingTypeExternalAccess), testAnalyzerArn)

		err := finding.GetPrincipal().Error
		require.Error(t, err)
		assert.ErrorIs(t, err, llx.ErrForbidden)
		e, ok := err.(*llx.Error)
		require.True(t, ok)
		assert.Equal(t, []string{"access-analyzer:GetFinding"}, e.Permissions)
		assert.ErrorIs(t, finding.GetSources().Error, llx.ErrForbidden)
		assert.Equal(t, 1, stub.getCalls)
	})

	t.Run("other errors are not classified", func(t *testing.T) {
		stub := &accessAnalyzerStub{listErr: awsAPIErr(500, "InternalServerException", "boom")}
		rt := stub.runtime(t)
		finding := testFinding(rt, "f-1", string(aatypes.FindingTypeExternalAccess), testAnalyzerArn)
		err := finding.GetPrincipal().Error
		require.Error(t, err)
		assert.NotErrorIs(t, err, llx.ErrForbidden)
	})
}

// Synthetic: a refused GetFindingV2 for the unused-access fields is Forbidden
// with structured errors, and reads empty without them.
func TestUnusedFieldsRefusalUnderFlag(t *testing.T) {
	newFinding := func(t *testing.T) (*mqlAwsIamAccessAnalyzerFinding, *accessAnalyzerStub) {
		stub := &accessAnalyzerStub{getErr: accessAnalyzerDenied("access-analyzer:GetFinding")}
		return testFinding(stub.runtime(t), "f-unused", string(aatypes.FindingTypeUnusedPermission), testAnalyzerArn), stub
	}

	t.Run("flag off", func(t *testing.T) {
		finding, _ := newFinding(t)
		ns, err := finding.unusedServiceNamespace()
		require.NoError(t, err)
		assert.Empty(t, ns)
		acts, err := finding.unusedActions()
		require.NoError(t, err)
		assert.Equal(t, []any{}, acts)
	})

	t.Run("flag on", func(t *testing.T) {
		enableStructuredErrors(t)
		finding, stub := newFinding(t)
		_, err := finding.unusedServiceNamespace()
		require.Error(t, err)
		assert.ErrorIs(t, err, llx.ErrForbidden)
		e, ok := err.(*llx.Error)
		require.True(t, ok)
		assert.Equal(t, []string{"access-analyzer:GetFinding"}, e.Permissions)
		_, err = finding.lastAccessedAt()
		assert.ErrorIs(t, err, llx.ErrForbidden, "the refusal is cached for every field")
		assert.Equal(t, 1, stub.getCalls)
	})
}

// Synthetic: analyzer() resolves from the cached analyzer list; an ARN that is
// not in the list reads null.
func TestAnalyzerAccessor(t *testing.T) {
	stub := &accessAnalyzerStub{}
	rt := stub.runtime(t)
	root, err := accessAnalyzerRoot(rt)
	require.NoError(t, err)
	listed := &mqlAwsIamAccessAnalyzerAnalyzer{Arn: setString(testAnalyzerArn), Type: setString("ACCOUNT")}
	root.Analyzers = plugin.TValue[[]any]{Data: []any{listed}, State: plugin.StateIsSet}

	found := testFinding(rt, "f-1", string(aatypes.FindingTypeExternalAccess), testAnalyzerArn).GetAnalyzer()
	require.NoError(t, found.Error)
	assert.Same(t, listed, found.Data)

	missing := testFinding(rt, "f-2", string(aatypes.FindingTypeExternalAccess), testAnalyzer2Arn).GetAnalyzer()
	require.NoError(t, missing.Error)
	assert.True(t, missing.IsNull())
	assert.Nil(t, missing.Data)
	assert.Empty(t, stub.unexpected)
}
