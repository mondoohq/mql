// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// setString / setMap / setDict build resolved TValue fields so resource methods
// can be exercised without a runtime — GetOrCompute returns the set value
// without invoking the (runtime-backed) compute function.
func setString(v string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: v, State: plugin.StateIsSet}
}

func setMap(v map[string]any) plugin.TValue[map[string]any] {
	return plugin.TValue[map[string]any]{Data: v, State: plugin.StateIsSet}
}

func setDict(v any) plugin.TValue[any] {
	return plugin.TValue[any]{Data: v, State: plugin.StateIsSet}
}

func TestPolicyStatementHasPublicPrincipal(t *testing.T) {
	tests := []struct {
		name       string
		effect     string
		principals map[string]any
		want       bool
	}{
		{"allow wildcard", "Allow", map[string]any{"AWS": []any{"*"}}, true},
		{"allow wildcard lowercase effect", "allow", map[string]any{"AWS": []any{"*"}}, true},
		{"deny wildcard", "Deny", map[string]any{"AWS": []any{"*"}}, false},
		{"allow specific", "Allow", map[string]any{"AWS": []any{"arn:aws:iam::123456789012:root"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := &mqlAwsIamPolicyStatement{
				Effect:     setString(tt.effect),
				Principals: setMap(tt.principals),
			}
			got, err := stmt.hasPublicPrincipal()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStatementsAllowPublic(t *testing.T) {
	wildcard := map[string]any{"AWS": []any{"*"}}
	specific := map[string]any{"AWS": []any{"arn:aws:iam::123456789012:root"}}
	// A condition on a source-scoping key makes a wildcard grant private.
	scopingCondition := map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-123"}}
	// A condition that does NOT scope the principal (region) leaves the grant
	// effectively public — this is the behaviour shared with allowsPublicAccess.
	regionCondition := map[string]any{"StringEquals": map[string]any{"aws:RequestedRegion": "us-east-1"}}
	// The AWS-generated default SNS topic policy: a wildcard principal pinned to
	// the owning account with aws:SourceOwner. Every default topic carries it.
	sourceOwnerCondition := map[string]any{"StringEquals": map[string]any{"AWS:SourceOwner": "123456789012"}}
	// A wildcard aws:SourceOwner pins nothing and stays public.
	wildcardSourceOwnerCondition := map[string]any{"StringEquals": map[string]any{"AWS:SourceOwner": "*"}}

	newStmt := func(effect string, principals map[string]any, conditions any) *mqlAwsIamPolicyStatement {
		return &mqlAwsIamPolicyStatement{
			Effect:     setString(effect),
			Principals: setMap(principals),
			Conditions: setDict(conditions),
		}
	}

	tests := []struct {
		name       string
		statements []any
		want       bool
	}{
		{"public, no conditions", []any{newStmt("Allow", wildcard, nil)}, true},
		{"public scoped by source condition", []any{newStmt("Allow", wildcard, scopingCondition)}, false},
		{"public with non-scoping region condition", []any{newStmt("Allow", wildcard, regionCondition)}, true},
		{"default sns topic policy scoped by source owner", []any{newStmt("Allow", wildcard, sourceOwnerCondition)}, false},
		{"public with wildcard source owner", []any{newStmt("Allow", wildcard, wildcardSourceOwnerCondition)}, true},
		{"wildcard but denied", []any{newStmt("Deny", wildcard, nil)}, false},
		{"specific principal", []any{newStmt("Allow", specific, nil)}, false},
		{"no statements", []any{}, false},
		{
			"mixed: scoped public then unscoped public",
			[]any{newStmt("Allow", wildcard, scopingCondition), newStmt("Allow", wildcard, nil)},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := statementsAllowPublic(tt.statements)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestPolicyStatementHasPublicPrincipalNotPrincipal covers Allow + NotPrincipal,
// which grants everyone *except* the listed principals and is therefore public
// by construction. Only Principal was consulted before, so a bucket policy of
// this shape reported not-public.
func TestPolicyStatementHasPublicPrincipalNotPrincipal(t *testing.T) {
	tests := []struct {
		name          string
		effect        string
		principals    map[string]any
		notPrincipals map[string]any
		want          bool
	}{
		{
			name:          "allow with notPrincipal is public",
			effect:        "Allow",
			notPrincipals: map[string]any{"AWS": []any{"arn:aws:iam::111111111111:role/Admin"}},
			want:          true,
		},
		{
			name:          "deny with notPrincipal is not public",
			effect:        "Deny",
			notPrincipals: map[string]any{"AWS": []any{"arn:aws:iam::111111111111:role/Admin"}},
			want:          false,
		},
		{
			name:          "empty notPrincipal falls back to principal",
			effect:        "Allow",
			principals:    map[string]any{"AWS": []any{"arn:aws:iam::111111111111:root"}},
			notPrincipals: map[string]any{},
			want:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := &mqlAwsIamPolicyStatement{
				Effect:        setString(tt.effect),
				Principals:    setMap(tt.principals),
				NotPrincipals: setMap(tt.notPrincipals),
			}
			got, err := stmt.hasPublicPrincipal()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestStatementsAllowPublicNegatedCondition covers the operator gate through
// the public-facing predicate: a wildcard principal scoped by a *negated*
// operator is not scoped at all, and must still report public.
func TestStatementsAllowPublicNegatedCondition(t *testing.T) {
	wildcard := map[string]any{"AWS": []any{"*"}}

	tests := []struct {
		name      string
		condition map[string]any
		want      bool
	}{
		{
			name:      "StringEquals on a scoping key is scoped",
			condition: map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": "o-123"}},
			want:      false,
		},
		{
			name:      "StringNotEquals on a scoping key is NOT scoped",
			condition: map[string]any{"StringNotEquals": map[string]any{"aws:PrincipalOrgID": "o-123"}},
			want:      true,
		},
		{
			name:      "Null on a scoping key is NOT scoped",
			condition: map[string]any{"Null": map[string]any{"aws:PrincipalOrgID": "true"}},
			want:      true,
		},
		{
			name:      "kms:CallerAccount is scoped",
			condition: map[string]any{"StringEquals": map[string]any{"kms:CallerAccount": "111111111111"}},
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := &mqlAwsIamPolicyStatement{
				Effect:     setString("Allow"),
				Principals: setMap(wildcard),
				Conditions: setDict(any(tt.condition)),
			}
			got, err := statementsAllowPublic([]any{stmt})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// setStrings builds a resolved list field, as setString does for scalars.
func setStrings(v ...string) plugin.TValue[[]any] {
	data := make([]any, 0, len(v))
	for _, s := range v {
		data = append(data, s)
	}
	return plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet}
}

// A NotAction or NotResource inverts the set the statement applies to, so an
// exclusion list only has to be non-empty to be broader than any wildcard the
// statement could have written out. hasPublicPrincipal already reads
// NotPrincipal this way.
func TestPolicyStatementWildcardsThroughNegatedFields(t *testing.T) {
	t.Run("action", func(t *testing.T) {
		tests := []struct {
			name       string
			actions    []string
			notActions []string
			want       bool
		}{
			{"specific actions", []string{"s3:GetObject"}, nil, false},
			{"global wildcard action", []string{"*"}, nil, true},
			{"service wildcard action", []string{"s3:*"}, nil, true},
			{
				// Every action in AWS except the IAM ones: near-administrator,
				// and reported as no wildcard while only Action was consulted.
				name:       "not action",
				actions:    nil,
				notActions: []string{"iam:*"},
				want:       true,
			},
			{"not action with a specific exclusion", nil, []string{"s3:DeleteBucket"}, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				stmt := &mqlAwsIamPolicyStatement{
					Actions:    setStrings(tt.actions...),
					NotActions: setStrings(tt.notActions...),
				}
				got, err := stmt.hasWildcardAction()
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("resource", func(t *testing.T) {
		tests := []struct {
			name         string
			resources    []string
			notResources []string
			want         bool
		}{
			{"specific resources", []string{"arn:aws:s3:::my-bucket"}, nil, false},
			{"global wildcard resource", []string{"*"}, nil, true},
			{"service namespace wildcard resource", []string{"arn:aws:s3:::*"}, nil, true},
			{
				// Every resource except the one named, which no written-out
				// wildcard could exceed.
				name:         "not resource",
				resources:    nil,
				notResources: []string{"arn:aws:secretsmanager:us-east-1:000000000000:secret:prod"},
				want:         true,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				stmt := &mqlAwsIamPolicyStatement{
					Resources:    setStrings(tt.resources...),
					NotResources: setStrings(tt.notResources...),
				}
				got, err := stmt.hasWildcardResource()
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

// statementsAllowWildcard is what hasWildcardAllow reports, so the negated
// fields have to reach it through an Allow and stay out of it through a Deny.
func TestStatementsAllowWildcardWithNegatedFields(t *testing.T) {
	tests := []struct {
		name string
		stmt *mqlAwsIamPolicyStatement
		want bool
	}{
		{
			name: "allow with not action",
			stmt: &mqlAwsIamPolicyStatement{
				Effect:     setString("Allow"),
				Actions:    setStrings(),
				NotActions: setStrings("iam:*"),
				Resources:  setStrings("arn:aws:s3:::my-bucket"),
			},
			want: true,
		},
		{
			// A Deny that excludes a set is a guardrail, not a grant.
			name: "deny with not action",
			stmt: &mqlAwsIamPolicyStatement{
				Effect:     setString("Deny"),
				Actions:    setStrings(),
				NotActions: setStrings("iam:*"),
				Resources:  setStrings("arn:aws:s3:::my-bucket"),
			},
			want: false,
		},
		{
			name: "allow with not resource",
			stmt: &mqlAwsIamPolicyStatement{
				Effect:       setString("Allow"),
				Actions:      setStrings("s3:GetObject"),
				NotActions:   setStrings(),
				Resources:    setStrings(),
				NotResources: setStrings("arn:aws:s3:::my-bucket"),
			},
			want: true,
		},
		{
			name: "allow with neither",
			stmt: &mqlAwsIamPolicyStatement{
				Effect:       setString("Allow"),
				Actions:      setStrings("s3:GetObject"),
				NotActions:   setStrings(),
				Resources:    setStrings("arn:aws:s3:::my-bucket"),
				NotResources: setStrings(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := statementsAllowWildcard([]any{tt.stmt})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
