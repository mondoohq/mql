// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	orgpolicy "cloud.google.com/go/orgpolicy/apiv2"
	"cloud.google.com/go/orgpolicy/apiv2/orgpolicypb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mqlGcpProjectEffectiveOrgPolicyInternal struct {
	policy    *orgpolicypb.Policy
	policyErr error
	loaded    atomic.Bool
	lock      sync.Mutex
}

// normalizeConstraintName accepts a constraint either as it appears in an org
// policy resource path (compute.requireOsLogin) or with the "constraints/"
// prefix used throughout the org policy documentation and the
// gcp.orgPolicy.constraint resource, and returns the bare form the policy path
// expects.
func normalizeConstraintName(constraint string) string {
	return strings.TrimPrefix(constraint, "constraints/")
}

// initGcpProjectEffectiveOrgPolicy scopes the lookup to the connected project and
// derives the cache key from the constraint under test. Both selectors are
// declared as real fields so the named-argument form compiles.
func initGcpProjectEffectiveOrgPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args == nil {
		args = make(map[string]*llx.RawData)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	if args["projectId"] == nil {
		args["projectId"] = llx.StringData(conn.ResourceID())
	}
	if args["constraint"] == nil {
		args["constraint"] = llx.StringData("")
	}

	// Parameterized resource: the cache key must carry the constraint or every
	// constraint queried in one scan resolves to the first one's answer.
	args["__id"] = llx.StringData(fmt.Sprintf("%s\x00effectiveOrgPolicy\x00%s",
		rawDataString(args["projectId"]), normalizeConstraintName(rawDataString(args["constraint"]))))

	return args, nil, nil
}

// effectivePolicy resolves the constraint's policy with inheritance applied. All
// the derived fields read from this one call.
func (g *mqlGcpProjectEffectiveOrgPolicy) effectivePolicy() (*orgpolicypb.Policy, error) {
	if g.loaded.Load() {
		return g.policy, g.policyErr
	}
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.loaded.Load() {
		return g.policy, g.policyErr
	}
	defer g.loaded.Store(true)

	g.policy, g.policyErr = g.fetchEffectivePolicy()
	return g.policy, g.policyErr
}

func (g *mqlGcpProjectEffectiveOrgPolicy) fetchEffectivePolicy() (*orgpolicypb.Policy, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Constraint.Error != nil {
		return nil, g.Constraint.Error
	}
	projectId := g.ProjectId.Data
	constraint := normalizeConstraintName(g.Constraint.Data)

	if constraint == "" {
		return nil, errors.New("gcp.project.effectiveOrgPolicy requires a constraint, e.g. " +
			`gcp.project.effectiveOrgPolicy(constraint: "constraints/compute.requireOsLogin")`)
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	creds, err := conn.Credentials(orgpolicy.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := orgpolicy.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetEffectivePolicy(ctx, &orgpolicypb.GetEffectivePolicyRequest{
		Name: fmt.Sprintf("projects/%s/policies/%s", projectId, constraint),
	})
	if err != nil {
		// A constraint with no policy anywhere in the hierarchy is reported as
		// NotFound. That is the answer, not a failure: nothing is enforced. Erroring
		// here would make the query fail for exactly the case an audit most wants to
		// detect, so return a nil policy and let interpretPolicySpec yield the zero
		// value.
		//
		// Only NotFound is treated this way. PermissionDenied must stay an error: a
		// read the caller is not allowed to make would otherwise be indistinguishable
		// from "not enforced", and a list-constraint assertion over empty
		// allowedValues would pass vacuously. Logged at warn because a misspelled
		// constraint name reaches this path too.
		if status.Code(err) == codes.NotFound {
			log.Warn().Str("project", projectId).Str("constraint", constraint).
				Msg("no effective organization policy found for constraint; reporting it as unset")
			return nil, nil
		}
		return nil, err
	}
	return policy, nil
}

// interpret decodes the effective spec. The effective policy carries a single
// merged spec, so unlike gcp.orgPolicy there is no separate dry-run spec to
// distinguish.
func (g *mqlGcpProjectEffectiveOrgPolicy) interpret() (policySpecSummary, error) {
	policy, err := g.effectivePolicy()
	if err != nil {
		return policySpecSummary{}, err
	}
	return interpretPolicySpec(policy.GetSpec()), nil
}

func (g *mqlGcpProjectEffectiveOrgPolicy) enforced() (bool, error) {
	summary, err := g.interpret()
	return summary.enforced, err
}

func (g *mqlGcpProjectEffectiveOrgPolicy) allowAll() (bool, error) {
	summary, err := g.interpret()
	return summary.allowAll, err
}

func (g *mqlGcpProjectEffectiveOrgPolicy) denyAll() (bool, error) {
	summary, err := g.interpret()
	return summary.denyAll, err
}

func (g *mqlGcpProjectEffectiveOrgPolicy) allowedValues() ([]any, error) {
	summary, err := g.interpret()
	return summary.allowedValues, err
}

func (g *mqlGcpProjectEffectiveOrgPolicy) deniedValues() ([]any, error) {
	summary, err := g.interpret()
	return summary.deniedValues, err
}

// hasConditionalRules reports whether the effective policy is carried, wholly or
// in part, by rules gated by a CEL condition. Those rules are excluded from
// enforced/allowAll/denyAll, so without this field a constraint enforced only by
// a tag-scoped rule is byte-for-byte identical to a constraint with no policy
// anywhere in the hierarchy.
func (g *mqlGcpProjectEffectiveOrgPolicy) hasConditionalRules() (bool, error) {
	summary, err := g.interpret()
	return summary.hasConditionalRules, err
}

func (g *mqlGcpProjectEffectiveOrgPolicy) conditionalRules() ([]any, error) {
	summary, err := g.interpret()
	return summary.conditionalRules, err
}

func (g *mqlGcpProjectEffectiveOrgPolicy) spec() (any, error) {
	policy, err := g.effectivePolicy()
	if err != nil {
		return nil, err
	}
	return protoToDict(policy.GetSpec())
}
