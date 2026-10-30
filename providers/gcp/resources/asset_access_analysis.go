// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"google.golang.org/api/option"
)

// accessAnalysis holds the decomposed result of one AnalyzeIamPolicy call. Every
// computed field on gcp.project.assetService.whoCan is derived from a single
// call, so the whole analysis is resolved once and shared.
type accessAnalysis struct {
	principals            []any
	inheritedPrincipals   []any
	conditionalPrincipals []any
	roles                 []any
	fullyExplored         bool
}

type mqlGcpProjectAssetServiceWhoCanInternal struct {
	analysis    *accessAnalysis
	analysisErr error
	loaded      atomic.Bool
	lock        sync.Mutex
}

// initGcpProjectAssetServiceWhoCan scopes the analysis to the connected project
// and derives the cache key from the question under test. Both selectors are
// declared as real fields so the named-argument form compiles; mqlc resolves
// named arguments against fields and never against init arguments.
func initGcpProjectAssetServiceWhoCan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	for _, f := range []string{"permission", "resource"} {
		if _, ok := args[f]; !ok {
			args[f] = llx.StringData("")
		}
	}

	// __id is built here rather than passed to CreateResource because this
	// resource is parameterized: without a key derived from the arguments every
	// instance collides on the same cache entry and the first question answered
	// is returned for all later ones.
	args["__id"] = llx.StringData(fmt.Sprintf("%s\x00whoCan\x00perm=%s\x00res=%s",
		rawDataString(args["projectId"]), rawDataString(args["permission"]), rawDataString(args["resource"])))

	return args, nil, nil
}

// rawDataString reads a string out of a RawData argument, tolerating a missing
// entry or a non-string value rather than panicking on the type assertion.
func rawDataString(v *llx.RawData) string {
	if v == nil || v.Value == nil {
		return ""
	}
	if s, ok := v.Value.(string); ok {
		return s
	}
	return ""
}

// analyze resolves the IAM policy analysis for the queried permission and
// resource, expanding groups to their member principals and roles to their
// permissions so that the answer reflects effective rather than literal access.
func (g *mqlGcpProjectAssetServiceWhoCan) analyze() (*accessAnalysis, error) {
	if g.loaded.Load() {
		return g.analysis, g.analysisErr
	}
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.loaded.Load() {
		return g.analysis, g.analysisErr
	}
	defer g.loaded.Store(true)

	g.analysis, g.analysisErr = g.fetchAnalysis()
	return g.analysis, g.analysisErr
}

func (g *mqlGcpProjectAssetServiceWhoCan) fetchAnalysis() (*accessAnalysis, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Permission.Error != nil {
		return nil, g.Permission.Error
	}
	if g.Resource.Error != nil {
		return nil, g.Resource.Error
	}
	projectId := g.ProjectId.Data
	permission := g.Permission.Data
	resource := g.Resource.Data

	if permission == "" || resource == "" {
		return nil, errors.New("gcp.project.assetService.whoCan requires both a permission and a resource, e.g. " +
			`gcp.project.assetService.whoCan(permission: "storage.objects.get", resource: "//storage.googleapis.com/projects/_/buckets/my-bucket")`)
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	creds, err := conn.Credentials(asset.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := asset.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	resp, err := client.AnalyzeIamPolicy(ctx, &assetpb.AnalyzeIamPolicyRequest{
		AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
			Scope: "projects/" + projectId,
			ResourceSelector: &assetpb.IamPolicyAnalysisQuery_ResourceSelector{
				FullResourceName: resource,
			},
			AccessSelector: &assetpb.IamPolicyAnalysisQuery_AccessSelector{
				Permissions: []string{permission},
			},
			Options: &assetpb.IamPolicyAnalysisQuery_Options{
				// Groups expand to their member principals and roles to their
				// permissions; without both, a grant to a group or via a custom
				// role is missed entirely.
				ExpandGroups: true,
				ExpandRoles:  true,
			},
		},
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("permission", permission).Str("resource", resource).
				Msg("could not analyze IAM policy")
			// A skippable error means the question was not answered, so report
			// an incomplete analysis rather than an empty one. An empty result
			// with fullyExplored true would read as proof of no access.
			return &accessAnalysis{
				principals:            []any{},
				inheritedPrincipals:   []any{},
				conditionalPrincipals: []any{},
				roles:                 []any{},
				fullyExplored:         false,
			}, nil
		}
		return nil, err
	}

	return summarizeAccessAnalysis(resp, resource), nil
}

// summarizeAccessAnalysis decomposes an AnalyzeIamPolicy response into the
// principal sets exposed on the resource.
//
// A grant is inherited when the binding is attached to a resource other than the
// one under test, which is how a role granted on the enclosing project, folder,
// or organization surfaces. A grant is conditional when its binding carries an
// IAM condition, in which case it applies only when that condition evaluates
// true and cannot be read as unconditional access.
func summarizeAccessAnalysis(resp *assetpb.AnalyzeIamPolicyResponse, queriedResource string) *accessAnalysis {
	out := &accessAnalysis{fullyExplored: resp.GetFullyExplored()}

	all := map[string]struct{}{}
	inherited := map[string]struct{}{}
	conditional := map[string]struct{}{}
	roles := map[string]struct{}{}

	for _, r := range resp.GetMainAnalysis().GetAnalysisResults() {
		if role := r.GetIamBinding().GetRole(); role != "" {
			roles[role] = struct{}{}
		}

		isInherited := r.GetAttachedResourceFullName() != queriedResource
		isConditional := r.GetIamBinding().GetCondition() != nil

		// Prefer the expanded identity list. It is empty when the binding held
		// no expandable member, in which case the binding's own members are the
		// effective principals.
		names := make([]string, 0, len(r.GetIdentityList().GetIdentities()))
		for _, identity := range r.GetIdentityList().GetIdentities() {
			if n := identity.GetName(); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			names = append(names, r.GetIamBinding().GetMembers()...)
		}

		for _, n := range names {
			if n == "" {
				continue
			}
			all[n] = struct{}{}
			if isInherited {
				inherited[n] = struct{}{}
			}
			if isConditional {
				conditional[n] = struct{}{}
			}
		}
	}

	out.principals = sortedAnySet(all)
	out.inheritedPrincipals = sortedAnySet(inherited)
	out.conditionalPrincipals = sortedAnySet(conditional)
	out.roles = sortedAnySet(roles)
	return out
}

// sortedAnySet returns the set's members in a stable order so repeated queries
// produce identical output.
func sortedAnySet(set map[string]struct{}) []any {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, k)
	}
	return out
}

func (g *mqlGcpProjectAssetServiceWhoCan) principals() ([]any, error) {
	a, err := g.analyze()
	if err != nil {
		return nil, err
	}
	return a.principals, nil
}

func (g *mqlGcpProjectAssetServiceWhoCan) inheritedPrincipals() ([]any, error) {
	a, err := g.analyze()
	if err != nil {
		return nil, err
	}
	return a.inheritedPrincipals, nil
}

func (g *mqlGcpProjectAssetServiceWhoCan) conditionalPrincipals() ([]any, error) {
	a, err := g.analyze()
	if err != nil {
		return nil, err
	}
	return a.conditionalPrincipals, nil
}

func (g *mqlGcpProjectAssetServiceWhoCan) roles() ([]any, error) {
	a, err := g.analyze()
	if err != nil {
		return nil, err
	}
	return a.roles, nil
}

func (g *mqlGcpProjectAssetServiceWhoCan) fullyExplored() (bool, error) {
	a, err := g.analyze()
	if err != nil {
		return false, err
	}
	return a.fullyExplored, nil
}

// serviceAccountFullResourceName builds the Cloud Asset Inventory full resource
// name for a service account, the form the IAM policy analysis expects.
func serviceAccountFullResourceName(projectId, email string) string {
	return fmt.Sprintf("//iam.googleapis.com/projects/%s/serviceAccounts/%s", projectId, email)
}

// impersonators resolves who can effectively mint tokens for this service
// account. Unlike canBeImpersonated, which reads only the account's own IAM
// policy, this follows the resource hierarchy and expands groups, so it reaches
// the common case of an impersonation role granted at the project level.
func (g *mqlGcpProjectIamServiceServiceAccount) impersonators() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Email.Error != nil {
		return nil, g.Email.Error
	}
	projectId := g.ProjectId.Data
	email := g.Email.Data
	if email == "" {
		return []any{}, nil
	}

	res, err := NewResource(g.MqlRuntime, "gcp.project.assetService.whoCan", map[string]*llx.RawData{
		"projectId":  llx.StringData(projectId),
		"permission": llx.StringData("iam.serviceAccounts.getAccessToken"),
		"resource":   llx.StringData(serviceAccountFullResourceName(projectId, email)),
	})
	if err != nil {
		return nil, err
	}

	whoCan := res.(*mqlGcpProjectAssetServiceWhoCan)
	principals := whoCan.GetPrincipals()
	if principals.Error != nil {
		return nil, principals.Error
	}
	return principals.Data, nil
}
