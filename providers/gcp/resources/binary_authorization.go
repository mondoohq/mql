// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	binaryauthorization "cloud.google.com/go/binaryauthorization/apiv1"
	"cloud.google.com/go/binaryauthorization/apiv1/binaryauthorizationpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) binaryAuthorization() (*mqlGcpProjectBinaryAuthorizationControl, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_binaryauthorization)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_binaryauthorization).Msg("gcp service is not enabled, skipping")
		g.BinaryAuthorization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	credentials, err := conn.Credentials(binaryauthorization.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// The project's own Binary Authorization policy comes from the management
	// client's GetPolicy ("projects/*/policy"). GetSystemPolicy is a different
	// API: it takes "locations/*/policy" and returns Google's system policy,
	// which is not associated with a project and carries none of the project's
	// cluster/namespace admission rules.
	c, err := binaryauthorization.NewBinauthzManagementClient(ctx, option.WithCredentials(credentials), connection.GRPCClientTraceOption(), option.WithQuotaProject(projectId))
	if err != nil {
		return nil, err
	}

	defer c.Close()

	name := fmt.Sprintf("projects/%s/policy", projectId)
	resp, err := c.GetPolicy(ctx, &binaryauthorizationpb.GetPolicyRequest{
		Name: name,
	})
	if err != nil {
		if isSkippable(err) {
			g.BinaryAuthorization.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var admissionWhitelistPatterns []any
	for _, pattern := range resp.GetAdmissionWhitelistPatterns() {
		admissionWhitelistPatterns = append(admissionWhitelistPatterns, pattern.GetNamePattern())
	}

	clusterAdmissionRules, err := g.toMqlBinaryAuthzAdmissionRules(resp.GetClusterAdmissionRules(), name, "clusterAdmissionRules")
	if err != nil {
		return nil, err
	}

	kubernetesNamespaceAdmissionRules, err := g.toMqlBinaryAuthzAdmissionRules(resp.GetKubernetesNamespaceAdmissionRules(), name, "kubernetesNamespaceAdmissionRules")
	if err != nil {
		return nil, err
	}

	kubernetesServiceAccountAdmissionRules, err := g.toMqlBinaryAuthzAdmissionRules(resp.GetKubernetesServiceAccountAdmissionRules(), name, "kubernetesServiceAccountAdmissionRules")
	if err != nil {
		return nil, err
	}

	istioServiceIdentityAdmissionRules, err := g.toMqlBinaryAuthzAdmissionRules(resp.GetIstioServiceIdentityAdmissionRules(), name, "istioServiceIdentityAdmissionRules")
	if err != nil {
		return nil, err
	}

	defaultAdmissionRule, err := g.toMqlBinaryAuthzAdmissionRule(resp.GetDefaultAdmissionRule(), fmt.Sprintf("%s/defaultAdmissionRule", name))
	if err != nil {
		return nil, err
	}

	updateTime := timestampAsTimePtr(resp.GetUpdateTime())

	policy, err := CreateResource(g.MqlRuntime, "gcp.project.binaryAuthorizationControl.policy", map[string]*llx.RawData{
		"__id":                                   llx.StringData(name),
		"name":                                   llx.StringData(name),
		"admissionWhitelistPatterns":             llx.ArrayData(admissionWhitelistPatterns, types.String),
		"globalPolicyEvaluationMode":             llx.StringData(resp.GetGlobalPolicyEvaluationMode().String()),
		"clusterAdmissionRules":                  llx.MapData(clusterAdmissionRules, types.Resource("gcp.project.binaryAuthorizationControl.admissionRule")),
		"kubernetesNamespaceAdmissionRules":      llx.MapData(kubernetesNamespaceAdmissionRules, types.Resource("gcp.project.binaryAuthorizationControl.admissionRule")),
		"kubernetesServiceAccountAdmissionRules": llx.MapData(kubernetesServiceAccountAdmissionRules, types.Resource("gcp.project.binaryAuthorizationControl.admissionRule")),
		"istioServiceIdentityAdmissionRules":     llx.MapData(istioServiceIdentityAdmissionRules, types.Resource("gcp.project.binaryAuthorizationControl.admissionRule")),
		"defaultAdmissionRule":                   llx.ResourceData(defaultAdmissionRule, "gcp.project.binaryAuthorizationControl.admissionRule"),
		"updated":                                llx.TimeDataPtr(updateTime),
	})
	if err != nil {
		return nil, err
	}

	bauthz, err := CreateResource(g.MqlRuntime, "gcp.project.binaryAuthorizationControl", map[string]*llx.RawData{
		"__id":   llx.StringData(fmt.Sprintf("projects/%s/binaryAuthorizationControl", projectId)),
		"policy": llx.ResourceData(policy, "gcp.project.binaryAuthorizationControl.policy"),
	})
	if err != nil {
		return nil, err
	}

	return bauthz.(*mqlGcpProjectBinaryAuthorizationControl), nil
}

func (g *mqlGcpProject) toMqlBinaryAuthzAdmissionRules(rules map[string]*binaryauthorizationpb.AdmissionRule, policyName string, ruleSetName string) (map[string]any, error) {
	mqlRules := make(map[string]any)
	for ruleName, rule := range rules {
		mqlId := fmt.Sprintf("%s/%s/%s", policyName, ruleSetName, ruleName)
		mqlRule, err := g.toMqlBinaryAuthzAdmissionRule(rule, mqlId)
		if err != nil {
			return nil, err
		}
		mqlRules[ruleName] = mqlRule
	}
	return mqlRules, nil
}

func (g *mqlGcpProject) toMqlBinaryAuthzAdmissionRule(rule *binaryauthorizationpb.AdmissionRule, mqlId string) (plugin.Resource, error) {
	var requiresAttestationsBy []any
	for _, attestation := range rule.GetRequireAttestationsBy() {
		requiresAttestationsBy = append(requiresAttestationsBy, attestation)
	}
	return CreateResource(g.MqlRuntime, "gcp.project.binaryAuthorizationControl.admissionRule", map[string]*llx.RawData{
		"__id":                  llx.StringData(mqlId),
		"evaluationMode":        llx.StringData(rule.GetEvaluationMode().String()),
		"enforcementMode":       llx.StringData(rule.GetEnforcementMode().String()),
		"requireAttestationsBy": llx.ArrayData(requiresAttestationsBy, types.String),
	})
}

func (g *mqlGcpProjectBinaryAuthorizationControlAttestor) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBinaryAuthorizationControl) attestors() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	projectId := conn.ResourceID()

	credentials, err := conn.Credentials(binaryauthorization.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	c, err := binaryauthorization.NewBinauthzManagementClient(ctx, option.WithCredentials(credentials), connection.GRPCClientTraceOption(), option.WithQuotaProject(projectId))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	it := c.ListAttestors(ctx, &binaryauthorizationpb.ListAttestorsRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		attestor, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		note := attestor.GetUserOwnedGrafeasNote()
		publicKeys, err := flattenAttestorPublicKeys(g.MqlRuntime, attestor.GetName(), note)
		if err != nil {
			return nil, err
		}

		mqlAttestor, err := CreateResource(g.MqlRuntime, "gcp.project.binaryAuthorizationControl.attestor", map[string]*llx.RawData{
			"name":                          llx.StringData(attestor.GetName()),
			"description":                   llx.StringData(attestor.GetDescription()),
			"noteReference":                 llx.StringData(note.GetNoteReference()),
			"publicKeys":                    llx.ArrayData(publicKeys, types.Resource("gcp.project.binaryAuthorizationControl.attestor.publicKey")),
			"delegationServiceAccountEmail": llx.StringData(note.GetDelegationServiceAccountEmail()),
			"updated":                       llx.TimeDataPtr(timestampAsTimePtr(attestor.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAttestor)
	}

	return res, nil
}

func flattenAttestorPublicKeys(runtime *plugin.Runtime, attestorName string, note *binaryauthorizationpb.UserOwnedGrafeasNote) ([]any, error) {
	if note == nil {
		return []any{}, nil
	}
	keys := note.GetPublicKeys()
	res := make([]any, 0, len(keys))
	for _, k := range keys {
		var keyType, asciiPgp, pkixPem, pkixAlg string
		switch pk := k.GetPublicKey().(type) {
		case *binaryauthorizationpb.AttestorPublicKey_AsciiArmoredPgpPublicKey:
			keyType = "pgp"
			asciiPgp = pk.AsciiArmoredPgpPublicKey
		case *binaryauthorizationpb.AttestorPublicKey_PkixPublicKey:
			keyType = "pkix"
			if pk.PkixPublicKey != nil {
				pkixPem = pk.PkixPublicKey.PublicKeyPem
				pkixAlg = pk.PkixPublicKey.SignatureAlgorithm.String()
			}
		}

		mqlKey, err := CreateResource(runtime, "gcp.project.binaryAuthorizationControl.attestor.publicKey", map[string]*llx.RawData{
			"__id":                     llx.StringData(fmt.Sprintf("%s/keys/%s", attestorName, k.GetId())),
			"id":                       llx.StringData(k.GetId()),
			"comment":                  llx.StringData(k.GetComment()),
			"type":                     llx.StringData(keyType),
			"asciiArmoredPgpPublicKey": llx.StringData(asciiPgp),
			"pkixPublicKeyPem":         llx.StringData(pkixPem),
			"pkixSignatureAlgorithm":   llx.StringData(pkixAlg),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}
