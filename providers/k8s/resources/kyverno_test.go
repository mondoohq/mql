// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

func TestKyvernoManifestResources(t *testing.T) {
	kyverno := kyvernoTestResource(t)

	installed := kyverno.GetInstalled()
	require.NoError(t, installed.Error)
	assert.True(t, installed.Data)

	policyCount := kyverno.GetPolicyCount()
	require.NoError(t, policyCount.Error)
	assert.Equal(t, int64(6), policyCount.Data)

	resultCount := kyverno.GetResultCount()
	require.NoError(t, resultCount.Error)
	assert.Equal(t, int64(7), resultCount.Data)

	exceptionCount := kyverno.GetExceptionCount()
	require.NoError(t, exceptionCount.Error)
	assert.Equal(t, int64(11), exceptionCount.Data)

	assert.False(t, kyverno.GetMirrorPolicyExceptions().Data)
	assert.Equal(t, "externally-approved", kyverno.GetMirroredExceptionApproval().Data)
	assert.Equal(t, "RISK_ACCEPTED", kyverno.GetMirroredExceptionAction().Data)
	assert.True(t, kyverno.GetFailExpiredPolicyExceptions().Data)
	assert.True(t, kyverno.GetReportUnmappedPolicyExceptions().Data)
	assert.True(t, kyverno.GetReportUnmappedPolicyResults().Data)

	classicPolicy := kyvernoPolicyByName(t, kyverno, "disallow-privileged-containers")
	assert.Equal(t, "ClusterPolicy", classicPolicy.GetKind().Data)
	assert.Equal(t, "Disallow Privileged Containers", classicPolicy.GetTitle().Data)
	assert.Equal(t, "Pod Security Standards (Baseline)", classicPolicy.GetCategory().Data)
	assert.Equal(t, "medium", classicPolicy.GetSeverity().Data)
	assert.False(t, classicPolicy.GetBackground().Data)
	assert.Equal(t, "Audit", classicPolicy.GetValidationFailureAction().Data)
	assert.Equal(t, int64(1), classicPolicy.GetRuleCount().Data)

	classicRules := classicPolicy.GetRules()
	require.NoError(t, classicRules.Error)
	require.Len(t, classicRules.Data, 1)
	classicRule := classicRules.Data[0].(*mqlK8sKyvernoRule)
	assert.Equal(t, "validate-privileged", classicRule.GetName().Data)
	assert.Equal(t, "validate", classicRule.GetType().Data)
	assert.Equal(t, []any{"Pod"}, classicRule.GetMatchKinds().Data)

	celPolicy := kyvernoPolicyByName(t, kyverno, "require-run-as-non-root")
	assert.Equal(t, "ValidatingPolicy", celPolicy.GetKind().Data)
	assert.Equal(t, "Audit", celPolicy.GetValidationFailureAction().Data)

	mappings := kyverno.GetMappings()
	require.NoError(t, mappings.Error)
	assert.GreaterOrEqual(t, len(mappings.Data), 16)
	assertKyvernoMapping(t, mappings.Data, "disallow-host-path", "host-path", "mondoo-kubernetes-security-pod-hostpath-readonly", "medium")
	assertKyvernoMapping(t, mappings.Data, "disallow-host-ports-range", "host-port-range", "mondoo-kubernetes-security-pod-ports-hostport", "medium")
	assertKyvernoMapping(t, mappings.Data, "limit-hostpath-type-pv", "limit-hostpath-type-pv-to-slash-data", "mondoo-kubernetes-security-no-hostpath-persistent-volumes", "medium")

	results := kyverno.GetResults()
	require.NoError(t, results.Error)
	assert.Len(t, results.Data, 7)
	privilegedResult := kyvernoResultByPolicyRule(t, results.Data, "disallow-privileged-containers", "validate-privileged")
	assert.Equal(t, "fail", privilegedResult.GetResult().Data)
	assert.Equal(t, []any{"mondoo-k8s-privileged-container"}, privilegedResult.GetMappedMondooCheckUids().Data)
	assert.Empty(t, privilegedResult.GetMappedPolicyExceptionIds().Data)
	privilegedSkipResult := kyvernoResultByPolicyRuleScopeResult(t, results.Data, "disallow-privileged-containers", "validate-privileged", "default", "debug-shell", "skip")
	assert.Equal(t, []any{"policyexception:kyverno.io/v2:policyexception:kyverno:privileged-debug-pod"}, privilegedSkipResult.GetMappedPolicyExceptionIds().Data)
	hostPortsResult := kyvernoResultByPolicyRuleScope(t, results.Data, "disallow-host-ports", "host-ports-none", "default", "debug-shell")
	assert.Equal(t, "fail", hostPortsResult.GetResult().Data)
	assert.Contains(t, hostPortsResult.GetMappedMondooCheckUids().Data, "mondoo-kubernetes-security-pod-ports-hostport")
	assert.Contains(t, hostPortsResult.GetMappedMondooCheckUids().Data, "mondoo-kubernetes-security-deployment-ports-hostport")
	assert.NotContains(t, hostPortsResult.GetMappedPolicyExceptionIds().Data, "policyexception:kyverno.io/v2:policyexception:kyverno:host-ports-exception")
	assert.NotContains(t, hostPortsResult.GetMappedPolicyExceptionIds().Data, "policyexception:policies.kyverno.io/v1:policyexception:kyverno:modern-host-ports-exception")
	assert.NotContains(t, hostPortsResult.GetMappedPolicyExceptionIds().Data, "policyexception:kyverno.io/v2:policyexception:kyverno:selector-host-ports-exception")
	assert.NotContains(t, hostPortsResult.GetMappedPolicyExceptionIds().Data, "policyexception:kyverno.io/v2:policyexception:kyverno:namespace-selector-host-ports-exception")
	scopedHostPortsResult := kyvernoResultByPolicyRuleScope(t, results.Data, "disallow-host-ports", "host-ports-none", "kube-system", "node-local-dns")
	assert.Empty(t, scopedHostPortsResult.GetMappedPolicyExceptionIds().Data)
	scopedHostPortsSkipResult := kyvernoResultByPolicyRuleScopeResult(t, results.Data, "disallow-host-ports", "host-ports-none", "kube-system", "node-local-dns", "skip")
	assert.Contains(t, scopedHostPortsSkipResult.GetMappedPolicyExceptionIds().Data, "policyexception:kyverno.io/v2:policyexception:kyverno:host-ports-exception")
	assert.NotContains(t, scopedHostPortsResult.GetMappedPolicyExceptionIds().Data, "policyexception:policies.kyverno.io/v1:policyexception:kyverno:modern-host-ports-exception")
	assert.Contains(t, scopedHostPortsSkipResult.GetMappedPolicyExceptionIds().Data, "policyexception:kyverno.io/v2:policyexception:kyverno:selector-host-ports-exception")
	assert.Contains(t, scopedHostPortsSkipResult.GetMappedPolicyExceptionIds().Data, "policyexception:kyverno.io/v2:policyexception:kyverno:namespace-selector-host-ports-exception")

	exceptions := kyverno.GetPolicyExceptions()
	require.NoError(t, exceptions.Error)
	require.Len(t, exceptions.Data, 11)

	privilegedException := kyvernoPolicyExceptionByName(t, exceptions.Data, "privileged-debug-pod")
	assert.Equal(t, "applied", privilegedException.GetComputedStatus().Data)
	assert.Equal(t, []any{"disallow-privileged-containers"}, privilegedException.GetPolicyRefs().Data)
	assert.Equal(t, []any{"validate-privileged"}, privilegedException.GetRuleNames().Data)
	assert.Equal(t, []any{"mondoo-k8s-privileged-container"}, privilegedException.GetMappedMondooCheckUids().Data)
	assert.Empty(t, privilegedException.GetMappedMondooExceptionIds().Data)
	assert.Contains(t, privilegedException.GetStatusReasons().Data, "applied: matching exception skip result observed for disallow-privileged-containers/validate-privileged")

	hostPortsException := kyvernoPolicyExceptionByName(t, exceptions.Data, "host-ports-exception")
	assert.Equal(t, "applied", hostPortsException.GetComputedStatus().Data)
	assert.ElementsMatch(t, kyvernoExpectedHostPortCheckUids(), hostPortsException.GetMappedMondooCheckUids().Data)

	selectorHostPortsException := kyvernoPolicyExceptionByName(t, exceptions.Data, "selector-host-ports-exception")
	assert.Equal(t, "applied", selectorHostPortsException.GetComputedStatus().Data)
	assert.NotContains(t, selectorHostPortsException.GetStatusReasons().Data, "broad: exception matches a wide resource or rule scope")

	namespaceSelectorHostPortsException := kyvernoPolicyExceptionByName(t, exceptions.Data, "namespace-selector-host-ports-exception")
	assert.Equal(t, "applied", namespaceSelectorHostPortsException.GetComputedStatus().Data)
	assert.NotContains(t, namespaceSelectorHostPortsException.GetStatusReasons().Data, "broad: exception matches a wide resource or rule scope")

	hostPathException := kyvernoPolicyExceptionByName(t, exceptions.Data, "host-path-exception")
	assert.Equal(t, "notObserved", hostPathException.GetComputedStatus().Data)
	assert.Contains(t, hostPathException.GetMappedMondooCheckUids().Data, "mondoo-kubernetes-security-pod-hostpath-readonly")
	assert.Contains(t, hostPathException.GetStatusReasons().Data, "mapped: disallow-host-path/host-path")

	hostPortsRangeException := kyvernoPolicyExceptionByName(t, exceptions.Data, "host-ports-range-exception")
	assert.Equal(t, "notObserved", hostPortsRangeException.GetComputedStatus().Data)
	assert.Contains(t, hostPortsRangeException.GetMappedMondooCheckUids().Data, "mondoo-kubernetes-security-pod-ports-hostport")
	assert.Contains(t, hostPortsRangeException.GetStatusReasons().Data, "mapped: disallow-host-ports-range/host-port-range")

	hostPathPVException := kyvernoPolicyExceptionByName(t, exceptions.Data, "hostpath-pv-exception")
	assert.Equal(t, "notObserved", hostPathPVException.GetComputedStatus().Data)
	assert.Equal(t, []any{"mondoo-kubernetes-security-no-hostpath-persistent-volumes"}, hostPathPVException.GetMappedMondooCheckUids().Data)
	assert.Contains(t, hostPathPVException.GetStatusReasons().Data, "mapped: limit-hostpath-type-pv/limit-hostpath-type-pv-to-slash-data")

	modernPolicyException := kyvernoPolicyExceptionByName(t, exceptions.Data, "modern-host-ports-exception")
	assert.Equal(t, "unmapped", modernPolicyException.GetComputedStatus().Data)
	assert.Equal(t, []any{"ClusterPolicy:disallow-host-ports"}, modernPolicyException.GetPolicyRefs().Data)
	assert.Empty(t, modernPolicyException.GetRuleNames().Data)
	assert.ElementsMatch(t, kyvernoExpectedHostPortCheckUids(), modernPolicyException.GetMappedMondooCheckUids().Data)
	assert.Contains(t, modernPolicyException.GetStatusReasons().Data, "broad: no explicit rule names found")
	assert.NotContains(t, modernPolicyException.GetStatusReasons().Data, "invalid: PolicyException uses unsupported scope refinements")
	assert.Contains(t, modernPolicyException.GetStatusReasons().Data, "mapped: disallow-host-ports/host-ports-none")
	assert.Contains(t, modernPolicyException.GetStatusReasons().Data, "unmapped: disallow-host-ports/audit-host-ports-without-mondoo-map")

	policyRefException := kyvernoPolicyExceptionByName(t, exceptions.Data, "legacy-run-as-root")
	assert.Equal(t, "notObserved", policyRefException.GetComputedStatus().Data)
	assert.Equal(t, []any{"validation"}, policyRefException.GetRuleNames().Data)
	assert.Equal(t, []any{"mondoo-k8s-run-as-non-root"}, policyRefException.GetMappedMondooCheckUids().Data)

	policyLevelException := kyvernoPolicyExceptionByName(t, exceptions.Data, "policy-level-run-as-non-root")
	assert.Equal(t, "applied", policyLevelException.GetComputedStatus().Data)
	assert.Equal(t, []any{"ValidatingPolicy:require-run-as-non-root"}, policyLevelException.GetPolicyRefs().Data)
	assert.Empty(t, policyLevelException.GetRuleNames().Data)
	assert.Equal(t, []any{"mondoo-k8s-run-as-non-root"}, policyLevelException.GetMappedMondooCheckUids().Data)
	assert.Contains(t, policyLevelException.GetStatusReasons().Data, "applied: matching exception skip result observed for require-run-as-non-root/exception")

	expiredException := kyvernoPolicyExceptionByName(t, exceptions.Data, "expired-wide-exception")
	assert.Equal(t, "expired", expiredException.GetComputedStatus().Data)
	assert.Contains(t, expiredException.GetStatusReasons().Data, "expired: valid-until is in the past")
}

func TestKyvernoManifestResourcesWithConfiguredAnnotations(t *testing.T) {
	kyverno := kyvernoTestResourceWithOptions(t, map[string]string{
		shared.OPTION_KYVERNO_DEFAULT_MAPPINGS:                    "false",
		shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_UIDS:       "example.com/mondoo-check-uid",
		shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_MRNS:       "example.com/mondoo-check-mrn",
		shared.OPTION_KYVERNO_MAPPING_ANNOTATION_POLICY_UIDS:      "example.com/mondoo-policy-uid",
		shared.OPTION_KYVERNO_MAPPING_ANNOTATION_REASONS:          "example.com/mondoo-mapping-reason",
		shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_VALID_UNTIL:    "example.com/valid-until",
		shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_JUSTIFICATIONS: "example.com/justification",
		shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_OWNERS:         "example.com/owner",
		shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_TICKETS:        "example.com/ticket",
		shared.OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS:            "true",
		shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_APPROVAL:         "requires-approval",
		shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_ACTION:           "WORKAROUND",
		shared.OPTION_KYVERNO_FAIL_EXPIRED_POLICY_EXCEPTIONS:      "false",
		shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_EXCEPTIONS:   "false",
		shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_RESULTS:      "false",
	})

	assert.True(t, kyverno.GetMirrorPolicyExceptions().Data)
	assert.Equal(t, "requires-approval", kyverno.GetMirroredExceptionApproval().Data)
	assert.Equal(t, "WORKAROUND", kyverno.GetMirroredExceptionAction().Data)
	assert.False(t, kyverno.GetFailExpiredPolicyExceptions().Data)
	assert.False(t, kyverno.GetReportUnmappedPolicyExceptions().Data)
	assert.False(t, kyverno.GetReportUnmappedPolicyResults().Data)

	mappings := kyverno.GetMappings()
	require.NoError(t, mappings.Error)
	require.Len(t, mappings.Data, 2)
	for _, item := range mappings.Data {
		mapping := item.(*mqlK8sKyvernoMapping)
		assert.Equal(t, "annotation", mapping.GetSource().Data)
		assert.Equal(t, "custom-hostport-check", mapping.GetMondooCheckUid().Data)
		assert.Equal(t, "//policy.api.mondoo.app/spaces/test/checks/custom-hostport-check", mapping.GetMondooCheckMrn().Data)
		assert.Equal(t, "custom-kyverno-policy", mapping.GetMondooPolicyUid().Data)
		assert.Equal(t, "Configured Kyverno annotation mapping.", mapping.GetReason().Data)
	}
	assertKyvernoMapping(t, mappings.Data, "disallow-host-ports", "host-ports-none", "custom-hostport-check", "high")
	assertKyvernoMapping(t, mappings.Data, "disallow-host-ports", "audit-host-ports-without-mondoo-map", "custom-hostport-check", "high")

	results := kyverno.GetResults()
	require.NoError(t, results.Error)
	hostPortsResult := kyvernoResultByPolicyRule(t, results.Data, "disallow-host-ports", "host-ports-none")
	assert.Equal(t, []any{"custom-hostport-check"}, hostPortsResult.GetMappedMondooCheckUids().Data)

	exceptions := kyverno.GetPolicyExceptions()
	require.NoError(t, exceptions.Error)
	hostPortsException := kyvernoPolicyExceptionByName(t, exceptions.Data, "host-ports-exception")
	assert.Equal(t, []any{"custom-hostport-check"}, hostPortsException.GetMappedMondooCheckUids().Data)
	require.Len(t, hostPortsException.GetMappedMondooExceptionIds().Data, 1)
	assert.Regexp(t, `^mondoo-exception:kyverno:[0-9a-f]{16}$`, hostPortsException.GetMappedMondooExceptionIds().Data[0])
	assert.Contains(t, hostPortsException.GetStatusReasons().Data, "mirrored: 1 Mondoo exception links generated")

	modernPolicyException := kyvernoPolicyExceptionByName(t, exceptions.Data, "modern-host-ports-exception")
	assert.Equal(t, "2099-12-31T00:00:00Z", modernPolicyException.GetValidUntil().Data)
	require.NotNil(t, modernPolicyException.GetValidUntilTime().Data)
	assert.Equal(t, time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC), *modernPolicyException.GetValidUntilTime().Data)
	assert.Equal(t, "Configured current API exception.", modernPolicyException.GetJustification().Data)
	assert.Equal(t, "policy-security", modernPolicyException.GetOwner().Data)
	assert.Equal(t, "SEC-999", modernPolicyException.GetTicket().Data)
	assert.Equal(t, "broad", modernPolicyException.GetComputedStatus().Data)
	assert.NotContains(t, modernPolicyException.GetStatusReasons().Data, "invalid: PolicyException uses unsupported scope refinements")
	assert.Equal(t, []any{"custom-hostport-check"}, modernPolicyException.GetMappedMondooCheckUids().Data)
}

func TestKyvernoDataAccessorsReturnErrorsWhenUninitialized(t *testing.T) {
	_, err := (&mqlK8sKyvernoPolicy{}).labels()
	require.ErrorContains(t, err, "kyverno policy data not initialized")

	_, err = (&mqlK8sKyvernoPolicy{}).rules()
	require.ErrorContains(t, err, "kyverno policy data not initialized")

	_, err = (&mqlK8sKyvernoRule{}).matchKinds()
	require.ErrorContains(t, err, "kyverno rule data not initialized")

	_, err = (&mqlK8sKyvernoResult{}).properties()
	require.ErrorContains(t, err, "kyverno result data not initialized")

	_, err = (&mqlK8sKyvernoPolicyreport{}).manifest()
	require.ErrorContains(t, err, "kyverno policyreport data not initialized")

	_, err = (&mqlK8sKyvernoPolicyreport{}).results()
	require.ErrorContains(t, err, "kyverno policyreport data not initialized")

	_, err = (&mqlK8sKyvernoPolicyexception{}).labels()
	require.ErrorContains(t, err, "kyverno policyexception data not initialized")

	_, err = (&mqlK8sKyvernoPolicyexception{}).policyRefs()
	require.ErrorContains(t, err, "kyverno policyexception data not initialized")
}

func TestKyvernoResultMappedFieldsUseInitializedData(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	result, err := kyvernoResultResource(runtime, &kyvernoResultData{
		id:                 "result-id",
		mappedCheckUids:    []string{"check-uid"},
		mappedCheckMrns:    []string{"check-mrn"},
		mappedExceptionIds: []string{"exception-id"},
	})
	require.NoError(t, err)

	assert.Equal(t, []any{"check-uid"}, result.GetMappedMondooCheckUids().Data)
	assert.Equal(t, []any{"check-mrn"}, result.GetMappedMondooCheckMrns().Data)
	assert.Equal(t, []any{"exception-id"}, result.GetMappedPolicyExceptionIds().Data)
}

func TestEnrichedKyvernoResultDataDoesNotMutateOriginalMappings(t *testing.T) {
	original := &kyvernoResultData{
		policy:             "disallow-host-ports",
		rule:               "host-ports",
		mappedCheckUids:    []string{"previous-check"},
		mappedCheckMrns:    []string{"previous-mrn"},
		mappedExceptionIds: []string{"previous-exception"},
	}

	enriched := enrichedKyvernoResultData(original, map[string][]kyvernoMappingData{
		policyKey("ClusterPolicy", "", "disallow-host-ports") + "/host-ports": {
			{
				kyvernoKind:    "ClusterPolicy",
				kyvernoPolicy:  "disallow-host-ports",
				kyvernoRule:    "host-ports",
				source:         "generated",
				mondooCheckUid: "mapped-check",
				mondooCheckMrn: "mapped-mrn",
			},
		},
	}, nil)

	assert.Equal(t, []string{"previous-check"}, original.mappedCheckUids)
	assert.Equal(t, []string{"previous-mrn"}, original.mappedCheckMrns)
	assert.Equal(t, []string{"previous-exception"}, original.mappedExceptionIds)
	assert.Equal(t, []string{"mapped-check"}, enriched.mappedCheckUids)
	assert.Equal(t, []string{"mapped-mrn"}, enriched.mappedCheckMrns)
	assert.Empty(t, enriched.mappedExceptionIds)
}

func TestEnrichedKyvernoResultDataDoesNotMapAmbiguousBarePolicyNames(t *testing.T) {
	result := &kyvernoResultData{
		policy: "require-labels",
		rule:   "check-labels",
		source: "kyverno",
	}

	enriched := enrichedKyvernoResultData(result, map[string][]kyvernoMappingData{
		policyKey("ClusterPolicy", "", "require-labels") + "/check-labels": {
			{kyvernoKind: "ClusterPolicy", kyvernoPolicy: "require-labels", kyvernoRule: "check-labels", mondooCheckUid: "cluster-check", source: "annotation"},
		},
		policyKey("Policy", "team-a", "require-labels") + "/check-labels": {
			{kyvernoKind: "Policy", kyvernoNamespace: "team-a", kyvernoPolicy: "require-labels", kyvernoRule: "check-labels", mondooCheckUid: "namespaced-check", source: "annotation"},
		},
	}, nil)

	assert.Empty(t, enriched.mappedCheckUids)
}

func TestEnrichedKyvernoResultDataMapsOpenReportsNamespacedPolicyNames(t *testing.T) {
	result := &kyvernoResultData{
		policy:     "team-a/require-labels",
		rule:       "check-labels",
		source:     "kyverno",
		result:     "skip",
		properties: map[string]string{"exceptions": "team-a-label-exception"},
	}

	enriched := enrichedKyvernoResultData(result, map[string][]kyvernoMappingData{
		policyKey("ClusterPolicy", "", "require-labels") + "/check-labels": {
			{kyvernoKind: "ClusterPolicy", kyvernoPolicy: "require-labels", kyvernoRule: "check-labels", mondooCheckUid: "cluster-check", source: "annotation"},
		},
		policyKey("Policy", "team-a", "require-labels") + "/check-labels": {
			{kyvernoKind: "Policy", kyvernoNamespace: "team-a", kyvernoPolicy: "require-labels", kyvernoRule: "check-labels", mondooCheckUid: "namespaced-check", source: "annotation"},
		},
	}, map[string][]kyvernoPolicyExceptionMatch{
		policyKey("Policy", "team-a", "require-labels") + "/check-labels": {
			{
				id:        "policyexception:v2:policyexception:kyverno:team-a-label-exception",
				policyRef: "Policy:team-a/require-labels",
				data:      &kyvernoExceptionData{namespace: "kyverno", name: "team-a-label-exception"},
			},
		},
	})

	assert.Equal(t, []string{"namespaced-check"}, enriched.mappedCheckUids)
	assert.Equal(t, []string{"policyexception:v2:policyexception:kyverno:team-a-label-exception"}, enriched.mappedExceptionIds)
	assert.Equal(t, []string{policyKey("Policy", "team-a", "require-labels")}, kyvernoResultIdentityKeys(result))
	assert.True(t, kyvernoExceptionHasMatchingResult(
		"Policy:team-a/require-labels",
		policyKey("Policy", "team-a", "require-labels"),
		"require-labels",
		[]string{"check-labels"},
		&kyvernoExceptionData{namespace: "kyverno", name: "team-a-label-exception"},
		map[string][]*kyvernoResultData{policyKey("Policy", "team-a", "require-labels") + "/check-labels": {result}},
	))
}

func TestKyvernoPolicyExceptionScopeMatching(t *testing.T) {
	tests := []struct {
		name      string
		exception *kyvernoExceptionData
		result    *kyvernoResultData
		want      bool
	}{
		{
			name:      "empty exception scope matches any result scope",
			exception: &kyvernoExceptionData{},
			result:    &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "nginx"},
			want:      true,
		},
		{
			name:      "exact kind namespace and name match",
			exception: &kyvernoExceptionData{matchKinds: []string{"Pod"}, matchNamespaces: []string{"kube-system"}, matchNames: []string{"node-local-dns"}},
			result:    &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns"},
			want:      true,
		},
		{
			name:      "plural kind and wildcard name match",
			exception: &kyvernoExceptionData{matchKinds: []string{"pods"}, matchNamespaces: []string{"kube-system"}, matchNames: []string{"node-*"}},
			result:    &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns"},
			want:      true,
		},
		{
			name:      "api group kind is normalized",
			exception: &kyvernoExceptionData{matchKinds: []string{"apps/v1/Deployments"}},
			result:    &kyvernoResultData{scopeKind: "Deployment", scopeNamespace: "default", scopeName: "web"},
			want:      true,
		},
		{
			name:      "singular kind ending with s is preserved",
			exception: &kyvernoExceptionData{matchKinds: []string{"Ingress"}},
			result:    &kyvernoResultData{scopeKind: "Ingress", scopeNamespace: "default", scopeName: "web"},
			want:      true,
		},
		{
			name:      "known ingress plural kind alias matches singular kind",
			exception: &kyvernoExceptionData{matchKinds: []string{"ingresses"}},
			result:    &kyvernoResultData{scopeKind: "Ingress", scopeNamespace: "default", scopeName: "web"},
			want:      true,
		},
		{
			name:      "known namespace plural kind alias matches singular kind",
			exception: &kyvernoExceptionData{matchKinds: []string{"namespaces"}},
			result:    &kyvernoResultData{scopeKind: "Namespace", scopeName: "default"},
			want:      true,
		},
		{
			name: "cel only match conditions use extracted scope hints",
			exception: &kyvernoExceptionData{
				matchNamespaces: []string{"kube-system"},
				matchNames:      []string{"node-local-dns"},
				matchScope: kyvernoMatchScopeFromMatch(map[string]any{
					"matchConditions": []any{
						map[string]any{"expression": "object.metadata.namespace == 'kube-system' && object.metadata.name == 'node-local-dns'"},
					},
				}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend"},
			want:   false,
		},
		{
			name: "structured match still respects top level cel namespace and name",
			exception: func() *kyvernoExceptionData {
				match := kyvernoPolicyExceptionMatchFromSpec(map[string]any{
					"match": map[string]any{
						"resources": map[string]any{"kinds": []any{"Pod"}},
					},
					"matchConditions": []any{
						map[string]any{"expression": "object.metadata.namespace == 'kube-system' && object.metadata.name == 'node-local-dns'"},
					},
				})
				return &kyvernoExceptionData{
					match:      match,
					matchScope: kyvernoMatchScopeFromMatch(match),
				}
			}(),
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend"},
			want:   false,
		},
		{
			name: "structured match and top level cel scope both match",
			exception: func() *kyvernoExceptionData {
				match := kyvernoPolicyExceptionMatchFromSpec(map[string]any{
					"match": map[string]any{
						"resources": map[string]any{"kinds": []any{"Pod"}},
					},
					"matchConditions": []any{
						map[string]any{"expression": "object.metadata.namespace == 'kube-system' && object.metadata.name == 'node-local-dns'"},
					},
				})
				return &kyvernoExceptionData{
					match:      match,
					matchScope: kyvernoMatchScopeFromMatch(match),
				}
			}(),
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns"},
			want:   true,
		},
		{
			name:      "different namespace does not match",
			exception: &kyvernoExceptionData{matchKinds: []string{"Pod"}, matchNamespaces: []string{"kyverno"}, matchNames: []string{"node-local-dns"}},
			result:    &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns"},
			want:      false,
		},
		{
			name:      "constrained exception does not match result with empty scope value",
			exception: &kyvernoExceptionData{matchKinds: []string{"Pod"}, matchNamespaces: []string{"kube-system"}},
			result:    &kyvernoResultData{scopeKind: "Pod"},
			want:      false,
		},
		{
			name: "resource label selector matches result labels",
			exception: &kyvernoExceptionData{
				matchKinds:          []string{"Pod"},
				matchLabelSelectors: mustKyvernoSelectors(t, map[string]any{"matchLabels": map[string]any{"app": "dns"}}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns", scopeLabels: map[string]string{"app": "dns"}},
			want:   true,
		},
		{
			name: "resource label selector mismatch does not match",
			exception: &kyvernoExceptionData{
				matchKinds:          []string{"Pod"},
				matchLabelSelectors: mustKyvernoSelectors(t, map[string]any{"matchLabels": map[string]any{"app": "dns"}}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend", scopeLabels: map[string]string{"app": "frontend"}},
			want:   false,
		},
		{
			name: "resource label selector fails closed when labels are unavailable",
			exception: &kyvernoExceptionData{
				matchKinds:          []string{"Pod"},
				matchLabelSelectors: mustKyvernoSelectors(t, map[string]any{"matchLabels": map[string]any{"app": "dns"}}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns"},
			want:   false,
		},
		{
			name: "namespace selector matches namespace labels",
			exception: &kyvernoExceptionData{
				matchKinds:              []string{"Pod"},
				matchNamespaceSelectors: mustKyvernoSelectors(t, map[string]any{"matchLabels": map[string]any{"team": "platform"}}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns", scopeNamespaceLabels: map[string]string{"team": "platform"}},
			want:   true,
		},
		{
			name: "namespace selector mismatch does not match",
			exception: &kyvernoExceptionData{
				matchKinds:              []string{"Pod"},
				matchNamespaceSelectors: mustKyvernoSelectors(t, map[string]any{"matchLabels": map[string]any{"team": "platform"}}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend", scopeNamespaceLabels: map[string]string{"team": "app"}},
			want:   false,
		},
		{
			name: "unsupported exception scope fails closed",
			exception: &kyvernoExceptionData{
				matchKinds:       []string{"Pod"},
				unsupportedScope: true,
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend"},
			want:   false,
		},
		{
			name: "exclude scope prevents matching result",
			exception: &kyvernoExceptionData{
				matchScope:   kyvernoMatchScopeFromMatch(map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}}}),
				excludeScope: kyvernoMatchScopeFromMatch(map[string]any{"resources": map[string]any{"names": []any{"debug-shell"}}}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "debug-shell"},
			want:   false,
		},
		{
			name: "structured any clauses do not mix selectors between branches",
			exception: &kyvernoExceptionData{
				matchScope: kyvernoMatchScopeFromMatch(map[string]any{
					"any": []any{
						map[string]any{"resources": map[string]any{
							"kinds":    []any{"Pod"},
							"selector": map[string]any{"matchLabels": map[string]any{"app": "dns"}},
						}},
						map[string]any{"resources": map[string]any{
							"kinds":    []any{"Deployment"},
							"selector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
						}},
					},
				}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "default", scopeName: "web", scopeLabels: map[string]string{"app": "web"}},
			want:   false,
		},
		{
			name: "structured all clauses require every clause",
			exception: &kyvernoExceptionData{
				matchScope: kyvernoMatchScopeFromMatch(map[string]any{
					"all": []any{
						map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}}},
						map[string]any{"resources": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "dns"}}}},
					},
				}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns", scopeLabels: map[string]string{"app": "dns"}},
			want:   true,
		},
		{
			name: "malformed selector fails closed",
			exception: &kyvernoExceptionData{
				matchScope: kyvernoMatchScopeFromMatch(map[string]any{
					"resources": map[string]any{
						"kinds": []any{"Pod"},
						"selector": map[string]any{
							"matchExpressions": []any{map[string]any{"operator": "In", "values": []any{"dns"}}},
						},
					},
				}),
			},
			result: &kyvernoResultData{scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns", scopeLabels: map[string]string{"app": "dns"}},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, kyvernoPolicyExceptionMatchesResult(tt.exception, tt.result))
		})
	}
}

func mustKyvernoSelectors(t *testing.T, selector map[string]any) []labels.Selector {
	t.Helper()
	parsed, ok := labelSelectorFromAny(selector)
	require.True(t, ok)
	return []labels.Selector{parsed}
}

func TestKyvernoExceptionHasMatchingResultRespectsScope(t *testing.T) {
	resultIndex := map[string][]*kyvernoResultData{
		"disallow-host-ports/host-ports-none": {
			{policy: "disallow-host-ports", rule: "host-ports-none", result: "fail", scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend"},
			{policy: "disallow-host-ports", rule: "host-ports-none", result: "skip", scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns", properties: map[string]string{"exceptions": "host-ports-exception"}},
		},
		"disallow-host-ports/audit-host-ports-without-mondoo-map": {
			{policy: "disallow-host-ports", rule: "audit-host-ports-without-mondoo-map", result: "fail", scopeKind: "Pod", scopeNamespace: "default", scopeName: "frontend"},
		},
	}
	exception := &kyvernoExceptionData{
		namespace:       "kyverno",
		name:            "host-ports-exception",
		matchKinds:      []string{"Pod"},
		matchNamespaces: []string{"kube-system"},
		matchNames:      []string{"node-local-*"},
	}

	assert.True(t, kyvernoExceptionHasMatchingResult("disallow-host-ports", "disallow-host-ports", "disallow-host-ports", []string{"host-ports-none"}, exception, resultIndex))
	assert.False(t, kyvernoExceptionHasMatchingResult("disallow-host-ports", "disallow-host-ports", "disallow-host-ports", []string{"audit-host-ports-without-mondoo-map"}, exception, resultIndex))
	assert.True(t, kyvernoExceptionHasMatchingResult("disallow-host-ports", "disallow-host-ports", "disallow-host-ports", []string{"*"}, exception, resultIndex))
	assert.False(t, kyvernoExceptionHasMatchingResult("disallow-privileged-containers", "disallow-privileged-containers", "disallow-privileged-containers", []string{"*"}, exception, resultIndex))

	failOnlyIndex := map[string][]*kyvernoResultData{
		"disallow-host-ports/host-ports-none": {
			{policy: "disallow-host-ports", rule: "host-ports-none", result: "fail", scopeKind: "Pod", scopeNamespace: "kube-system", scopeName: "node-local-dns"},
		},
	}
	assert.False(t, kyvernoExceptionHasMatchingResult("disallow-host-ports", "disallow-host-ports", "disallow-host-ports", []string{"host-ports-none"}, exception, failOnlyIndex))
}

func TestKyvernoPolicyExceptionPolicyLevelReportRules(t *testing.T) {
	assert.Equal(t, []string{"exception"}, policyExceptionResultRules("ValidatingPolicy:require-run-as-non-root", "validation", nil))
	assert.Equal(t, []string{"exception"}, policyExceptionResultRules("NamespacedValidatingPolicy:default/require-run-as-non-root", "validation", nil))
	assert.Equal(t, []string{"exception"}, policyExceptionResultRules("NamespacedImageValidatingPolicy:default/require-signed-images", "attestor", nil))
	assert.Equal(t, []string{"exception"}, policyExceptionResultRules("NamespacedMutatingPolicy:default/add-defaults", "mutation", nil))
	assert.Equal(t, []string{"exception"}, policyExceptionResultRules("NamespacedGeneratingPolicy:default/add-networkpolicy", "generation", nil))
	assert.Equal(t, []string{"exception"}, policyExceptionResultRules("NamespacedDeletingPolicy:default/delete-stale-pods", "deletion", nil))
	assert.Equal(t, []string{"validation"}, policyExceptionResultRules("ValidatingPolicy:require-run-as-non-root", "validation", []string{"validation"}))
	assert.Equal(t, []string{"host-ports-none"}, policyExceptionResultRules("ClusterPolicy:disallow-host-ports", "host-ports-none", nil))
}

func TestKyvernoSupportsNamespacedMutatingAndGeneratingPolicyRefs(t *testing.T) {
	lookups := map[string]struct{}{}
	for _, kind := range kyvernoPolicyKinds {
		lookups[kind.lookup] = struct{}{}
	}
	assert.Contains(t, lookups, "namespacedmutatingpolicies.v1.policies.kyverno.io")
	assert.Contains(t, lookups, "namespacedgeneratingpolicies.v1.policies.kyverno.io")
	assert.True(t, policyRefKindIsNamespaced("NamespacedMutatingPolicy"))
	assert.True(t, policyRefKindIsNamespaced("NamespacedGeneratingPolicy"))
	assert.True(t, kyvernoResultSourceMatchesPolicyRef("NamespacedMutatingPolicy:default/add-defaults", &kyvernoResultData{source: "KyvernoNamespacedMutatingPolicy"}))
	assert.True(t, kyvernoResultSourceMatchesPolicyRef("NamespacedGeneratingPolicy:default/add-networkpolicy", &kyvernoResultData{source: "KyvernoNamespacedGeneratingPolicy"}))
}

func TestKyvernoResultsFromReportUsesResultResourcesBeforeReportScope(t *testing.T) {
	results := kyvernoResultsFromReport(&metav1.ObjectMeta{Name: "report", Namespace: "default"}, kyvernoTestType{
		apiVersion: "wgpolicyk8s.io/v1alpha2",
		kind:       "PolicyReport",
	}, map[string]any{
		"scope": map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"namespace":  "default",
			"name":       "report-scope",
			"uid":        "report-scope-uid",
		},
		"results": []any{
			map[string]any{
				"policy": "disallow-host-ports",
				"rule":   "host-ports-none",
				"source": "kyverno",
				"result": "warn",
				"resources": []any{
					map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": "default", "name": "debug-a", "uid": "debug-a-uid"},
					map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": "prod", "name": "debug-b", "uid": "debug-b-uid"},
				},
			},
		},
	})

	require.Len(t, results, 2)
	assert.Equal(t, "warn", results[0].result)
	assert.Equal(t, "debug-a", results[0].scopeName)
	assert.Equal(t, "debug-a-uid", results[0].scopeUid)
	assert.Equal(t, "prod", results[1].scopeNamespace)
	assert.Equal(t, "debug-b", results[1].scopeName)
}

func TestKyvernoPolicyExceptionDefaultsNamespacedCELPolicyRefsToExceptionNamespace(t *testing.T) {
	namespacedPolicyKey := policyKey("NamespacedValidatingPolicy", "kyverno", "require-team-label")
	resultIndex := map[string][]*kyvernoResultData{
		namespacedPolicyKey + "/exception": {
			{
				policy:         "require-team-label",
				rule:           "exception",
				source:         "KyvernoNamespacedValidatingPolicy",
				result:         "skip",
				scopeKind:      "Pod",
				scopeNamespace: "default",
				scopeName:      "api",
				properties:     map[string]string{"exceptions": "namespace-policy-exception"},
			},
		},
	}

	data := kyvernoPolicyExceptionData(kyvernoTestResource(t).MqlRuntime, &metav1.ObjectMeta{
		Name:      "namespace-policy-exception",
		Namespace: "kyverno",
	}, map[string]any{
		"spec": map[string]any{
			"policyRefs": []any{
				map[string]any{
					"kind": "NamespacedValidatingPolicy",
					"name": "require-team-label",
				},
			},
			"match": map[string]any{
				"resources": map[string]any{
					"kinds":      []any{"Pod"},
					"namespaces": []any{"default"},
					"names":      []any{"api"},
				},
			},
		},
	}, map[string]struct{}{
		namespacedPolicyKey: {},
	}, map[string]struct{}{
		namespacedPolicyKey + "/validation": {},
	}, map[string][]kyvernoMappingData{
		namespacedPolicyKey + "/validation": {
			{
				kyvernoPolicy:    "require-team-label",
				kyvernoKind:      "NamespacedValidatingPolicy",
				kyvernoNamespace: "kyverno",
				kyvernoRule:      "validation",
				mondooCheckUid:   "mondoo-k8s-require-team-label",
				source:           "annotation",
			},
		},
	}, resultIndex)

	assert.Equal(t, "applied", data.computedStatus)
	assert.Equal(t, []string{"NamespacedValidatingPolicy:kyverno/require-team-label"}, data.policyRefs)
	assert.Equal(t, []string{"mondoo-k8s-require-team-label"}, data.mappedMondooCheckUids)
	assert.NotContains(t, data.statusReasons, "orphaned: policy NamespacedValidatingPolicy:kyverno/require-team-label not found")
	assert.Contains(t, data.statusReasons, "mapped: require-team-label/validation")
	assert.Contains(t, data.statusReasons, "applied: matching exception skip result observed for require-team-label/exception")
}

func TestKyvernoPolicyExceptionDefaultsClassicPolicyRefsToExceptionNamespace(t *testing.T) {
	classicPolicyKey := policyKey("Policy", "kyverno", "restrict-host-path")
	resultIndex := map[string][]*kyvernoResultData{
		classicPolicyKey + "/host-path": {
			{
				policy:         "restrict-host-path",
				rule:           "host-path",
				source:         "kyverno",
				result:         "skip",
				scopeKind:      "Pod",
				scopeNamespace: "default",
				scopeName:      "debug",
				properties:     map[string]string{"exceptions": "classic-policy-exception"},
			},
		},
	}

	data := kyvernoPolicyExceptionData(kyvernoTestResource(t).MqlRuntime, &metav1.ObjectMeta{
		Name:      "classic-policy-exception",
		Namespace: "kyverno",
	}, map[string]any{
		"spec": map[string]any{
			"policyRefs": []any{
				map[string]any{
					"kind":      "Policy",
					"name":      "restrict-host-path",
					"ruleNames": []any{"host-path"},
				},
			},
			"match": map[string]any{
				"resources": map[string]any{
					"kinds":      []any{"Pod"},
					"namespaces": []any{"default"},
					"names":      []any{"debug"},
				},
			},
		},
	}, map[string]struct{}{
		classicPolicyKey: {},
	}, map[string]struct{}{
		classicPolicyKey + "/host-path": {},
	}, map[string][]kyvernoMappingData{
		classicPolicyKey + "/host-path": {
			{
				kyvernoPolicy:    "restrict-host-path",
				kyvernoKind:      "Policy",
				kyvernoNamespace: "kyverno",
				kyvernoRule:      "host-path",
				mondooCheckUid:   "mondoo-k8s-host-path",
				source:           "annotation",
			},
		},
	}, resultIndex)

	assert.Equal(t, "applied", data.computedStatus)
	assert.Equal(t, []string{"Policy:kyverno/restrict-host-path"}, data.policyRefs)
	assert.Equal(t, []string{"mondoo-k8s-host-path"}, data.mappedMondooCheckUids)
	assert.NotContains(t, data.statusReasons, "orphaned: policy Policy:kyverno/restrict-host-path not found")
	assert.NotContains(t, data.statusReasons, "orphaned: rule restrict-host-path/host-path not found")
	assert.Contains(t, data.statusReasons, "mapped: restrict-host-path/host-path")
	assert.Contains(t, data.statusReasons, "applied: matching exception skip result observed for restrict-host-path/host-path")
}

func TestKyvernoPolicyExceptionPolicyRefsKeepPerPolicyRules(t *testing.T) {
	policyIndex := map[string]struct{}{
		policyKey("ClusterPolicy", "", "first"):  {},
		policyKey("ClusterPolicy", "", "second"): {},
	}
	ruleIndex := map[string]struct{}{
		policyKey("ClusterPolicy", "", "first") + "/first-rule":   {},
		policyKey("ClusterPolicy", "", "second") + "/second-rule": {},
	}
	data := kyvernoPolicyExceptionData(nil, &metav1.ObjectMeta{
		Name:      "two-policy-exception",
		Namespace: "kyverno",
	}, map[string]any{
		"spec": map[string]any{
			"policyRefs": []any{
				map[string]any{
					"kind":      "ClusterPolicy",
					"name":      "first",
					"ruleNames": []any{"first-rule"},
				},
				map[string]any{
					"kind":      "ClusterPolicy",
					"name":      "second",
					"ruleNames": []any{"second-rule"},
				},
			},
		},
	}, policyIndex, ruleIndex, nil, nil)

	assert.Equal(t, []string{"first-rule"}, data.ruleNamesForPolicyRef("ClusterPolicy:first"))
	assert.Equal(t, []string{"second-rule"}, data.ruleNamesForPolicyRef("ClusterPolicy:second"))
	assert.ElementsMatch(t, []string{"first-rule", "second-rule"}, data.ruleNames)
	assert.NotContains(t, data.statusReasons, "orphaned: rule first/second-rule not found")
	assert.NotContains(t, data.statusReasons, "orphaned: rule second/first-rule not found")
}

func TestKyvernoResultReferencesExceptionRequiresExactToken(t *testing.T) {
	exception := &kyvernoExceptionData{namespace: "kyverno", name: "foo"}

	tests := []struct {
		name   string
		result *kyvernoResultData
		want   bool
	}{
		{
			name:   "namespace name property token",
			result: &kyvernoResultData{properties: map[string]string{"exceptions": "kyverno/foo"}},
			want:   true,
		},
		{
			name:   "punctuated short name token",
			result: &kyvernoResultData{properties: map[string]string{"exceptions": "foo,"}},
			want:   true,
		},
		{
			name:   "hyphenated prefix property is not a match",
			result: &kyvernoResultData{properties: map[string]string{"exceptions": "foo-old"}},
			want:   false,
		},
		{
			name:   "hyphenated prefix message is not a match",
			result: &kyvernoResultData{properties: map[string]string{}, message: "PolicyException foo-old applied"},
			want:   false,
		},
		{
			name:   "quoted message token",
			result: &kyvernoResultData{properties: map[string]string{}, message: `PolicyException "foo" applied`},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, kyvernoResultReferencesException(exception, tt.result))
		})
	}
}

func TestKyvernoBroadExceptionDetectionIsBranchAware(t *testing.T) {
	narrow := &kyvernoExceptionData{
		ruleNames: []string{"validate"},
		matchScope: kyvernoMatchScopeFromMatch(map[string]any{
			"any": []any{
				map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}, "namespaces": []any{"prod"}}},
				map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}, "names": []any{"debug"}}},
			},
		}),
	}
	assert.False(t, isBroadException(narrow))

	broad := &kyvernoExceptionData{
		ruleNames: []string{"validate"},
		matchScope: kyvernoMatchScopeFromMatch(map[string]any{
			"any": []any{
				map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}, "namespaces": []any{"prod"}}},
				map[string]any{"resources": map[string]any{"kinds": []any{"Pod"}}},
			},
		}),
	}
	assert.True(t, isBroadException(broad))
}

func TestKyvernoPolicyExceptionRulesForMappingPrefersIndexedPolicyRules(t *testing.T) {
	policyLookupKey := policyKey("ClusterPolicy", "", "disallow-host-ports")
	mappingIndex := map[string][]kyvernoMappingData{
		policyLookupKey + "/host-ports-none": {{kyvernoKind: "ClusterPolicy", kyvernoPolicy: "disallow-host-ports", kyvernoRule: "host-ports-none"}},
	}
	ruleIndex := map[string]struct{}{
		policyLookupKey + "/host-ports-none":                     {},
		policyLookupKey + "/audit-host-ports-without-mondoo-map": {},
	}

	assert.ElementsMatch(t, []string{
		"audit-host-ports-without-mondoo-map",
		"host-ports-none",
	}, policyExceptionRulesForMapping(policyLookupKey, nil, mappingIndex, ruleIndex))
	assert.Equal(t, []string{"explicit-rule"}, policyExceptionRulesForMapping(policyLookupKey, []string{"explicit-rule"}, mappingIndex, ruleIndex))
	assert.Equal(t, []string{"host-ports-none"}, policyExceptionRulesForMapping(policyLookupKey, nil, mappingIndex, map[string]struct{}{}))
	assert.Equal(t, []string{"*"}, policyExceptionRulesForMapping("unknown-policy", nil, mappingIndex, map[string]struct{}{}))
}

func TestKyvernoMatchScopeParsesResourceSelectorsAndCEL(t *testing.T) {
	match := map[string]any{
		"any": []any{
			map[string]any{
				"resources": map[string]any{
					"kinds":      []any{"Pod", "apps/v1/Deployment"},
					"namespaces": []any{"prod-*"},
					"names":      []any{"api-*"},
					"selector": map[string]any{
						"matchLabels": map[string]any{"app": "api"},
					},
					"namespaceSelector": map[string]any{
						"matchExpressions": []any{
							map[string]any{"key": "team", "operator": "In", "values": []any{"platform"}},
						},
					},
				},
			},
		},
		"matchConditions": []any{
			map[string]any{"expression": "object.metadata.namespace == 'kube-system' && object.metadata.name == \"node-local-dns\" && object.kind == 'Pod'"},
			map[string]any{"expression": "request.namespace == 'kyverno'"},
		},
	}

	assert.ElementsMatch(t, []string{"Pod", "apps/v1/Deployment"}, matchKinds(match))
	assert.ElementsMatch(t, []string{"prod-*", "kube-system", "kyverno"}, matchNamespaces(match))
	assert.ElementsMatch(t, []string{"api-*", "node-local-dns"}, matchNames(match))
	resourceSelectors := matchResourceLabelSelectors(match, "selector")
	require.Len(t, resourceSelectors, 1)
	assert.True(t, resourceSelectors[0].Matches(labels.Set{"app": "api"}))
	assert.False(t, resourceSelectors[0].Matches(labels.Set{"app": "worker"}))
	namespaceSelectors := matchResourceLabelSelectors(match, "namespaceSelector")
	require.Len(t, namespaceSelectors, 1)
	assert.True(t, namespaceSelectors[0].Matches(labels.Set{"team": "platform"}))

	typedMatchConditions := map[string]any{
		"matchConditions": []map[string]any{
			{"expression": "request.namespace == 'typed-ns' && request.metadata.name == 'typed-pod'"},
		},
	}
	assert.Equal(t, []string{"typed-ns"}, matchNamespaces(typedMatchConditions))
	assert.Equal(t, []string{"typed-pod"}, matchNames(typedMatchConditions))
}

func TestKyvernoBuiltinMappingsCoverReviewedCatalogPolicies(t *testing.T) {
	expected := []struct {
		policy string
		rule   string
	}{
		{policy: "disallow-privileged-containers", rule: "privileged-containers"},
		{policy: "disallow-privilege-escalation", rule: "privilege-escalation"},
		{policy: "block-ephemeral-containers", rule: "block-ephemeral-containers"},
		{policy: "require-run-as-nonroot", rule: "run-as-non-root"},
		{policy: "require-run-as-non-root-user", rule: "run-as-non-root-user"},
		{policy: "require-run-as-containeruser", rule: "require-run-as-containeruser"},
		{policy: "require-non-root-groups", rule: "check-runasgroup"},
		{policy: "require-non-root-groups", rule: "check-supplementalgroups"},
		{policy: "require-non-root-groups", rule: "check-fsgroup"},
		{policy: "service-mesh-require-run-as-nonroot", rule: "run-as-non-root-istio"},
		{policy: "disallow-host-namespaces", rule: "host-namespaces"},
		{policy: "disallow-host-ports", rule: "host-ports-none"},
		{policy: "disallow-host-ports-range", rule: "host-port-range"},
		{policy: "disallow-host-path", rule: "host-path"},
		{policy: "disallow-host-process", rule: "host-process-containers"},
		{policy: "restrict-apparmor-profiles", rule: "app-armor"},
		{policy: "disallow-proc-mount", rule: "check-proc-mount"},
		{policy: "disallow-selinux", rule: "selinux-type"},
		{policy: "disallow-selinux", rule: "selinux-user-role"},
		{policy: "restrict-sysctls", rule: "check-sysctls"},
		{policy: "prevent-cr8escape", rule: "restrict-sysctls-cr8escape"},
		{policy: "restrict-seccomp", rule: "check-seccomp"},
		{policy: "restrict-seccomp-strict", rule: "check-seccomp-strict"},
		{policy: "require-ro-rootfs", rule: "validate-readOnlyRootFilesystem"},
		{policy: "drop-all-capabilities", rule: "require-drop-all"},
		{policy: "drop-cap-net-raw", rule: "require-drop-cap-net-raw"},
		{policy: "disallow-capabilities-strict", rule: "require-drop-all"},
		{policy: "disallow-capabilities-strict", rule: "adding-capabilities-strict"},
		{policy: "disallow-capabilities", rule: "adding-capabilities"},
		{policy: "psp-restrict-adding-capabilities", rule: "allowed-capabilities"},
		{policy: "service-mesh-disallow-capabilities", rule: "adding-capabilities-istio-linkerd"},
		{policy: "podsecurity-subrule-baseline", rule: "baseline"},
		{policy: "podsecurity-subrule-restricted", rule: "restricted"},
		{policy: "podsecurity-subrule-restricted-capabilities", rule: "restricted-exempt-capabilities"},
		{policy: "podsecurity-subrule-restricted-seccomp", rule: "restricted-exempt-seccomp"},
		{policy: "disallow-default-namespace", rule: "validate-namespace"},
		{policy: "disallow-default-namespace", rule: "validate-podcontroller-namespace"},
		{policy: "prevent-bare-pods", rule: "bare-pods"},
		{policy: "require-requests-limits", rule: "validate-resources"},
		{policy: "add-default-resources", rule: "add-default-requests"},
		{policy: "apply-pss-restricted-profile", rule: "add-pss-fields"},
		{policy: "add-psa-labels", rule: "add-baseline-enforce-restricted-warn"},
		{policy: "add-psa-namespace-reporting", rule: "check-namespace-labels"},
		{policy: "deny-privileged-profile", rule: "check-privileged"},
		{policy: "require-cpu-limits", rule: "check-cpu-limits"},
		{policy: "require-qos-burstable", rule: "burstable"},
		{policy: "require-qos-guaranteed", rule: "guaranteed"},
		{policy: "memory-requests-equal-limits", rule: "memory-requests-equal-limits"},
		{policy: "imagepullpolicy-always", rule: "imagepullpolicy-always"},
		{policy: "disallow-latest-tag", rule: "require-and-validate-image-tag"},
		{policy: "disallow-latest-tag", rule: "require-image-tag"},
		{policy: "disallow-latest-tag", rule: "validate-image-tag"},
		{policy: "always-pull-images", rule: "always-pull-images"},
		{policy: "require-image-checksum", rule: "require-image-checksum"},
		{policy: "require-imagepullsecrets", rule: "check-for-image-pull-secrets"},
		{policy: "resolve-image-to-digest", rule: "resolve-to-digest"},
		{policy: "require-pod-probes", rule: "validate-probes"},
		{policy: "validate-probes", rule: "validate-probes"},
		{policy: "deny-commands-in-exec-probe", rule: "check-commands"},
		{policy: "require-container-port-names", rule: "port-name"},
		{policy: "restrict-automount-sa-token", rule: "validate-automountServiceAccountToken"},
		{policy: "restrict-sa-automount-sa-token", rule: "validate-sa-automountServiceAccountToken"},
		{policy: "disable-automountserviceaccounttoken", rule: "disable-automountserviceaccounttoken"},
		{policy: "check-serviceaccount-secrets", rule: "deny-secrets"},
		{policy: "deny-secret-service-account-token-type", rule: "deny-secret-service-account-token-type"},
		{policy: "secrets-not-from-env-vars", rule: "secrets-not-from-env-vars"},
		{policy: "secrets-not-from-env-vars", rule: "secrets-not-from-envfrom"},
		{policy: "no-secrets", rule: "secrets-not-from-env"},
		{policy: "no-secrets", rule: "secrets-not-from-envfrom"},
		{policy: "no-secrets", rule: "secrets-not-from-volumes"},
		{policy: "no-secrets", rule: "secrets-not-from-env-envFrom-and-volumes"},
		{policy: "restrict-binding-clusteradmin", rule: "clusteradmin-bindings"},
		{policy: "restrict-binding-system-groups", rule: "restrict-anonymous"},
		{policy: "restrict-binding-system-groups", rule: "restrict-masters"},
		{policy: "restrict-binding-system-groups", rule: "restrict-subject-groups"},
		{policy: "restrict-binding-system-groups", rule: "restrict-unauthenticated"},
		{policy: "restrict-wildcard-verbs", rule: "wildcard-verbs"},
		{policy: "restrict-wildcard-resources", rule: "wildcard-resources"},
		{policy: "restrict-secret-role-verbs", rule: "secret-verbs"},
		{policy: "restrict-escalation-verbs-roles", rule: "escalate"},
		{policy: "restrict-clusterrole-nodesproxy", rule: "clusterrole-nodesproxy"},
		{policy: "restrict-deprecated-registry", rule: "restrict-deprecated-registry"},
		{policy: "ensure-readonly-hostpath", rule: "ensure-hostpaths-readonly"},
		{policy: "restrict-volume-types", rule: "restricted-volumes"},
		{policy: "limit-hostpath-type-pv", rule: "limit-hostpath-type-pv-to-slash-data"},
		{policy: "disallow-container-sock-mounts", rule: "validate-docker-sock-mount"},
		{policy: "disallow-container-sock-mounts", rule: "validate-containerd-sock-mount"},
		{policy: "disallow-container-sock-mounts", rule: "validate-crio-sock-mount"},
		{policy: "docker-socket-check", rule: "conditional-anchor-dockersock"},
		{policy: "docker-socket-check", rule: "docker-socket-check"},
		{policy: "disallow-helm-tiller", rule: "validate-helm-tiller"},
		{policy: "disallow-ingress-nginx-custom-snippets", rule: "check-config-map"},
		{policy: "disallow-ingress-nginx-custom-snippets", rule: "check-ingress-annotations"},
		{policy: "restrict-ingress-paths", rule: "check-paths"},
		{policy: "restrict-annotations", rule: "check-ingress"},
		{policy: "restrict-annotations", rule: "block-flux-v1"},
		{policy: "restrict-jobs", rule: "restrict-job-from-cronjob"},
		{policy: "limit-hostpath-vols", rule: "limit-hostpath-to-slash-data"},
		{policy: "remove-hostpath-volumes", rule: "remove-hostpath-all"},
		{policy: "remove-serviceaccount-token", rule: "remove-vol-volmount"},
		{policy: "add-default-securitycontext", rule: "add-default-securitycontext"},
		{policy: "no-loadbalancer-service", rule: "no-LoadBalancer"},
		{policy: "no-localhost-service", rule: "no-localhost-service"},
		{policy: "restrict-external-ips", rule: "check-ips"},
		{policy: "restrict-nodeport", rule: "validate-nodeport"},
		{policy: "restrict-service-port-range", rule: "restrict-port-range"},
		{policy: "disallow-empty-ingress-host", rule: "disallow-empty-ingress-host"},
		{policy: "restrict-ingress-defaultbackend", rule: "restrict-ingress-defaultbackend"},
		{policy: "restrict-ingress-wildcard", rule: "block-ingress-wildcard"},
		{policy: "restrict-ingress-classes", rule: "validate-ingress"},
		{policy: "require-ingress-https", rule: "has-annotation"},
		{policy: "require-ingress-https", rule: "has-tls"},
		{policy: "ingress-host-match-tls", rule: "host-match-tls"},
		{policy: "limit-containers-per-pod", rule: "limit-containers-per-pod"},
		{policy: "deployment-has-multiple-replicas", rule: "deployment-has-multiple-replicas"},
		{policy: "add-networkpolicy", rule: "default-deny"},
		{policy: "add-networkpolicy-dns", rule: "add-netpol-dns"},
		{policy: "generate-networkpolicy-existing", rule: "generate-existing-networkpolicy"},
		{policy: "add-ns-quota", rule: "generate-limitrange"},
		{policy: "add-ns-quota", rule: "generate-resourcequota"},
		{policy: "namespace-inventory-check", rule: "resourcequotas"},
		{policy: "namespace-inventory-check", rule: "networkpolicies"},
		{policy: "pdb-maxunavailable", rule: "pdb-maxunavailable"},
		{policy: "pdb-maxunavailable-with-deployments", rule: "pdb-maxunavailable"},
		{policy: "prevent-duplicate-hpa", rule: "check-targetref-duplicates"},
		{policy: "prevent-duplicate-hpa", rule: "verify-kind-name-duplicates"},
		{policy: "check-hpa-exists", rule: "validate-hpa"},
		{policy: "readwriteonce-pod", rule: "readwrite-pvc-single-pod"},
		{policy: "require-pod-priorityclassname", rule: "check-priorityclassname"},
		{policy: "add-ttl-jobs", rule: "add-ttlSecondsAfterFinished"},
		{policy: "add-emptydir-sizelimit", rule: "mutate-emptydir"},
		{policy: "require-emptydir-requests-and-limits", rule: "check-emptydir-requests-limits"},
		{policy: "forbid-cpu-limits", rule: "check-cpu-limits"},
		{policy: "require-storageclass", rule: "pvc-storageclass"},
		{policy: "require-storageclass", rule: "ss-storageclass"},
		{policy: "restrict-storageclass", rule: "storageclass-delete"},
		{policy: "restrict-networkpolicy-empty-podselector", rule: "empty-podselector"},
		{policy: "restrict-node-selection", rule: "restrict-nodeselector"},
		{policy: "require-labels", rule: "check-for-labels"},
	}

	actual := map[string]struct{}{}
	for _, mapping := range kyvernoBuiltinPolicyMappings {
		for _, rule := range mapping.rules {
			actual[mapping.policy+"/"+rule] = struct{}{}
		}
	}
	for _, item := range expected {
		_, ok := actual[item.policy+"/"+item.rule]
		require.True(t, ok, "missing built-in Kyverno mapping for %s/%s", item.policy, item.rule)
	}
}

func TestKyvernoBuiltinMappingsUseDedicatedLatestTagChecks(t *testing.T) {
	var latestTagMapping *kyvernoBuiltinPolicyMapping
	for i := range kyvernoBuiltinPolicyMappings {
		if kyvernoBuiltinPolicyMappings[i].policy == "disallow-latest-tag" {
			latestTagMapping = &kyvernoBuiltinPolicyMappings[i]
			break
		}
	}
	require.NotNil(t, latestTagMapping)
	assert.Equal(t, "high", latestTagMapping.confidence)
	assert.Contains(t, latestTagMapping.checks, "mondoo-kubernetes-security-pod-image-tag-not-latest")
	assert.Contains(t, latestTagMapping.checks, "mondoo-kubernetes-security-deployment-image-tag-not-latest")
	for _, check := range latestTagMapping.checks {
		assert.NotContains(t, check, "-imagepull")
	}
}

func TestKyvernoBuiltinMappingsSupportRequireImagePullSecretsChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "require-imagepullsecrets", "check-for-image-pull-secrets", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-pod-imagepullsecret-required-for-restricted-registries"}, checks)
}

func TestKyvernoBuiltinMappingsSupportIngressNginxSnippetChecks(t *testing.T) {
	var snippetMapping *kyvernoBuiltinPolicyMapping
	for i := range kyvernoBuiltinPolicyMappings {
		if kyvernoBuiltinPolicyMappings[i].policy == "disallow-ingress-nginx-custom-snippets" {
			snippetMapping = &kyvernoBuiltinPolicyMappings[i]
			break
		}
	}
	require.NotNil(t, snippetMapping)
	assert.Contains(t, snippetMapping.rules, "check-config-map")
	assert.Contains(t, snippetMapping.rules, "check-ingress-annotations")
	assert.Contains(t, snippetMapping.checks, "mondoo-kubernetes-security-configmap-ingress-nginx-snippet-annotations-disabled")
	assert.Contains(t, snippetMapping.checks, "mondoo-kubernetes-security-ingress-nginx-no-custom-snippets")
}

func TestKyvernoBuiltinMappingsSupportRestrictIngressPathsChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-ingress-paths", "check-paths", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-security-ingress-nginx-no-sensitive-paths")
}

func TestKyvernoBuiltinMappingsSupportRestrictAnnotationIngressChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-annotations", "check-ingress", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-security-ingress-nginx-no-dangerous-annotation-values")
}

func TestKyvernoBuiltinMappingsSupportRestrictAnnotationFluxChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-annotations", "block-flux-v1", kyvernoBuiltinMondooPolicyUid)
	assert.ElementsMatch(t, []string{
		"mondoo-kubernetes-security-pod-no-flux-v1-annotations",
		"mondoo-kubernetes-security-cronjob-no-flux-v1-annotations",
		"mondoo-kubernetes-security-job-no-flux-v1-annotations",
		"mondoo-kubernetes-security-daemonset-no-flux-v1-annotations",
		"mondoo-kubernetes-security-deployment-no-flux-v1-annotations",
		"mondoo-kubernetes-security-statefulset-no-flux-v1-annotations",
	}, checks)
	assert.NotContains(t, checks, "mondoo-kubernetes-security-replicaset-no-flux-v1-annotations")
}

func TestKyvernoBuiltinMappingsSupportRestrictJobsChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-jobs", "restrict-job-from-cronjob", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-job-created-by-cronjob"}, checks)
}

func TestKyvernoBuiltinMappingsSupportRunAsContainerUserChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "require-run-as-containeruser", "require-run-as-containeruser", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-pod-windows-runas-containeruser"}, checks)
}

func TestKyvernoBuiltinMappingsSupportAddTtlJobsChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "add-ttl-jobs", "add-ttlSecondsAfterFinished", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-job-ttl-after-finished"}, checks)
}

func TestKyvernoBuiltinMappingsSupportAppArmorChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-apparmor-profiles", "app-armor", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-pod-apparmor-profile"}, checks)
}

func TestKyvernoBuiltinMappingsSupportEmptyDirChecks(t *testing.T) {
	sizeChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-emptydir-sizelimit", "mutate-emptydir", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-pod-emptydir-size-limit"}, sizeChecks)

	resourceChecks := kyvernoBuiltinChecksForPolicyRule(t, "require-emptydir-requests-and-limits", "check-emptydir-requests-limits", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-pod-emptydir-ephemeral-storage-resources"}, resourceChecks)
}

func TestKyvernoBuiltinMappingsSupportPsaNamespaceLabelChecks(t *testing.T) {
	labelsChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-psa-labels", "add-baseline-enforce-restricted-warn", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-namespace-psa-enforce-warn-labels"}, labelsChecks)

	reportingChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-psa-namespace-reporting", "check-namespace-labels", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-namespace-psa-labels"}, reportingChecks)

	denyPrivilegedChecks := kyvernoBuiltinChecksForPolicyRule(t, "deny-privileged-profile", "check-privileged", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-namespace-psa-enforce-not-privileged"}, denyPrivilegedChecks)
}

func TestKyvernoBuiltinMappingsSupportNamespaceQuotaChecks(t *testing.T) {
	limitRangeChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-ns-quota", "generate-limitrange", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-namespace-limitrange"}, limitRangeChecks)

	resourceQuotaChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-ns-quota", "generate-resourcequota", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-namespace-resourcequota"}, resourceQuotaChecks)
}

func TestKyvernoBuiltinMappingsSupportDefaultDenyNetworkPolicyChecks(t *testing.T) {
	defaultDenyChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-networkpolicy", "default-deny", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-namespace-default-deny-networkpolicy"}, defaultDenyChecks)

	dnsChecks := kyvernoBuiltinChecksForPolicyRule(t, "add-networkpolicy-dns", "add-netpol-dns", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-namespace-allow-dns-networkpolicy"}, dnsChecks)

	egressDefaultDenyChecks := kyvernoBuiltinChecksForPolicyRule(t, "generate-networkpolicy-existing", "generate-existing-networkpolicy", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-namespace-egress-default-deny-networkpolicy"}, egressDefaultDenyChecks)
}

func TestKyvernoRulesFromGeneratingPolicySingularGenerate(t *testing.T) {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion("policies.kyverno.io/v1alpha1")
	obj.SetKind("GeneratingPolicy")
	obj.SetName("add-networkpolicy")
	rules := kyvernoRulesFromPolicy(obj, obj, map[string]any{
		"spec": map[string]any{
			"generate": map[string]any{
				"name": "default-deny",
				"matchConstraints": map[string]any{
					"resourceRules": []any{map[string]any{"resources": []any{"namespaces"}}},
				},
			},
		},
	})

	require.Len(t, rules, 1)
	assert.Equal(t, "default-deny", rules[0].name)
	assert.Equal(t, "generation", rules[0].ruleType)
	assert.Equal(t, []string{"namespaces"}, rules[0].matchKinds)
	checks := kyvernoBuiltinChecksForPolicyRule(t, "add-networkpolicy", rules[0].name, kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-namespace-default-deny-networkpolicy"}, checks)
}

func TestKyvernoBuiltinMappingsSupportPartialNodeSelectionChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-node-selection", "restrict-nodeselector", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-pod-no-node-selector"}, checks)
	for _, mapping := range kyvernoBuiltinPolicyMappings {
		assert.False(t, mapping.policy == "restrict-node-selection" && containsString(mapping.rules, "restrict-nodename"))
	}
}

func TestKyvernoBuiltinMappingsSupportDeprecatedRegistryChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-deprecated-registry", "restrict-deprecated-registry", kyvernoBuiltinMondooPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-security-pod-no-deprecated-k8s-gcr-registry"}, checks)
}

func TestKyvernoBuiltinMappingsSupportRestrictStorageClassChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-storageclass", "storageclass-delete", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Equal(t, []string{"mondoo-kubernetes-best-practices-storageclass-reclaim-policy-delete"}, checks)
}

func TestKyvernoBuiltinMappingsSupportValidateProbesChecks(t *testing.T) {
	var validateProbesMapping *kyvernoBuiltinPolicyMapping
	for i := range kyvernoBuiltinPolicyMappings {
		if kyvernoBuiltinPolicyMappings[i].policy == "validate-probes" {
			validateProbesMapping = &kyvernoBuiltinPolicyMappings[i]
			break
		}
	}
	require.NotNil(t, validateProbesMapping)
	assert.Equal(t, kyvernoBuiltinMondooBestPracticesPolicyUid, validateProbesMapping.mondooPolicyUid)
	assert.Contains(t, validateProbesMapping.rules, "validate-probes")
	assert.Contains(t, validateProbesMapping.checks, "mondoo-kubernetes-best-practices-daemonset-probes-different")
	assert.Contains(t, validateProbesMapping.checks, "mondoo-kubernetes-best-practices-deployment-probes-different")
	assert.Contains(t, validateProbesMapping.checks, "mondoo-kubernetes-best-practices-statefulset-probes-different")
}

func TestKyvernoBuiltinMappingsSupportIngressTlsHostChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "ingress-host-match-tls", "host-match-tls", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-ingress-tls-hosts-match-rules")
}

func TestKyvernoBuiltinMappingsSupportRestrictIngressClassesChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-ingress-classes", "validate-ingress", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-ingress-approved-class-annotation")
}

func TestKyvernoBuiltinMappingsSupportServicePortRangeChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "restrict-service-port-range", "restrict-port-range", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-service-ports-approved-range")
}

func TestKyvernoBuiltinMappingsSupportLimitContainersPerPodChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "limit-containers-per-pod", "limit-containers-per-pod", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-pod-max-four-containers")
}

func TestKyvernoBuiltinMappingsSupportHpaExistsChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "check-hpa-exists", "validate-hpa", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-workloads-have-hpa")
}

func TestKyvernoBuiltinMappingsSupportRequireQosBurstableChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "require-qos-burstable", "burstable", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-pod-not-besteffort")
}

func TestKyvernoBuiltinMappingsSupportForbidCpuLimitsChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "forbid-cpu-limits", "check-cpu-limits", kyvernoBuiltinMondooBestPracticesPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-pod-no-cpu-limits")
	assert.Contains(t, checks, "mondoo-kubernetes-best-practices-deployment-no-cpu-limits")
}

func TestKyvernoBuiltinMappingsSupportPartialPdbWithDeploymentsChecks(t *testing.T) {
	var mapping *kyvernoBuiltinPolicyMapping
	for i := range kyvernoBuiltinPolicyMappings {
		if kyvernoBuiltinPolicyMappings[i].policy == "pdb-maxunavailable-with-deployments" {
			mapping = &kyvernoBuiltinPolicyMappings[i]
			break
		}
	}
	require.NotNil(t, mapping)
	assert.Equal(t, "medium", mapping.confidence)
	assert.Equal(t, kyvernoBuiltinMondooBestPracticesPolicyUid, mapping.mondooPolicyUid)
	assert.Contains(t, mapping.checks, "mondoo-kubernetes-best-practices-pdb-maxunavailable-nonzero")
}

func TestKyvernoBuiltinMappingsSupportBestPracticesPolicy(t *testing.T) {
	bestPracticeMappings := map[string]struct{}{}
	for _, mapping := range kyvernoBuiltinPolicyMappings {
		if mapping.mondooPolicyUid != kyvernoBuiltinMondooBestPracticesPolicyUid {
			continue
		}
		bestPracticeMappings[mapping.policy] = struct{}{}
		for _, check := range mapping.checks {
			assert.Contains(t, check, "mondoo-kubernetes-best-practices-")
		}
	}

	assert.Contains(t, bestPracticeMappings, "disallow-default-namespace")
	assert.Contains(t, bestPracticeMappings, "disallow-host-ports")
	assert.Contains(t, bestPracticeMappings, "disallow-host-ports-range")
	assert.Contains(t, bestPracticeMappings, "podsecurity-subrule-baseline")
	assert.Contains(t, bestPracticeMappings, "podsecurity-subrule-restricted")
	assert.Contains(t, bestPracticeMappings, "podsecurity-subrule-restricted-capabilities")
	assert.Contains(t, bestPracticeMappings, "podsecurity-subrule-restricted-seccomp")
	assert.Contains(t, bestPracticeMappings, "add-default-resources")
	assert.Contains(t, bestPracticeMappings, "prevent-bare-pods")
	assert.Contains(t, bestPracticeMappings, "require-qos-burstable")
	assert.Contains(t, bestPracticeMappings, "require-qos-guaranteed")
	assert.Contains(t, bestPracticeMappings, "memory-requests-equal-limits")
	assert.Contains(t, bestPracticeMappings, "require-pod-probes")
	assert.Contains(t, bestPracticeMappings, "validate-probes")
	assert.Contains(t, bestPracticeMappings, "require-requests-limits")
	assert.Contains(t, bestPracticeMappings, "no-loadbalancer-service")
	assert.Contains(t, bestPracticeMappings, "no-localhost-service")
	assert.Contains(t, bestPracticeMappings, "restrict-external-ips")
	assert.Contains(t, bestPracticeMappings, "restrict-nodeport")
	assert.Contains(t, bestPracticeMappings, "restrict-service-port-range")
	assert.Contains(t, bestPracticeMappings, "disallow-empty-ingress-host")
	assert.Contains(t, bestPracticeMappings, "restrict-ingress-defaultbackend")
	assert.Contains(t, bestPracticeMappings, "restrict-ingress-wildcard")
	assert.Contains(t, bestPracticeMappings, "restrict-ingress-classes")
	assert.Contains(t, bestPracticeMappings, "require-ingress-https")
	assert.Contains(t, bestPracticeMappings, "ingress-host-match-tls")
	assert.Contains(t, bestPracticeMappings, "limit-containers-per-pod")
	assert.Contains(t, bestPracticeMappings, "deployment-has-multiple-replicas")
	assert.Contains(t, bestPracticeMappings, "namespace-inventory-check")
	assert.Contains(t, bestPracticeMappings, "pdb-maxunavailable")
	assert.Contains(t, bestPracticeMappings, "pdb-maxunavailable-with-deployments")
	assert.Contains(t, bestPracticeMappings, "prevent-duplicate-hpa")
	assert.Contains(t, bestPracticeMappings, "check-hpa-exists")
	assert.Contains(t, bestPracticeMappings, "readwriteonce-pod")
	assert.Contains(t, bestPracticeMappings, "require-pod-priorityclassname")
	assert.Contains(t, bestPracticeMappings, "require-storageclass")
	assert.Contains(t, bestPracticeMappings, "restrict-networkpolicy-empty-podselector")
	assert.Contains(t, bestPracticeMappings, "require-labels")
}

func TestKyvernoBuiltinMappingsSupportPodSecurityProfiles(t *testing.T) {
	baselineChecks := kyvernoBuiltinChecksForPolicyRule(t, "podsecurity-subrule-baseline", "baseline", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-privilegedcontainer")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-ports-hostport")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-hostprocess")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-proc-mount")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-safe-sysctls")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-selinux-type")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-selinux-user-role")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-seccomp-profile")
	assert.Contains(t, baselineChecks, "mondoo-kubernetes-security-pod-capability-net-raw")
	assert.NotContains(t, baselineChecks, "mondoo-kubernetes-security-pod-allowprivilegeescalation")
	assert.NotContains(t, baselineChecks, "mondoo-kubernetes-security-pod-runasnonroot")
	assert.NotContains(t, baselineChecks, "mondoo-kubernetes-security-pod-capability-drop-all")

	restrictedChecks := kyvernoBuiltinChecksForPolicyRule(t, "podsecurity-subrule-restricted", "restricted", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, restrictedChecks, "mondoo-kubernetes-security-pod-allowprivilegeescalation")
	assert.Contains(t, restrictedChecks, "mondoo-kubernetes-security-pod-runasnonroot")
	assert.Contains(t, restrictedChecks, "mondoo-kubernetes-security-pod-capability-drop-all")
	assert.Contains(t, restrictedChecks, "mondoo-kubernetes-security-pod-capability-net-raw")

	restrictedCapabilitiesChecks := kyvernoBuiltinChecksForPolicyRule(t, "podsecurity-subrule-restricted-capabilities", "restricted-exempt-capabilities", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, restrictedCapabilitiesChecks, "mondoo-kubernetes-security-pod-allowprivilegeescalation")
	assert.Contains(t, restrictedCapabilitiesChecks, "mondoo-kubernetes-security-pod-runasnonroot")
	assert.Contains(t, restrictedCapabilitiesChecks, "mondoo-kubernetes-security-pod-seccomp-profile")
	assert.NotContains(t, restrictedCapabilitiesChecks, "mondoo-kubernetes-security-pod-capability-drop-all")
	assert.NotContains(t, restrictedCapabilitiesChecks, "mondoo-kubernetes-security-pod-capability-net-raw")
	assert.NotContains(t, restrictedCapabilitiesChecks, "mondoo-kubernetes-security-pod-capability-sys-admin")

	restrictedSeccompChecks := kyvernoBuiltinChecksForPolicyRule(t, "podsecurity-subrule-restricted-seccomp", "restricted-exempt-seccomp", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, restrictedSeccompChecks, "mondoo-kubernetes-security-pod-allowprivilegeescalation")
	assert.Contains(t, restrictedSeccompChecks, "mondoo-kubernetes-security-pod-runasnonroot")
	assert.Contains(t, restrictedSeccompChecks, "mondoo-kubernetes-security-pod-capability-drop-all")
	assert.NotContains(t, restrictedSeccompChecks, "mondoo-kubernetes-security-pod-seccomp-profile")
	assert.Contains(t, restrictedSeccompChecks, "mondoo-kubernetes-security-pod-capability-net-raw")
}

func TestKyvernoBuiltinMappingsSupportCr8escapeSysctlChecks(t *testing.T) {
	checks := kyvernoBuiltinChecksForPolicyRule(t, "prevent-cr8escape", "restrict-sysctls-cr8escape", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, checks, "mondoo-kubernetes-security-pod-sysctls-no-cr8escape-values")
	assert.Contains(t, checks, "mondoo-kubernetes-security-deployment-sysctls-no-cr8escape-values")
}

func TestKyvernoBuiltinMappingsSupportNoSecretsCombinedRule(t *testing.T) {
	combinedChecks := kyvernoBuiltinChecksForPolicyRule(t, "no-secrets", "secrets-not-from-env-envFrom-and-volumes", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, combinedChecks, "mondoo-kubernetes-security-pod-no-secret-env-vars")
	assert.Contains(t, combinedChecks, "mondoo-kubernetes-security-pod-no-secret-volumes")

	volumeChecks := kyvernoBuiltinChecksForPolicyRule(t, "no-secrets", "secrets-not-from-volumes", kyvernoBuiltinMondooPolicyUid)
	assert.Contains(t, volumeChecks, "mondoo-kubernetes-security-pod-no-secret-volumes")
	assert.NotContains(t, volumeChecks, "mondoo-kubernetes-security-pod-no-secret-env-vars")
}

func kyvernoBuiltinChecksForPolicyRule(t *testing.T, policy string, rule string, mondooPolicyUid string) []string {
	t.Helper()

	out := []string{}
	for _, mapping := range kyvernoBuiltinPolicyMappings {
		policyUid := mapping.mondooPolicyUid
		if policyUid == "" {
			policyUid = kyvernoBuiltinMondooPolicyUid
		}
		if mapping.policy == policy && policyUid == mondooPolicyUid && containsString(mapping.rules, rule) {
			out = append(out, mapping.checks...)
		}
	}
	require.NotEmptyf(t, out, "missing built-in Kyverno mapping for %s/%s in %s", policy, rule, mondooPolicyUid)
	return out
}

func kyvernoExpectedHostPortCheckUids() []any {
	return []any{
		"mondoo-kubernetes-security-pod-ports-hostport",
		"mondoo-kubernetes-security-cronjob-ports-hostport",
		"mondoo-kubernetes-security-daemonset-ports-hostport",
		"mondoo-kubernetes-security-deployment-ports-hostport",
		"mondoo-kubernetes-security-job-ports-hostport",
		"mondoo-kubernetes-security-replicaset-ports-hostport",
		"mondoo-kubernetes-security-statefulset-ports-hostport",
		"mondoo-kubernetes-best-practices-pod-ports-hostport",
		"mondoo-kubernetes-best-practices-cronjob-ports-hostport",
		"mondoo-kubernetes-best-practices-daemonset-ports-hostport",
		"mondoo-kubernetes-best-practices-deployment-ports-hostport",
		"mondoo-kubernetes-best-practices-job-ports-hostport",
		"mondoo-kubernetes-best-practices-replicaset-ports-hostport",
		"mondoo-kubernetes-best-practices-statefulset-ports-hostport",
	}
}

func kyvernoTestResource(t *testing.T) *mqlK8sKyverno {
	t.Helper()

	return kyvernoTestResourceWithOptions(t, nil)
}

func kyvernoTestResourceWithOptions(t *testing.T, options map[string]string) *mqlK8sKyverno {
	t.Helper()

	if options == nil {
		options = map[string]string{}
	}
	options[shared.OPTION_NAMESPACE] = ""

	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: options,
			},
		},
	}, manifest.WithManifestContent([]byte(kyvernoManifestFixture)))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	res, err := CreateResource(runtime, "k8s.kyverno", nil)
	require.NoError(t, err)
	return res.(*mqlK8sKyverno)
}

type kyvernoTestType struct {
	apiVersion string
	kind       string
}

func (t kyvernoTestType) GetAPIVersion() string {
	return t.apiVersion
}

func (t kyvernoTestType) SetAPIVersion(version string) {
	t.apiVersion = version
}

func (t kyvernoTestType) GetKind() string {
	return t.kind
}

func (t kyvernoTestType) SetKind(kind string) {
	t.kind = kind
}

func kyvernoPolicyByName(t *testing.T, kyverno *mqlK8sKyverno, name string) *mqlK8sKyvernoPolicy {
	t.Helper()

	policies := kyverno.GetPolicies()
	require.NoError(t, policies.Error)
	for _, item := range policies.Data {
		policy := item.(*mqlK8sKyvernoPolicy)
		if policy.GetName().Data == name {
			return policy
		}
	}
	t.Fatalf("Kyverno policy %q not found", name)
	return nil
}

func kyvernoResultByPolicyRule(t *testing.T, results []any, policyName, ruleName string) *mqlK8sKyvernoResult {
	t.Helper()

	for _, item := range results {
		result := item.(*mqlK8sKyvernoResult)
		if result.GetPolicy().Data == policyName && result.GetRule().Data == ruleName {
			return result
		}
	}
	t.Fatalf("Kyverno result %q/%q not found", policyName, ruleName)
	return nil
}

func kyvernoResultByPolicyRuleScope(t *testing.T, results []any, policyName, ruleName, scopeNamespace, scopeName string) *mqlK8sKyvernoResult {
	t.Helper()

	for _, item := range results {
		result := item.(*mqlK8sKyvernoResult)
		if result.GetPolicy().Data == policyName &&
			result.GetRule().Data == ruleName &&
			result.GetScopeNamespace().Data == scopeNamespace &&
			result.GetScopeName().Data == scopeName {
			return result
		}
	}
	t.Fatalf("Kyverno result %q/%q for scope %q/%q not found", policyName, ruleName, scopeNamespace, scopeName)
	return nil
}

func kyvernoResultByPolicyRuleScopeResult(t *testing.T, results []any, policyName, ruleName, scopeNamespace, scopeName, reportResult string) *mqlK8sKyvernoResult {
	t.Helper()

	for _, item := range results {
		result := item.(*mqlK8sKyvernoResult)
		if result.GetPolicy().Data == policyName &&
			result.GetRule().Data == ruleName &&
			result.GetScopeNamespace().Data == scopeNamespace &&
			result.GetScopeName().Data == scopeName &&
			result.GetResult().Data == reportResult {
			return result
		}
	}
	t.Fatalf("Kyverno result %q/%q/%q for scope %q/%q not found", policyName, ruleName, reportResult, scopeNamespace, scopeName)
	return nil
}

func assertKyvernoMapping(t *testing.T, mappings []any, policyName, ruleName, checkUid, confidence string) {
	t.Helper()

	for _, item := range mappings {
		mapping := item.(*mqlK8sKyvernoMapping)
		if mapping.GetKyvernoPolicy().Data == policyName &&
			mapping.GetKyvernoRule().Data == ruleName &&
			mapping.GetMondooCheckUid().Data == checkUid {
			assert.Equal(t, confidence, mapping.GetConfidence().Data)
			return
		}
	}
	t.Fatalf("Kyverno mapping %q/%q -> %q not found", policyName, ruleName, checkUid)
}

func kyvernoPolicyExceptionByName(t *testing.T, exceptions []any, name string) *mqlK8sKyvernoPolicyexception {
	t.Helper()

	for _, item := range exceptions {
		exception := item.(*mqlK8sKyvernoPolicyexception)
		if exception.GetName().Data == name {
			return exception
		}
	}
	t.Fatalf("Kyverno PolicyException %q not found", name)
	return nil
}

const kyvernoManifestFixture = `
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: Privileged containers are not allowed.
    mondoo.com/check-uid: mondoo-k8s-privileged-container
    mondoo.com/check-mrn: //policy.api.mondoo.app/spaces/test/checks/mondoo-k8s-privileged-container
spec:
  validationFailureAction: Audit
  background: false
  rules:
    - name: validate-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: Privileged containers are not allowed.
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): false
---
apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: require-run-as-non-root
  annotations:
    policies.kyverno.io/title: Require Run As Non-Root
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    mondoo.com/check-uid: mondoo-k8s-run-as-non-root
spec:
  validationActions:
    - Audit
  matchConstraints:
    resourceRules:
      - apiGroups:
          - ""
        apiVersions:
          - v1
        operations:
          - CREATE
          - UPDATE
        resources:
          - pods
  validations:
    - name: validation
      expression: "object.spec.securityContext.runAsNonRoot == true"
      message: Pods must run as non-root.
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-ports
  annotations:
    policies.kyverno.io/title: Disallow hostPorts
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    example.com/mondoo-check-uid: custom-hostport-check
    example.com/mondoo-check-mrn: //policy.api.mondoo.app/spaces/test/checks/custom-hostport-check
    example.com/mondoo-policy-uid: custom-kyverno-policy
    example.com/mondoo-mapping-reason: Configured Kyverno annotation mapping.
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: host-ports-none
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: Host ports are not allowed.
        pattern:
          spec:
            containers:
              - =(ports):
                  - =(hostPort): 0
    - name: audit-host-ports-without-mondoo-map
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: Alternate host port rule without a Mondoo mapping.
        pattern:
          spec:
            containers:
              - =(ports):
                  - =(hostPort): 0
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-path
  annotations:
    policies.kyverno.io/title: Disallow hostPath
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod,Volume
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: host-path
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: HostPath volumes are forbidden.
        pattern:
          spec:
            =(volumes):
              - X(hostPath): "null"
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-ports-range
  annotations:
    policies.kyverno.io/title: Disallow hostPorts Range (Alternate)
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: host-port-range
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: The only permitted hostPorts are in the range 5000-6000 or 0.
        deny:
          conditions:
            all:
              - key: "{{ request.object.spec.[ephemeralContainers, initContainers, containers][].ports[].hostPort }}"
                operator: AnyNotIn
                value: 5000-6000
---
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: limit-hostpath-type-pv
  annotations:
    policies.kyverno.io/title: Limit hostPath PersistentVolumes to Specific Directories
    policies.kyverno.io/category: Other
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: PersistentVolume
spec:
  validationFailureAction: Audit
  background: false
  rules:
    - name: limit-hostpath-type-pv-to-slash-data
      match:
        any:
          - resources:
              kinds:
                - PersistentVolume
      validate:
        message: hostPath type persistent volumes are confined to /data.
        pattern:
          spec:
            =(hostPath):
              path: /data*
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: privileged-debug-pod
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
    exceptions.mondoo.com/justification: Temporary debugging.
    exceptions.mondoo.com/owner: platform-security
    exceptions.mondoo.com/ticket: SEC-123
spec:
  exceptions:
    - policyName: disallow-privileged-containers
      ruleNames:
        - validate-privileged
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - default
          names:
            - debug-shell
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: host-ports-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
    exceptions.mondoo.com/justification: NodeLocal DNS exemption.
    exceptions.mondoo.com/owner: platform-security
spec:
  exceptions:
    - policyName: disallow-host-ports
      ruleNames:
        - host-ports-none
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - kube-system
          names:
            - node-local-dns
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: host-path-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  exceptions:
    - policyName: disallow-host-path
      ruleNames:
        - host-path
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - logging
          names:
            - node-agent
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: selector-host-ports-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  exceptions:
    - policyName: disallow-host-ports
      ruleNames:
        - host-ports-none
  match:
    any:
      - resources:
          kinds:
            - Pod
          selector:
            matchLabels:
              k8s-app: node-local-dns
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: namespace-selector-host-ports-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  exceptions:
    - policyName: disallow-host-ports
      ruleNames:
        - host-ports-none
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaceSelector:
            matchLabels:
              network-owner: platform
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: host-ports-range-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  exceptions:
    - policyName: disallow-host-ports-range
      ruleNames:
        - host-port-range
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - telemetry
          names:
            - collector
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: hostpath-pv-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  exceptions:
    - policyName: limit-hostpath-type-pv
      ruleNames:
        - limit-hostpath-type-pv-to-slash-data
  match:
    any:
      - resources:
          kinds:
            - PersistentVolume
          names:
            - data-pv
---
apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata:
  name: modern-host-ports-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
    exceptions.mondoo.com/justification: Current Kyverno PolicyException API shape.
    example.com/valid-until: "2099-12-31T00:00:00Z"
    example.com/justification: Configured current API exception.
    example.com/owner: policy-security
    example.com/ticket: SEC-999
spec:
  policyRefs:
    - kind: ClusterPolicy
      name: disallow-host-ports
  matchConditions:
    - name: namespaced-node-dns
      expression: "object.metadata.namespace == 'kube-system'"
---
apiVersion: policies.kyverno.io/v1alpha1
kind: PolicyException
metadata:
  name: legacy-run-as-root
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  policyRefs:
    - kind: ValidatingPolicy
      name: require-run-as-non-root
      ruleNames:
        - validation
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - default
          names:
            - legacy-app
---
apiVersion: policies.kyverno.io/v1alpha1
kind: PolicyException
metadata:
  name: policy-level-run-as-non-root
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2099-01-01T00:00:00Z"
spec:
  policyRefs:
    - kind: ValidatingPolicy
      name: require-run-as-non-root
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - default
          names:
            - legacy-app
---
apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: expired-wide-exception
  namespace: kyverno
  annotations:
    exceptions.mondoo.com/valid-until: "2000-01-01T00:00:00Z"
spec:
  exceptions:
    - policyName: disallow-privileged-containers
      ruleNames:
        - validate-privileged
  match:
    any:
      - resources:
          kinds:
            - Pod
---
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    network-owner: platform
---
apiVersion: v1
kind: Pod
metadata:
  name: node-local-dns
  namespace: kube-system
  labels:
    k8s-app: node-local-dns
spec:
  containers:
    - name: dns
      image: registry.k8s.io/dns/k8s-dns-node-cache:1.23.1
---
apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata:
  name: pod-policy-report
  namespace: default
scope:
  apiVersion: v1
  kind: Pod
  namespace: default
  name: debug-shell
  uid: debug-pod-uid
results:
  - policy: disallow-privileged-containers
    rule: validate-privileged
    category: Pod Security Standards (Baseline)
    severity: medium
    source: kyverno
    result: fail
    scored: true
    message: Privileged container detected.
    timestamp:
      seconds: 4070908800
  - policy: disallow-privileged-containers
    rule: validate-privileged
    category: Pod Security Standards (Baseline)
    severity: medium
    source: kyverno
    result: skip
    scored: true
    message: 'rule is skipped due to policy exception: kyverno/privileged-debug-pod'
    properties:
      exceptions: privileged-debug-pod
  - policy: disallow-host-ports
    rule: host-ports-none
    category: Pod Security Standards (Baseline)
    severity: medium
    source: kyverno
    result: fail
    scored: true
    message: Host port detected.
---
apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
metadata:
  name: node-local-dns-policy-report
  namespace: kube-system
scope:
  apiVersion: v1
  kind: Pod
  namespace: kube-system
  name: node-local-dns
  uid: node-local-dns-uid
results:
  - policy: disallow-host-ports
    rule: host-ports-none
    category: Pod Security Standards (Baseline)
    severity: medium
    source: kyverno
    result: fail
    scored: true
    message: Host port detected.
  - policy: disallow-host-ports
    rule: host-ports-none
    category: Pod Security Standards (Baseline)
    severity: medium
    source: kyverno
    result: skip
    scored: true
    message: 'rule is skipped due to policy exception: kyverno/host-ports-exception'
    properties:
      exceptions: host-ports-exception,selector-host-ports-exception,namespace-selector-host-ports-exception
---
apiVersion: openreports.io/v1alpha1
kind: Report
metadata:
  name: run-as-non-root-report
  namespace: default
scope:
  apiVersion: v1
  kind: Pod
  namespace: default
  name: legacy-app
  uid: legacy-pod-uid
results:
  - policy: require-run-as-non-root
    rule: validation
    category: Pod Security Standards (Restricted)
    severity: medium
    source: kyverno
    result: fail
    scored: true
    message: Pod must run as non-root.
  - policy: require-run-as-non-root
    rule: exception
    category: Pod Security Standards (Restricted)
    severity: medium
    source: KyvernoValidatingPolicy
    result: skip
    scored: true
    message: 'rule is skipped due to policy exception: kyverno/policy-level-run-as-non-root'
    properties:
      exceptions: policy-level-run-as-non-root
`
