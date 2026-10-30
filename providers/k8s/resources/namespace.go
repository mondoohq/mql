// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

type mqlK8sNamespaceInternal struct {
	lock sync.Mutex
	obj  *corev1.Namespace
}

func initK8sNamespace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initResource[*mqlK8sNamespace](runtime, args, func(k *mqlK8s) *plugin.TValue[[]any] { return k.GetNamespaces() })
}

func (k *mqlK8s) namespaces() ([]any, error) {
	kp, err := k8sProvider(k.MqlRuntime.Connection)
	if err != nil {
		return nil, err
	}

	nss, err := kp.Namespaces()
	if err != nil {
		return nil, err
	}

	resp := make([]any, 0, len(nss))
	for _, ns := range nss {
		ts := ns.GetCreationTimestamp()

		objT, err := meta.TypeAccessor(&ns)
		if err != nil {
			log.Error().Err(err).Msg("could not access object attributes")
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.namespace", map[string]*llx.RawData{
			"id":      llx.StringData(objIdFromK8sObj(&ns.ObjectMeta, objT)),
			"uid":     llx.StringData(string(ns.UID)),
			"name":    llx.StringData(ns.Name),
			"created": llx.TimeData(ts.Time),
			"kind":    llx.StringData(ns.Kind),
		})
		if err != nil {
			return nil, err
		}

		r.(*mqlK8sNamespace).obj = &ns
		resp = append(resp, r)
	}
	return resp, nil
}

func (k *mqlK8sNamespace) manifest() (map[string]any, error) {
	manifest, err := convert.JsonToDict(k.obj)
	if err != nil {
		return nil, err
	}
	return manifest, nil
}

func (k *mqlK8sNamespace) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sNamespace) annotations() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sNamespace) labels() (map[string]any, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sNamespace) pods() ([]any, error) {
	return filterByNamespace[*mqlK8sPod](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetPods() })
}

func (k *mqlK8sNamespace) deployments() ([]any, error) {
	return filterByNamespace[*mqlK8sDeployment](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetDeployments() })
}

func (k *mqlK8sNamespace) statefulsets() ([]any, error) {
	return filterByNamespace[*mqlK8sStatefulset](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetStatefulsets() })
}

func (k *mqlK8sNamespace) daemonsets() ([]any, error) {
	return filterByNamespace[*mqlK8sDaemonset](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetDaemonsets() })
}

func (k *mqlK8sNamespace) replicasets() ([]any, error) {
	return filterByNamespace[*mqlK8sReplicaset](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetReplicasets() })
}

func (k *mqlK8sNamespace) jobs() ([]any, error) {
	return filterByNamespace[*mqlK8sJob](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetJobs() })
}

func (k *mqlK8sNamespace) cronjobs() ([]any, error) {
	return filterByNamespace[*mqlK8sCronjob](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetCronjobs() })
}

func (k *mqlK8sNamespace) services() ([]any, error) {
	return filterByNamespace[*mqlK8sService](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetServices() })
}

func (k *mqlK8sNamespace) ingresses() ([]any, error) {
	return filterByNamespace[*mqlK8sIngress](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetIngresses() })
}

func (k *mqlK8sNamespace) endpointSlices() ([]any, error) {
	return filterByNamespace[*mqlK8sEndpointslice](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetEndpointSlices() })
}

func (k *mqlK8sNamespace) networkPolicies() ([]any, error) {
	return filterByNamespace[*mqlK8sNetworkpolicy](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetNetworkPolicies() })
}

func (k *mqlK8sNamespace) secrets() ([]any, error) {
	return filterByNamespace[*mqlK8sSecret](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetSecrets() })
}

func (k *mqlK8sNamespace) configmaps() ([]any, error) {
	return filterByNamespace[*mqlK8sConfigmap](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetConfigmaps() })
}

func (k *mqlK8sNamespace) serviceaccounts() ([]any, error) {
	return filterByNamespace[*mqlK8sServiceaccount](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetServiceaccounts() })
}

func (k *mqlK8sNamespace) persistentVolumeClaims() ([]any, error) {
	return filterByNamespace[*mqlK8sPersistentvolumeclaim](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetPersistentVolumeClaims() })
}

func (k *mqlK8sNamespace) horizontalPodAutoscalers() ([]any, error) {
	return filterByNamespace[*mqlK8sHorizontalpodautoscaler](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetHorizontalPodAutoscalers() })
}

func (k *mqlK8sNamespace) resourceQuotas() ([]any, error) {
	return filterByNamespace[*mqlK8sResourcequota](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetResourceQuotas() })
}

func (k *mqlK8sNamespace) limitRanges() ([]any, error) {
	return filterByNamespace[*mqlK8sLimitrange](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetLimitRanges() })
}

func (k *mqlK8sNamespace) podDisruptionBudgets() ([]any, error) {
	return filterByNamespace[*mqlK8sPoddisruptionbudget](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetPodDisruptionBudgets() })
}

func (k *mqlK8sNamespace) roles() ([]any, error) {
	return filterByNamespace[*mqlK8sRbacRole](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetRoles() })
}

func (k *mqlK8sNamespace) rolebindings() ([]any, error) {
	return filterByNamespace[*mqlK8sRbacRolebinding](k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] { return c.GetRolebindings() })
}

// Pod Security admission label keys. See
// https://kubernetes.io/docs/concepts/security/pod-security-admission/
const (
	psaEnforceLabel        = "pod-security.kubernetes.io/enforce"
	psaEnforceVersionLabel = "pod-security.kubernetes.io/enforce-version"
	psaAuditLabel          = "pod-security.kubernetes.io/audit"
	psaAuditVersionLabel   = "pod-security.kubernetes.io/audit-version"
	psaWarnLabel           = "pod-security.kubernetes.io/warn"
	psaWarnVersionLabel    = "pod-security.kubernetes.io/warn-version"
)

func (k *mqlK8sNamespace) podSecurityEnforce() (string, error) {
	return k.obj.GetLabels()[psaEnforceLabel], nil
}

func (k *mqlK8sNamespace) podSecurityEnforceVersion() (string, error) {
	return k.obj.GetLabels()[psaEnforceVersionLabel], nil
}

func (k *mqlK8sNamespace) podSecurityAudit() (string, error) {
	return k.obj.GetLabels()[psaAuditLabel], nil
}

func (k *mqlK8sNamespace) podSecurityAuditVersion() (string, error) {
	return k.obj.GetLabels()[psaAuditVersionLabel], nil
}

func (k *mqlK8sNamespace) podSecurityWarn() (string, error) {
	return k.obj.GetLabels()[psaWarnLabel], nil
}

func (k *mqlK8sNamespace) podSecurityWarnVersion() (string, error) {
	return k.obj.GetLabels()[psaWarnVersionLabel], nil
}

// enforcesPodSecurity reports whether the namespace actively enforces a
// non-privileged Pod Security Standards level. An unset or "privileged" enforce
// label means workloads are not constrained at admission, so PSS findings on
// those workloads are advisory rather than enforced.
func (k *mqlK8sNamespace) enforcesPodSecurity() (bool, error) {
	level := k.obj.GetLabels()[psaEnforceLabel]
	return level == "baseline" || level == "restricted", nil
}

func (k *mqlK8sNamespace) ownerReferences() ([]any, error) {
	return k8sOwnerReferences(k.MqlRuntime, k.obj)
}

func (k *mqlK8sNamespace) managedFields() ([]any, error) {
	return k8sManagedFields(k.MqlRuntime, k.obj)
}
