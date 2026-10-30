// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// Resolving whether an API token is mounted needs both the pod spec and the
// ServiceAccount it runs as. Kubernetes applies the pod-level setting when it
// is present, otherwise the ServiceAccount's, otherwise its default of true.
//
// Unlike imagePullSecrets, which the ServiceAccount admission controller copies
// into the pod spec, the automount decision is never written back to the spec:
// the controller simply omits the projected token volume. Reading the spec
// alone therefore reports "token mounted" for every workload hardened by
// setting automountServiceAccountToken: false on the ServiceAccount, which is
// the recommended way to disable it for a whole namespace.

import (
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	corev1 "k8s.io/api/core/v1"
)

// automountFromSpecAndAccount applies the Kubernetes precedence rule: the
// pod-level setting wins, then the ServiceAccount's, and an unset value at both
// levels means the default, true.
func automountFromSpecAndAccount(podLevel, accountLevel *bool) bool {
	if podLevel != nil {
		return *podLevel
	}
	if accountLevel != nil {
		return *accountLevel
	}
	return true
}

// podServiceAccountName returns the ServiceAccount a pod spec runs as, falling
// back to the deprecated field and then to "default", which is what Kubernetes
// assigns when the spec names none.
func podServiceAccountName(spec *corev1.PodSpec) string {
	if spec == nil {
		return "default"
	}
	if spec.ServiceAccountName != "" {
		return spec.ServiceAccountName
	}
	if spec.DeprecatedServiceAccount != "" {
		return spec.DeprecatedServiceAccount
	}
	return "default"
}

// serviceAccountIndex returns the cluster's ServiceAccounts indexed by
// namespace/name, building the index once per scan. Every workload resolves its
// account through here, so rebuilding it per workload would cost one pass over
// every ServiceAccount per workload.
//
// Two cold callers can both build it; that is harmless because they produce the
// same content and the underlying list is already deduplicated by the runtime.
// The lock only keeps a reader from observing a half-assigned map.
func (k *mqlK8s) serviceAccountIndex() (map[string]*mqlK8sServiceaccount, error) {
	k.lock.Lock()
	cached := k.serviceAccountsByName
	k.lock.Unlock()
	if cached != nil {
		return cached, nil
	}

	index, err := namespacedByName[*mqlK8sServiceaccount](
		k.MqlRuntime, func(x *mqlK8s) *plugin.TValue[[]any] { return x.GetServiceaccounts() })
	if err != nil {
		return nil, err
	}

	k.lock.Lock()
	k.serviceAccountsByName = index
	k.lock.Unlock()
	return index, nil
}

// serviceAccountAutomount returns the named ServiceAccount's automount setting,
// or nil when the account cannot be resolved. It reads the already-fetched
// ServiceAccount collection rather than looking each account up individually,
// so it costs no extra API calls.
func serviceAccountAutomount(runtime *plugin.Runtime, namespace, name string) *bool {
	o, err := CreateResource(runtime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		log.Debug().Err(err).Msg("cannot reach the k8s resource to resolve automountServiceAccountToken")
		return nil
	}
	index, err := o.(*mqlK8s).serviceAccountIndex()
	if err != nil {
		// A scan without permission to list ServiceAccounts cannot tell what the
		// account asks for, so the Kubernetes default applies.
		log.Debug().Err(err).Msg("cannot list service accounts to resolve automountServiceAccountToken")
		return nil
	}
	sa, ok := index[namespace+"/"+name]
	if !ok || sa == nil {
		return nil
	}
	v := sa.GetAutomountServiceAccountToken()
	if v.Error != nil {
		log.Debug().Err(v.Error).Str("serviceaccount", name).Msg("cannot read automountServiceAccountToken")
		return nil
	}
	value := v.Data
	return &value
}

// effectiveAutomountServiceAccountToken reports whether Kubernetes mounts an API
// token for a workload running under the given pod spec.
func effectiveAutomountServiceAccountToken(runtime *plugin.Runtime, spec *corev1.PodSpec, namespace string) bool {
	var podLevel *bool
	if spec != nil {
		podLevel = spec.AutomountServiceAccountToken
	}

	// The account only matters when the spec is silent, so skip the lookup
	// entirely when the pod already decided.
	var accountLevel *bool
	if podLevel == nil {
		accountLevel = serviceAccountAutomount(runtime, namespace, podServiceAccountName(spec))
	}
	return automountFromSpecAndAccount(podLevel, accountLevel)
}
