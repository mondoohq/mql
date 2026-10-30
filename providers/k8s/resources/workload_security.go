// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// This file wires the workload-level securityContext rollup predicates
// (runsPrivileged, runsAsRoot, usesHostNamespaces, etc.) onto every K8s
// workload kind that owns a pod template: deployment, daemonset, statefulset,
// replicaset, job, and cronjob.
//
// k8s.pod is intentionally asymmetric. The pod resource already exposes
// automountServiceAccountToken (its own implementation in pod.go, present
// since schema 13.0.16) and securityContext, hostNetwork, hostPID, and hostIPC
// as plain schema fields, so this file only adds the container-rollup
// predicates to it and deliberately does NOT re-add those five fields. Future
// maintainers should not duplicate them on the pod.

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
)

// allWorkloadContainers returns every container that contributes to a pod's
// security posture: regular, init, and ephemeral containers.
func allWorkloadContainers(spec *corev1.PodSpec) []corev1.Container {
	if spec == nil {
		return nil
	}
	out := make([]corev1.Container, 0, len(spec.Containers)+len(spec.InitContainers)+len(spec.EphemeralContainers))
	out = append(out, spec.Containers...)
	out = append(out, spec.InitContainers...)
	for i := range spec.EphemeralContainers {
		out = append(out, corev1.Container(spec.EphemeralContainers[i].EphemeralContainerCommon))
	}
	return out
}

func specRunsPrivileged(spec *corev1.PodSpec) bool {
	for _, c := range allWorkloadContainers(spec) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

func specAllowsPrivilegeEscalation(spec *corev1.PodSpec) bool {
	for _, c := range allWorkloadContainers(spec) {
		sc := c.SecurityContext
		if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			return true
		}
	}
	return false
}

func specRunsAsRoot(spec *corev1.PodSpec) bool {
	var podNonRoot bool
	var podRunAsUser *int64
	if spec != nil && spec.SecurityContext != nil {
		if spec.SecurityContext.RunAsNonRoot != nil {
			podNonRoot = *spec.SecurityContext.RunAsNonRoot
		}
		podRunAsUser = spec.SecurityContext.RunAsUser
	}
	for _, c := range allWorkloadContainers(spec) {
		if containerCanRunAsRoot(c, podNonRoot, podRunAsUser) {
			return true
		}
	}
	return false
}

// containerCanRunAsRoot reports whether the container is NOT guaranteed to run
// as a non-root user, folding the pod-level runAsNonRoot and runAsUser settings.
func containerCanRunAsRoot(c corev1.Container, podNonRoot bool, podRunAsUser *int64) bool {
	sc := c.SecurityContext
	// runAsNonRoot=true at the container level (or inherited from the pod when
	// the container is silent) guarantees a non-root user.
	if sc != nil && sc.RunAsNonRoot != nil {
		if *sc.RunAsNonRoot {
			return false
		}
	} else if podNonRoot {
		return false
	}
	// A non-zero runAsUser also guarantees non-root; the container value wins
	// over the pod default.
	runAsUser := podRunAsUser
	if sc != nil && sc.RunAsUser != nil {
		runAsUser = sc.RunAsUser
	}
	if runAsUser != nil && *runAsUser != 0 {
		return false
	}
	return true
}

func specHasWritableRootFilesystem(spec *corev1.PodSpec) bool {
	for _, c := range allWorkloadContainers(spec) {
		sc := c.SecurityContext
		if sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
			return true
		}
	}
	return false
}

func specDropsAllCapabilities(spec *corev1.PodSpec) bool {
	containers := allWorkloadContainers(spec)
	if len(containers) == 0 {
		return false
	}
	for _, c := range containers {
		sc := c.SecurityContext
		if sc == nil || sc.Capabilities == nil {
			return false
		}
		dropsAll := false
		for _, d := range sc.Capabilities.Drop {
			// containerd and CRI-O both match ALL case-insensitively, so a
			// lowercase "all" drops every capability at runtime.
			if strings.EqualFold(string(d), "ALL") {
				dropsAll = true
				break
			}
		}
		if !dropsAll {
			return false
		}
	}
	return true
}

func specAddedCapabilities(spec *corev1.PodSpec) []any {
	seen := map[string]struct{}{}
	out := []any{}
	for _, c := range allWorkloadContainers(spec) {
		if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
			continue
		}
		for _, a := range c.SecurityContext.Capabilities.Add {
			s := string(a)
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func specUsesHostNamespaces(spec *corev1.PodSpec) bool {
	return spec != nil && (spec.HostNetwork || spec.HostPID || spec.HostIPC)
}

func specUsesHostPath(spec *corev1.PodSpec) bool {
	if spec == nil {
		return false
	}
	for i := range spec.Volumes {
		if spec.Volumes[i].HostPath != nil {
			return true
		}
	}
	return false
}

// effectiveSeccompType resolves the seccomp profile type that applies to a
// container: a container-level profile wins over the pod-level default, and an
// empty string means no profile is set at either level.
func effectiveSeccompType(spec *corev1.PodSpec, c corev1.Container) corev1.SeccompProfileType {
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		return c.SecurityContext.SeccompProfile.Type
	}
	if spec != nil && spec.SecurityContext != nil && spec.SecurityContext.SeccompProfile != nil {
		return spec.SecurityContext.SeccompProfile.Type
	}
	return ""
}

// specUsesUnconfinedSeccomp reports whether any container effectively runs with
// the Unconfined seccomp profile (no syscall filtering). This is the Pod
// Security Standards "baseline" seccomp check.
func specUsesUnconfinedSeccomp(spec *corev1.PodSpec) bool {
	for _, c := range allWorkloadContainers(spec) {
		if effectiveSeccompType(spec, c) == corev1.SeccompProfileTypeUnconfined {
			return true
		}
	}
	return false
}

// specHasSeccompProfile reports whether every container has an effective seccomp
// profile explicitly set to a confining value (RuntimeDefault or Localhost).
// An unset or Unconfined profile on any container makes this false. This is the
// stricter Pod Security Standards "restricted" seccomp check.
func specHasSeccompProfile(spec *corev1.PodSpec) bool {
	containers := allWorkloadContainers(spec)
	if len(containers) == 0 {
		return false
	}
	for _, c := range containers {
		switch effectiveSeccompType(spec, c) {
		case corev1.SeccompProfileTypeRuntimeDefault, corev1.SeccompProfileTypeLocalhost:
			// confined
		default:
			return false
		}
	}
	return true
}

// boolFromSpec and friends adapt the spec-level helpers to the (value, error)
// shape the generated resource accessors expect.
func boolFromSpec(spec *corev1.PodSpec, err error, fn func(*corev1.PodSpec) bool) (bool, error) {
	if err != nil {
		return false, err
	}
	return fn(spec), nil
}

func stringsFromSpec(spec *corev1.PodSpec, err error, fn func(*corev1.PodSpec) []any) ([]any, error) {
	if err != nil {
		return nil, err
	}
	return fn(spec), nil
}

func dictFromSpec(spec *corev1.PodSpec, err error) (map[string]any, error) {
	if err != nil {
		return nil, err
	}
	if spec == nil {
		return nil, nil
	}
	return convert.JsonToDict(spec.SecurityContext)
}

// specHostUsers reports whether the pod shares the host user namespace.
// Kubernetes leaves hostUsers unset by default and treats unset as true, so an
// absent field reports true: the workload never asked for a user namespace, so
// root inside its containers is root on the node. A spec we could not read
// reports the same, which is the direction that fails safe.
func specHostUsers(spec *corev1.PodSpec) bool {
	if spec == nil || spec.HostUsers == nil {
		return true
	}
	return *spec.HostUsers
}

// volumesFromSpec builds the k8s.volume list for a workload. id scopes the
// volume cache keys to the owning object, since volume names are only unique
// within one pod spec.
func volumesFromSpec(runtime *plugin.Runtime, id, namespace string, spec *corev1.PodSpec, err error) ([]any, error) {
	if err != nil {
		return nil, err
	}
	return newVolumes(runtime, id, namespace, spec)
}

// ---- k8s.pod ----

func (k *mqlK8sPod) runsPrivileged() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sPod) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sPod) runsAsRoot() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sPod) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sPod) dropsAllCapabilities() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sPod) addedCapabilities() ([]any, error) {
	spec, err := k.podSpecTyped()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sPod) usesHostNamespaces() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sPod) usesHostPath() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sPod) hostUsers() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sPod) volumes() ([]any, error) {
	spec, err := k.podSpecTyped()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sPod) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sPod) hasSeccompProfile() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}

// ---- k8s.deployment ----

func (k *mqlK8sDeployment) securitySpec() (*corev1.PodSpec, error) {
	d, err := k.getDeployment()
	if err != nil {
		return nil, err
	}
	return resources.GetPodSpec(d)
}

func (k *mqlK8sDeployment) automountServiceAccountToken() (bool, error) {
	spec, err := k.securitySpec()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sDeployment) hostNetwork() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostNetwork })
}

func (k *mqlK8sDeployment) hostPID() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostPID })
}

func (k *mqlK8sDeployment) hostIPC() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostIPC })
}

func (k *mqlK8sDeployment) securityContext() (map[string]any, error) {
	return dictFromSpec(k.securitySpec())
}

func (k *mqlK8sDeployment) runsPrivileged() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sDeployment) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sDeployment) runsAsRoot() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sDeployment) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sDeployment) dropsAllCapabilities() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sDeployment) addedCapabilities() ([]any, error) {
	spec, err := k.securitySpec()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sDeployment) usesHostNamespaces() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sDeployment) usesHostPath() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sDeployment) hostUsers() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sDeployment) volumes() ([]any, error) {
	spec, err := k.securitySpec()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sDeployment) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sDeployment) hasSeccompProfile() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}

// ---- k8s.daemonset ----

func (k *mqlK8sDaemonset) securitySpec() (*corev1.PodSpec, error) {
	d, err := k.getDaemonSet()
	if err != nil {
		return nil, err
	}
	return resources.GetPodSpec(d)
}

func (k *mqlK8sDaemonset) automountServiceAccountToken() (bool, error) {
	spec, err := k.securitySpec()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sDaemonset) hostNetwork() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostNetwork })
}

func (k *mqlK8sDaemonset) hostPID() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostPID })
}

func (k *mqlK8sDaemonset) hostIPC() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostIPC })
}

func (k *mqlK8sDaemonset) securityContext() (map[string]any, error) {
	return dictFromSpec(k.securitySpec())
}

func (k *mqlK8sDaemonset) runsPrivileged() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sDaemonset) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sDaemonset) runsAsRoot() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sDaemonset) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sDaemonset) dropsAllCapabilities() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sDaemonset) addedCapabilities() ([]any, error) {
	spec, err := k.securitySpec()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sDaemonset) usesHostNamespaces() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sDaemonset) usesHostPath() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sDaemonset) hostUsers() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sDaemonset) volumes() ([]any, error) {
	spec, err := k.securitySpec()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sDaemonset) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sDaemonset) hasSeccompProfile() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}

// ---- k8s.statefulset ----

func (k *mqlK8sStatefulset) securitySpec() (*corev1.PodSpec, error) {
	s, err := k.getStatefulSet()
	if err != nil {
		return nil, err
	}
	return resources.GetPodSpec(s)
}

func (k *mqlK8sStatefulset) automountServiceAccountToken() (bool, error) {
	spec, err := k.securitySpec()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sStatefulset) hostNetwork() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostNetwork })
}

func (k *mqlK8sStatefulset) hostPID() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostPID })
}

func (k *mqlK8sStatefulset) hostIPC() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostIPC })
}

func (k *mqlK8sStatefulset) securityContext() (map[string]any, error) {
	return dictFromSpec(k.securitySpec())
}

func (k *mqlK8sStatefulset) runsPrivileged() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sStatefulset) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sStatefulset) runsAsRoot() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sStatefulset) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sStatefulset) dropsAllCapabilities() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sStatefulset) addedCapabilities() ([]any, error) {
	spec, err := k.securitySpec()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sStatefulset) usesHostNamespaces() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sStatefulset) usesHostPath() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sStatefulset) hostUsers() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sStatefulset) volumes() ([]any, error) {
	spec, err := k.securitySpec()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sStatefulset) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sStatefulset) hasSeccompProfile() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}

// ---- k8s.replicaset ----

func (k *mqlK8sReplicaset) securitySpec() (*corev1.PodSpec, error) {
	r, err := k.getReplicaSet()
	if err != nil {
		return nil, err
	}
	return resources.GetPodSpec(r)
}

func (k *mqlK8sReplicaset) automountServiceAccountToken() (bool, error) {
	spec, err := k.securitySpec()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sReplicaset) hostNetwork() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostNetwork })
}

func (k *mqlK8sReplicaset) hostPID() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostPID })
}

func (k *mqlK8sReplicaset) hostIPC() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostIPC })
}

func (k *mqlK8sReplicaset) securityContext() (map[string]any, error) {
	return dictFromSpec(k.securitySpec())
}

func (k *mqlK8sReplicaset) runsPrivileged() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sReplicaset) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sReplicaset) runsAsRoot() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sReplicaset) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sReplicaset) dropsAllCapabilities() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sReplicaset) addedCapabilities() ([]any, error) {
	spec, err := k.securitySpec()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sReplicaset) usesHostNamespaces() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sReplicaset) usesHostPath() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sReplicaset) hostUsers() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sReplicaset) volumes() ([]any, error) {
	spec, err := k.securitySpec()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sReplicaset) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sReplicaset) hasSeccompProfile() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}

// ---- k8s.job ----

func (k *mqlK8sJob) securitySpec() (*corev1.PodSpec, error) {
	j, err := k.getJob()
	if err != nil {
		return nil, err
	}
	return resources.GetPodSpec(j)
}

func (k *mqlK8sJob) automountServiceAccountToken() (bool, error) {
	spec, err := k.securitySpec()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sJob) hostNetwork() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostNetwork })
}

func (k *mqlK8sJob) hostPID() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostPID })
}

func (k *mqlK8sJob) hostIPC() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostIPC })
}

func (k *mqlK8sJob) securityContext() (map[string]any, error) {
	return dictFromSpec(k.securitySpec())
}

func (k *mqlK8sJob) runsPrivileged() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sJob) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sJob) runsAsRoot() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sJob) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sJob) dropsAllCapabilities() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sJob) addedCapabilities() ([]any, error) {
	spec, err := k.securitySpec()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sJob) usesHostNamespaces() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sJob) usesHostPath() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sJob) hostUsers() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sJob) volumes() ([]any, error) {
	spec, err := k.securitySpec()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sJob) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sJob) hasSeccompProfile() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}

// ---- k8s.cronjob ----

func (k *mqlK8sCronjob) securitySpec() (*corev1.PodSpec, error) {
	c, err := k.getCronJob()
	if err != nil {
		return nil, err
	}
	return resources.GetPodSpec(c)
}

func (k *mqlK8sCronjob) automountServiceAccountToken() (bool, error) {
	spec, err := k.securitySpec()
	if err != nil {
		return false, err
	}
	return effectiveAutomountServiceAccountToken(k.MqlRuntime, spec, k.Namespace.Data), nil
}

func (k *mqlK8sCronjob) hostNetwork() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostNetwork })
}

func (k *mqlK8sCronjob) hostPID() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostPID })
}

func (k *mqlK8sCronjob) hostIPC() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, func(s *corev1.PodSpec) bool { return s != nil && s.HostIPC })
}

func (k *mqlK8sCronjob) securityContext() (map[string]any, error) {
	return dictFromSpec(k.securitySpec())
}

func (k *mqlK8sCronjob) runsPrivileged() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsPrivileged)
}

func (k *mqlK8sCronjob) allowsPrivilegeEscalation() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specAllowsPrivilegeEscalation)
}

func (k *mqlK8sCronjob) runsAsRoot() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specRunsAsRoot)
}

func (k *mqlK8sCronjob) hasWritableRootFilesystem() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasWritableRootFilesystem)
}

func (k *mqlK8sCronjob) dropsAllCapabilities() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specDropsAllCapabilities)
}

func (k *mqlK8sCronjob) addedCapabilities() ([]any, error) {
	spec, err := k.securitySpec()
	return stringsFromSpec(spec, err, specAddedCapabilities)
}

func (k *mqlK8sCronjob) usesHostNamespaces() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostNamespaces)
}

func (k *mqlK8sCronjob) usesHostPath() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesHostPath)
}

func (k *mqlK8sCronjob) hostUsers() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHostUsers)
}

func (k *mqlK8sCronjob) volumes() ([]any, error) {
	spec, err := k.securitySpec()
	return volumesFromSpec(k.MqlRuntime, k.Id.Data, k.Namespace.Data, spec, err)
}

func (k *mqlK8sCronjob) usesUnconfinedSeccomp() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specUsesUnconfinedSeccomp)
}

func (k *mqlK8sCronjob) hasSeccompProfile() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specHasSeccompProfile)
}
