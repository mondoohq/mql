// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// This file computes a workload's Pod Security Standards (PSS) level — the
// upstream Kubernetes security benchmark that replaced PodSecurityPolicy. Each
// workload kind exposes:
//
//   - podSecurityStandard()       the highest level the pod template satisfies,
//                                 one of "restricted", "baseline", "privileged"
//   - meetsPodSecurityBaseline()  whether it satisfies the baseline profile
//   - meetsPodSecurityRestricted() whether it satisfies the restricted profile
//
// The controls are evaluated against the typed PodSpec and reuse the rollup
// helpers in workload_security.go. Coverage follows the PSS control list at
// https://kubernetes.io/docs/concepts/security/pod-security-standards/ with two
// documented simplifications: AppArmor and seccomp are read from the typed
// securityContext fields only (the deprecated alpha annotations are not parsed),
// and Linux-only controls treat the absence of a field as "not set" rather than
// inferring node defaults. A pod template with no containers cannot satisfy the
// restricted "must explicitly set" controls, so it resolves to "baseline".

import (
	corev1 "k8s.io/api/core/v1"
)

// baselineAllowedCapabilities is the set of Linux capabilities a baseline pod
// may add beyond the runtime default. Adding anything outside this set (or the
// ALL meta-capability) violates baseline.
var baselineAllowedCapabilities = map[string]struct{}{
	"AUDIT_WRITE": {}, "CHOWN": {}, "DAC_OVERRIDE": {}, "FOWNER": {},
	"FSETID": {}, "KILL": {}, "MKNOD": {}, "NET_BIND_SERVICE": {},
	"SETFCAP": {}, "SETGID": {}, "SETPCAP": {}, "SETUID": {}, "SYS_CHROOT": {},
}

// allowedSELinuxTypes are the SELinux types permitted by baseline; an empty
// type is also allowed. User and role must always be empty.
var allowedSELinuxTypes = map[string]struct{}{
	"container_t": {}, "container_init_t": {}, "container_kvm_t": {},
}

// safeSysctls is the kubelet's safe sysctl set; baseline forbids any sysctl
// outside it. It mirrors the Pod Security Standards "Sysctls" allowed values,
// which gained the TCP keepalive and fin_timeout entries in Kubernetes 1.29 and
// net.ipv4.tcp_rmem / net.ipv4.tcp_wmem in 1.32. Tuning TCP keepalives is
// routine for long-lived connections, so a stale list here reports ordinary
// workloads as baseline violations.
var safeSysctls = map[string]struct{}{
	"kernel.shm_rmid_forced":              {},
	"net.ipv4.ip_local_port_range":        {},
	"net.ipv4.ip_unprivileged_port_start": {},
	"net.ipv4.tcp_syncookies":             {},
	"net.ipv4.ping_group_range":           {},
	"net.ipv4.ip_local_reserved_ports":    {},
	"net.ipv4.tcp_keepalive_time":         {},
	"net.ipv4.tcp_fin_timeout":            {},
	"net.ipv4.tcp_keepalive_intvl":        {},
	"net.ipv4.tcp_keepalive_probes":       {},
	"net.ipv4.tcp_rmem":                   {},
	"net.ipv4.tcp_wmem":                   {},
}

// ---- baseline controls ----

func specBaselineHostPorts(spec *corev1.PodSpec) bool {
	for _, c := range allWorkloadContainers(spec) {
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				return false
			}
		}
	}
	return true
}

func specBaselineCapabilities(spec *corev1.PodSpec) bool {
	for _, name := range specAddedCapabilities(spec) {
		if _, ok := baselineAllowedCapabilities[name.(string)]; !ok {
			return false
		}
	}
	return true
}

func seLinuxAllowed(o *corev1.SELinuxOptions) bool {
	if o == nil {
		return true
	}
	if o.User != "" || o.Role != "" {
		return false
	}
	if o.Type == "" {
		return true
	}
	_, ok := allowedSELinuxTypes[o.Type]
	return ok
}

func specBaselineSELinux(spec *corev1.PodSpec) bool {
	if spec == nil {
		return true
	}
	if spec.SecurityContext != nil && !seLinuxAllowed(spec.SecurityContext.SELinuxOptions) {
		return false
	}
	for _, c := range allWorkloadContainers(spec) {
		if c.SecurityContext != nil && !seLinuxAllowed(c.SecurityContext.SELinuxOptions) {
			return false
		}
	}
	return true
}

func specBaselineProcMount(spec *corev1.PodSpec) bool {
	for _, c := range allWorkloadContainers(spec) {
		if c.SecurityContext != nil && c.SecurityContext.ProcMount != nil &&
			*c.SecurityContext.ProcMount != corev1.DefaultProcMount {
			return false
		}
	}
	return true
}

func appArmorAllowed(p *corev1.AppArmorProfile) bool {
	return p == nil || p.Type != corev1.AppArmorProfileTypeUnconfined
}

func specBaselineAppArmor(spec *corev1.PodSpec) bool {
	if spec == nil {
		return true
	}
	if spec.SecurityContext != nil && !appArmorAllowed(spec.SecurityContext.AppArmorProfile) {
		return false
	}
	for _, c := range allWorkloadContainers(spec) {
		if c.SecurityContext != nil && !appArmorAllowed(c.SecurityContext.AppArmorProfile) {
			return false
		}
	}
	return true
}

func specBaselineSysctls(spec *corev1.PodSpec) bool {
	if spec == nil || spec.SecurityContext == nil {
		return true
	}
	for _, s := range spec.SecurityContext.Sysctls {
		if _, ok := safeSysctls[s.Name]; !ok {
			return false
		}
	}
	return true
}

func specBaselineHostProcess(spec *corev1.PodSpec) bool {
	hostProcess := func(w *corev1.WindowsSecurityContextOptions) bool {
		return w != nil && w.HostProcess != nil && *w.HostProcess
	}
	if spec == nil {
		return true
	}
	if spec.SecurityContext != nil && hostProcess(spec.SecurityContext.WindowsOptions) {
		return false
	}
	for _, c := range allWorkloadContainers(spec) {
		if c.SecurityContext != nil && hostProcess(c.SecurityContext.WindowsOptions) {
			return false
		}
	}
	return true
}

func specMeetsPodSecurityBaseline(spec *corev1.PodSpec) bool {
	return !specRunsPrivileged(spec) &&
		!specUsesHostNamespaces(spec) &&
		// HostPath Volumes is a *baseline* control upstream, not restricted-only.
		// Omitting it here reported a node-agent DaemonSet as baseline-compliant
		// while PodSecurity enforcement refuses to admit it.
		!specUsesHostPath(spec) &&
		!specUsesUnconfinedSeccomp(spec) &&
		specBaselineHostPorts(spec) &&
		specBaselineCapabilities(spec) &&
		specBaselineSELinux(spec) &&
		specBaselineProcMount(spec) &&
		specBaselineAppArmor(spec) &&
		specBaselineSysctls(spec) &&
		specBaselineHostProcess(spec)
}

// ---- restricted controls (evaluated on top of baseline) ----

// restrictedAllowedVolume reports whether a volume uses one of the restricted
// profile's allowed source types. Exactly one source is set on a volume, so a
// match on any allowed source means the volume is permitted.
func restrictedAllowedVolume(v corev1.Volume) bool {
	s := v.VolumeSource
	return s.ConfigMap != nil || s.CSI != nil || s.DownwardAPI != nil ||
		s.EmptyDir != nil || s.Ephemeral != nil || s.PersistentVolumeClaim != nil ||
		s.Projected != nil || s.Secret != nil
}

func specRestrictedVolumeTypes(spec *corev1.PodSpec) bool {
	if spec == nil {
		return true
	}
	for i := range spec.Volumes {
		if !restrictedAllowedVolume(spec.Volumes[i]) {
			return false
		}
	}
	return true
}

// specRestrictedRunAsNonRoot reports whether every container is required to run
// as non-root: the effective runAsNonRoot (container value, else pod default)
// must be explicitly true.
func specRestrictedRunAsNonRoot(spec *corev1.PodSpec) bool {
	containers := allWorkloadContainers(spec)
	if len(containers) == 0 {
		return false
	}
	var podNonRoot *bool
	if spec != nil && spec.SecurityContext != nil {
		podNonRoot = spec.SecurityContext.RunAsNonRoot
	}
	for _, c := range containers {
		nonRoot := podNonRoot
		if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
			nonRoot = c.SecurityContext.RunAsNonRoot
		}
		if nonRoot == nil || !*nonRoot {
			return false
		}
	}
	return true
}

// specRestrictedRunAsUser reports whether no container is pinned to UID 0; the
// effective runAsUser (container value, else pod default) must not be 0.
func specRestrictedRunAsUser(spec *corev1.PodSpec) bool {
	var podUser *int64
	if spec != nil && spec.SecurityContext != nil {
		podUser = spec.SecurityContext.RunAsUser
	}
	for _, c := range allWorkloadContainers(spec) {
		user := podUser
		if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
			user = c.SecurityContext.RunAsUser
		}
		if user != nil && *user == 0 {
			return false
		}
	}
	return true
}

// specRestrictedCapabilities reports whether every container drops ALL and adds
// nothing beyond NET_BIND_SERVICE.
func specRestrictedCapabilities(spec *corev1.PodSpec) bool {
	if !specDropsAllCapabilities(spec) {
		return false
	}
	for _, name := range specAddedCapabilities(spec) {
		if name.(string) != "NET_BIND_SERVICE" {
			return false
		}
	}
	return true
}

func specMeetsPodSecurityRestricted(spec *corev1.PodSpec) bool {
	return specMeetsPodSecurityBaseline(spec) &&
		specHasSeccompProfile(spec) &&
		specRestrictedVolumeTypes(spec) &&
		!specAllowsPrivilegeEscalation(spec) &&
		specRestrictedRunAsNonRoot(spec) &&
		specRestrictedRunAsUser(spec) &&
		specRestrictedCapabilities(spec)
}

// specPodSecurityStandard returns the highest (most restrictive) Pod Security
// Standards level the pod template satisfies.
func specPodSecurityStandard(spec *corev1.PodSpec) string {
	switch {
	case specMeetsPodSecurityRestricted(spec):
		return "restricted"
	case specMeetsPodSecurityBaseline(spec):
		return "baseline"
	default:
		return "privileged"
	}
}

// stringFromSpec adapts a string-returning spec helper to the (value, error)
// shape the generated resource accessors expect.
func stringFromSpec(spec *corev1.PodSpec, err error, fn func(*corev1.PodSpec) string) (string, error) {
	if err != nil {
		return "", err
	}
	return fn(spec), nil
}

// ---- per-kind wiring ----

func (k *mqlK8sPod) podSecurityStandard() (string, error) {
	spec, err := k.podSpecTyped()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sPod) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sPod) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.podSpecTyped()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}

func (k *mqlK8sDeployment) podSecurityStandard() (string, error) {
	spec, err := k.securitySpec()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sDeployment) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sDeployment) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}

func (k *mqlK8sDaemonset) podSecurityStandard() (string, error) {
	spec, err := k.securitySpec()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sDaemonset) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sDaemonset) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}

func (k *mqlK8sStatefulset) podSecurityStandard() (string, error) {
	spec, err := k.securitySpec()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sStatefulset) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sStatefulset) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}

func (k *mqlK8sReplicaset) podSecurityStandard() (string, error) {
	spec, err := k.securitySpec()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sReplicaset) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sReplicaset) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}

func (k *mqlK8sJob) podSecurityStandard() (string, error) {
	spec, err := k.securitySpec()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sJob) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sJob) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}

func (k *mqlK8sCronjob) podSecurityStandard() (string, error) {
	spec, err := k.securitySpec()
	return stringFromSpec(spec, err, specPodSecurityStandard)
}

func (k *mqlK8sCronjob) meetsPodSecurityBaseline() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityBaseline)
}

func (k *mqlK8sCronjob) meetsPodSecurityRestricted() (bool, error) {
	spec, err := k.securitySpec()
	return boolFromSpec(spec, err, specMeetsPodSecurityRestricted)
}
