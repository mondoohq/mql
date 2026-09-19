// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	corev1 "k8s.io/api/core/v1"
)

// boolPtr is defined in provenance_test.go.
func int64Ptr(v int64) *int64 { return &v }

// restrictedSpec returns a pod spec that satisfies the restricted profile. Each
// control test mutates a copy of it to drop exactly one requirement.
func restrictedSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name: "app",
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: boolPtr(false),
				RunAsNonRoot:             boolPtr(true),
				RunAsUser:                int64Ptr(1000),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
		}},
	}
}

// container returns the single mutable container of a spec built by
// restrictedSpec, for terse per-control mutation.
func container(spec *corev1.PodSpec) *corev1.SecurityContext {
	return spec.Containers[0].SecurityContext
}

func TestPodSecurityStandard_Levels(t *testing.T) {
	t.Run("restricted base is restricted", func(t *testing.T) {
		spec := restrictedSpec()
		assert.True(t, specMeetsPodSecurityBaseline(spec), "baseline")
		assert.True(t, specMeetsPodSecurityRestricted(spec), "restricted")
		assert.Equal(t, "restricted", specPodSecurityStandard(spec))
	})

	t.Run("privileged container is privileged level", func(t *testing.T) {
		spec := restrictedSpec()
		container(spec).Privileged = boolPtr(true)
		assert.False(t, specMeetsPodSecurityBaseline(spec), "baseline")
		assert.Equal(t, "privileged", specPodSecurityStandard(spec))
	})

	t.Run("baseline-compliant but no seccomp is baseline level", func(t *testing.T) {
		spec := restrictedSpec()
		spec.SecurityContext.SeccompProfile = nil // unset: ok for baseline, fails restricted
		assert.True(t, specMeetsPodSecurityBaseline(spec), "baseline")
		assert.False(t, specMeetsPodSecurityRestricted(spec), "restricted")
		assert.Equal(t, "baseline", specPodSecurityStandard(spec))
	})

	t.Run("nil and empty specs resolve to baseline", func(t *testing.T) {
		assert.NotPanics(t, func() {
			assert.Equal(t, "baseline", specPodSecurityStandard(nil))
			assert.Equal(t, "baseline", specPodSecurityStandard(&corev1.PodSpec{}))
		})
	})
}

// TestPodSecurityBaseline_Controls checks that each baseline control, violated
// in isolation, drops the spec below baseline.
func TestPodSecurityBaseline_Controls(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*corev1.PodSpec)
	}{
		{"privileged", func(s *corev1.PodSpec) { container(s).Privileged = boolPtr(true) }},
		{"hostNetwork", func(s *corev1.PodSpec) { s.HostNetwork = true }},
		{"hostPort", func(s *corev1.PodSpec) {
			s.Containers[0].Ports = []corev1.ContainerPort{{HostPort: 8080}}
		}},
		{"disallowed capability", func(s *corev1.PodSpec) {
			container(s).Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		}},
		{"unconfined seccomp", func(s *corev1.PodSpec) {
			s.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeUnconfined
		}},
		{"unconfined apparmor", func(s *corev1.PodSpec) {
			container(s).AppArmorProfile = &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}
		}},
		{"selinux user set", func(s *corev1.PodSpec) {
			container(s).SELinuxOptions = &corev1.SELinuxOptions{User: "system_u"}
		}},
		{"selinux disallowed type", func(s *corev1.PodSpec) {
			container(s).SELinuxOptions = &corev1.SELinuxOptions{Type: "unconfined_t"}
		}},
		{"procMount unmasked", func(s *corev1.PodSpec) {
			pm := corev1.UnmaskedProcMount
			container(s).ProcMount = &pm
		}},
		{"unsafe sysctl", func(s *corev1.PodSpec) {
			s.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "kernel.msgmax", Value: "65536"}}
		}},
		{"hostPath volume", func(s *corev1.PodSpec) {
			s.Volumes = []corev1.Volume{{
				Name:         "host",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}},
			}}
		}},
		{"windows hostProcess", func(s *corev1.PodSpec) {
			container(s).WindowsOptions = &corev1.WindowsSecurityContextOptions{HostProcess: boolPtr(true)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := restrictedSpec()
			tc.mutate(spec)
			assert.False(t, specMeetsPodSecurityBaseline(spec), "must fail baseline")
			assert.Equal(t, "privileged", specPodSecurityStandard(spec))
		})
	}
}

// TestPodSecurityRestricted_Controls checks that each restricted-only control,
// violated in isolation, drops a baseline-compliant spec from restricted to
// baseline.
func TestPodSecurityRestricted_Controls(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*corev1.PodSpec)
	}{
		{"allowPrivilegeEscalation unset", func(s *corev1.PodSpec) {
			container(s).AllowPrivilegeEscalation = nil
		}},
		{"allowPrivilegeEscalation true", func(s *corev1.PodSpec) {
			container(s).AllowPrivilegeEscalation = boolPtr(true)
		}},
		{"runAsNonRoot unset", func(s *corev1.PodSpec) {
			s.SecurityContext.RunAsNonRoot = nil
			container(s).RunAsNonRoot = nil
		}},
		{"runAsUser 0", func(s *corev1.PodSpec) {
			container(s).RunAsUser = int64Ptr(0)
		}},
		{"missing seccomp profile", func(s *corev1.PodSpec) {
			s.SecurityContext.SeccompProfile = nil
		}},
		{"does not drop ALL", func(s *corev1.PodSpec) {
			container(s).Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}}
		}},
		{"adds baseline-allowed cap beyond NET_BIND_SERVICE", func(s *corev1.PodSpec) {
			// CHOWN is allowed by baseline but not by restricted's add list.
			container(s).Capabilities.Add = []corev1.Capability{"CHOWN"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := restrictedSpec()
			tc.mutate(spec)
			assert.True(t, specMeetsPodSecurityBaseline(spec), "still meets baseline")
			assert.False(t, specMeetsPodSecurityRestricted(spec), "must fail restricted")
			assert.Equal(t, "baseline", specPodSecurityStandard(spec))
		})
	}
}

// TestPodSecurityStandard_Wiring confirms each workload kind wires the computed
// level to its own accessor, using the shared fixtures: hardened is restricted,
// podlevelnonroot is baseline (no seccomp), and the privileged kinds are
// privileged.
func TestPodSecurityStandard_Wiring(t *testing.T) {
	k8s := workloadSecurityK8s(t)

	t.Run("deployment tiers", func(t *testing.T) {
		hardened := deploymentByName(t, k8s, "hardened")
		assert.Equal(t, "restricted", hardened.GetPodSecurityStandard().Data, "hardened")
		assert.True(t, hardened.GetMeetsPodSecurityRestricted().Data, "hardened restricted")

		baseline := deploymentByName(t, k8s, "podlevelnonroot")
		assert.Equal(t, "baseline", baseline.GetPodSecurityStandard().Data, "podlevelnonroot")
		assert.True(t, baseline.GetMeetsPodSecurityBaseline().Data, "podlevelnonroot baseline")
		assert.False(t, baseline.GetMeetsPodSecurityRestricted().Data, "podlevelnonroot restricted")

		risky := deploymentByName(t, k8s, "risky")
		assert.Equal(t, "privileged", risky.GetPodSecurityStandard().Data, "risky")
		assert.False(t, risky.GetMeetsPodSecurityBaseline().Data, "risky baseline")
	})

	t.Run("privileged kinds", func(t *testing.T) {
		cases := []struct {
			name string
			list *plugin.TValue[[]any]
		}{
			{"ds-privileged", k8s.GetDaemonsets()},
			{"ss-privileged", k8s.GetStatefulsets()},
			{"rs-privileged", k8s.GetReplicasets()},
			{"job-privileged", k8s.GetJobs()},
			{"cronjob-privileged", k8s.GetCronjobs()},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				require.NoError(t, tc.list.Error)
				r := findPSSReader(t, tc.list.Data, tc.name)
				assert.Equal(t, "privileged", r.GetPodSecurityStandard().Data)
				assert.False(t, r.GetMeetsPodSecurityBaseline().Data)
				assert.False(t, r.GetMeetsPodSecurityRestricted().Data)
			})
		}
	})
}

// pssReader is the PSS accessor surface shared by every workload kind.
type pssReader interface {
	GetName() *plugin.TValue[string]
	GetPodSecurityStandard() *plugin.TValue[string]
	GetMeetsPodSecurityBaseline() *plugin.TValue[bool]
	GetMeetsPodSecurityRestricted() *plugin.TValue[bool]
}

func findPSSReader(t *testing.T, list []any, name string) pssReader {
	t.Helper()
	for i := range list {
		r := list[i].(pssReader)
		if r.GetName().Data == name {
			return r
		}
	}
	require.FailNowf(t, "workload not found", "%q not found", name)
	return nil
}

// The Pod Security Standards "Sysctls" allowed-values list grows between
// Kubernetes releases, and a stale copy reports ordinary workloads as baseline
// violations. Each name below was accepted at baseline by a live 1.34
// apiserver, and pods setting them were admitted by the kubelet, which only
// allows its own safe set.
func TestPodSecurityBaselineAllowsCurrentSafeSysctls(t *testing.T) {
	for _, name := range []string{
		"net.ipv4.tcp_keepalive_time",  // added in 1.29
		"net.ipv4.tcp_fin_timeout",     // added in 1.29
		"net.ipv4.tcp_keepalive_intvl", // added in 1.29
		"net.ipv4.tcp_keepalive_probes",
		"net.ipv4.tcp_rmem", // added in 1.32
		"net.ipv4.tcp_wmem",
	} {
		t.Run(name, func(t *testing.T) {
			spec := restrictedSpec()
			spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: name, Value: "600"}}
			assert.True(t, specBaselineSysctls(spec), "%s is a safe sysctl", name)
			assert.True(t, specMeetsPodSecurityBaseline(spec),
				"%s must not drop the spec out of baseline", name)
		})
	}
}

// A sysctl outside the safe set must still fail, or the test above would pass
// on an implementation that simply allowed everything.
func TestPodSecurityBaselineRejectsUnsafeSysctl(t *testing.T) {
	spec := restrictedSpec()
	spec.SecurityContext.Sysctls = []corev1.Sysctl{{Name: "kernel.shmall", Value: "1"}}
	assert.False(t, specBaselineSysctls(spec))
	assert.Equal(t, "privileged", specPodSecurityStandard(spec))
}
