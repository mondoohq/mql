// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/processes"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
)

// TestCreateConfigurationMatchesConfigz checks the merged kubelet config
// against what the running kubelet itself reported. Each fixture under
// testdata/kubelet was captured from a live node: the kubelet's command line
// (argv.txt), its config file (config), and its /configz (configz.json),
// which is the configuration the kubelet actually runs with.
func TestCreateConfigurationMatchesConfigz(t *testing.T) {
	// The kubelet decides these itself at startup, from the host rather than
	// from its config or flags, so the config cannot say them.
	selfSignedServingCert := map[string]string{
		"tlsCertFile":       "generated in --cert-dir when no serving cert is configured",
		"tlsPrivateKeyFile": "generated in --cert-dir when no serving cert is configured",
	}
	for _, tc := range []struct {
		node    string
		host    kubeletHost
		minor   int
		derived map[string]string
	}{
		{"flatcar", kubeletStandalone, 37, selfSignedServingCert},  // Flatcar 4757.2.1 with kubeadm 1.37.1
		{"minikube", kubeletStandalone, 37, selfSignedServingCert}, // minikube 1.39 node, Kubernetes 1.37.0
		{"k0s", kubeletStandalone, 36, nil},                        // k0s 1.36.4
		{"nixos", kubeletStandalone, 36, nil},                      // NixOS 26.05 services.kubernetes, 1.36.3
		// Canonical Kubernetes 1.32.13, configured by flags alone. Its own
		// kubelet build picks the systemd-resolved file; upstream defaults to
		// /etc/resolv.conf and no flag sets it.
		{"canonical", kubeletStandalone, 32, map[string]string{"resolvConf": "chosen by Canonical's kubelet build"}},
		// K3s 1.36.5: the kubelet runs in k3s-server, configured by the
		// drop-in K3s writes (dropins/) and arguments K3s passes internally
		{"k3s", kubeletInK3s, 36, nil},
		// MicroK8s 1.35.6: the kubelet runs in kubelite, configured by
		// args/kubelet
		{"microk8s", kubeletInKubelite, 35, selfSignedServingCert},
	} {
		t.Run(tc.node, func(t *testing.T) {
			dir := filepath.Join("testdata", "kubelet", tc.node)
			argv, err := os.ReadFile(filepath.Join(dir, "argv.txt"))
			require.NoError(t, err)
			configFile, err := os.ReadFile(filepath.Join(dir, "config"))
			if errors.Is(err, fs.ErrNotExist) {
				configFile = nil
			} else {
				require.NoError(t, err)
			}
			configzRaw, err := os.ReadFile(filepath.Join(dir, "configz.json"))
			require.NoError(t, err)

			command := strings.Join(strings.Fields(string(argv)), " ")
			var flags map[string]any
			switch tc.host {
			case kubeletInK3s:
				flags = k3sKubeletFlags(command, "")
				assert.Equal(t, "/var/lib/rancher/k3s/agent/etc/kubelet.conf.d", flags["config-dir"])
			case kubeletInKubelite:
				args, err := os.ReadFile(filepath.Join(dir, "args-kubelet"))
				require.NoError(t, err)
				flags = microk8sKubeletFlags(string(args), "/var/snap/microk8s/9072/args/kubelet")
			default:
				flagSet := processes.FlagSet{}
				require.NoError(t, flagSet.ParseCommand(command))
				flags = map[string]any{}
				for k, v := range flagSet.Map() {
					flags[k] = v
				}
			}

			var dropIns []string
			if entries, err := os.ReadDir(filepath.Join(dir, "dropins")); err == nil {
				names := []string{}
				for _, e := range entries {
					names = append(names, e.Name())
				}
				for _, name := range kubeletDropInFiles(names) {
					b, err := os.ReadFile(filepath.Join(dir, "dropins", name))
					require.NoError(t, err)
					dropIns = append(dropIns, string(b))
				}
			}

			config, err := createConfiguration(flags, string(configFile), dropIns, tc.minor)
			require.NoError(t, err)

			var configz map[string]any
			require.NoError(t, json.Unmarshal(configzRaw, &configz))
			// compare through JSON so numbers and nested maps have one form
			got := map[string]any{}
			b, err := json.Marshal(config)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(b, &got))

			for key, want := range configz {
				if key == "kind" || key == "apiVersion" {
					continue
				}
				if _, ok := tc.derived[key]; ok {
					continue
				}
				have, ok := got[key]
				if !ok {
					// The config map leaves out fields at their zero value,
					// which configz lists (enableSystemLogQuery: false).
					assert.True(t, isZeroJSON(want), "%s: missing, kubelet runs with %v", key, want)
					continue
				}
				assert.Equal(t, want, have, key)
			}
		})
	}
}

// isZeroJSON reports whether a decoded JSON value is its type's zero value.
func isZeroJSON(v any) bool {
	return v == nil || reflect.ValueOf(v).IsZero() ||
		(reflect.ValueOf(v).Kind() == reflect.Map || reflect.ValueOf(v).Kind() == reflect.Slice) && reflect.ValueOf(v).Len() == 0
}

func TestKubeletMinorVersion(t *testing.T) {
	assert.Equal(t, 36, kubeletMinorVersion("v1.36.4+k0s"))
	assert.Equal(t, 37, kubeletMinorVersion("v1.37.0"))
	assert.Equal(t, 35, kubeletMinorVersion("v1.35.7+rke2r1"))
	assert.Equal(t, 32, kubeletMinorVersion("v1.32.13"))
	assert.Equal(t, 0, kubeletMinorVersion(""))
	assert.Equal(t, 0, kubeletMinorVersion("v2.0.0"))
	assert.Equal(t, 0, kubeletMinorVersion("unknown"))
}

// mergeDeprecatedFlagsIntoConfig used to read the wrong map key for
// "manifest-url-header" (a literal tab), which both dropped the value and
// panicked on the type assertion when the flag was actually set.
func TestMergeDeprecatedFlags_ManifestURLHeader(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"manifest-url-header": "X-Example:value,Authorization:Bearer token",
	}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(config, flags)
		require.NoError(t, err)
	})

	header, ok := config["staticPodURLHeader"].(map[string]any)
	require.True(t, ok, "expected staticPodURLHeader to be set")
	assert.Equal(t, "value", header["X-Example"])
	assert.Equal(t, "Bearer token", header["Authorization"])
}

// A header value without a colon must be skipped instead of panicking on the
// missing split element.
func TestMergeDeprecatedFlags_ManifestURLHeaderMalformed(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"manifest-url-header": "no-colon-here",
	}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(config, flags)
		require.NoError(t, err)
	})

	header, ok := config["staticPodURLHeader"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, header)
}

// The anonymous-auth flag must land in the config even when the config has no
// pre-existing authentication block (the previous code built the nested maps
// but never linked them back, silently dropping the flag).
func TestMergeDeprecatedFlags_AnonymousAuthFromEmptyConfig(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"anonymous-auth": "false",
	}

	err := mergeDeprecatedFlagsIntoConfig(config, flags)
	require.NoError(t, err)

	auth, ok := config["authentication"].(map[string]any)
	require.True(t, ok, "expected authentication block to be created")
	anon, ok := auth["anonymous"].(map[string]any)
	require.True(t, ok, "expected anonymous block to be created")
	assert.Equal(t, "false", anon["enabled"])
}

// The authentication-token-webhook flag must likewise survive when no
// authentication block exists yet.
func TestMergeDeprecatedFlags_AuthTokenWebhookFromEmptyConfig(t *testing.T) {
	config := map[string]any{}
	flags := map[string]any{
		"authentication-token-webhook": "true",
	}

	err := mergeDeprecatedFlagsIntoConfig(config, flags)
	require.NoError(t, err)

	auth, ok := config["authentication"].(map[string]any)
	require.True(t, ok, "expected authentication block to be created")
	webhook, ok := auth["webhook"].(map[string]any)
	require.True(t, ok, "expected webhook block to be created")
	assert.Equal(t, "true", webhook["enabled"])
}

func TestParseKubeletVersion(t *testing.T) {
	assert.Equal(t, "v1.34.0", parseKubeletVersion("Kubernetes v1.34.0\n"))
	assert.Equal(t, "v1.28.3", parseKubeletVersion("  Kubernetes v1.28.3  "))
	// tolerate output that omits the "Kubernetes" prefix
	assert.Equal(t, "v1.30.1", parseKubeletVersion("v1.30.1"))
	assert.Equal(t, "", parseKubeletVersion(""))
}

func TestResolveKubeletExecutable(t *testing.T) {
	// links maps a path to the file it resolves to; a path not in it resolves
	// to itself
	// rootExe is what a trusted process snapshot returned, "" for an untrusted one
	probe := func(rootExe, argv0 string, links map[string]string, trusted ...string) kubeletBinaryProbe {
		return kubeletBinaryProbe{
			rootExe: func() string { return rootExe },
			argv0:   func() string { return argv0 },
			resolve: func(p string) string {
				if target, ok := links[p]; ok {
					return target
				}
				return p
			},
			trustedBinary: func(p string) bool {
				for _, have := range trusted {
					if p == have {
						return true
					}
				}
				return false
			},
		}
	}

	// the command lines and /proc/<pid>/exe links seen on live nodes
	k0s := "/var/lib/k0s/bin/kubelet"
	assert.Equal(t, k0s, resolveKubeletExecutable("kubelet", probe(k0s, k0s, nil)), "k0s")
	// minikube copies its binaries in as uid 1001: root runs that file anyway
	mk := "/var/lib/minikube/binaries/v1.37.0/kubelet"
	assert.Equal(t, mk, resolveKubeletExecutable("kubelet", probe(mk, mk, nil)), "minikube")
	nix := "/nix/store/b5gip1vkhws3gnhr0hmn1z83xzb1hjjv-kubernetes-1.36.3/bin/kubelet"
	assert.Equal(t, nix, resolveKubeletExecutable("kubelet", probe(nix, nix, nil)), "NixOS")
	// Canonical Kubernetes's kubelet is a link to a multi-call binary that
	// acts as kubelet only under that name
	assert.Equal(t, "/snap/k8s/5562/bin/kubelet", resolveKubeletExecutable("kubelet",
		probe("/snap/k8s/5562/bin/kubernetes", "/snap/k8s/5562/bin/kubelet",
			map[string]string{"/snap/k8s/5562/bin/kubelet": "/snap/k8s/5562/bin/kubernetes"})), "Canonical Kubernetes")
	// RKE2 starts kubelet by bare name, so only the link names the binary
	rke2 := "/var/lib/rancher/rke2/data/v1.35.7-rke2r1-1234/bin/kubelet"
	assert.Equal(t, rke2, resolveKubeletExecutable("kubelet", probe(rke2, "kubelet", nil)), "RKE2")
	// no trusted snapshot (a non-root scan): RKE2's fixed path, root's alone
	assert.Equal(t, "/var/lib/rancher/rke2/bin/kubelet", resolveKubeletExecutable("kubelet",
		probe("", "kubelet", nil, "/var/lib/rancher/rke2/bin/kubelet")))
	// kubelet on PATH and nothing else known: the bare name runs as before
	assert.Equal(t, "kubelet", resolveKubeletExecutable("kubelet", probe("", "kubelet", nil)))
	assert.Equal(t, "/usr/bin/kubelet", resolveKubeletExecutable("/usr/bin/kubelet", probe("", "", nil)),
		"an absolute executable is kept")

	// an untrusted process (another user's, or in a container): its paths never run
	assert.Equal(t, "kubelet", resolveKubeletExecutable("kubelet", probe("", "/home/user/kubelet", nil)))
	// root's kubelet whose argv[0] names some other file than the one it runs
	assert.Equal(t, "/usr/bin/kubelet", resolveKubeletExecutable("kubelet", probe("/usr/bin/kubelet", "/tmp/kubelet", nil)))
	// argv[0] that cannot be resolved
	assert.Equal(t, "/usr/bin/kubelet", resolveKubeletExecutable("kubelet",
		probe("/usr/bin/kubelet", "/opt/gone/kubelet", map[string]string{"/opt/gone/kubelet": ""})))
}

func TestParseKubeletProcSnapshot(t *testing.T) {
	snapshot := func(uid1, exe, mountNS, initMountNS, uid2 string) string {
		return "Uid:\t" + uid1 + "\t" + uid1 + "\t" + uid1 + "\t" + uid1 + "\n" + exe + "\n" +
			mountNS + "\n" + initMountNS + "\n" + "Uid:\t" + uid2 + "\t" + uid2 + "\t" + uid2 + "\t" + uid2 + "\n"
	}

	// captured with kubeletProcSnapshotCommand on live nodes
	assert.Equal(t, "/var/lib/k0s/bin/kubelet",
		parseKubeletProcSnapshot(snapshot("0", "/var/lib/k0s/bin/kubelet", "mnt:[4026531832]", "mnt:[4026531832]", "0")), "k0s")
	assert.Equal(t, "/snap/k8s/5562/bin/kubernetes",
		parseKubeletProcSnapshot(snapshot("0", "/snap/k8s/5562/bin/kubernetes", "mnt:[4026531832]", "mnt:[4026531832]", "0")),
		"Canonical Kubernetes, a classic snap, shares init's mount namespace")
	assert.Equal(t, "/var/lib/minikube/binaries/v1.37.0/kubelet",
		parseKubeletProcSnapshot(snapshot("0", "/var/lib/minikube/binaries/v1.37.0/kubelet", "mnt:[4026532241]", "mnt:[4026532241]", "0")),
		"minikube, scanned inside its node container")
	assert.Equal(t, "",
		parseKubeletProcSnapshot(snapshot("0", "/var/lib/minikube/binaries/v1.37.0/kubelet", "mnt:[4026532241]", "mnt:[4026531832]", "0")),
		"minikube's kubelet seen from its host: a container's path names another file on the host")

	assert.Equal(t, "", parseKubeletProcSnapshot(snapshot("1000", "/home/user/kubelet", "mnt:[4026531832]", "mnt:[4026531832]", "1000")),
		"another user's process")
	assert.Equal(t, "", parseKubeletProcSnapshot(snapshot("0", "/tmp/kubelet", "mnt:[4026531832]", "mnt:[4026531832]", "1000")),
		"the pid was taken over by a user's process between the reads")
	assert.Equal(t, "", parseKubeletProcSnapshot(snapshot("0", "/usr/bin/kubelet (deleted)", "mnt:[4026531832]", "mnt:[4026531832]", "0")),
		"the binary was replaced on disk since it started")
	assert.Equal(t, "", parseKubeletProcSnapshot("Uid:\t0\t0\t0\t0\n"), "a read failed")
	assert.Equal(t, "", parseKubeletProcSnapshot(""))
}

func TestParseProcStatusRealUID(t *testing.T) {
	// /proc/<pid>/status of the kubelet on a k0s node
	uid, ok := parseProcStatusRealUID("Name:\tkubelet\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
	assert.True(t, ok)
	assert.Equal(t, int64(0), uid)
	// a setuid-root binary started by a user: the real uid is the user's
	uid, ok = parseProcStatusRealUID("Name:\tkubelet\nUid:\t1000\t0\t0\t0\n")
	assert.True(t, ok)
	assert.Equal(t, int64(1000), uid)
	_, ok = parseProcStatusRealUID("Name:\tkubelet\n")
	assert.False(t, ok)
}

func TestParseStatOwnerMode(t *testing.T) {
	// stat -L -c '%u %a' on /var/lib/k0s/bin/kubelet (0750)
	uid, mode, ok := parseStatOwnerMode("0 750\n")
	assert.True(t, ok)
	assert.Equal(t, int64(0), uid)
	assert.Equal(t, uint32(0o750), mode)
	assert.True(t, isRootOnlyWritable(uid, mode))

	assert.False(t, isRootOnlyWritable(0, 0o775), "group-writable")
	assert.False(t, isRootOnlyWritable(0, 0o757), "world-writable")
	assert.False(t, isRootOnlyWritable(1000, 0o755), "owned by a user")
	assert.True(t, isRootOnlyWritable(0, 0o555), "the read-only /nix/store")

	_, _, ok = parseStatOwnerMode("stat: cannot statx '/x': No such file or directory")
	assert.False(t, ok)
}

func TestKubeletValueCoercion(t *testing.T) {
	// flags arrive as strings, config/defaults as native types
	assert.True(t, kubeletBool(true))
	assert.True(t, kubeletBool("true"))
	assert.False(t, kubeletBool("false"))
	assert.False(t, kubeletBool(nil))

	assert.Equal(t, int64(0), kubeletInt("0"))
	assert.Equal(t, int64(50), kubeletInt(50.0))
	assert.Equal(t, int64(10255), kubeletInt(int64(10255)))
	assert.Equal(t, int64(0), kubeletInt(nil))

	assert.Equal(t, "Webhook", kubeletString("Webhook"))
	assert.Equal(t, "", kubeletString(nil))
}

// createConfiguration applies the kubelet defaults. These assertions lock in
// the values from the release-1.34 defaults (the oldest supported Kubernetes
// release) so an accidental regression in kubelet_defaults.go is caught.
func TestCreateConfiguration_Defaults_1_34(t *testing.T) {
	// a kubelet started with --config whose file sets nothing
	config, err := createConfiguration(map[string]any{"config": "/var/lib/kubelet/config.yaml"}, "", nil, 0)
	require.NoError(t, err)

	// values bumped in newer releases (were 5 / 10 in 1.25)
	assert.Equal(t, 50.0, config["eventRecordQPS"])
	assert.Equal(t, 100.0, config["eventBurst"])
	assert.Equal(t, 50.0, config["kubeAPIQPS"])
	assert.Equal(t, 100.0, config["kubeAPIBurst"])
	assert.Equal(t, 0.9, config["memoryThrottlingFactor"])

	// fields introduced after 1.25
	assert.Equal(t, "/var/log/pods", config["podLogsDir"])
	assert.Equal(t, "unix:///run/containerd/containerd.sock", config["containerRuntimeEndpoint"])
	assert.Equal(t, false, config["failCgroupV1"])
	assert.Equal(t, false, config["mergeDefaultEvictionSettings"])
	assert.Equal(t, 1.0, config["containerLogMaxWorkers"])

	// security-relevant defaults that must remain stable
	assert.Equal(t, false, config["authentication"].(map[string]any)["anonymous"].(map[string]any)["enabled"])
	assert.Equal(t, "Webhook", config["authorization"].(map[string]any)["mode"])
}

// Feature-gated defaults must stay unset unless the operator explicitly
// enabled the gate, and must be applied when it is.
func TestSetDefaults_FeatureGatedDefaults(t *testing.T) {
	// an unknown version gets the 1.34 defaults: both gates off
	off := &kubeletconfigv1beta1.KubeletConfiguration{}
	SetDefaults_KubeletConfiguration(off, 0)
	assert.Empty(t, off.ImagePullCredentialsVerificationPolicy)
	assert.Nil(t, off.CrashLoopBackOff.MaxContainerRestartPeriod)

	// on when the operator enables them
	on := &kubeletconfigv1beta1.KubeletConfiguration{
		FeatureGates: map[string]bool{
			"KubeletEnsureSecretPulledImages": true,
			"KubeletCrashLoopBackOffMax":      true,
		},
	}
	SetDefaults_KubeletConfiguration(on, 0)
	assert.Equal(t, kubeletconfigv1beta1.NeverVerifyPreloadedImages, on.ImagePullCredentialsVerificationPolicy)
	assert.NotNil(t, on.CrashLoopBackOff.MaxContainerRestartPeriod)

	// on by default from 1.35
	v135 := &kubeletconfigv1beta1.KubeletConfiguration{}
	SetDefaults_KubeletConfiguration(v135, 35)
	assert.Equal(t, kubeletconfigv1beta1.NeverVerifyPreloadedImages, v135.ImagePullCredentialsVerificationPolicy)
	assert.NotNil(t, v135.CrashLoopBackOff.MaxContainerRestartPeriod)

	// and off again when the operator disables them
	disabled := &kubeletconfigv1beta1.KubeletConfiguration{
		FeatureGates: map[string]bool{
			"KubeletEnsureSecretPulledImages": false,
			"KubeletCrashLoopBackOffMax":      false,
		},
	}
	SetDefaults_KubeletConfiguration(disabled, 37)
	assert.Empty(t, disabled.ImagePullCredentialsVerificationPolicy)
	assert.Nil(t, disabled.CrashLoopBackOff.MaxContainerRestartPeriod)
}

// Defaults that changed after 1.34 follow the kubelet's version.
func TestSetDefaults_ByVersion(t *testing.T) {
	v134 := &kubeletconfigv1beta1.KubeletConfiguration{}
	SetDefaults_KubeletConfiguration(v134, 34)
	assert.False(t, *v134.FailCgroupV1)
	assert.Equal(t, 0.9, *v134.MemoryThrottlingFactor)
	assert.Empty(t, v134.MemoryReservationPolicy)

	v136 := &kubeletconfigv1beta1.KubeletConfiguration{}
	SetDefaults_KubeletConfiguration(v136, 36)
	assert.True(t, *v136.FailCgroupV1)
	assert.Equal(t, 0.9, *v136.MemoryThrottlingFactor)
	assert.Equal(t, kubeletconfigv1beta1.NoneMemoryReservationPolicy, v136.MemoryReservationPolicy)

	v137 := &kubeletconfigv1beta1.KubeletConfiguration{}
	SetDefaults_KubeletConfiguration(v137, 37)
	assert.True(t, *v137.FailCgroupV1)
	assert.Nil(t, v137.MemoryThrottlingFactor, "no longer defaulted in 1.37")

	// a value the file sets is kept
	set := &kubeletconfigv1beta1.KubeletConfiguration{FailCgroupV1: ptrBool(false)}
	SetDefaults_KubeletConfiguration(set, 37)
	assert.False(t, *set.FailCgroupV1)
}

func ptrBool(b bool) *bool { return &b }

// kubeadm writes explicit zero durations into config.yaml, which the kubelet
// replaces with its defaults.
func TestCreateConfiguration_ZeroValuesTakeDefaults(t *testing.T) {
	config, err := createConfiguration(map[string]any{}, "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nstreamingConnectionIdleTimeout: 0s\nsyncFrequency: 0s\n", nil, 37)
	require.NoError(t, err)
	assert.Equal(t, "4h0m0s", config["streamingConnectionIdleTimeout"])
	assert.Equal(t, "1m0s", config["syncFrequency"])

	// an evictionHard the file sets replaces the default map
	config, err = createConfiguration(map[string]any{}, "evictionHard:\n  nodefs.available: \"0%\"\n", nil, 37)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"nodefs.available": "0%"}, config["evictionHard"])
}

// When an authentication block already exists (e.g. from the applied defaults),
// the flag must update it in place without clobbering sibling settings.
func TestMergeDeprecatedFlags_AnonymousAuthMergesExisting(t *testing.T) {
	config := map[string]any{
		"authentication": map[string]any{
			"anonymous": map[string]any{"enabled": true},
			"webhook":   map[string]any{"enabled": true},
		},
	}
	flags := map[string]any{
		"anonymous-auth": false,
	}

	err := mergeDeprecatedFlagsIntoConfig(config, flags)
	require.NoError(t, err)

	auth := config["authentication"].(map[string]any)
	assert.Equal(t, false, auth["anonymous"].(map[string]any)["enabled"])
	// sibling webhook block must be preserved
	assert.Equal(t, true, auth["webhook"].(map[string]any)["enabled"])
}

// /var/lib/kubelet/config.yaml at 0600 (CIS) on a non-root scan: reading it
// as empty reported kubelet's defaults (readOnlyPort 0, Webhook).
func TestKubeletConfigContent(t *testing.T) {
	refused := &plugin.TValue[string]{Error: &fs.PathError{Op: "open", Path: "/var/lib/kubelet/config.yaml", Err: fs.ErrPermission}, State: plugin.StateIsSet | plugin.StateIsNull}

	t.Run("content", func(t *testing.T) {
		c, err := kubeletConfigContent(&plugin.TValue[string]{Data: "readOnlyPort: 10255\n", State: plugin.StateIsSet})
		require.NoError(t, err)
		assert.Equal(t, "readOnlyPort: 10255\n", c)
	})

	t.Run("no config file", func(t *testing.T) {
		c, err := kubeletConfigContent(&plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull})
		require.NoError(t, err)
		assert.Equal(t, "", c)
		c, err = kubeletConfigContent(nil)
		require.NoError(t, err)
		assert.Equal(t, "", c)
	})

	t.Run("refused before structured errors", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		_, err := kubeletConfigContent(refused)
		assert.NoError(t, err)
	})

	t.Run("refused with structured errors", func(t *testing.T) {
		enableStructuredErrorsForTest(t)
		_, err := kubeletConfigContent(refused)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		_, err = kubeletConfigContent(&plugin.TValue[string]{Error: fs.ErrNotExist, State: plugin.StateIsSet | plugin.StateIsNull})
		assert.NoError(t, err)
	})

	t.Run("an I/O error is not swallowed", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		_, err := kubeletConfigContent(&plugin.TValue[string]{Error: errors.New("read: input/output error"), State: plugin.StateIsSet | plugin.StateIsNull})
		assert.Error(t, err)
	})
}

// Without --config the kubelet starts from its legacy flag defaults, which
// drop-ins and flags then override.
func TestCreateConfiguration_LegacyFlagDefaults(t *testing.T) {
	config, err := createConfiguration(map[string]any{}, "", nil, 37)
	require.NoError(t, err)
	auth := config["authentication"].(map[string]any)
	assert.Equal(t, true, auth["anonymous"].(map[string]any)["enabled"])
	assert.Equal(t, false, auth["webhook"].(map[string]any)["enabled"])
	assert.Equal(t, "AlwaysAllow", config["authorization"].(map[string]any)["mode"])
	assert.Equal(t, 10255.0, config["readOnlyPort"])

	// MicroK8s's flags set three of the four, but not --authorization-mode
	config, err = createConfiguration(map[string]any{
		"anonymous-auth":               "false",
		"authentication-token-webhook": "true",
		"read-only-port":               "0",
	}, "", nil, 35)
	require.NoError(t, err)
	assert.Equal(t, false, config["authentication"].(map[string]any)["anonymous"].(map[string]any)["enabled"])
	assert.Equal(t, "AlwaysAllow", config["authorization"].(map[string]any)["mode"])
	assert.Equal(t, 0.0, config["readOnlyPort"])

	// a drop-in overrides the legacy defaults (K3s)
	config, err = createConfiguration(map[string]any{"config-dir": "/var/lib/rancher/k3s/agent/etc/kubelet.conf.d"}, "",
		[]string{"authorization:\n  mode: Webhook\nreadOnlyPort: 0\n"}, 36)
	require.NoError(t, err)
	assert.Equal(t, "Webhook", config["authorization"].(map[string]any)["mode"])
	assert.Equal(t, 0.0, config["readOnlyPort"])
}

func TestKubeletAdmissionSnapshotAllowed(t *testing.T) {
	snapshot := func(uid, exe, mountNS, initMountNS, cmdline string) string {
		return "Uid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\n" + exe + "\n" +
			mountNS + "\n" + initMountNS + "\n" + "Uid:\t" + uid + "\t" + uid + "\t" + uid + "\t" + uid + "\n" + cmdline + " \n"
	}
	kubelite := "/snap/microk8s/9072/kubelite --kubelet-args-file=/var/snap/microk8s/9072/args/kubelet --start-control-plane=true"

	// root's kubelite in init's mount namespace, as on a MicroK8s node
	assert.True(t, kubeletAdmissionSnapshotAllowed(
		snapshot("0", "/snap/microk8s/9072/kubelite", "mnt:[4026531832]", "mnt:[4026531832]", kubelite), kubelite))
	// a user's own kubelite, whose --kubelet-args-file would be read as root
	fake := "/tmp/kubelite -c sleep 120; true --kubelet-args-file=/etc/shadow"
	assert.False(t, kubeletAdmissionSnapshotAllowed(
		snapshot("1000", "/usr/bin/bash", "mnt:[4026531832]", "mnt:[4026531832]", fake), fake))
	// a container's kubelet seen from its host
	mk := "/var/lib/minikube/binaries/v1.37.0/kubelet --config=/var/lib/kubelet/config.yaml"
	assert.False(t, kubeletAdmissionSnapshotAllowed(
		snapshot("0", "/var/lib/minikube/binaries/v1.37.0/kubelet", "mnt:[4026532241]", "mnt:[4026531832]", mk), mk))
	// the pid now belongs to another root process than the one listed
	assert.False(t, kubeletAdmissionSnapshotAllowed(
		snapshot("0", "/usr/sbin/sshd", "mnt:[4026531832]", "mnt:[4026531832]", "sshd: /usr/sbin/sshd -D"), fake))
	// the process exited before the snapshot: nothing to read
	assert.False(t, kubeletAdmissionSnapshotAllowed("", kubelite))
	assert.False(t, kubeletAdmissionSnapshotAllowed("Uid:\t0\t0\t0\t0\n", kubelite))
}
