// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// Compiled once: applied to each eviction threshold flag.
var evictionRegex = regexp.MustCompile(`^(.+)[<>=]+([\d]+[A-Za-z%]*)$`)

// mergeFlagsIntoConfig adds flags to the kubelet config
// It does not take care of deprecated flags
// The flags are not just kubelet specific, but can also be global flags
// That also means, that some flags do not have a matching parameter in the kubelet config file and are added as is
// The list of flags is taken from
// /var/lib/minikube/binaries/v1.24.3/kubelet --help | grep -v DEPRECATED | grep -v -E "(vmodule|version|help|v level)"
func mergeFlagsIntoConfig(kubeletConfig map[string]any, flags map[string]any) error {
	cliOnlyFlags := []string{
		"azure-container-registry-config",
		"bootstrap-kubeconfig",
		"cert-dir",
		"config",
		"container-runtime-endpoint",
		"exit-on-lock-contention",
		"hostname-override",
		"housekeeping-interval",
		"image-credential-provider-bin-dir",
		"image-credential-provider-config",
		"image-service-endpoint",
		"kubeconfig",
		"lock-file",
		"log-flush-frequency",
		"logging-format",
		"node-ip",
		"root-dir",
		"runtime-cgroups",
		"seccomp-default",
	}
	for _, key := range cliOnlyFlags {
		if _, ok := flags[key]; ok {
			kubeletConfig[key] = flags[key]
		}
	}

	// --container-runtime-endpoint is also the config file's
	// containerRuntimeEndpoint (Canonical Kubernetes sets it only as a flag).
	if v, ok := flags["container-runtime-endpoint"]; ok {
		kubeletConfig["containerRuntimeEndpoint"] = v
	}

	// -v / --v sets the log verbosity of the kubelet's logging config (k0s
	// passes --v=1).
	if v, ok := flags["v"]; ok {
		logging := map[string]any{}
		if existing, ok := kubeletConfig["logging"].(map[string]any); ok {
			logging = existing
		}
		logging["verbosity"] = v
		kubeletConfig["logging"] = logging
	}

	if _, ok := flags["node-labels"]; ok {
		nodeLabels := map[string]string{}
		for _, label := range strings.Split(flags["node-labels"].(string), ",") {
			labelSplit := strings.Split(label, "=")
			labelVal := ""
			if len(labelSplit) > 1 {
				labelVal = labelSplit[1]
			}
			nodeLabels[labelSplit[0]] = labelVal
		}
		data, err := convert.JsonToDict(nodeLabels)
		if err != nil {
			return err
		}
		kubeletConfig["node-labels"] = data
	}

	return nil
}

// parseKeyValueListFlag parses a comma-separated `key=value` flag list into a
// map. Entries without a `=` are skipped rather than indexed out of range,
// which previously panicked on malformed input (e.g. a trailing comma).
func parseKeyValueListFlag(s string) map[string]string {
	res := map[string]string{}
	for _, item := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(kv) < 2 {
			continue
		}
		res[kv[0]] = kv[1]
	}
	return res
}

// mergeDeprecatedFlagsIntoConfig merges deprecated cli flags into the kubelet config
// It only takes care of deprecated flags.
// This is a separate function in hope we can get rid of it in the future
// The list of flags is taken from
// https://github.com/kubernetes/kubernetes/blob/release-1.25/cmd/kubelet/app/options/options.go
func mergeDeprecatedFlagsIntoConfig(kubeletConfig map[string]any, flags map[string]any) error {
	if _, ok := flags["enable-server"]; ok {
		kubeletConfig["enableServer"] = flags["enable-server"]
	}
	if _, ok := flags["fail-swap-on"]; ok {
		kubeletConfig["failSwapOn"] = flags["fail-swap-on"]
	}
	if _, ok := flags["pod-manifest-path"]; ok {
		kubeletConfig["staticPodPath"] = flags["pod-manifest-path"]
	}
	if _, ok := flags["sync-frequency"]; ok {
		kubeletConfig["syncFrequency"] = flags["sync-frequency"]
	}
	if _, ok := flags["file-check-frequency"]; ok {
		kubeletConfig["fileCheckFrequency"] = flags["file-check-frequency"]
	}
	if _, ok := flags["http-check-frequency"]; ok {
		kubeletConfig["httpCheckFrequency"] = flags["http-check-frequency"]
	}
	if _, ok := flags["manifest-url"]; ok {
		kubeletConfig["staticPodURL"] = flags["manifest-url"]
	}
	if v, ok := flags["manifest-url-header"]; ok {
		urlHeaders := map[string]string{}
		for _, urlHeader := range strings.Split(v.(string), ",") {
			urlHeaderSplit := strings.SplitN(urlHeader, ":", 2)
			if len(urlHeaderSplit) < 2 {
				continue
			}
			urlHeaders[urlHeaderSplit[0]] = urlHeaderSplit[1]
		}
		data, err := convert.JsonToDict(urlHeaders)
		if err != nil {
			return err
		}
		kubeletConfig["staticPodURLHeader"] = data
	}
	if _, ok := flags["address"]; ok {
		kubeletConfig["address"] = flags["address"]
	}
	if _, ok := flags["port"]; ok {
		kubeletConfig["port"] = flags["port"]
	}
	if _, ok := flags["read-only-port"]; ok {
		kubeletConfig["readOnlyPort"] = flags["read-only-port"]
	}
	if v, ok := flags["anonymous-auth"]; ok {
		auth := map[string]any{}
		if existing, ok := kubeletConfig["authentication"].(map[string]any); ok {
			auth = existing
		}
		anon := map[string]any{}
		if existing, ok := auth["anonymous"].(map[string]any); ok {
			anon = existing
		}
		anon["enabled"] = v
		auth["anonymous"] = anon
		kubeletConfig["authentication"] = auth
	}
	if v, ok := flags["authentication-token-webhook"]; ok {
		auth := map[string]any{}
		if existing, ok := kubeletConfig["authentication"].(map[string]any); ok {
			auth = existing
		}
		webhook := map[string]any{}
		if existing, ok := auth["webhook"].(map[string]any); ok {
			webhook = existing
		}
		webhook["enabled"] = v
		auth["webhook"] = webhook
		kubeletConfig["authentication"] = auth
	}
	if v, ok := flags["authentication-token-webhook-cache-ttl"]; ok {
		auth := map[string]any{}
		if existing, ok := kubeletConfig["authentication"].(map[string]any); ok {
			auth = existing
		}
		webhook := map[string]any{}
		if existing, ok := auth["webhook"].(map[string]any); ok {
			webhook = existing
		}
		webhook["cacheTTL"] = v
		auth["webhook"] = webhook
		kubeletConfig["authentication"] = auth
	}
	if v, ok := flags["client-ca-file"]; ok {
		auth := map[string]any{}
		if existing, ok := kubeletConfig["authentication"].(map[string]any); ok {
			auth = existing
		}
		x509 := map[string]any{}
		if existing, ok := auth["x509"].(map[string]any); ok {
			x509 = existing
		}
		x509["clientCAFile"] = v
		auth["x509"] = x509
		kubeletConfig["authentication"] = auth
	}
	if v, ok := flags["authorization-mode"]; ok {
		authz := map[string]any{}
		if existing, ok := kubeletConfig["authorization"].(map[string]any); ok {
			authz = existing
		}
		authz["mode"] = v
		kubeletConfig["authorization"] = authz
	}
	if v, ok := flags["authorization-webhook-cache-authorized-ttl"]; ok {
		authz := map[string]any{}
		if existing, ok := kubeletConfig["authorization"].(map[string]any); ok {
			authz = existing
		}
		webhook := map[string]any{}
		if existing, ok := authz["webhook"].(map[string]any); ok {
			webhook = existing
		}
		webhook["cacheAuthorizedTTL"] = v
		authz["webhook"] = webhook
		kubeletConfig["authorization"] = authz
	}
	if v, ok := flags["authorization-webhook-cache-unauthorized-ttl"]; ok {
		authz := map[string]any{}
		if existing, ok := kubeletConfig["authorization"].(map[string]any); ok {
			authz = existing
		}
		webhook := map[string]any{}
		if existing, ok := authz["webhook"].(map[string]any); ok {
			webhook = existing
		}
		webhook["cacheUnauthorizedTTL"] = v
		authz["webhook"] = webhook
		kubeletConfig["authorization"] = authz
	}
	if _, ok := flags["tls-cert-file"]; ok {
		kubeletConfig["tlsCertFile"] = flags["tls-cert-file"]
	}
	if _, ok := flags["tls-private-key-file"]; ok {
		kubeletConfig["tlsPrivateKeyFile"] = flags["tls-private-key-file"]
	}
	if _, ok := flags["rotate-server-certificates"]; ok {
		kubeletConfig["serverTLSBootstrap"] = flags["rotate-server-certificates"]
	}
	if _, ok := flags["tls-cipher-suites"]; ok {
		ciphers := strings.Split(flags["tls-cipher-suites"].(string), ",")
		data, err := convert.JsonToDictSlice(ciphers)
		if err != nil {
			return err
		}
		kubeletConfig["tlsCipherSuites"] = data
	}
	if _, ok := flags["tls-min-version"]; ok {
		kubeletConfig["tlsMinVersion"] = flags["tls-min-version"]
	}
	if _, ok := flags["rotate-certificates"]; ok {
		kubeletConfig["rotateCertificates"] = flags["rotate-certificates"]
	}
	if _, ok := flags["registry-qps"]; ok {
		kubeletConfig["registryPullQPS"] = flags["registry-qps"]
	}
	if _, ok := flags["registry-burst"]; ok {
		kubeletConfig["registryBurst"] = flags["registry-burst"]
	}
	if _, ok := flags["event-qps"]; ok {
		kubeletConfig["eventRecordQPS"] = flags["event-qps"]
	}
	if _, ok := flags["event-burst"]; ok {
		kubeletConfig["eventBurst"] = flags["event-burst"]
	}
	if _, ok := flags["enable-debugging-handlers"]; ok {
		kubeletConfig["enableDebuggingHandlers"] = flags["enable-debugging-handlers"]
	}
	if _, ok := flags["contention-profiling"]; ok {
		kubeletConfig["enableContentionProfiling"] = flags["contention-profiling"]
	}
	if _, ok := flags["healthz-port"]; ok {
		kubeletConfig["healthzPort"] = flags["healthz-port"]
	}
	if _, ok := flags["healthz-bind-address"]; ok {
		kubeletConfig["healthzBindAddress"] = flags["healthz-bind-address"]
	}
	if _, ok := flags["oom-score-adj"]; ok {
		kubeletConfig["oomScoreAdj"] = flags["oom-score-adj"]
	}
	if _, ok := flags["cluster-domain"]; ok {
		kubeletConfig["clusterDomain"] = flags["cluster-domain"]
	}
	if _, ok := flags["volume-plugin-dir"]; ok {
		kubeletConfig["volumePluginDir"] = flags["volume-plugin-dir"]
	}
	if _, ok := flags["cluster-dns"]; ok {
		kubeletConfig["clusterDNS"] = flags["cluster-dns"]
	}
	if _, ok := flags["streaming-connection-idle-timeout"]; ok {
		kubeletConfig["streamingConnectionIdleTimeout"] = flags["streaming-connection-idle-timeout"]
	}
	if _, ok := flags["node-status-update-frequency"]; ok {
		kubeletConfig["nodeStatusUpdateFrequency"] = flags["node-status-update-frequency"]
	}
	if _, ok := flags["minimum-image-ttl-duration"]; ok {
		kubeletConfig["imageMinimumGCAge"] = flags["minimum-image-ttl-duration"]
	}
	if _, ok := flags["image-gc-high-threshold"]; ok {
		kubeletConfig["imageGCHighThresholdPercent"] = flags["image-gc-high-threshold"]
	}
	if _, ok := flags["image-gc-low-threshold"]; ok {
		kubeletConfig["imageGCLowThresholdPercent"] = flags["image-gc-low-threshold"]
	}
	if _, ok := flags["volume-stats-agg-period"]; ok {
		kubeletConfig["volumeStatsAggPeriod"] = flags["volume-stats-agg-period"]
	}
	if _, ok := flags["feature-gates"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["feature-gates"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["featureGates"] = data
	}
	if _, ok := flags["kubelet-cgroups"]; ok {
		kubeletConfig["kubeletCgroups"] = flags["kubelet-cgroups"]
	}
	if _, ok := flags["system-cgroups"]; ok {
		kubeletConfig["systemCgroups"] = flags["system-cgroups"]
	}
	if _, ok := flags["provider-id"]; ok {
		kubeletConfig["providerID"] = flags["provider-id"]
	}
	if _, ok := flags["cgroups-per-qos"]; ok {
		kubeletConfig["cgroupsPerQOS"] = flags["cgroups-per-qos"]
	}
	if _, ok := flags["cgroup-driver"]; ok {
		kubeletConfig["cgroupDriver"] = flags["cgroup-driver"]
	}
	if _, ok := flags["cgroup-root"]; ok {
		kubeletConfig["cgroupRoot"] = flags["cgroup-root"]
	}
	if _, ok := flags["cpu-manager-policy"]; ok {
		kubeletConfig["cpuManagerPolicy"] = flags["cpu-manager-policy"]
	}
	if _, ok := flags["cpu-manager-policy-options"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["cpu-manager-policy-options"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["cpuManagerPolicyOptions"] = data
	}
	if _, ok := flags["cpu-manager-reconcile-period"]; ok {
		kubeletConfig["cpuManagerReconcilePeriod"] = flags["cpu-manager-reconcile-period"]
	}
	if _, ok := flags["qos-reserved"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["qos-reserved"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["qosReserved"] = data
	}
	if _, ok := flags["topology-manager-policy"]; ok {
		kubeletConfig["topologyManagerPolicy"] = flags["topology-manager-policy"]
	}
	if _, ok := flags["runtime-request-timeout"]; ok {
		kubeletConfig["runtimeRequestTimeout"] = flags["runtime-request-timeout"]
	}
	if _, ok := flags["hairpin-mode"]; ok {
		kubeletConfig["hairpinMode"] = flags["hairpin-mode"]
	}
	if _, ok := flags["max-pods"]; ok {
		kubeletConfig["maxPods"] = flags["max-pods"]
	}
	if _, ok := flags["pod-cidr"]; ok {
		kubeletConfig["podCIDR"] = flags["pod-cidr"]
	}
	if _, ok := flags["pod-max-pids"]; ok {
		kubeletConfig["podPidsLimit"] = flags["pod-max-pids"]
	}
	if _, ok := flags["resolv-conf"]; ok {
		kubeletConfig["resolverConfig"] = flags["resolv-conf"]
	}
	if _, ok := flags["runonce"]; ok {
		kubeletConfig["runOnce"] = flags["runonce"]
	}
	if _, ok := flags["cpu-cfs-quota"]; ok {
		kubeletConfig["cpuCFSQuota"] = flags["cpu-cfs-quota"]
	}
	if _, ok := flags["cpu-cfs-quota-period"]; ok {
		kubeletConfig["cpuCFSQuotaPeriod"] = flags["cpu-cfs-quota-period"]
	}
	if _, ok := flags["enable-controller-attach-detach"]; ok {
		kubeletConfig["enableControllerAttachDetach"] = flags["enable-controller-attach-detach"]
	}
	if _, ok := flags["make-iptables-util-chains"]; ok {
		kubeletConfig["makeIPTablesUtilChains"] = flags["make-iptables-util-chains"]
	}
	if _, ok := flags["iptables-masquerade-bit"]; ok {
		kubeletConfig["iptablesMasqueradeBit"] = flags["iptables-masquerade-bit"]
	}
	if _, ok := flags["iptables-drop-bit"]; ok {
		kubeletConfig["iptablesDropBit"] = flags["iptables-drop-bit"]
	}
	if _, ok := flags["container-log-max-size"]; ok {
		kubeletConfig["containerLogMaxSize"] = flags["container-log-max-size"]
	}
	if _, ok := flags["container-log-max-files"]; ok {
		kubeletConfig["containerLogMaxFiles"] = flags["container-log-max-files"]
	}
	if _, ok := flags["allowed-unsafe-sysctls"]; ok {
		kubeletConfig["allowedUnsafeSysctls"] = flags["allowed-unsafe-sysctls"]
	}
	if _, ok := flags["node-status-max-images"]; ok {
		kubeletConfig["nodeStatusMaxImages"] = flags["node-status-max-images"]
	}
	if _, ok := flags["kernel-memcg-notification"]; ok {
		kubeletConfig["kernelMemcgNotification"] = flags["kernel-memcg-notification"]
	}
	if _, ok := flags["local-storage-capacity-isolation"]; ok {
		kubeletConfig["localStorageCapacityIsolation"] = flags["local-storage-capacity-isolation"]
	}
	if _, ok := flags["max-open-files"]; ok {
		kubeletConfig["maxOpenFiles"] = flags["max-open-files"]
	}
	if _, ok := flags["kube-api-content-type"]; ok {
		kubeletConfig["contentType"] = flags["kube-api-content-type"]
	}
	if _, ok := flags["kube-api-qps"]; ok {
		kubeletConfig["kubeAPIQPS"] = flags["kube-api-qps"]
	}
	if _, ok := flags["kube-api-burst"]; ok {
		kubeletConfig["kubeAPIBurst"] = flags["kube-api-burst"]
	}
	if _, ok := flags["serialize-image-pulls"]; ok {
		kubeletConfig["serializeImagePulls"] = flags["serialize-image-pulls"]
	}
	if _, ok := flags["eviction-hard"]; ok {
		evictions := map[string]string{}
		for _, eviction := range strings.Split(flags["eviction-hard"].(string), ",") {
			m := evictionRegex.FindStringSubmatch(eviction)
			if len(m) == 0 {
				continue
			}
			evictions[m[1]] = m[2]
		}
		data, err := convert.JsonToDict(evictions)
		if err != nil {
			return err
		}
		kubeletConfig["evictionHard"] = data
	}
	if _, ok := flags["eviction-soft"]; ok {
		evictions := map[string]string{}
		for _, eviction := range strings.Split(flags["eviction-soft"].(string), ",") {
			m := evictionRegex.FindStringSubmatch(eviction)
			if len(m) == 0 {
				continue
			}
			evictions[m[1]] = m[2]
		}
		data, err := convert.JsonToDict(evictions)
		if err != nil {
			return err
		}
		kubeletConfig["evictionSoft"] = data
	}
	if _, ok := flags["eviction-soft-grace-period"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["eviction-soft-grace-period"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["evictionSoftGracePeriod"] = data
	}
	if _, ok := flags["eviction-pressure-transition-period"]; ok {
		kubeletConfig["evictionPressureTransitionPeriod"] = flags["eviction-pressure-transition-period"]
	}
	if _, ok := flags["eviction-max-pod-grace-period"]; ok {
		kubeletConfig["evictionMaxPodGracePeriod"] = flags["eviction-max-pod-grace-period"]
	}
	if _, ok := flags["eviction-minimum-reclaim"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["eviction-minimum-reclaim"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["evictionMinimumReclaim"] = data
	}
	if _, ok := flags["pods-per-core"]; ok {
		kubeletConfig["podsPerCore"] = flags["pods-per-core"]
	}
	if _, ok := flags["protect-kernel-defaults"]; ok {
		kubeletConfig["protectKernelDefaults"] = flags["protect-kernel-defaults"]
	}
	if _, ok := flags["reserved-cpus"]; ok {
		kubeletConfig["reservedSystemCPUs"] = flags["reserved-cpus"]
	}
	if _, ok := flags["topology-manager-scope"]; ok {
		kubeletConfig["topologyManagerScope"] = flags["topology-manager-scope"]
	}
	if _, ok := flags["system-reserved"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["system-reserved"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["systemReserved"] = data
	}
	if _, ok := flags["kube-reserved"]; ok {
		data, err := convert.JsonToDict(parseKeyValueListFlag(flags["kube-reserved"].(string)))
		if err != nil {
			return err
		}
		kubeletConfig["kubeReserved"] = data
	}
	if _, ok := flags["enforce-node-allocatable"]; ok {
		kubeletConfig["enforceNodeAllocatable"] = flags["enforce-node-allocatable"]
	}
	if _, ok := flags["system-reserved-cgroup"]; ok {
		kubeletConfig["systemReservedCgroup"] = flags["system-reserved-cgroup"]
	}
	if _, ok := flags["kube-reserved-cgroup"]; ok {
		kubeletConfig["kubeReservedCgroup"] = flags["kube-reserved-cgroup"]
	}
	if _, ok := flags["memory-manager-policy"]; ok {
		kubeletConfig["memoryManagerPolicy"] = flags["memory-manager-policy"]
	}
	if _, ok := flags["reserved-memory"]; ok {
		reservations := strings.Split(flags["reserved-memory"].(string), ",")
		data, err := convert.JsonToDictSlice(reservations)
		if err != nil {
			return err
		}
		kubeletConfig["reservedMemory"] = data
	}
	if _, ok := flags["register-node"]; ok {
		kubeletConfig["registerNode"] = flags["register-node"]
	}
	if _, ok := flags["register-with-taints"]; ok {
		taints := strings.Split(flags["register-with-taints"].(string), ",")
		data, err := convert.JsonToDictSlice(taints)
		if err != nil {
			return err
		}
		kubeletConfig["registerWithTaints"] = data
	}

	// Looks like these flags do not have a corresponding config option in the file:
	deprecatedCliOnlyFlags := []string{
		"minimum-container-ttl-duration",
		"maximum-dead-containers-per-container",
		"maximum-dead-containers",
		"master-service-namespace",
		"register-schedulable",
		"keep-terminated-pod-volumes",
		"experimental-mounter-path",
		"cloud-provider",
		"cloud-config",
		"experimental-allocatable-ignore-eviction",
	}
	for _, key := range deprecatedCliOnlyFlags {
		if _, ok := flags[key]; ok {
			kubeletConfig[key] = flags[key]
		}
	}

	return nil
}
