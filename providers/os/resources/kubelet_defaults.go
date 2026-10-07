/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// https://github.com/kubernetes/kubernetes/blob/release-1.34/pkg/kubelet/apis/config/v1beta1/defaults.go
//
// Based on release-1.34, the oldest Kubernetes release that is still supported
// upstream, with the defaults that changed up to release-1.37 applied by the
// kubelet's minor version (see SetDefaults_KubeletConfiguration). An unknown
// version gets the release-1.34 defaults. The constants and the eviction
// defaults that upstream keeps in dependency-heavy packages
// (k8s.io/kubernetes/...) are inlined here so this package does not have to
// depend on the full Kubernetes tree.
package resources

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"

	// TODO: Cut references to k8s.io/kubernetes, eventually there should be none from this package
	logsapi "k8s.io/component-base/logs/api/v1"
	"k8s.io/utils/ptr"
)

const (
	// TODO: Move these constants to k8s.io/kubelet/config/v1beta1 instead?
	DefaultIPTablesMasqueradeBit = 14
	DefaultIPTablesDropBit       = 15
	DefaultVolumePluginDir       = "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"
	DefaultPodLogsDir            = "/var/log/pods"

	// See https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/2570-memory-qos
	DefaultMemoryThrottlingFactor = 0.9

	// MaxContainerBackOff is the max backoff period for container restarts,
	// applied when the KubeletCrashLoopBackOffMax feature gate is enabled.
	MaxContainerBackOff = 300 * time.Second
)

// https://github.com/kubernetes/kubernetes/blob/release-1.34/pkg/kubelet/types/constants.go
const (
	// ResolvConfDefault is the system default DNS resolver configuration.
	ResolvConfDefault = "/etc/resolv.conf"
)

// https://github.com/kubernetes/kubernetes/blob/release-1.34/pkg/cluster/ports/ports.go
const (
	// KubeletPort is the default port for the kubelet server on each host machine.
	// May be overridden by a flag at startup.
	KubeletPort = 10250
	// KubeletReadOnlyPort exposes basic read-only services from the kubelet.
	// May be overridden by a flag at startup.
	// This is necessary for heapster to collect monitoring stats from the kubelet
	// until heapster can transition to using the SSL endpoint.
	// TODO(roberthbailey): Remove this once we have a better solution for heapster.
	KubeletReadOnlyPort = 10255
	// KubeletHealthzPort exposes a healthz endpoint from the kubelet.
	// May be overridden by a flag at startup.
	KubeletHealthzPort = 10248
)

// https://github.com/kubernetes/kubernetes/blob/release-1.34/pkg/kubelet/qos/policy.go
const (
	// KubeletOOMScoreAdj is the OOM score adjustment for Kubelet
	KubeletOOMScoreAdj int = -999
)

// https://github.com/kubernetes/kubernetes/blob/release-1.34/pkg/kubelet/apis/config/v1beta1/defaults_linux.go
// DefaultEvictionHard includes default options for hard eviction on Linux nodes.
var DefaultEvictionHard = map[string]string{
	"memory.available":   "100Mi",
	"nodefs.available":   "10%",
	"nodefs.inodesFree":  "5%",
	"imagefs.available":  "15%",
	"imagefs.inodesFree": "5%",
}

var (
	zeroDuration = metav1.Duration{}
	// TODO: Move these constants to k8s.io/kubelet/config/v1beta1 instead?
	// Refer to [Node Allocatable](https://github.com/kubernetes/design-proposals-archive/blob/main/node/node-allocatable.md) doc for more information.
	DefaultNodeAllocatableEnforcement = []string{"pods"}
)

// featureGateEnabled reports whether the named feature gate is on for a
// kubelet of the given minor version. A gate the kubelet's FeatureGates map
// sets explicitly wins. Otherwise the gate is on from the minor version
// upstream turned it on by default (defaultOnSince); upstream resolves those
// defaults through k8s.io/kubernetes, which this package does not depend on,
// so the versions are recorded here. An unknown version (0) gets the
// release-1.34 default.
func featureGateEnabled(obj *kubeletconfigv1beta1.KubeletConfiguration, name string, minor, defaultOnSince int) bool {
	if enabled, ok := obj.FeatureGates[name]; ok {
		return enabled
	}
	return minor >= defaultOnSince
}

// SetDefaults_KubeletConfiguration fills the fields the kubelet leaves at
// their zero value with the defaults of a kubelet of the given minor version
// (36 for 1.36). An unknown version (0) gets the release-1.34 defaults.
func SetDefaults_KubeletConfiguration(obj *kubeletconfigv1beta1.KubeletConfiguration, minor int) {
	if obj.EnableServer == nil {
		obj.EnableServer = ptr.To(true)
	}
	if obj.SyncFrequency == zeroDuration {
		obj.SyncFrequency = metav1.Duration{Duration: 1 * time.Minute}
	}
	if obj.FileCheckFrequency == zeroDuration {
		obj.FileCheckFrequency = metav1.Duration{Duration: 20 * time.Second}
	}
	if obj.HTTPCheckFrequency == zeroDuration {
		obj.HTTPCheckFrequency = metav1.Duration{Duration: 20 * time.Second}
	}
	if obj.Address == "" {
		obj.Address = "0.0.0.0"
	}
	if obj.Port == 0 {
		obj.Port = KubeletPort
	}
	if obj.Authentication.Anonymous.Enabled == nil {
		obj.Authentication.Anonymous.Enabled = ptr.To(false)
	}
	if obj.Authentication.Webhook.Enabled == nil {
		obj.Authentication.Webhook.Enabled = ptr.To(true)
	}
	if obj.Authentication.Webhook.CacheTTL == zeroDuration {
		obj.Authentication.Webhook.CacheTTL = metav1.Duration{Duration: 2 * time.Minute}
	}
	if obj.Authorization.Mode == "" {
		obj.Authorization.Mode = kubeletconfigv1beta1.KubeletAuthorizationModeWebhook
	}
	if obj.Authorization.Webhook.CacheAuthorizedTTL == zeroDuration {
		obj.Authorization.Webhook.CacheAuthorizedTTL = metav1.Duration{Duration: 5 * time.Minute}
	}
	if obj.Authorization.Webhook.CacheUnauthorizedTTL == zeroDuration {
		obj.Authorization.Webhook.CacheUnauthorizedTTL = metav1.Duration{Duration: 30 * time.Second}
	}
	if obj.RegistryPullQPS == nil {
		obj.RegistryPullQPS = ptr.To(int32(5))
	}
	if obj.RegistryBurst == 0 {
		obj.RegistryBurst = 10
	}
	if obj.EventRecordQPS == nil {
		obj.EventRecordQPS = ptr.To(int32(50))
	}
	if obj.EventBurst == 0 {
		obj.EventBurst = 100
	}
	if obj.EnableDebuggingHandlers == nil {
		obj.EnableDebuggingHandlers = ptr.To(true)
	}
	if obj.HealthzPort == nil {
		obj.HealthzPort = ptr.To(int32(10248))
	}
	if obj.HealthzBindAddress == "" {
		obj.HealthzBindAddress = "127.0.0.1"
	}
	if obj.OOMScoreAdj == nil {
		obj.OOMScoreAdj = ptr.To(int32(KubeletOOMScoreAdj))
	}
	if obj.StreamingConnectionIdleTimeout == zeroDuration {
		obj.StreamingConnectionIdleTimeout = metav1.Duration{Duration: 4 * time.Hour}
	}
	if obj.NodeStatusReportFrequency == zeroDuration {
		// For backward compatibility, NodeStatusReportFrequency's default value is
		// set to NodeStatusUpdateFrequency if NodeStatusUpdateFrequency is set
		// explicitly.
		if obj.NodeStatusUpdateFrequency == zeroDuration {
			obj.NodeStatusReportFrequency = metav1.Duration{Duration: 5 * time.Minute}
		} else {
			obj.NodeStatusReportFrequency = obj.NodeStatusUpdateFrequency
		}
	}
	if obj.NodeStatusUpdateFrequency == zeroDuration {
		obj.NodeStatusUpdateFrequency = metav1.Duration{Duration: 10 * time.Second}
	}
	if obj.NodeLeaseDurationSeconds == 0 {
		obj.NodeLeaseDurationSeconds = 40
	}
	if obj.ImageMinimumGCAge == zeroDuration {
		obj.ImageMinimumGCAge = metav1.Duration{Duration: 2 * time.Minute}
	}
	if obj.ImageGCHighThresholdPercent == nil {
		// default is below docker's default dm.min_free_space of 90%
		obj.ImageGCHighThresholdPercent = ptr.To(int32(85))
	}
	if obj.ImageGCLowThresholdPercent == nil {
		obj.ImageGCLowThresholdPercent = ptr.To(int32(80))
	}
	if obj.VolumeStatsAggPeriod == zeroDuration {
		obj.VolumeStatsAggPeriod = metav1.Duration{Duration: time.Minute}
	}
	if obj.CgroupsPerQOS == nil {
		obj.CgroupsPerQOS = ptr.To(true)
	}
	if obj.CgroupDriver == "" {
		obj.CgroupDriver = "cgroupfs"
	}
	if obj.CPUManagerPolicy == "" {
		obj.CPUManagerPolicy = "none"
	}
	if obj.CPUManagerReconcilePeriod == zeroDuration {
		// Keep the same as default NodeStatusUpdateFrequency
		obj.CPUManagerReconcilePeriod = metav1.Duration{Duration: 10 * time.Second}
	}
	if obj.MemoryManagerPolicy == "" {
		obj.MemoryManagerPolicy = kubeletconfigv1beta1.NoneMemoryManagerPolicy
	}
	if obj.TopologyManagerPolicy == "" {
		obj.TopologyManagerPolicy = kubeletconfigv1beta1.NoneTopologyManagerPolicy
	}
	if obj.TopologyManagerScope == "" {
		obj.TopologyManagerScope = kubeletconfigv1beta1.ContainerTopologyManagerScope
	}
	if obj.RuntimeRequestTimeout == zeroDuration {
		obj.RuntimeRequestTimeout = metav1.Duration{Duration: 2 * time.Minute}
	}
	if obj.HairpinMode == "" {
		obj.HairpinMode = kubeletconfigv1beta1.PromiscuousBridge
	}
	if obj.MaxPods == 0 {
		obj.MaxPods = 110
	}
	// default nil or negative value to -1 (implies node allocatable pid limit)
	if obj.PodPidsLimit == nil || *obj.PodPidsLimit < int64(0) {
		obj.PodPidsLimit = ptr.To(int64(-1))
	}

	if obj.ResolverConfig == nil {
		obj.ResolverConfig = ptr.To(ResolvConfDefault)
	}
	if obj.CPUCFSQuota == nil {
		obj.CPUCFSQuota = ptr.To(true)
	}
	if obj.CPUCFSQuotaPeriod == nil {
		obj.CPUCFSQuotaPeriod = &metav1.Duration{Duration: 100 * time.Millisecond}
	}
	if obj.NodeStatusMaxImages == nil {
		obj.NodeStatusMaxImages = ptr.To(int32(50))
	}
	if obj.MaxOpenFiles == 0 {
		obj.MaxOpenFiles = 1000000
	}
	if obj.ContentType == "" {
		obj.ContentType = "application/vnd.kubernetes.protobuf"
	}
	if obj.KubeAPIQPS == nil {
		obj.KubeAPIQPS = ptr.To(int32(50))
	}
	if obj.KubeAPIBurst == 0 {
		obj.KubeAPIBurst = 100
	}
	if obj.SerializeImagePulls == nil {
		// SerializeImagePulls defaults to true unless parallel image pulls are
		// explicitly requested via MaxParallelImagePulls >= 2.
		if obj.MaxParallelImagePulls == nil || *obj.MaxParallelImagePulls < 2 {
			obj.SerializeImagePulls = ptr.To(true)
		} else {
			obj.SerializeImagePulls = ptr.To(false)
		}
	}
	if obj.EvictionHard == nil {
		obj.EvictionHard = DefaultEvictionHard
	}
	if obj.EvictionPressureTransitionPeriod == zeroDuration {
		obj.EvictionPressureTransitionPeriod = metav1.Duration{Duration: 5 * time.Minute}
	}
	if obj.MergeDefaultEvictionSettings == nil {
		obj.MergeDefaultEvictionSettings = ptr.To(false)
	}
	if obj.EnableControllerAttachDetach == nil {
		obj.EnableControllerAttachDetach = ptr.To(true)
	}
	if obj.MakeIPTablesUtilChains == nil {
		obj.MakeIPTablesUtilChains = ptr.To(true)
	}
	if obj.IPTablesMasqueradeBit == nil {
		obj.IPTablesMasqueradeBit = ptr.To(int32(DefaultIPTablesMasqueradeBit))
	}
	if obj.IPTablesDropBit == nil {
		obj.IPTablesDropBit = ptr.To(int32(DefaultIPTablesDropBit))
	}
	if obj.FailSwapOn == nil {
		obj.FailSwapOn = ptr.To(true)
	}
	if obj.ContainerLogMaxSize == "" {
		obj.ContainerLogMaxSize = "10Mi"
	}
	if obj.ContainerLogMaxFiles == nil {
		obj.ContainerLogMaxFiles = ptr.To(int32(5))
	}
	if obj.ContainerLogMaxWorkers == nil {
		obj.ContainerLogMaxWorkers = ptr.To(int32(1))
	}
	if obj.ContainerLogMonitorInterval == nil {
		obj.ContainerLogMonitorInterval = &metav1.Duration{Duration: 10 * time.Second}
	}
	if obj.ConfigMapAndSecretChangeDetectionStrategy == "" {
		obj.ConfigMapAndSecretChangeDetectionStrategy = kubeletconfigv1beta1.WatchChangeDetectionStrategy
	}
	if obj.EnforceNodeAllocatable == nil {
		obj.EnforceNodeAllocatable = DefaultNodeAllocatableEnforcement
	}
	if obj.VolumePluginDir == "" {
		obj.VolumePluginDir = DefaultVolumePluginDir
	}
	// Use the Default LoggingConfiguration option
	logsapi.SetRecommendedLoggingConfiguration(&obj.Logging)
	if obj.EnableSystemLogHandler == nil {
		obj.EnableSystemLogHandler = ptr.To(true)
	}
	if obj.EnableProfilingHandler == nil {
		obj.EnableProfilingHandler = ptr.To(true)
	}
	if obj.EnableDebugFlagsHandler == nil {
		obj.EnableDebugFlagsHandler = ptr.To(true)
	}
	if obj.SeccompDefault == nil {
		obj.SeccompDefault = ptr.To(false)
	}
	if obj.FailCgroupV1 == nil {
		// true from 1.35
		obj.FailCgroupV1 = ptr.To(minor >= 35)
	}
	// no longer defaulted from 1.37
	if obj.MemoryThrottlingFactor == nil && minor < 37 {
		obj.MemoryThrottlingFactor = ptr.To(DefaultMemoryThrottlingFactor)
	}
	// defaulted from 1.36
	if obj.MemoryReservationPolicy == "" && minor >= 36 {
		obj.MemoryReservationPolicy = kubeletconfigv1beta1.NoneMemoryReservationPolicy
	}
	if obj.RegisterNode == nil {
		obj.RegisterNode = ptr.To(true)
	}
	if obj.LocalStorageCapacityIsolation == nil {
		obj.LocalStorageCapacityIsolation = ptr.To(true)
	}
	if obj.ContainerRuntimeEndpoint == "" {
		obj.ContainerRuntimeEndpoint = "unix:///run/containerd/containerd.sock"
	}
	if obj.PodLogsDir == "" {
		obj.PodLogsDir = DefaultPodLogsDir
	}

	// The following defaults are guarded by feature gates upstream, both on by
	// default from 1.35 (see featureGateEnabled).
	if featureGateEnabled(obj, "KubeletCrashLoopBackOffMax", minor, 35) {
		if obj.CrashLoopBackOff.MaxContainerRestartPeriod == nil {
			obj.CrashLoopBackOff.MaxContainerRestartPeriod = &metav1.Duration{Duration: MaxContainerBackOff}
		}
	}
	if featureGateEnabled(obj, "KubeletEnsureSecretPulledImages", minor, 35) {
		if obj.ImagePullCredentialsVerificationPolicy == "" {
			obj.ImagePullCredentialsVerificationPolicy = kubeletconfigv1beta1.NeverVerifyPreloadedImages
		}
	}
}
