// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/container/apiv1/containerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// disabledAddons and enabledAddons name the field each addon resource hangs off
// and the switch it carries, so a renamed or dropped addon fails here rather
// than reading null in a policy.
var (
	disabledAddons = []string{
		"httpLoadBalancingAddon",
		"horizontalPodAutoscalingAddon",
		"kubernetesDashboardAddon",
		"networkPolicyAddon",
		"cloudRunAddon",
	}
	enabledAddons = []string{
		"dnsCacheAddon",
		"configConnectorAddon",
		"gcePersistentDiskCsiDriverAddon",
		"gcpFilestoreCsiDriverAddon",
		"gkeBackupAgentAddon",
		"gcsFuseCsiDriverAddon",
		"statefulHaAddon",
	}
)

// GKE omits an addon's wrapper message entirely when the addon sits at its
// default. Read through the dict that reported null, so a policy written as
// `networkPolicyConfig.disabled == false` evaluated against null and passed
// without having read anything. Every addon resource must be built regardless,
// and must report false for an absent message, which is the default the absence
// stands for.
func TestGkeAddonsConfigChildArgsAbsentAddonsReadFalseNotNull(t *testing.T) {
	children := gkeAddonsConfigChildArgs("cluster/addonsConfig", &containerpb.AddonsConfig{})

	for _, field := range disabledAddons {
		require.Contains(t, children, field)
		assert.Equal(t, false, children[field]["disabled"].Value, field)
	}
	for _, field := range enabledAddons {
		require.Contains(t, children, field)
		assert.Equal(t, false, children[field]["enabled"].Value, field)
	}
	assert.Equal(t, "", children["cloudRunAddon"]["loadBalancerType"].Value)
}

// A nil AddonsConfig is the same claim as an empty one: every addon at its
// default. It must not panic and must not report an addon as enabled.
func TestGkeAddonsConfigChildArgsNilConfig(t *testing.T) {
	children := gkeAddonsConfigChildArgs("cluster/addonsConfig", nil)

	assert.Equal(t, false, children["kubernetesDashboardAddon"]["disabled"].Value)
	assert.Equal(t, false, children["dnsCacheAddon"]["enabled"].Value)
}

// An addon message that is present carries the real value, in both directions.
func TestGkeAddonsConfigChildArgsPresentAddons(t *testing.T) {
	children := gkeAddonsConfigChildArgs("cluster/addonsConfig", &containerpb.AddonsConfig{
		NetworkPolicyConfig:              &containerpb.NetworkPolicyConfig{Disabled: true},
		KubernetesDashboard:              &containerpb.KubernetesDashboard{Disabled: false},
		HttpLoadBalancing:                &containerpb.HttpLoadBalancing{Disabled: true},
		DnsCacheConfig:                   &containerpb.DnsCacheConfig{Enabled: true},
		ConfigConnectorConfig:            &containerpb.ConfigConnectorConfig{Enabled: false},
		GkeBackupAgentConfig:             &containerpb.GkeBackupAgentConfig{Enabled: true},
		GcsFuseCsiDriverConfig:           &containerpb.GcsFuseCsiDriverConfig{Enabled: true},
		StatefulHaConfig:                 &containerpb.StatefulHAConfig{Enabled: true},
		GcpFilestoreCsiDriverConfig:      &containerpb.GcpFilestoreCsiDriverConfig{Enabled: true},
		GcePersistentDiskCsiDriverConfig: &containerpb.GcePersistentDiskCsiDriverConfig{Enabled: true},
		HorizontalPodAutoscaling:         &containerpb.HorizontalPodAutoscaling{Disabled: true},
		CloudRunConfig: &containerpb.CloudRunConfig{
			Disabled:         false,
			LoadBalancerType: containerpb.CloudRunConfig_LOAD_BALANCER_TYPE_EXTERNAL,
		},
	})

	assert.Equal(t, true, children["networkPolicyAddon"]["disabled"].Value)
	assert.Equal(t, false, children["kubernetesDashboardAddon"]["disabled"].Value)
	assert.Equal(t, true, children["httpLoadBalancingAddon"]["disabled"].Value)
	assert.Equal(t, true, children["horizontalPodAutoscalingAddon"]["disabled"].Value)
	assert.Equal(t, true, children["dnsCacheAddon"]["enabled"].Value)
	assert.Equal(t, false, children["configConnectorAddon"]["enabled"].Value)
	assert.Equal(t, true, children["gkeBackupAgentAddon"]["enabled"].Value)
	assert.Equal(t, true, children["gcsFuseCsiDriverAddon"]["enabled"].Value)
	assert.Equal(t, true, children["statefulHaAddon"]["enabled"].Value)
	assert.Equal(t, true, children["gcpFilestoreCsiDriverAddon"]["enabled"].Value)
	assert.Equal(t, true, children["gcePersistentDiskCsiDriverAddon"]["enabled"].Value)
	assert.Equal(t, false, children["cloudRunAddon"]["disabled"].Value)

	// The enum has to reach MQL as its name. An external load balancer is what
	// publishes the cluster's Cloud Run services on the internet, and a bare
	// ordinal cannot be compared against in a policy.
	assert.Equal(t, "LOAD_BALANCER_TYPE_EXTERNAL", children["cloudRunAddon"]["loadBalancerType"].Value)
}

// Every addon resource caches under its own key. A shared or missing suffix
// would make eleven addons resolve to whichever one was created first, so every
// cluster would report the same answer for all of them.
func TestGkeAddonsConfigChildArgsIdsAreDistinct(t *testing.T) {
	children := gkeAddonsConfigChildArgs("cluster/addonsConfig", &containerpb.AddonsConfig{})

	seen := map[string]string{}
	for field, args := range children {
		require.Contains(t, args, "__id")
		id, ok := args["__id"].Value.(string)
		require.True(t, ok, field)
		if other, dup := seen[id]; dup {
			t.Fatalf("%s and %s share the cache key %q", field, other, id)
		}
		seen[id] = field
	}
	assert.Len(t, seen, len(disabledAddons)+len(enabledAddons))
}

// The deprecated dicts keep their shipped behavior: an absent addon message
// leaves the dict null rather than inventing a value for it.
func TestGkeAddonsConfigDictArgsKeepNullForAbsentAddons(t *testing.T) {
	args := gkeAddonsConfigDictArgs("cluster/addonsConfig", &containerpb.AddonsConfig{
		NetworkPolicyConfig: &containerpb.NetworkPolicyConfig{Disabled: true},
	})

	assert.Nil(t, args["cloudRunConfig"].Value)
	assert.Nil(t, args["kubernetesDashboard"].Value)
	assert.Equal(t, map[string]any{"disabled": true}, args["networkPolicyConfig"].Value)
}
