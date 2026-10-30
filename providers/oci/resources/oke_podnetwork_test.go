// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"github.com/stretchr/testify/assert"
)

// ClusterPodNetworkOptions is a polymorphic list, so the CNI type is recovered
// by type switch rather than read off a field. A switch arm that names the
// wrong concrete type still compiles and yields an empty list, which reads as
// "this cluster has no pod networking" instead of as an error - so pin both
// variants against the shapes the SDK actually unmarshals into.

func TestOkePodNetworkTypesVcnNative(t *testing.T) {
	out := okePodNetworkTypes([]containerengine.ClusterPodNetworkOptionDetails{
		containerengine.OciVcnIpNativeClusterPodNetworkOptionDetails{},
	})

	assert.Equal(t, []any{"OCI_VCN_IP_NATIVE"}, out)
}

func TestOkePodNetworkTypesFlannelOverlay(t *testing.T) {
	out := okePodNetworkTypes([]containerengine.ClusterPodNetworkOptionDetails{
		containerengine.FlannelOverlayClusterPodNetworkOptionDetails{},
	})

	assert.Equal(t, []any{"FLANNEL_OVERLAY"}, out)
}

func TestOkePodNetworkTypesBoth(t *testing.T) {
	out := okePodNetworkTypes([]containerengine.ClusterPodNetworkOptionDetails{
		containerengine.OciVcnIpNativeClusterPodNetworkOptionDetails{},
		containerengine.FlannelOverlayClusterPodNetworkOptionDetails{},
	})

	assert.Equal(t, []any{"OCI_VCN_IP_NATIVE", "FLANNEL_OVERLAY"}, out)
}

func TestOkePodNetworkTypesEmpty(t *testing.T) {
	assert.Equal(t, []any{}, okePodNetworkTypes(nil))
	assert.Equal(t, []any{}, okePodNetworkTypes([]containerengine.ClusterPodNetworkOptionDetails{}))
}

// An unmarshalled response can carry a variant this build does not know. It
// must be skipped rather than emitted as an empty string, which would compare
// equal to "no CNI configured".
func TestOkePodNetworkTypesSkipsUnknownVariant(t *testing.T) {
	out := okePodNetworkTypes([]containerengine.ClusterPodNetworkOptionDetails{
		unknownPodNetworkOption{},
		containerengine.OciVcnIpNativeClusterPodNetworkOptionDetails{},
	})

	assert.Equal(t, []any{"OCI_VCN_IP_NATIVE"}, out)
}

type unknownPodNetworkOption struct{}

func (unknownPodNetworkOption) String() string { return "unknown" }

func (unknownPodNetworkOption) ValidateEnumValue() (bool, error) { return true, nil }

func (unknownPodNetworkOption) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
