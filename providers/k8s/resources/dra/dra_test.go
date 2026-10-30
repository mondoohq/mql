// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dra_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/k8s/resources/dra"
)

// resourceSliceJSON is shaped like a slice an SR-IOV DRA driver publishes for
// one node, with one virtual function per device.
const resourceSliceJSON = `{
  "apiVersion": "resource.k8s.io/v1",
  "kind": "ResourceSlice",
  "metadata": {"name": "node-a-sriov"},
  "spec": {
    "driver": "sriov.networking.k8s.io",
    "pool": {"name": "node-a", "generation": 4, "resourceSliceCount": 2},
    "nodeName": "node-a",
    "devices": [
      {
        "name": "vf-0",
        "attributes": {
          "pciAddress": {"string": "0000:19:00.2"},
          "pfName": {"string": "enp25s0f0"},
          "vfIndex": {"int": 0},
          "rdma": {"bool": true},
          "driverVersion": {"version": "1.2.0"},
          "unreadable": {}
        },
        "capacity": {"bandwidth": {"value": "10Gi"}},
        "allowMultipleAllocations": true,
        "bindingConditions": ["dra.example.com/bound"]
      },
      {"name": "vf-1"}
    ]
  }
}`

func TestDecodeResourceSlice(t *testing.T) {
	slice, err := decode[dra.ResourceSlice](t, resourceSliceJSON)
	require.NoError(t, err)

	assert.Equal(t, "sriov.networking.k8s.io", slice.Spec.Driver)
	assert.Equal(t, "node-a", slice.Spec.Pool.Name)
	assert.Equal(t, int64(4), slice.Spec.Pool.Generation)
	assert.Equal(t, int64(2), slice.Spec.Pool.ResourceSliceCount)
	assert.Equal(t, "node-a", slice.Spec.NodeName)
	assert.False(t, slice.Spec.AllNodes)
	assert.Equal(t, []string{"vf-0", "vf-1"}, slice.Spec.DeviceNames())

	device := slice.Spec.Devices[0]
	assert.True(t, device.AllowMultipleAllocations)
	assert.Equal(t, []string{"dra.example.com/bound"}, device.BindingConditions)
	assert.Equal(t, map[string]string{
		"pciAddress":    "0000:19:00.2",
		"pfName":        "enp25s0f0",
		"vfIndex":       "0",
		"rdma":          "true",
		"driverVersion": "1.2.0",
	}, device.StringAttributes())
	assert.Equal(t, map[string]string{"bandwidth": "10Gi"}, device.Capacities())

	// A device without attributes or capacity reports no map rather than an
	// empty one, so a policy can tell "none published" from "empty".
	assert.Nil(t, slice.Spec.Devices[1].StringAttributes())
	assert.Nil(t, slice.Spec.Devices[1].Capacities())
}

func TestDeviceAttrValue(t *testing.T) {
	number := int64(7)
	yes := true
	text := "abc"
	version := "2.0.1"

	for _, test := range []struct {
		title string
		attr  dra.DeviceAttr
		want  string
		ok    bool
	}{
		{"int", dra.DeviceAttr{Int: &number}, "7", true},
		{"bool", dra.DeviceAttr{Bool: &yes}, "true", true},
		{"string", dra.DeviceAttr{String: &text}, "abc", true},
		{"version", dra.DeviceAttr{Version: &version}, "2.0.1", true},
		{"empty", dra.DeviceAttr{}, "", false},
	} {
		t.Run(test.title, func(t *testing.T) {
			value, ok := test.attr.Value()
			assert.Equal(t, test.want, value)
			assert.Equal(t, test.ok, ok)
		})
	}
}

func TestQuantityAcceptsStringAndNumber(t *testing.T) {
	var capacity struct {
		Value dra.Quantity `json:"value"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"value":"1Gi"}`), &capacity))
	assert.Equal(t, dra.Quantity("1Gi"), capacity.Value)

	require.NoError(t, json.Unmarshal([]byte(`{"value":8}`), &capacity))
	assert.Equal(t, dra.Quantity("8"), capacity.Value)
}

const allocatedClaimJSON = `{
  "apiVersion": "resource.k8s.io/v1",
  "kind": "ResourceClaim",
  "metadata": {"name": "dpdk-claim", "namespace": "workloads"},
  "spec": {
    "devices": {
      "requests": [
        {"name": "primary", "exactly": {"deviceClassName": "sriov-vf", "adminAccess": false}},
        {"name": "fallback", "firstAvailable": [
          {"name": "fast", "deviceClassName": "sriov-vf-rdma"},
          {"name": "slow", "deviceClassName": "sriov-vf"}
        ]}
      ],
      "constraints": [{"matchAttribute": "resource.k8s.io/pcieRoot"}]
    }
  },
  "status": {
    "allocation": {
      "devices": {
        "results": [
          {"request": "primary", "driver": "sriov.networking.k8s.io", "pool": "node-a", "device": "vf-0", "adminAccess": true}
        ]
      },
      "nodeSelector": {"nodeSelectorTerms": [{"matchFields": [{"key": "metadata.name", "operator": "In", "values": ["node-a"]}]}]}
    },
    "reservedFor": [
      {"resource": "pods", "name": "dpdk-app-0", "uid": "11111111-1111-1111-1111-111111111111"},
      {"resource": "pods", "name": "dpdk-app-1", "uid": "22222222-2222-2222-2222-222222222222"},
      {"apiGroup": "example.com", "resource": "widgets", "name": "widget-0", "uid": "33333333-3333-3333-3333-333333333333"}
    ],
    "devices": [
      {
        "driver": "sriov.networking.k8s.io",
        "pool": "node-a",
        "device": "vf-0",
        "networkData": {
          "interfaceName": "net1",
          "ips": ["192.0.2.5/24", "2001:db8::5/64"],
          "hardwareAddress": "aa:bb:cc:dd:ee:ff"
        }
      }
    ]
  }
}`

func TestDecodeAllocatedResourceClaim(t *testing.T) {
	claim, err := decode[dra.ResourceClaim](t, allocatedClaimJSON)
	require.NoError(t, err)

	assert.True(t, claim.Status.Allocated())
	assert.True(t, claim.Status.UsesAdminAccess())
	assert.Equal(t, []string{"primary", "fallback"}, claim.Spec.Devices.DeviceRequestNames())
	assert.Equal(t, []string{"sriov-vf", "sriov-vf-rdma"}, claim.Spec.Devices.DeviceClassNames())
	assert.Len(t, claim.Spec.Devices.Constraints, 1)

	// The claim spec asks for no admin access. Only the allocation granted it,
	// so the two readings must not be conflated.
	assert.False(t, claim.Spec.Devices.UsesAdminAccess())

	allocated := claim.Status.AllocatedDevices()
	require.Len(t, allocated, 1)
	assert.Equal(t, "primary", allocated[0].Request)
	assert.Equal(t, "vf-0", allocated[0].Device)
	assert.Equal(t, "node-a", allocated[0].Pool)

	// Only pod consumers in the core group are reported as pods.
	assert.Equal(t, []string{"dpdk-app-0", "dpdk-app-1"}, claim.Status.ReservedPodNames())

	require.Len(t, claim.Status.Devices, 1)
	network := claim.Status.Devices[0].NetworkData
	require.NotNil(t, network)
	assert.Equal(t, "net1", network.InterfaceName)
	assert.Equal(t, []string{"192.0.2.5/24", "2001:db8::5/64"}, network.IPs)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", network.HardwareAddress)
}

func TestDecodePendingResourceClaim(t *testing.T) {
	claim, err := decode[dra.ResourceClaim](t, `{
      "apiVersion": "resource.k8s.io/v1",
      "kind": "ResourceClaim",
      "spec": {"devices": {"requests": [{"name": "primary", "exactly": {"deviceClassName": "sriov-vf"}}]}},
      "status": {}
    }`)
	require.NoError(t, err)

	assert.False(t, claim.Status.Allocated())
	assert.False(t, claim.Status.UsesAdminAccess())
	assert.Empty(t, claim.Status.AllocatedDevices())
	assert.Empty(t, claim.Status.ReservedPodNames())
}

func TestDecodeResourceClaimTemplate(t *testing.T) {
	template, err := decode[dra.ResourceClaimTemplate](t, `{
      "apiVersion": "resource.k8s.io/v1",
      "kind": "ResourceClaimTemplate",
      "metadata": {"name": "dpdk", "namespace": "workloads"},
      "spec": {
        "metadata": {"labels": {"app": "dpdk"}, "annotations": {"owner": "net"}},
        "spec": {"devices": {"requests": [
          {"name": "primary", "exactly": {"deviceClassName": "sriov-vf", "adminAccess": true}}
        ]}}
      }
    }`)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"app": "dpdk"}, template.Spec.Metadata.Labels)
	assert.Equal(t, map[string]string{"owner": "net"}, template.Spec.Metadata.Annotations)
	assert.Equal(t, []string{"sriov-vf"}, template.Spec.Spec.Devices.DeviceClassNames())
	assert.True(t, template.Spec.Spec.Devices.UsesAdminAccess())
}

// TestDecodeLegacyRequestShape pins the pre-split request shape, where the
// device class sits directly on the request rather than under exactly.
func TestDecodeLegacyRequestShape(t *testing.T) {
	claim, err := decode[dra.ResourceClaim](t, `{
      "spec": {"devices": {"requests": [
        {"name": "primary", "deviceClassName": "sriov-vf", "adminAccess": true}
      ]}}
    }`)
	require.NoError(t, err)

	assert.Equal(t, []string{"primary"}, claim.Spec.Devices.DeviceRequestNames())
	assert.Equal(t, []string{"sriov-vf"}, claim.Spec.Devices.DeviceClassNames())
	assert.True(t, claim.Spec.Devices.UsesAdminAccess())
}

func TestDecodeDeviceClass(t *testing.T) {
	class, err := decode[dra.DeviceClass](t, `{
      "apiVersion": "resource.k8s.io/v1",
      "kind": "DeviceClass",
      "metadata": {"name": "sriov-vf"},
      "spec": {
        "selectors": [{"cel": {"expression": "device.attributes[\"sriov.networking.k8s.io\"].rdma == true"}}],
        "extendedResourceName": "example.com/sriov-vf"
      }
    }`)
	require.NoError(t, err)

	require.Len(t, class.Spec.Selectors, 1)
	assert.Equal(t, "example.com/sriov-vf", class.Spec.ExtendedResourceName)
	assert.Empty(t, class.Spec.Config)
}

// decode mirrors the provider path, which hands the decoder a decoded
// Kubernetes object rather than raw bytes.
func decode[T any](t *testing.T, raw string) (*T, error) {
	t.Helper()
	var object map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &object))
	return dra.Decode[T](object)
}
