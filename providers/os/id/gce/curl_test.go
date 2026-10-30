// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gce_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id/gce"
)

func TestRawMetadataLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/metadata_raw_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	metadata := gce.NewCommandInstanceMetadata(conn, platform)
	raw, err := metadata.RawMetadata()
	assert.Nil(t, err)
	// Convert to JSON for readability
	jsonData, _ := json.MarshalIndent(raw, "", "  ")
	expected := `{
  "hostname": "instance-afiune-cloud-test.us-central1-f.c.dev-123.internal",
  "image": "projects/cloud/global/images/debian-12-v123",
  "network-interfaces": {
	  "0": {
		  "access-configs":{
			  "0": {
				  "external-ip": "1.2.3.4",
          "type": "ONE_TO_ONE_NAT"
				}
			},
      "dns-servers":"2.2.2.2",
      "forwarded-ips":"",
      "gateway":"3.3.3.3",
      "ip":"172.1.2.3",
      "mac":"42:01:0a:80:00:11",
      "mtu":1460,
      "network":"projects/123456789012/networks/default",
      "subnetmask":"255.255.240.0",
      "target-instance-ips":""
		}
	}
}`

	// Compare actual vs expected JSON output
	assert.JSONEq(t, expected, string(jsonData))
}
