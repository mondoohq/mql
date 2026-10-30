// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	sharedres "go.mondoo.com/mql/providers/k8s/connection/shared/resources"
)

func TestManifestFile_OutdatedApi(t *testing.T) {
	manifestFile := "./testdata/nginx-deployment.yaml"

	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					shared.OPTION_NAMESPACE: "default",
				},
			},
		},
	}, manifest.WithManifestFile(manifestFile))
	require.NoError(t, err)
	require.NotNil(t, conn)

	manifestConn := conn.(*manifest.Connection)
	deployment := manifestConn.ManifestParser.Objects[0]

	parsed, err := sharedres.GetPodSpec(deployment)
	require.Error(t, err)
	require.Nil(t, parsed)
	require.Equal(t, "object Deployment with version apps/v1beta1 is not supported", err.Error())
}
