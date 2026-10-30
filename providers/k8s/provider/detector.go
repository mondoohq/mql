// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
)

func (s *Service) detect(asset *inventory.Asset, conn shared.Connection) error {
	asset.Platform = conn.Platform()
	// the cloud account the cluster runs in; discovery copies a root asset's
	// annotations onto everything found under it
	asset.AddAnnotations(conn.Distro().AssetAnnotations())

	return nil
}
