// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azureinstancesnapshot

import (
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/mrn"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/detector"
	"go.mondoo.com/mql/providers/os/id/azcompute"
)

// the VM from which we're performing the scan
type azureScannerInstance struct {
	subscriptionId string
	resourceGroup  string
	name           string
}

func determineScannerInstanceInfo(localConn *local.LocalConnection) (azureScannerInstance, error) {
	pf, detected := detector.DetectOS(localConn)
	if !detected {
		return azureScannerInstance{}, errors.New("could not detect platform")
	}
	scannerInstanceInfo, err := azcompute.Resolve(localConn, pf)
	if err != nil {
		return azureScannerInstance{}, errors.Wrap(err, "Azure snapshot provider must run from an Azure VM instance")
	}
	identity, err := scannerInstanceInfo.Identify()
	if err != nil {
		return azureScannerInstance{}, errors.Wrap(err, "Azure snapshot provider must run from an Azure VM instance")
	}
	instanceID := identity.InstanceID

	// parse the platform id
	// platformid.api.mondoo.app/runtime/azure/subscriptions/f1a2873a-6b27-4097-aa7c-3df51f103e96/resourceGroups/preslav-test-ssh_group/providers/Microsoft.Compute/virtualMachines/preslav-test-ssh
	platformMrn, err := mrn.NewMRN(instanceID)
	if err != nil {
		return azureScannerInstance{}, err
	}
	subId, err := platformMrn.ResourceID("subscriptions")
	if err != nil {
		return azureScannerInstance{}, err
	}
	resourceGrp, err := platformMrn.ResourceID("resourceGroups")
	if err != nil {
		return azureScannerInstance{}, err
	}
	instanceName, err := platformMrn.ResourceID("virtualMachines")
	if err != nil {
		return azureScannerInstance{}, err
	}

	return azureScannerInstance{
		subscriptionId: subId,
		resourceGroup:  resourceGrp,
		name:           instanceName,
	}, nil
}
