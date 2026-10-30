// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// vmGuestAccess collects the settings that decide who reaches the inside of a
// VM without going through the guest OS login.
//
// Every value stays a pointer so an absent block reports null instead of a
// fabricated false. That matters here: `null && null` is true in MQL, so a
// false invented for a VM whose OS profile was never returned would let an
// assertion over these flags pass without anything having been read. A Linux VM
// legitimately has no Windows configuration, so its WinRM values are null
// rather than false.
type vmGuestAccess struct {
	allowExtensionOperations    *bool
	requireGuestProvisionSignal *bool
	winRmHTTPListenerEnabled    *bool
	winRmHTTPSListenerEnabled   *bool
	certificateSourceVaultIDs   []string
	encryptionIdentityID        string
}

func vmGuestAccessSettings(props *compute.VirtualMachineProperties) vmGuestAccess {
	var access vmGuestAccess
	if props == nil {
		return access
	}

	if sp := props.SecurityProfile; sp != nil && sp.EncryptionIdentity != nil {
		access.encryptionIdentityID = convert.ToValue(sp.EncryptionIdentity.UserAssignedIdentityResourceID)
	}

	osp := props.OSProfile
	if osp == nil {
		return access
	}
	access.allowExtensionOperations = osp.AllowExtensionOperations
	access.requireGuestProvisionSignal = osp.RequireGuestProvisionSignal

	for _, group := range osp.Secrets {
		if group == nil || group.SourceVault == nil {
			continue
		}
		if id := convert.ToValue(group.SourceVault.ID); id != "" {
			access.certificateSourceVaultIDs = append(access.certificateSourceVaultIDs, id)
		}
	}

	// WinRM listeners exist only on a Windows configuration. Once that block is
	// present, a missing listener list means no listener is configured, which is
	// a real false rather than an unknown.
	if wc := osp.WindowsConfiguration; wc != nil {
		var http, https bool
		if wc.WinRM != nil {
			for _, listener := range wc.WinRM.Listeners {
				if listener == nil || listener.Protocol == nil {
					continue
				}
				switch *listener.Protocol {
				case compute.ProtocolTypesHTTP:
					http = true
				case compute.ProtocolTypesHTTPS:
					https = true
				}
			}
		}
		access.winRmHTTPListenerEnabled = &http
		access.winRmHTTPSListenerEnabled = &https
	}

	return access
}

// certificateSourceVaults resolves the Key Vaults the guest pulls certificates
// from. Each vault is resolved from the subscription's cached vault list.
func (a *mqlAzureSubscriptionComputeServiceVm) certificateSourceVaults() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.keyVaultService.vault", a.cacheCertificateSourceVaultIds)
}

// encryptionIdentity resolves the user-assigned managed identity Azure Disk
// Encryption uses to reach Key Vault, or null when the VM does not set one.
func (a *mqlAzureSubscriptionComputeServiceVm) encryptionIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheEncryptionIdentityId == "" {
		a.EncryptionIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheEncryptionIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}
