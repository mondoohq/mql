// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databox/armdatabox/v3"
	"github.com/stretchr/testify/assert"
)

// The regression this guards: a job that states no encryption preference is
// three levels of nil deep. Reading it without the guards panics, and
// collapsing the absence into "Disabled" would report a job that never asked
// either way as one that explicitly turned double encryption off.
func TestDataBoxEncryptionPreferences(t *testing.T) {
	enum := func(d armdatabox.DoubleEncryption) *armdatabox.DoubleEncryption { return &d }
	hw := func(h armdatabox.HardwareEncryption) *armdatabox.HardwareEncryption { return &h }

	t.Run("no details", func(t *testing.T) {
		double, hardware := dataBoxEncryptionPreferences(nil)
		assert.Equal(t, "", double)
		assert.Equal(t, "", hardware)
	})

	t.Run("no preferences", func(t *testing.T) {
		double, hardware := dataBoxEncryptionPreferences(&armdatabox.CommonJobDetails{})
		assert.Equal(t, "", double)
		assert.Equal(t, "", hardware)
	})

	t.Run("preferences without an encryption block", func(t *testing.T) {
		double, hardware := dataBoxEncryptionPreferences(&armdatabox.CommonJobDetails{
			Preferences: &armdatabox.Preferences{},
		})
		assert.Equal(t, "", double)
		assert.Equal(t, "", hardware)
	})

	t.Run("double encryption enabled", func(t *testing.T) {
		double, hardware := dataBoxEncryptionPreferences(&armdatabox.CommonJobDetails{
			Preferences: &armdatabox.Preferences{
				EncryptionPreferences: &armdatabox.EncryptionPreferences{
					DoubleEncryption:   enum(armdatabox.DoubleEncryptionEnabled),
					HardwareEncryption: hw(armdatabox.HardwareEncryptionEnabled),
				},
			},
		})
		assert.Equal(t, "Enabled", double)
		assert.Equal(t, "Enabled", hardware)
	})

	// Explicitly off has to read differently from never asked, or a policy
	// cannot tell a deliberate choice from a default.
	t.Run("double encryption explicitly disabled", func(t *testing.T) {
		double, _ := dataBoxEncryptionPreferences(&armdatabox.CommonJobDetails{
			Preferences: &armdatabox.Preferences{
				EncryptionPreferences: &armdatabox.EncryptionPreferences{
					DoubleEncryption: enum(armdatabox.DoubleEncryptionDisabled),
				},
			},
		})
		assert.Equal(t, "Disabled", double)
	})
}

func TestDataBoxKeyEncryptionKey(t *testing.T) {
	str := func(s string) *string { return &s }
	kek := func(k armdatabox.KekType) *armdatabox.KekType { return &k }

	t.Run("no details", func(t *testing.T) {
		kekType, kekURL, vaultID := dataBoxKeyEncryptionKey(nil)
		assert.Equal(t, "", kekType)
		assert.Equal(t, "", kekURL)
		assert.Equal(t, "", vaultID)
	})

	t.Run("no key encryption key block", func(t *testing.T) {
		kekType, kekURL, vaultID := dataBoxKeyEncryptionKey(&armdatabox.CommonJobDetails{})
		assert.Equal(t, "", kekType)
		assert.Equal(t, "", kekURL)
		assert.Equal(t, "", vaultID)
	})

	// A Microsoft-managed passkey carries no URL and no vault. That is the
	// answer, not a missing reading, so the type still has to come back.
	t.Run("Microsoft-managed passkey", func(t *testing.T) {
		kekType, kekURL, vaultID := dataBoxKeyEncryptionKey(&armdatabox.CommonJobDetails{
			KeyEncryptionKey: &armdatabox.KeyEncryptionKey{
				KekType: kek(armdatabox.KekTypeMicrosoftManaged),
			},
		})
		assert.Equal(t, "MicrosoftManaged", kekType)
		assert.Equal(t, "", kekURL)
		assert.Equal(t, "", vaultID)
	})

	t.Run("customer-managed passkey", func(t *testing.T) {
		kekType, kekURL, vaultID := dataBoxKeyEncryptionKey(&armdatabox.CommonJobDetails{
			KeyEncryptionKey: &armdatabox.KeyEncryptionKey{
				KekType:            kek(armdatabox.KekTypeCustomerManaged),
				KekURL:             str("https://contoso.vault.azure.net/keys/databox-kek/abc123"),
				KekVaultResourceID: str("/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/contoso"),
			},
		})
		assert.Equal(t, "CustomerManaged", kekType)
		assert.Equal(t, "https://contoso.vault.azure.net/keys/databox-kek/abc123", kekURL)
		assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/contoso", vaultID)
	})
}
