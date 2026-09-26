// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	win "go.mondoo.com/mql/providers/os/detector/windows"
)

func TestDetectIntuneDeviceID(t *testing.T) {
	intuneCommandHash := win.IntuneInfoCommand()

	intuneEnrolledMock := &mock.TomlData{
		Commands: map[string]*mock.Command{
			intuneCommandHash: {
				Stdout: `{"EnrollmentGUID":"12345678-1234-1234-1234-123456789012","EntDMID":"abcdef12-3456-7890-abcd-ef1234567890"}`,
			},
		},
	}

	intuneNotEnrolledMock := &mock.TomlData{
		Commands: map[string]*mock.Command{
			intuneCommandHash: {
				Stdout: "",
			},
		},
	}

	t.Run("workstation should detect Intune device ID", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title: "Windows 10 Enterprise",
			Labels: map[string]string{
				"windows.mondoo.com/product-type": "1",
			},
		}

		detectIntuneDeviceID(pf, conn)
		assert.Equal(t, "abcdef12-3456-7890-abcd-ef1234567890", pf.Labels["windows.mondoo.com/intune-device-id"])
	})

	t.Run("device certificates set the Microsoft identity labels", func(t *testing.T) {
		// Made-up identifiers; the tenant GUID is stored in Microsoft byte order.
		const tenant = "11223344-5566-7788-99aa-bbccddeeff00"
		const device = "0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8f9"
		tenantBytes, err := asn1.Marshal([]byte{0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00})
		require.NoError(t, err)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			Subject:         pkix.Name{CommonName: device},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 840, 113556, 5, 14}, Value: tenantBytes}},
		}, &x509.Certificate{Subject: pkix.Name{CommonName: "Microsoft Intune MDM Device CA"}}, &key.PublicKey, key)
		require.NoError(t, err)

		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
			Commands: map[string]*mock.Command{
				intuneCommandHash: {
					Stdout: `{"EnrollmentGUID":"g","EntDMID":"` + device + `","Certs":"` + base64.StdEncoding.EncodeToString(der) + `"}`,
				},
			},
		}))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title:  "Windows 11 Enterprise",
			Labels: map[string]string{"windows.mondoo.com/product-type": "1"},
		}
		detectIntuneDeviceID(pf, conn)
		assert.Equal(t, device, pf.Labels["windows.mondoo.com/intune-device-id"])
		assert.Equal(t, device, pf.Labels[win.LabelIntuneDeviceID])
		assert.Equal(t, tenant, pf.Labels[win.LabelEntraTenantID])
		_, hasEntra := pf.Labels[win.LabelEntraDeviceID]
		assert.False(t, hasEntra, "no Entra device certificate was reported")
	})

	t.Run("workstation not enrolled should not set label", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneNotEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title: "Windows 10 Enterprise",
			Labels: map[string]string{
				"windows.mondoo.com/product-type": "1",
			},
		}

		detectIntuneDeviceID(pf, conn)
		_, exists := pf.Labels["windows.mondoo.com/intune-device-id"]
		assert.False(t, exists)
	})

	t.Run("Windows 11 multi-session should detect Intune device ID", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title: "Windows 11 Enterprise Multi-Session",
			Labels: map[string]string{
				"windows.mondoo.com/product-type": "3",
			},
		}

		detectIntuneDeviceID(pf, conn)
		assert.Equal(t, "abcdef12-3456-7890-abcd-ef1234567890", pf.Labels["windows.mondoo.com/intune-device-id"])
	})

	t.Run("Windows Server should skip Intune detection", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title: "Windows Server 2022 Datacenter",
			Labels: map[string]string{
				"windows.mondoo.com/product-type": "3",
			},
		}

		detectIntuneDeviceID(pf, conn)
		_, exists := pf.Labels["windows.mondoo.com/intune-device-id"]
		assert.False(t, exists)
	})

	t.Run("Windows Server 2025 should skip Intune detection", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title: "Windows Server 2025 Datacenter",
			Labels: map[string]string{
				"windows.mondoo.com/product-type": "3",
			},
		}

		detectIntuneDeviceID(pf, conn)
		_, exists := pf.Labels["windows.mondoo.com/intune-device-id"]
		assert.False(t, exists)
	})

	t.Run("domain controller should skip Intune detection", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title: "Windows Server 2022 Datacenter",
			Labels: map[string]string{
				"windows.mondoo.com/product-type": "2",
			},
		}

		detectIntuneDeviceID(pf, conn)
		_, exists := pf.Labels["windows.mondoo.com/intune-device-id"]
		assert.False(t, exists)
	})

	t.Run("empty product-type should skip Intune detection", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(intuneEnrolledMock))
		require.NoError(t, err)

		pf := &inventory.Platform{
			Title:  "Windows",
			Labels: map[string]string{},
		}

		detectIntuneDeviceID(pf, conn)
		_, exists := pf.Labels["windows.mondoo.com/intune-device-id"]
		assert.False(t, exists)
	})
}
