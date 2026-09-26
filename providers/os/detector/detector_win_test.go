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
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	win "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/registry"
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

// fakeHive serves registry children and values of a SOFTWARE hive from maps,
// standing in for a hive loaded from a filesystem connection.
type fakeHive struct {
	children map[string][]registry.RegistryKeyChild
	items    map[string][]registry.RegistryKeyItem
}

func (h fakeHive) GetNativeRegistryKeyChildren(id, path string) ([]registry.RegistryKeyChild, error) {
	if c, ok := h.children[id+"|"+path]; ok {
		return c, nil
	}
	return nil, errors.New("key not found")
}

func (h fakeHive) GetNativeRegistryKeyItems(id, path string) ([]registry.RegistryKeyItem, error) {
	if i, ok := h.items[id+"|"+path]; ok {
		return i, nil
	}
	return nil, errors.New("key not found")
}

// storeElement wraps a DER certificate the way the registry certificate store
// serializes it: properties of ID, reserved (1), length, data, with the
// certificate as property 32 after a hash property.
func storeElement(der []byte) []byte {
	prop := func(id uint32, data []byte) []byte {
		b := make([]byte, 12, 12+len(data))
		binary.LittleEndian.PutUint32(b[0:], id)
		binary.LittleEndian.PutUint32(b[4:], 1)
		binary.LittleEndian.PutUint32(b[8:], uint32(len(data)))
		return append(b, data...)
	}
	return append(prop(3, make([]byte, 20)), prop(32, der)...)
}

func TestStaticIntuneInfo(t *testing.T) {
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

	sw := registry.Software + "|"
	enrolled := fakeHive{
		children: map[string][]registry.RegistryKeyChild{
			sw + `Microsoft\Enrollments`:                        {{Name: "Context"}, {Name: "ENROLLMENT-GUID"}},
			sw + `Microsoft\SystemCertificates\MY\Certificates`: {{Name: "THUMB-A"}, {Name: "THUMB-CORRUPT"}, {Name: "THUMB-NOBLOB"}},
		},
		items: map[string][]registry.RegistryKeyItem{
			sw + `Microsoft\Enrollments\ENROLLMENT-GUID\DMClient\MS DM Server`: {
				{Key: "entdmid", Value: registry.RegistryKeyValue{Kind: registry.SZ, String: device}},
			},
			sw + `Microsoft\SystemCertificates\MY\Certificates\THUMB-A`: {
				{Key: "Blob", Value: registry.RegistryKeyValue{Kind: registry.BINARY, Binary: storeElement(der)}},
			},
			sw + `Microsoft\SystemCertificates\MY\Certificates\THUMB-CORRUPT`: {
				{Key: "Blob", Value: registry.RegistryKeyValue{Kind: registry.BINARY, Binary: []byte{0x20, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0, 0}}},
			},
			sw + `Microsoft\SystemCertificates\MY\Certificates\THUMB-NOBLOB`: {},
		},
	}

	t.Run("enrollment and certificate from the hive", func(t *testing.T) {
		info := staticIntuneInfo(enrolled)
		require.NotNil(t, info)
		assert.Equal(t, device, info.EntDMID)
		require.Len(t, info.Certificates, 1, "corrupt and blob-less entries are skipped")

		pf := &inventory.Platform{Title: "Windows 11 Enterprise", Labels: map[string]string{"windows.mondoo.com/product-type": "1"}}
		applyIntuneInfo(pf, info)
		assert.Equal(t, device, pf.Labels["windows.mondoo.com/intune-device-id"])
		assert.Equal(t, device, pf.Labels[win.LabelIntuneDeviceID])
		assert.Equal(t, tenant, pf.Labels[win.LabelEntraTenantID])
	})

	t.Run("nothing in the hive", func(t *testing.T) {
		assert.Nil(t, staticIntuneInfo(fakeHive{}))
	})

	t.Run("servers are not Intune-manageable", func(t *testing.T) {
		assert.False(t, intuneManageable(&inventory.Platform{Labels: map[string]string{"windows.mondoo.com/product-type": "3"}, Title: "Windows Server 2022"}))
		assert.True(t, intuneManageable(&inventory.Platform{Labels: map[string]string{"windows.mondoo.com/product-type": "3"}, Title: "Windows 11 Enterprise Multi-Session"}))
	})
}

// selectHive answers only Select\Current, the way a SYSTEM hive loaded from a
// file does; it has no CurrentControlSet.
type selectHive struct {
	current int64
	missing bool
}

func (h selectHive) GetRegistryItemValue(registryId string, path, key string) (registry.RegistryKeyItem, error) {
	if h.missing || registryId != registry.System || path != "Select" || key != "Current" {
		return registry.RegistryKeyItem{}, errors.New("not found")
	}
	return registry.RegistryKeyItem{Key: key, Value: registry.RegistryKeyValue{Number: h.current}}, nil
}

func TestStaticControlSet(t *testing.T) {
	assert.Equal(t, "ControlSet001", staticControlSet(selectHive{current: 1}))
	assert.Equal(t, "ControlSet002", staticControlSet(selectHive{current: 2}))
	// No Select key, or a value out of range: the first control set.
	assert.Equal(t, "ControlSet001", staticControlSet(selectHive{missing: true}))
	assert.Equal(t, "ControlSet001", staticControlSet(selectHive{current: 0}))
}
