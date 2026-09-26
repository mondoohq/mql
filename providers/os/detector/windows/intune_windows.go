// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package windows

import (
	"runtime"
	"unsafe"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// GetIntuneInfo returns the Intune enrollment ID and the device certificates.
// Locally on Windows it reads the registry and the certificate store directly,
// which is faster than PowerShell; every other connection uses PowerShell.
func GetIntuneInfo(conn shared.Connection) (*IntuneInfo, error) {
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
		entDMID, err := getIntuneDeviceIDFromRegistry()
		if err != nil {
			return nil, err
		}
		certs := localMachineCertificates()
		if entDMID == "" && len(certs) == 0 {
			return nil, nil
		}
		return &IntuneInfo{EntDMID: entDMID, Certificates: certs}, nil
	}
	return powershellGetIntuneInfo(conn)
}

// getIntuneDeviceIDFromRegistry reads the Intune device ID directly from the Windows registry.
func getIntuneDeviceIDFromRegistry() (string, error) {
	enrollmentsKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		log.Debug().Err(err).Msg("could not open Enrollments registry key")
		return "", nil
	}
	defer enrollmentsKey.Close()

	subkeys, err := enrollmentsKey.ReadSubKeyNames(-1)
	if err != nil {
		log.Debug().Err(err).Msg("could not read Enrollments subkeys")
		return "", nil
	}

	for _, subkey := range subkeys {
		dmClientPath := `SOFTWARE\Microsoft\Enrollments\` + subkey + `\DMClient\MS DM Server`
		dmClientKey, err := registry.OpenKey(registry.LOCAL_MACHINE, dmClientPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		entDMID, _, err := dmClientKey.GetStringValue("EntDMID")
		dmClientKey.Close()
		if err != nil {
			continue
		}

		if entDMID != "" {
			log.Debug().Str("EntDMID", entDMID).Msg("found Intune device ID")
			return entDMID, nil
		}
	}

	return "", nil
}

// localMachineCertificates returns the DER of every certificate in the local
// machine's personal store, opened read-only. Only the public encoding is
// read. An unreadable store yields no certificates, never an error: the
// identity labels are then simply absent.
func localMachineCertificates() [][]byte {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(unsafe.Pointer(storeName)),
	)
	// CertOpenStore takes the store name as a uintptr, which does not keep the
	// UTF-16 buffer alive on its own. Keep it reachable until the call returns.
	runtime.KeepAlive(storeName)
	if err != nil {
		log.Debug().Err(err).Msg("could not open the local machine certificate store")
		return nil
	}
	defer windows.CertCloseStore(store, 0) //nolint:errcheck

	var certs [][]byte
	var ctx *windows.CertContext
	for {
		// CertEnumCertificatesInStore frees the previous context itself.
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil || ctx == nil {
			break
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		certs = append(certs, append([]byte(nil), der...))
	}
	return certs
}
