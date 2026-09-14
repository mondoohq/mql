// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// mqlWindowsCertificateInternal caches the PEM body between the list walk and
// the certificate accessor, so the store is read once rather than once per
// certificate parsed.
type mqlWindowsCertificateInternal struct {
	pem string
}

func (r *mqlWindowsCertificate) id() (string, error) {
	if r.Thumbprint.Error != nil {
		return "", r.Thumbprint.Error
	}
	// The same certificate appears in more than one store and means something
	// different in each, so the store and location are part of the identity.
	// Keying on the thumbprint alone would let the second entry collide with
	// the first in the resource cache and report the first one's store.
	if r.Thumbprint.Data == "" {
		return "", errors.New("windows.certificate has no thumbprint")
	}
	return r.Location.Data + "/" + r.Store.Data + "/" + r.Thumbprint.Data, nil
}

func (r *mqlWindowsCertificates) list() ([]any, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand(powershell.Encode(windows.CertificatesScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve certificates: " + string(stderr))
	}

	certs, err := windows.ParseCertificates(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(certs))
	for _, c := range certs {
		res, err := CreateResource(r.MqlRuntime, "windows.certificate", map[string]*llx.RawData{
			"location":      llx.StringData(c.Location),
			"store":         llx.StringData(c.Store),
			"thumbprint":    llx.StringData(c.Thumbprint),
			"hasPrivateKey": llx.BoolData(c.HasPrivateKey),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlWindowsCertificate).pem = c.Pem()
		out = append(out, res)
	}
	return out, nil
}

// certificate parses the stored bytes into the shared certificate type, so a
// store entry carries the same subject, issuer, validity and extension fields
// as a certificate read from a file or off a TLS connection.
func (r *mqlWindowsCertificate) certificate() (plugin.Resource, error) {
	if r.pem == "" {
		// Bytes that are absent or not valid base64. The entry itself is still
		// worth reporting, so the state is set explicitly rather than dropping
		// the certificate from the list or failing the whole store.
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	sharedRes, err := r.MqlRuntime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(r.pem),
	})
	if err != nil {
		return nil, err
	}

	list, err := r.MqlRuntime.GetSharedData("certificates", sharedRes.MqlID(), "list")
	if err != nil {
		return nil, err
	}
	if list == nil || list.Error != nil {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	entries, ok := list.Value.([]any)
	if !ok || len(entries) == 0 {
		// A store entry whose bytes are well-formed base64 but not a
		// certificate. Reported as null rather than as an error, so one bad
		// entry does not blind the store.
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	cert, ok := entries[0].(plugin.Resource)
	if !ok {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cert, nil
}
