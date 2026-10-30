// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// parsedCertificate parses the first certificate in pem into the shared
// network.certificate type, so a certificate read from a store or a
// signature carries the same subject, issuer, validity and extension fields
// as one read from a file or off a TLS connection. It returns nil without
// an error when pem holds no certificate that parses.
func parsedCertificate(runtime *plugin.Runtime, pem string) (plugin.Resource, error) {
	sharedRes, err := runtime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(pem),
	})
	if err != nil {
		return nil, err
	}

	list, err := runtime.GetSharedData("certificates", sharedRes.MqlID(), "list")
	if err != nil {
		return nil, err
	}
	if list == nil || list.Error != nil {
		return nil, nil
	}
	entries, ok := list.Value.([]any)
	if !ok || len(entries) == 0 {
		return nil, nil
	}
	cert, ok := entries[0].(plugin.Resource)
	if !ok {
		return nil, nil
	}
	return cert, nil
}
