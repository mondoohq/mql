// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/compute/v1"
)

type mqlGcpProjectComputeServiceCustomerEncryptionKeyInternal struct {
	cacheKmsKeyName string
}

// newMqlCustomerEncryptionKey builds the shared customer-encryption-key resource
// for a Compute Engine disk, snapshot, image, or instance. It returns
// llx.NilData when the resource carries no encryption key of its own, which is
// what Google-managed encryption looks like on the wire.
//
// The raw customer-supplied key material (RawKey / RsaEncryptedKey) is
// deliberately not exposed: those are write-only inputs, and echoing them back
// would put key bytes into scan results.
func newMqlCustomerEncryptionKey(runtime *plugin.Runtime, parentID string, field string, key *compute.CustomerEncryptionKey) (*llx.RawData, error) {
	if key == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "gcp.project.computeService.customerEncryptionKey", map[string]*llx.RawData{
		"__id":                 llx.StringData(parentID + "/" + field),
		"kmsKeyServiceAccount": llx.StringData(key.KmsKeyServiceAccount),
		"sha256":               llx.StringData(key.Sha256),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlGcpProjectComputeServiceCustomerEncryptionKey).cacheKmsKeyName = key.KmsKeyName
	return llx.ResourceData(res, "gcp.project.computeService.customerEncryptionKey"), nil
}

func (g *mqlGcpProjectComputeServiceCustomerEncryptionKey) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}
