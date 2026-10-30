// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/databricks/databricks-sdk-go/service/provisioning"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlDatabricks) customerManagedKeys() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	keys, err := acc.EncryptionKeys.List(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range keys {
		res, err := newMqlDatabricksCustomerManagedKey(r.MqlRuntime, keys[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksCustomerManagedKey maps a customer-managed encryption key to
// its resource. Shared by the list path and the init lookup so a key hydrated
// by id carries the same fields as a listed one.
func newMqlDatabricksCustomerManagedKey(runtime *plugin.Runtime, k provisioning.CustomerManagedKey) (*mqlDatabricksCustomerManagedKey, error) {
	useCases := make([]any, 0, len(k.UseCases))
	for _, uc := range k.UseCases {
		useCases = append(useCases, string(uc))
	}

	var keyArn, keyAlias, keyRegion, kmsKeyId string
	if k.AwsKeyInfo != nil {
		keyArn = k.AwsKeyInfo.KeyArn
		keyAlias = k.AwsKeyInfo.KeyAlias
		keyRegion = k.AwsKeyInfo.KeyRegion
	}
	if k.GcpKeyInfo != nil {
		kmsKeyId = k.GcpKeyInfo.KmsKeyId
	}

	res, err := CreateResource(runtime, "databricks.customerManagedKey", map[string]*llx.RawData{
		"__id":         llx.StringData("databricks.customerManagedKey/" + k.CustomerManagedKeyId),
		"id":           llx.StringData(k.CustomerManagedKeyId),
		"useCases":     llx.ArrayData(useCases, types.String),
		"creationTime": llx.TimeDataPtr(epochMsTime(k.CreationTime)),
		"keyArn":       llx.StringData(keyArn),
		"keyAlias":     llx.StringData(keyAlias),
		"keyRegion":    llx.StringData(keyRegion),
		"kmsKeyId":     llx.StringData(kmsKeyId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksCustomerManagedKey), nil
}

// initDatabricksCustomerManagedKey resolves a single customer-managed key by id
// so typed references (such as databricks.workspace.storageCustomerManagedKey)
// can hydrate a full key from just its id.
func initDatabricksCustomerManagedKey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, fmt.Errorf("databricks.customerManagedKey requires a non-empty id")
	}

	acc, err := accountClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	key, err := acc.EncryptionKeys.GetByCustomerManagedKeyId(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksCustomerManagedKey(runtime, *key)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}
