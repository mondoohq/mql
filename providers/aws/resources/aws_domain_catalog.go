// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	es_types "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
	opensearch_types "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// domainCatalog is the catalog a search domain publishes to, decoded from the
// CatalogOptions both the OpenSearch and the Elasticsearch APIs report.
type domainCatalog struct {
	enabled bool
	// catalogType is nil when the domain publishes to no catalog.
	catalogType *string
	// encryptionEnabled is nil when the domain publishes to no catalog.
	encryptionEnabled *bool
	kmsKeyArn         string
}

const catalogTypeServiceManagedS3Tables = "ServiceManagedS3Tables"

func (c domainCatalog) args() map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"catalogEnabled":           llx.BoolData(c.enabled),
		"catalogType":              llx.StringDataPtr(c.catalogType),
		"catalogEncryptionEnabled": llx.BoolDataPtr(c.encryptionEnabled),
	}
}

func newDomainCatalog(enabled bool, catalogType string, encEnabled *bool, kmsKeyArn *string) domainCatalog {
	if !enabled {
		return domainCatalog{}
	}
	c := domainCatalog{enabled: true}
	if catalogType != "" {
		c.catalogType = &catalogType
	}
	cmk := convert.ToValue(encEnabled) && convert.ToValue(kmsKeyArn) != ""
	c.encryptionEnabled = &cmk
	if cmk {
		c.kmsKeyArn = *kmsKeyArn
	}
	return c
}

func opensearchDomainCatalog(o *opensearch_types.CatalogOptions) domainCatalog {
	if o == nil {
		return domainCatalog{}
	}
	switch v := o.Catalog.(type) {
	case *opensearch_types.CatalogConfigurationMemberServiceManagedS3Tables:
		var enc, key = (*bool)(nil), (*string)(nil)
		if e := v.Value.EncryptionConfiguration; e != nil {
			enc, key = e.Enabled, e.KmsKeyArn
		}
		return newDomainCatalog(convert.ToValue(o.Enabled), catalogTypeServiceManagedS3Tables, enc, key)
	case *opensearch_types.UnknownUnionMember:
		return newDomainCatalog(convert.ToValue(o.Enabled), v.Tag, nil, nil)
	default:
		return newDomainCatalog(convert.ToValue(o.Enabled), "", nil, nil)
	}
}

func esDomainCatalog(o *es_types.CatalogOptions) domainCatalog {
	if o == nil {
		return domainCatalog{}
	}
	switch v := o.Catalog.(type) {
	case *es_types.CatalogConfigurationMemberServiceManagedS3Tables:
		var enc, key = (*bool)(nil), (*string)(nil)
		if e := v.Value.EncryptionConfiguration; e != nil {
			enc, key = e.Enabled, e.KmsKeyArn
		}
		return newDomainCatalog(convert.ToValue(o.Enabled), catalogTypeServiceManagedS3Tables, enc, key)
	case *es_types.UnknownUnionMember:
		return newDomainCatalog(convert.ToValue(o.Enabled), v.Tag, nil, nil)
	default:
		return newDomainCatalog(convert.ToValue(o.Enabled), "", nil, nil)
	}
}

// catalogKmsKey resolves the customer-managed key of a domain's catalog,
// marking the field null when the catalog uses none.
func catalogKmsKey(runtime *plugin.Runtime, arn string, state *plugin.State) (*mqlAwsKmsKey, error) {
	if arn == "" {
		*state = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, ResourceAwsKmsKey, map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}
