// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

func (o *mqlOkta) domains() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	domainList, _, err := client.CustomDomainAPI.ListCustomDomains(ctx).Execute()
	if err != nil {
		return nil, err
	}

	if domainList == nil || len(domainList.Domains) == 0 {
		return nil, nil
	}

	list := []any{}
	for i := range domainList.Domains {
		r, err := newMqlOktaDomain(o.MqlRuntime, &domainList.Domains[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}

	return list, nil
}

func newMqlOktaDomain(runtime *plugin.Runtime, entry *okta.DomainResponse) (any, error) {
	publicCertificate, err := convert.JsonToDict(entry.PublicCertificate)
	if err != nil {
		return nil, err
	}

	dnsRecords, err := convert.JsonToDictSlice(entry.DnsRecords)
	if err != nil {
		return nil, err
	}

	return runtime.CreateResource(runtime, "okta.domain", map[string]*llx.RawData{
		"id":                llx.StringData(oktaStr(entry.Id)),
		"domain":            llx.StringData(oktaStr(entry.Domain)),
		"validationStatus":  llx.StringData(oktaStr(entry.ValidationStatus)),
		"publicCertificate": llx.DictData(publicCertificate),
		"dnsRecords":        llx.DictData(dnsRecords),
	})
}

func (o *mqlOktaDomain) id() (string, error) {
	return "okta.domain/" + o.Id.Data, o.Id.Error
}
