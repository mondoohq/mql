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
	"go.mondoo.com/mql/providers/okta/resources/sdk"
	"go.mondoo.com/mql/types"
)

func (o *mqlOkta) emailDomains() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.EmailDomainAPI.ListEmailDomains(ctx).Execute()
	if err != nil {
		// Orgs that have not configured a custom mail domain have none.
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	for i := range slice {
		r, err := newMqlOktaEmailDomain(o.MqlRuntime, &slice[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaEmailDomain(runtime *plugin.Runtime, entry *okta.EmailDomainResponseWithEmbedded) (any, error) {
	records, err := convert.JsonToDictSlice(entry.DnsValidationRecords)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.emailDomain", map[string]*llx.RawData{
		"id":                   llx.StringData(oktaStr(entry.Id)),
		"domain":               llx.StringData(oktaStr(entry.Domain)),
		"validationSubdomain":  llx.StringData(oktaStr(entry.ValidationSubdomain)),
		"validationStatus":     llx.StringData(oktaStr(entry.ValidationStatus)),
		"displayName":          llx.StringData(entry.DisplayName),
		"userName":             llx.StringData(entry.UserName),
		"dnsValidationRecords": llx.ArrayData(records, types.Dict),
	})
}

func (o *mqlOktaEmailDomain) id() (string, error) {
	return "okta.emailDomain/" + o.Id.Data, o.Id.Error
}

func (o *mqlOkta) emailServers() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	servers, resp, err := conn.ApiExtension().ListEmailServers(ctx)
	if err != nil {
		// Orgs sending through Okta's own mail infrastructure have none.
		if isOktaRawFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	for i := range servers {
		r, err := newMqlOktaEmailServer(o.MqlRuntime, &servers[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaEmailServer(runtime *plugin.Runtime, entry *sdk.EmailServer) (any, error) {
	var port *int64
	if entry.Port != nil {
		p := int64(*entry.Port)
		port = &p
	}

	return CreateResource(runtime, "okta.emailServer", map[string]*llx.RawData{
		"id":       llx.StringData(oktaStr(entry.Id)),
		"alias":    llx.StringData(oktaStr(entry.Alias)),
		"enabled":  llx.BoolDataPtr(entry.Enabled),
		"host":     llx.StringData(oktaStr(entry.Host)),
		"port":     llx.IntDataPtr(port),
		"username": llx.StringData(oktaStr(entry.Username)),
	})
}

func (o *mqlOktaEmailServer) id() (string, error) {
	return "okta.emailServer/" + o.Id.Data, o.Id.Error
}
