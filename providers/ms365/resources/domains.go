// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/domains"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (m *mqlMicrosoftDomain) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftDomaindnsrecord) id() (string, error) {
	return m.Id.Data, nil
}

func (a *mqlMicrosoft) domains() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.Domains().Get(ctx, &domains.DomainsRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	allDomains, err := iterate[models.Domainable](ctx, resp, graphClient.GetAdapter(), models.CreateDomainCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, domain := range allDomains {
		supportedServices := []any{}
		for _, service := range domain.GetSupportedServices() {
			supportedServices = append(supportedServices, service)
		}
		mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.domain",
			map[string]*llx.RawData{
				"id":                               llx.StringDataPtr(domain.GetId()),
				"authenticationType":               llx.StringDataPtr(domain.GetAuthenticationType()),
				"availabilityStatus":               llx.StringDataPtr(domain.GetAvailabilityStatus()),
				"isAdminManaged":                   llx.BoolDataPtr(domain.GetIsAdminManaged()),
				"isDefault":                        llx.BoolDataPtr(domain.GetIsDefault()),
				"isInitial":                        llx.BoolDataPtr(domain.GetIsInitial()),
				"isRoot":                           llx.BoolDataPtr(domain.GetIsRoot()),
				"isVerified":                       llx.BoolDataPtr(domain.GetIsVerified()),
				"passwordNotificationWindowInDays": llx.IntDataDefault(domain.GetPasswordNotificationWindowInDays(), 0),
				"passwordValidityPeriodInDays":     llx.IntDataDefault(domain.GetPasswordValidityPeriodInDays(), 0),
				"supportedServices":                llx.ArrayData(supportedServices, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

func (a *mqlMicrosoftDomain) serviceConfigurationRecords() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	id := a.Id.Data
	ctx := context.Background()
	resp, err := graphClient.Domains().ByDomainId(id).ServiceConfigurationRecords().Get(ctx, &domains.ItemServiceConfigurationRecordsRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	records, err := iterate[models.DomainDnsRecordable](ctx, resp, graphClient.GetAdapter(), models.CreateDomainDnsRecordCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, record := range records {
		args := map[string]*llx.RawData{
			"id":               llx.StringDataPtr(record.GetId()),
			"isOptional":       llx.BoolDataPtr(record.GetIsOptional()),
			"label":            llx.StringDataPtr(record.GetLabel()),
			"recordType":       llx.StringDataPtr(record.GetRecordType()),
			"supportedService": llx.StringDataPtr(record.GetSupportedService()),
			"ttl":              llx.IntDataDefault(record.GetTtl(), 0),
			"text":             llx.StringData(""),
			"canonicalName":    llx.StringData(""),
			"mailExchange":     llx.StringData(""),
			"preference":       llx.IntData(0),
			"nameTarget":       llx.StringData(""),
			"service":          llx.StringData(""),
			"protocol":         llx.StringData(""),
			"port":             llx.IntData(0),
			"priority":         llx.IntData(0),
			"weight":           llx.IntData(0),
		}
		setDomainsDnsRecordTypedFields(record, args)
		mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.domaindnsrecord", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

// setDomainsDnsRecordTypedFields populates the per-record-type value fields
// (text, canonicalName, mailExchange, etc.) from the concrete record subtype.
func setDomainsDnsRecordTypedFields(record models.DomainDnsRecordable, args map[string]*llx.RawData) {
	switch r := record.(type) {
	case *models.DomainDnsTxtRecord:
		if r.GetText() != nil {
			args["text"] = llx.StringDataPtr(r.GetText())
		}
	case *models.DomainDnsCnameRecord:
		if r.GetCanonicalName() != nil {
			args["canonicalName"] = llx.StringDataPtr(r.GetCanonicalName())
		}
	case *models.DomainDnsMxRecord:
		if r.GetMailExchange() != nil {
			args["mailExchange"] = llx.StringDataPtr(r.GetMailExchange())
		}
		if r.GetPreference() != nil {
			args["preference"] = llx.IntDataDefault(r.GetPreference(), 0)
		}
	case *models.DomainDnsSrvRecord:
		if r.GetNameTarget() != nil {
			args["nameTarget"] = llx.StringDataPtr(r.GetNameTarget())
		}
		if r.GetService() != nil {
			args["service"] = llx.StringDataPtr(r.GetService())
		}
		if r.GetProtocol() != nil {
			args["protocol"] = llx.StringDataPtr(r.GetProtocol())
		}
		if r.GetPort() != nil {
			args["port"] = llx.IntDataDefault(r.GetPort(), 0)
		}
		if r.GetPriority() != nil {
			args["priority"] = llx.IntDataDefault(r.GetPriority(), 0)
		}
		if r.GetWeight() != nil {
			args["weight"] = llx.IntDataDefault(r.GetWeight(), 0)
		}
	}
}
