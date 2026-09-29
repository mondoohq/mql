// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	apim "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azure/connection"
)

func (a *mqlAzureSubscriptionApiManagementServiceServiceBackend) id() (string, error) {
	return a.Id.Data, nil
}

// apimBackendArgs builds the backend args. Credential values (authorization
// parameter, header and query values, client certificates, proxy password)
// are never copied; only whether each is configured.
func apimBackendArgs(b *apim.BackendContract) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(b.ID),
		"name":                          llx.StringDataPtr(b.Name),
		"title":                         llx.NilData,
		"description":                   llx.NilData,
		"url":                           llx.NilData,
		"protocol":                      llx.NilData,
		"backendType":                   llx.NilData,
		"resourceId":                    llx.NilData,
		"validateCertificateChain":      llx.NilData,
		"validateCertificateName":       llx.NilData,
		"authorizationHeaderConfigured": llx.BoolData(false),
		"credentialHeadersConfigured":   llx.BoolData(false),
		"credentialQueryConfigured":     llx.BoolData(false),
		"clientCertificateConfigured":   llx.BoolData(false),
		"proxyUrl":                      llx.NilData,
		"proxyCredentialsConfigured":    llx.BoolData(false),
	}
	p := b.Properties
	if p == nil {
		return args
	}
	args["title"] = llx.StringDataPtr(p.Title)
	args["description"] = llx.StringDataPtr(p.Description)
	if p.URL != nil {
		clean, _ := stripURLCredentials(*p.URL)
		args["url"] = llx.StringData(clean)
	}
	args["protocol"] = llx.StringDataPtr(stringEnumPtr(p.Protocol))
	args["backendType"] = llx.StringDataPtr(stringEnumPtr(p.Type))
	args["resourceId"] = llx.StringDataPtr(p.ResourceID)
	if tls := p.TLS; tls != nil {
		args["validateCertificateChain"] = llx.BoolDataPtr(tls.ValidateCertificateChain)
		args["validateCertificateName"] = llx.BoolDataPtr(tls.ValidateCertificateName)
	}
	if c := p.Credentials; c != nil {
		args["authorizationHeaderConfigured"] = llx.BoolData(c.Authorization != nil)
		args["credentialHeadersConfigured"] = llx.BoolData(len(c.Header) > 0)
		args["credentialQueryConfigured"] = llx.BoolData(len(c.Query) > 0)
		args["clientCertificateConfigured"] = llx.BoolData(len(c.Certificate) > 0 || len(c.CertificateIDs) > 0)
	}
	if proxy := p.Proxy; proxy != nil {
		if proxy.URL != nil {
			clean, _ := stripURLCredentials(*proxy.URL)
			args["proxyUrl"] = llx.StringData(clean)
		}
		args["proxyCredentialsConfigured"] = llx.BoolData(
			(proxy.Username != nil && *proxy.Username != "") || (proxy.Password != nil && *proxy.Password != ""))
	}
	return args
}

func (a *mqlAzureSubscriptionApiManagementServiceService) backends() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, serviceName, err := apimServiceCoordinates(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := apim.NewBackendClient(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListByServicePager(rg, serviceName, &apim.BackendClientListByServiceOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.ApiManagement/service/backends/read")
		}
		for _, b := range page.Value {
			if b == nil || b.ID == nil {
				continue
			}
			mqlB, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionApiManagementServiceServiceBackend, apimBackendArgs(b))
			if err != nil {
				return nil, err
			}
			res = append(res, mqlB)
		}
	}
	return res, nil
}
