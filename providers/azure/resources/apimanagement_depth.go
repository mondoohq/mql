// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	apim "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// apimServiceCoordinates pulls the subscription, resource group and service name
// out of an API Management service's ARM ID, which every child listing below
// needs.
func apimServiceCoordinates(id string) (subscriptionID, resourceGroup, serviceName string, err error) {
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return "", "", "", err
	}
	serviceName, err = resourceID.Component("service")
	if err != nil {
		return "", "", "", err
	}
	return resourceID.SubscriptionID, resourceID.ResourceGroup, serviceName, nil
}

// The client factory is constructed inline at every call site rather than via a
// helper: the permissions extractor tracks client variables per function body,
// so a constructor behind a helper contributes nothing to
// azure.permissions.json.

// apimPolicyNotFound reports whether a policy fetch failed simply because no
// policy is defined at that scope. Azure answers 404 for an absent policy, which
// is an ordinary state rather than an error: it means the scope inherits
// whatever the enclosing scope defines.
func apimPolicyNotFound(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == 404
}

// apimPolicyXML extracts the policy document from a policy contract. The format
// is requested as rawxml so the value is the policy as authored rather than an
// XML-escaped string.
func apimPolicyXML(props *apim.PolicyContractProperties) string {
	if props == nil {
		return ""
	}
	return convert.ToValue(props.Value)
}

func (a *mqlAzureSubscriptionApiManagementServiceService) policyXml() (string, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return "", errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, serviceName, err := apimServiceCoordinates(a.Id.Data)
	if err != nil {
		return "", err
	}
	factory, err := apim.NewClientFactory(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return "", err
	}

	format := apim.PolicyExportFormatRawxml
	resp, err := factory.NewPolicyClient().Get(context.Background(), rg, serviceName,
		apim.PolicyIDNamePolicy, &apim.PolicyClientGetOptions{Format: &format})
	if err != nil {
		if apimPolicyNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return apimPolicyXML(resp.Properties), nil
}

type mqlAzureSubscriptionApiManagementServiceServiceApiInternal struct {
	subscriptionID string
	resourceGroup  string
	serviceName    string
	apiID          string
}

func (a *mqlAzureSubscriptionApiManagementServiceService) apis() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, serviceName, err := apimServiceCoordinates(a.Id.Data)
	if err != nil {
		return nil, err
	}
	factory, err := apim.NewClientFactory(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewAPIClient().NewListByServicePager(rg, serviceName, &apim.APIClientListByServiceOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, api := range page.Value {
			if api == nil {
				continue
			}

			protocols := []any{}
			var displayName, description, path, serviceURL, apiType, apiRevision, apiVersion string
			var keyHeader, keyQueryParam string
			subscriptionRequired, isCurrent, isOnline := false, false, false
			authSettings := map[string]any{}

			if props := api.Properties; props != nil {
				displayName = convert.ToValue(props.DisplayName)
				description = convert.ToValue(props.Description)
				path = convert.ToValue(props.Path)
				serviceURL = convert.ToValue(props.ServiceURL)
				apiType = string(convert.ToValue(props.APIType))
				apiRevision = convert.ToValue(props.APIRevision)
				apiVersion = convert.ToValue(props.APIVersion)
				subscriptionRequired = convert.ToValue(props.SubscriptionRequired)
				isCurrent = convert.ToValue(props.IsCurrent)
				isOnline = convert.ToValue(props.IsOnline)

				for _, p := range props.Protocols {
					if p != nil {
						protocols = append(protocols, string(*p))
					}
				}
				if kp := props.SubscriptionKeyParameterNames; kp != nil {
					keyHeader = convert.ToValue(kp.Header)
					keyQueryParam = convert.ToValue(kp.Query)
				}
				if as := props.AuthenticationSettings; as != nil {
					d, err := convert.JsonToDict(as)
					if err != nil {
						return nil, err
					}
					authSettings = d
				}
			}

			mqlApi, err := CreateResource(a.MqlRuntime, "azure.subscription.apiManagementService.service.api",
				map[string]*llx.RawData{
					"__id":                          llx.StringDataPtr(api.ID),
					"id":                            llx.StringDataPtr(api.ID),
					"name":                          llx.StringDataPtr(api.Name),
					"displayName":                   llx.StringData(displayName),
					"description":                   llx.StringData(description),
					"path":                          llx.StringData(path),
					"protocols":                     llx.ArrayData(protocols, types.String),
					"serviceUrl":                    llx.StringData(serviceURL),
					"subscriptionRequired":          llx.BoolData(subscriptionRequired),
					"subscriptionKeyHeaderName":     llx.StringData(keyHeader),
					"subscriptionKeyQueryParamName": llx.StringData(keyQueryParam),
					"apiType":                       llx.StringData(apiType),
					"apiRevision":                   llx.StringData(apiRevision),
					"apiVersion":                    llx.StringData(apiVersion),
					"isCurrent":                     llx.BoolData(isCurrent),
					"isOnline":                      llx.BoolData(isOnline),
					"authenticationSettings":        llx.DictData(authSettings),
				})
			if err != nil {
				return nil, err
			}
			mqlApiRes := mqlApi.(*mqlAzureSubscriptionApiManagementServiceServiceApi)
			mqlApiRes.subscriptionID = subID
			mqlApiRes.resourceGroup = rg
			mqlApiRes.serviceName = serviceName
			mqlApiRes.apiID = convert.ToValue(api.Name)
			res = append(res, mqlApiRes)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionApiManagementServiceServiceApi) policyXml() (string, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return "", errors.New("invalid connection provided, it is not an Azure connection")
	}
	factory, err := apim.NewClientFactory(a.subscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return "", err
	}

	format := apim.PolicyExportFormatRawxml
	resp, err := factory.NewAPIPolicyClient().Get(context.Background(), a.resourceGroup, a.serviceName, a.apiID,
		apim.PolicyIDNamePolicy, &apim.APIPolicyClientGetOptions{Format: &format})
	if err != nil {
		// No policy on the API means it inherits the gateway's global policy.
		if apimPolicyNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return apimPolicyXML(resp.Properties), nil
}

type mqlAzureSubscriptionApiManagementServiceServiceProductInternal struct {
	subscriptionID string
	resourceGroup  string
	serviceName    string
	productID      string
}

func (a *mqlAzureSubscriptionApiManagementServiceService) products() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, serviceName, err := apimServiceCoordinates(a.Id.Data)
	if err != nil {
		return nil, err
	}
	factory, err := apim.NewClientFactory(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewProductClient().NewListByServicePager(rg, serviceName, &apim.ProductClientListByServiceOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, product := range page.Value {
			if product == nil {
				continue
			}

			var displayName, description, state, terms string
			subscriptionRequired, approvalRequired := false, false
			var subscriptionsLimit *int64
			if props := product.Properties; props != nil {
				displayName = convert.ToValue(props.DisplayName)
				description = convert.ToValue(props.Description)
				state = string(convert.ToValue(props.State))
				terms = convert.ToValue(props.Terms)
				subscriptionRequired = convert.ToValue(props.SubscriptionRequired)
				approvalRequired = convert.ToValue(props.ApprovalRequired)
				if props.SubscriptionsLimit != nil {
					v := int64(*props.SubscriptionsLimit)
					subscriptionsLimit = &v
				}
			}

			mqlProduct, err := CreateResource(a.MqlRuntime, "azure.subscription.apiManagementService.service.product",
				map[string]*llx.RawData{
					"__id":                 llx.StringDataPtr(product.ID),
					"id":                   llx.StringDataPtr(product.ID),
					"name":                 llx.StringDataPtr(product.Name),
					"displayName":          llx.StringData(displayName),
					"description":          llx.StringData(description),
					"state":                llx.StringData(state),
					"subscriptionRequired": llx.BoolData(subscriptionRequired),
					"approvalRequired":     llx.BoolData(approvalRequired),
					"subscriptionsLimit":   llx.IntDataPtr(subscriptionsLimit),
					"terms":                llx.StringData(terms),
				})
			if err != nil {
				return nil, err
			}
			p := mqlProduct.(*mqlAzureSubscriptionApiManagementServiceServiceProduct)
			p.subscriptionID = subID
			p.resourceGroup = rg
			p.serviceName = serviceName
			p.productID = convert.ToValue(product.Name)
			res = append(res, p)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionApiManagementServiceServiceProduct) policyXml() (string, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return "", errors.New("invalid connection provided, it is not an Azure connection")
	}
	factory, err := apim.NewClientFactory(a.subscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return "", err
	}

	format := apim.PolicyExportFormatRawxml
	resp, err := factory.NewProductPolicyClient().Get(context.Background(), a.resourceGroup, a.serviceName, a.productID,
		apim.PolicyIDNamePolicy, &apim.ProductPolicyClientGetOptions{Format: &format})
	if err != nil {
		if apimPolicyNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return apimPolicyXML(resp.Properties), nil
}

func (a *mqlAzureSubscriptionApiManagementServiceService) namedValues() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, serviceName, err := apimServiceCoordinates(a.Id.Data)
	if err != nil {
		return nil, err
	}
	factory, err := apim.NewClientFactory(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewNamedValueClient().NewListByServicePager(rg, serviceName, &apim.NamedValueClientListByServiceOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, nv := range page.Value {
			if nv == nil {
				continue
			}

			var displayName string
			secret := false
			tags := []any{}
			keyVault := map[string]any{}
			if props := nv.Properties; props != nil {
				displayName = convert.ToValue(props.DisplayName)
				secret = convert.ToValue(props.Secret)
				for _, t := range props.Tags {
					if t != nil {
						tags = append(tags, *t)
					}
				}
				// The value itself is deliberately not exposed; only where it
				// lives and whether it is encrypted.
				if kv := props.KeyVault; kv != nil {
					d, err := convert.JsonToDict(kv)
					if err != nil {
						return nil, err
					}
					keyVault = d
				}
			}

			mqlNv, err := CreateResource(a.MqlRuntime, "azure.subscription.apiManagementService.service.namedValue",
				map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(nv.ID),
					"id":          llx.StringDataPtr(nv.ID),
					"name":        llx.StringDataPtr(nv.Name),
					"displayName": llx.StringData(displayName),
					"secret":      llx.BoolData(secret),
					"tags":        llx.ArrayData(tags, types.String),
					"keyVault":    llx.DictData(keyVault),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlNv)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionApiManagementServiceService) subscriptions() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subID, rg, serviceName, err := apimServiceCoordinates(a.Id.Data)
	if err != nil {
		return nil, err
	}
	factory, err := apim.NewClientFactory(subID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := factory.NewSubscriptionClient().NewListPager(rg, serviceName, &apim.SubscriptionClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sub := range page.Value {
			if sub == nil {
				continue
			}

			var displayName, scope, ownerID, state string
			allowTracing := false
			var createdDate, startDate, expirationDate *time.Time
			if props := sub.Properties; props != nil {
				displayName = convert.ToValue(props.DisplayName)
				scope = convert.ToValue(props.Scope)
				ownerID = convert.ToValue(props.OwnerID)
				state = string(convert.ToValue(props.State))
				allowTracing = convert.ToValue(props.AllowTracing)
				createdDate = props.CreatedDate
				startDate = props.StartDate
				expirationDate = props.ExpirationDate
			}

			mqlSub, err := CreateResource(a.MqlRuntime, "azure.subscription.apiManagementService.service.subscription",
				map[string]*llx.RawData{
					"__id":           llx.StringDataPtr(sub.ID),
					"id":             llx.StringDataPtr(sub.ID),
					"name":           llx.StringDataPtr(sub.Name),
					"displayName":    llx.StringData(displayName),
					"scope":          llx.StringData(scope),
					"ownerId":        llx.StringData(ownerID),
					"state":          llx.StringData(state),
					"allowTracing":   llx.BoolData(allowTracing),
					"createdDate":    llx.TimeDataPtr(createdDate),
					"startDate":      llx.TimeDataPtr(startDate),
					"expirationDate": llx.TimeDataPtr(expirationDate),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSub)
		}
	}
	return res, nil
}
