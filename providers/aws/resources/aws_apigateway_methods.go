// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/types"
)

type mqlAwsApigatewayRestapiInternal struct {
	resourcesLock    sync.Mutex
	resourcesFetched bool
	resourcesCache   []any
	// resourcesDenied records a refused GetResources read, so resources and
	// methods each report their own field as null rather than empty.
	resourcesDenied bool
}

// apigatewayMethodSpec is the part of an embedded method the schema reads,
// taken out of the SDK shape so it can be tested without the runtime.
type apigatewayMethodSpec struct {
	httpMethod                string
	authorizationType         string
	authorizerID              string
	requestValidatorID        string
	apiKeyRequired            bool
	authorizationScopes       []any
	operationName             string
	integrationType           *string
	integrationConnectionType *string
}

// apigatewayMethodSpecs flattens the methods GetResources embeds on a
// resource, ordered by HTTP verb so the list is stable between scans.
func apigatewayMethodSpecs(methods map[string]types.Method) []apigatewayMethodSpec {
	verbs := make([]string, 0, len(methods))
	for verb := range methods {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)

	res := make([]apigatewayMethodSpec, 0, len(verbs))
	for _, verb := range verbs {
		m := methods[verb]
		httpMethod := convert.ToValue(m.HttpMethod)
		if httpMethod == "" {
			httpMethod = verb
		}
		scopes := make([]any, 0, len(m.AuthorizationScopes))
		for _, s := range m.AuthorizationScopes {
			scopes = append(scopes, s)
		}
		spec := apigatewayMethodSpec{
			httpMethod:          httpMethod,
			authorizationType:   convert.ToValue(m.AuthorizationType),
			authorizerID:        convert.ToValue(m.AuthorizerId),
			requestValidatorID:  convert.ToValue(m.RequestValidatorId),
			apiKeyRequired:      convert.ToValue(m.ApiKeyRequired),
			authorizationScopes: scopes,
			operationName:       convert.ToValue(m.OperationName),
		}
		if m.MethodIntegration != nil {
			spec.integrationType = nonEmptyEnum(m.MethodIntegration.Type)
			spec.integrationConnectionType = nonEmptyEnum(m.MethodIntegration.ConnectionType)
		}
		res = append(res, spec)
	}
	return res
}

// fetchResources lists the REST API's resources with their methods embedded,
// once, and shares the result between resources and methods. A nil list with
// a nil error means the read was refused and structured errors are off.
func (a *mqlAwsApigatewayRestapi) fetchResources() ([]any, error) {
	a.resourcesLock.Lock()
	defer a.resourcesLock.Unlock()
	if a.resourcesFetched {
		if a.resourcesDenied {
			return nil, nil
		}
		return a.resourcesCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	restApiId := a.Id.Data
	svc := conn.Apigateway(region)
	ctx := context.Background()

	res := []any{}
	paginator := apigateway.NewGetResourcesPaginator(svc, &apigateway.GetResourcesInput{
		RestApiId: &restApiId,
		Embed:     []string{"methods"},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					a.resourcesFetched = true
					a.resourcesDenied = true
					return nil, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("apigateway:GET"))
			}
			return nil, errors.Wrap(err, "could not gather AWS API Gateway resources")
		}
		for _, r := range page.Items {
			mqlRes, err := a.newApigatewayResource(r)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRes)
		}
	}
	a.resourcesFetched = true
	a.resourcesCache = res
	return res, nil
}

func (a *mqlAwsApigatewayRestapi) newApigatewayResource(r types.Resource) (plugin.Resource, error) {
	region := a.Region.Data
	restApiId := a.Id.Data
	resourceId := convert.ToValue(r.Id)
	path := convert.ToValue(r.Path)
	resourceKey := "aws.apigateway.resource/" + region + "/" + restApiId + "/" + resourceId

	methods := []any{}
	for _, spec := range apigatewayMethodSpecs(r.ResourceMethods) {
		mqlMethod, err := CreateResource(a.MqlRuntime, ResourceAwsApigatewayMethod, map[string]*llx.RawData{
			"__id":                      llx.StringData(resourceKey + "/" + spec.httpMethod),
			"httpMethod":                llx.StringData(spec.httpMethod),
			"path":                      llx.StringData(path),
			"resourceId":                llx.StringData(resourceId),
			"restApiId":                 llx.StringData(restApiId),
			"region":                    llx.StringData(region),
			"authorizationType":         llx.StringData(spec.authorizationType),
			"authorizationScopes":       llx.ArrayData(spec.authorizationScopes, mqltypes.String),
			"apiKeyRequired":            llx.BoolData(spec.apiKeyRequired),
			"operationName":             llx.StringData(spec.operationName),
			"integrationType":           llx.StringDataPtr(spec.integrationType),
			"integrationConnectionType": llx.StringDataPtr(spec.integrationConnectionType),
		})
		if err != nil {
			return nil, err
		}
		m := mqlMethod.(*mqlAwsApigatewayMethod)
		m.restApi = a
		m.cacheAuthorizerId = spec.authorizerID
		m.cacheRequestValidatorId = spec.requestValidatorID
		methods = append(methods, m)
	}

	return CreateResource(a.MqlRuntime, ResourceAwsApigatewayResource, map[string]*llx.RawData{
		"__id":      llx.StringData(resourceKey),
		"id":        llx.StringData(resourceId),
		"restApiId": llx.StringData(restApiId),
		"path":      llx.StringData(path),
		"pathPart":  llx.StringData(convert.ToValue(r.PathPart)),
		"parentId":  llx.StringData(convert.ToValue(r.ParentId)),
		"region":    llx.StringData(region),
		"methods":   llx.ArrayData(methods, mqltypes.Resource(ResourceAwsApigatewayMethod)),
	})
}

func (a *mqlAwsApigatewayRestapi) resources() ([]any, error) {
	resources, err := a.fetchResources()
	if err != nil {
		return nil, err
	}
	if resources == nil {
		a.Resources.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resources, nil
}

func (a *mqlAwsApigatewayRestapi) methods() ([]any, error) {
	resources, err := a.fetchResources()
	if err != nil {
		return nil, err
	}
	if resources == nil {
		a.Methods.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, r := range resources {
		res = append(res, r.(*mqlAwsApigatewayResource).Methods.Data...)
	}
	return res, nil
}

func (a *mqlAwsApigatewayResource) id() (string, error) {
	return a.__id, nil
}

type mqlAwsApigatewayMethodInternal struct {
	restApi                 *mqlAwsApigatewayRestapi
	cacheAuthorizerId       string
	cacheRequestValidatorId string
}

func (a *mqlAwsApigatewayMethod) id() (string, error) {
	return a.__id, nil
}

// authorizer resolves the method's authorizer from the REST API's authorizer
// list, which is fetched once per API rather than once per method.
func (a *mqlAwsApigatewayMethod) authorizer() (*mqlAwsApigatewayAuthorizer, error) {
	if a.cacheAuthorizerId == "" || a.restApi == nil {
		a.Authorizer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	authorizers := a.restApi.GetAuthorizers()
	if authorizers.Error != nil {
		return nil, authorizers.Error
	}
	for _, raw := range authorizers.Data {
		auth := raw.(*mqlAwsApigatewayAuthorizer)
		if auth.Id.Data == a.cacheAuthorizerId {
			return auth, nil
		}
	}
	a.Authorizer.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsApigatewayMethod) requestValidator() (*mqlAwsApigatewayRequestValidator, error) {
	if a.cacheRequestValidatorId == "" || a.restApi == nil {
		a.RequestValidator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	validators := a.restApi.GetRequestValidators()
	if validators.Error != nil {
		return nil, validators.Error
	}
	for _, raw := range validators.Data {
		v := raw.(*mqlAwsApigatewayRequestValidator)
		if v.Id.Data == a.cacheRequestValidatorId {
			return v, nil
		}
	}
	a.RequestValidator.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
