// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armdeployments "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armdeployments/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionDeploymentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionDeployment) id() (string, error) {
	return a.Id.Data, nil
}

// deployments lists Azure Resource Manager deployments scoped to the
// subscription itself (subscription-scoped templates). Resource-group-scoped
// deployments are reached through azure.subscription.resourcegroup.deployments.
func (a *mqlAzureSubscription) deployments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	client, err := armdeployments.NewDeploymentsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListAtSubscriptionScopePager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, deployment := range page.Value {
			if deployment == nil {
				continue
			}
			mqlDeployment, err := newMqlAzureDeployment(a.MqlRuntime, deployment)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDeployment)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionResourcegroup) deployments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	subId, err := extractSubscriptionID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := armdeployments.NewDeploymentsClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListByResourceGroupPager(a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, deployment := range page.Value {
			if deployment == nil {
				continue
			}
			mqlDeployment, err := newMqlAzureDeployment(a.MqlRuntime, deployment)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDeployment)
		}
	}
	return res, nil
}

func newMqlAzureDeployment(runtime *plugin.Runtime, deployment *armdeployments.DeploymentExtended) (*mqlAzureSubscriptionDeployment, error) {
	// Most fields live under Properties, which can be nil. Collect them into
	// locals (zero-valued when absent) so the resource map is built once below.
	var (
		provisioningState string
		mode              string
		timestamp         *time.Time
		duration          *string
		correlationID     *string
		templateHash      *string
		templateLink      *string
		parametersLink    *string
		parameters        any
		outputs           any
		deploymentErr     any

		debugDetailLevel      *string
		onErrorDeploymentType *string
		onErrorDeploymentName *string
		validationLevel       *string
	)
	providers := []any{}
	outputResources := []any{}
	provisionedResources := []any{}
	diagnostics := []any{}
	extensions := []any{}
	dependencies := []any{}
	template := llx.NilData

	deploymentID := convert.ToValue(deployment.ID)

	if props := deployment.Properties; props != nil {
		if props.ProvisioningState != nil {
			provisioningState = string(*props.ProvisioningState)
		}
		if props.Mode != nil {
			mode = string(*props.Mode)
		}
		timestamp = props.Timestamp
		duration = props.Duration
		correlationID = props.CorrelationID
		templateHash = props.TemplateHash
		if props.TemplateLink != nil {
			templateLink = templateURIWithoutCredentials(props.TemplateLink.URI)
		}
		if props.ParametersLink != nil {
			parametersLink = props.ParametersLink.URI
		}
		// Empty when debug logging is off, which is the safe setting: the debug
		// log persists with the deployment and is readable by anyone who can
		// read the deployment history.
		if ds := props.DebugSetting; ds != nil {
			debugDetailLevel = ds.DetailLevel
		}
		if oed := props.OnErrorDeployment; oed != nil {
			onErrorDeploymentType = stringEnumPtr(oed.Type)
			onErrorDeploymentName = oed.DeploymentName
		}
		validationLevel = stringEnumPtr(props.ValidationLevel)

		var err error
		if parameters, err = convert.JsonToDict(props.Parameters); err != nil {
			return nil, err
		}
		if outputs, err = convert.JsonToDict(props.Outputs); err != nil {
			return nil, err
		}
		if providers, err = convert.JsonToDictSlice(props.Providers); err != nil {
			return nil, err
		}
		for _, r := range props.OutputResources {
			if r != nil && r.ID != nil {
				outputResources = append(outputResources, *r.ID)
			}
		}
		if props.Error != nil {
			if deploymentErr, err = convert.JsonToDict(props.Error); err != nil {
				return nil, err
			}
		}

		if template, err = deploymentTemplateSource(runtime, deploymentID, props.TemplateLink); err != nil {
			return nil, err
		}
		if provisionedResources, err = deploymentProvisionedResources(runtime, deploymentID, props.OutputResources); err != nil {
			return nil, err
		}
		if diagnostics, err = deploymentDiagnostics(runtime, deploymentID, props.Diagnostics); err != nil {
			return nil, err
		}
		if extensions, err = deploymentExtensions(runtime, deploymentID, props.Extensions); err != nil {
			return nil, err
		}
		if dependencies, err = deploymentDependencies(runtime, deploymentID, props.Dependencies); err != nil {
			return nil, err
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.deployment", map[string]*llx.RawData{
		"id":                llx.StringDataPtr(deployment.ID),
		"name":              llx.StringDataPtr(deployment.Name),
		"type":              llx.StringDataPtr(deployment.Type),
		"location":          llx.StringDataPtr(deployment.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(deployment.Tags), types.String),
		"provisioningState": llx.StringData(provisioningState),
		"timestamp":         llx.TimeDataPtr(timestamp),
		"duration":          llx.StringDataPtr(duration),
		"correlationId":     llx.StringDataPtr(correlationID),
		"mode":              llx.StringData(mode),
		"templateHash":      llx.StringDataPtr(templateHash),

		"debugDetailLevel":      llx.StringDataPtr(debugDetailLevel),
		"onErrorDeploymentType": llx.StringDataPtr(onErrorDeploymentType),
		"onErrorDeploymentName": llx.StringDataPtr(onErrorDeploymentName),
		"validationLevel":       llx.StringDataPtr(validationLevel),

		"templateLink":    llx.StringDataPtr(templateLink),
		"template":        template,
		"parametersLink":  llx.StringDataPtr(parametersLink),
		"parameters":      llx.DictData(parameters),
		"outputs":         llx.DictData(outputs),
		"providers":       llx.ArrayData(providers, types.Dict),
		"outputResources": llx.ArrayData(outputResources, types.String),
		"error":           llx.DictData(deploymentErr),

		"provisionedResources": llx.ArrayData(provisionedResources, types.Resource(ResourceAzureSubscriptionDeploymentProvisionedResource)),
		"diagnostics":          llx.ArrayData(diagnostics, types.Resource(ResourceAzureSubscriptionDeploymentDiagnostic)),
		"extensions":           llx.ArrayData(extensions, types.Resource(ResourceAzureSubscriptionDeploymentExtension)),
		"dependencies":         llx.ArrayData(dependencies, types.Resource(ResourceAzureSubscriptionDeploymentDependency)),
	})
	if err != nil {
		return nil, err
	}
	mqlDeployment := res.(*mqlAzureSubscriptionDeployment)
	sysData, err := convert.JsonToDict(deployment.SystemData)
	if err != nil {
		return nil, err
	}
	mqlDeployment.cacheSystemData = sysData
	return mqlDeployment, nil
}

// templateURIWithoutCredentials strips the query string from a template link
// URI.
//
// ARM documents TemplateLink.QueryString as the place a SAS token goes, but a
// deployment run from a SAS-protected blob comes back with the whole signed
// URL in TemplateLink.URI and QueryString empty, so publishing URI verbatim
// puts a working storage credential in the scan result. The query string
// carries nothing else that identifies the template, so dropping all of it
// costs nothing and needs no list of parameter names to keep current.
func templateURIWithoutCredentials(uri *string) *string {
	if uri == nil {
		return nil
	}
	clean := *uri
	if i := strings.Index(clean, "?"); i >= 0 {
		clean = clean[:i]
	}
	return &clean
}

// deploymentChildKey keys one record that belongs to a deployment.
//
// Every one of these records describes what a deployment did, not a resource
// that stands on its own: the same virtual network is depended on by two
// machines in one template, and the same storage account is provisioned by
// every deployment that updates it, each recording the API version its own
// template was written against. subResourceCacheID is the wrong tool here
// because it returns the bare ARM ID whenever one is present, which is the
// value all of those cases share. Keying under the parent instead means the
// ARM ID stays in the key for readability without being the whole of it.
func deploymentChildKey(parentKey, collection string, index int, armID *string) string {
	key := parentKey + "/" + collection + "/" + strconv.Itoa(index)
	if armID != nil && *armID != "" {
		key += "/" + *armID
	}
	return key
}

// deploymentTemplateSource publishes props.TemplateLink as a child resource.
//
// A deployment whose template was supplied inline with the request carries no
// link at all, and reports null rather than a resource of empty members. The
// URI is published without its query string, which is where the SAS token the
// template was fetched with actually arrives.
func deploymentTemplateSource(runtime *plugin.Runtime, deploymentID string, link *armdeployments.TemplateLink) (*llx.RawData, error) {
	if link == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionDeploymentTemplateSource, map[string]*llx.RawData{
		"__id":           llx.StringData(deploymentID + "/template"),
		"templateSpecId": llx.StringDataPtr(link.ID),
		"uri":            llx.StringDataPtr(templateURIWithoutCredentials(link.URI)),
		"contentVersion": llx.StringDataPtr(link.ContentVersion),
		"relativePath":   llx.StringDataPtr(link.RelativePath),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, ResourceAzureSubscriptionDeploymentTemplateSource), nil
}

// deploymentProvisionedResources publishes props.OutputResources as typed
// children, carrying the resource type and API version that the []string
// outputResources field discards.
func deploymentProvisionedResources(runtime *plugin.Runtime, deploymentID string, refs []*armdeployments.ResourceReference) ([]any, error) {
	res := make([]any, 0, len(refs))
	for i, ref := range refs {
		if ref == nil {
			continue
		}
		identifiers, err := convert.JsonToDict(ref.Identifiers)
		if err != nil {
			return nil, err
		}
		key := deploymentChildKey(deploymentID, "provisionedResources", i, ref.ID)
		extension, err := deploymentExtensionResource(runtime, key+"/extension", ref.Extension)
		if err != nil {
			return nil, err
		}
		entry, err := CreateResource(runtime, ResourceAzureSubscriptionDeploymentProvisionedResource, map[string]*llx.RawData{
			"__id":             llx.StringData(key),
			"id":               llx.StringDataPtr(ref.ID),
			"resourceType":     llx.StringDataPtr(ref.ResourceType),
			"apiVersion":       llx.StringDataPtr(ref.APIVersion),
			"symbolicNamePath": llx.ArrayData(strPtrSliceToAny(ref.SymbolicNamePath), types.String),
			"identifiers":      llx.DictData(identifiers),
			"extension":        extension,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// deploymentDiagnostics publishes the validation findings ARM retained on the
// deployment. Nothing in the payload identifies a finding, so the key is the
// deployment's own ID and the position in the list.
func deploymentDiagnostics(runtime *plugin.Runtime, deploymentID string, diags []*armdeployments.DeploymentDiagnosticsDefinition) ([]any, error) {
	res := make([]any, 0, len(diags))
	for i, d := range diags {
		if d == nil {
			continue
		}
		additionalInfo, err := convert.JsonToDictSlice(d.AdditionalInfo)
		if err != nil {
			return nil, err
		}
		entry, err := CreateResource(runtime, ResourceAzureSubscriptionDeploymentDiagnostic, map[string]*llx.RawData{
			"__id":           llx.StringData(deploymentChildKey(deploymentID, "diagnostics", i, nil)),
			"level":          llx.StringDataPtr(stringEnumPtr(d.Level)),
			"code":           llx.StringDataPtr(d.Code),
			"message":        llx.StringDataPtr(d.Message),
			"target":         llx.StringDataPtr(d.Target),
			"additionalInfo": llx.ArrayData(additionalInfo, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// deploymentExtensions publishes the deployment extensions the template used.
func deploymentExtensions(runtime *plugin.Runtime, deploymentID string, exts []*armdeployments.DeploymentExtensionDefinition) ([]any, error) {
	res := make([]any, 0, len(exts))
	for i, ext := range exts {
		if ext == nil {
			continue
		}
		key := deploymentChildKey(deploymentID, "extensions", i, nil)
		data, err := deploymentExtensionResource(runtime, key, ext)
		if err != nil {
			return nil, err
		}
		res = append(res, data.Value)
	}
	return res, nil
}

// deploymentExtensionResource builds one extension resource under the given
// cache key, or reports null when the caller has no extension to publish.
//
// DeploymentExtensionDefinition.Config is deliberately not published: its
// values are the extension's own configuration, which can carry credentials
// for the system the extension deploys to. configHash identifies a
// configuration without disclosing it.
func deploymentExtensionResource(runtime *plugin.Runtime, cacheKey string, ext *armdeployments.DeploymentExtensionDefinition) (*llx.RawData, error) {
	if ext == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionDeploymentExtension, map[string]*llx.RawData{
		"__id":       llx.StringData(cacheKey),
		"name":       llx.StringDataPtr(ext.Name),
		"version":    llx.StringDataPtr(ext.Version),
		"alias":      llx.StringDataPtr(ext.Alias),
		"configId":   llx.StringDataPtr(ext.ConfigID),
		"configHash": llx.StringDataPtr(ext.ConfigHash),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, ResourceAzureSubscriptionDeploymentExtension), nil
}

// deploymentDependencies publishes the dependency graph the deployment
// resolved. ARM nests one level: each dependency carries the dependencies it
// waited on in turn, and those carry none of their own.
func deploymentDependencies(runtime *plugin.Runtime, deploymentID string, deps []*armdeployments.Dependency) ([]any, error) {
	res := make([]any, 0, len(deps))
	for i, dep := range deps {
		if dep == nil {
			continue
		}
		key := deploymentChildKey(deploymentID, "dependencies", i, dep.ID)
		dependsOn := make([]any, 0, len(dep.DependsOn))
		for j, basic := range dep.DependsOn {
			if basic == nil {
				continue
			}
			entry, err := newMqlDeploymentDependency(runtime,
				deploymentChildKey(key, "dependsOn", j, basic.ID),
				basic.ID, basic.ResourceName, basic.ResourceType, nil)
			if err != nil {
				return nil, err
			}
			dependsOn = append(dependsOn, entry)
		}
		entry, err := newMqlDeploymentDependency(runtime, key, dep.ID, dep.ResourceName, dep.ResourceType, dependsOn)
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// newMqlDeploymentDependency builds one node of the dependency graph. Both
// levels of the graph carry the same three members, so they share a resource
// and differ only in whether dependsOn has entries.
func newMqlDeploymentDependency(runtime *plugin.Runtime, cacheKey string, id, resourceName, resourceType *string, dependsOn []any) (plugin.Resource, error) {
	if dependsOn == nil {
		dependsOn = []any{}
	}
	return CreateResource(runtime, ResourceAzureSubscriptionDeploymentDependency, map[string]*llx.RawData{
		"__id":         llx.StringData(cacheKey),
		"id":           llx.StringDataPtr(id),
		"resourceName": llx.StringDataPtr(resourceName),
		"resourceType": llx.StringDataPtr(resourceType),
		"dependsOn":    llx.ArrayData(dependsOn, types.Resource(ResourceAzureSubscriptionDeploymentDependency)),
	})
}
