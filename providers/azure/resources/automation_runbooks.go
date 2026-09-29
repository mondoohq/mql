// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionAutomationServiceAccountRunbookInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionAutomationServiceAccountWebhookInternal struct {
	cacheSystemData      any
	cacheAccount         *mqlAzureSubscriptionAutomationServiceAccount
	cacheRunbookName     string
	cacheHybridGroupName string
}

type mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroupInternal struct {
	cacheSystemData     any
	cacheAccount        *mqlAzureSubscriptionAutomationServiceAccount
	cacheCredentialName string
}

func (a *mqlAzureSubscriptionAutomationServiceAccountRunbook) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountWebhook) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountRunbook) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAutomationServiceAccountWebhook) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// runbookArgs builds the runbook args. The runbook content and its
// parameters are never copied.
func runbookArgs(rb *armautomation.Runbook) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":                 llx.StringDataPtr(rb.ID),
		"name":               llx.StringDataPtr(rb.Name),
		"location":           llx.StringDataPtr(rb.Location),
		"tags":               llx.MapData(convert.PtrMapStrToInterface(rb.Tags), types.String),
		"runbookType":        llx.NilData,
		"state":              llx.NilData,
		"runtimeEnvironment": llx.NilData,
		"logVerbose":         llx.NilData,
		"logProgress":        llx.NilData,
		"logActivityTrace":   llx.NilData,
		"description":        llx.NilData,
		"provisioningState":  llx.NilData,
		"creationTime":       llx.NilData,
		"lastModifiedTime":   llx.NilData,
		"lastModifiedBy":     llx.NilData,
	}
	if p := rb.Properties; p != nil {
		args["runbookType"] = llx.StringDataPtr(stringEnumPtr(p.RunbookType))
		args["state"] = llx.StringDataPtr(stringEnumPtr(p.State))
		args["runtimeEnvironment"] = llx.StringDataPtr(p.RuntimeEnvironment)
		args["logVerbose"] = llx.BoolDataPtr(p.LogVerbose)
		args["logProgress"] = llx.BoolDataPtr(p.LogProgress)
		args["logActivityTrace"] = llx.IntDataPtr(p.LogActivityTrace)
		args["description"] = llx.StringDataPtr(p.Description)
		args["provisioningState"] = llx.StringDataPtr(p.ProvisioningState)
		args["creationTime"] = llx.TimeDataPtr(p.CreationTime)
		args["lastModifiedTime"] = llx.TimeDataPtr(p.LastModifiedTime)
		args["lastModifiedBy"] = llx.StringDataPtr(p.LastModifiedBy)
	}
	return args
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) runbooks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, name, err := a.accountScope()
	if err != nil {
		return nil, err
	}
	client, err := armautomation.NewRunbookClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByAutomationAccountPager(rg, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Automation/automationAccounts/runbooks/read")
		}
		for _, rb := range page.Value {
			if rb == nil || rb.ID == nil {
				continue
			}
			mqlRb, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionAutomationServiceAccountRunbook, runbookArgs(rb))
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(rb.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRb.(*mqlAzureSubscriptionAutomationServiceAccountRunbook).cacheSystemData = sysData
			res = append(res, mqlRb)
		}
	}
	return res, nil
}

// webhookArgs builds the webhook args. The webhook URI, which is the
// credential that starts the runbook, and the parameters passed to the
// runbook are never copied.
func webhookArgs(wh *armautomation.Webhook) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":               llx.StringDataPtr(wh.ID),
		"name":             llx.StringDataPtr(wh.Name),
		"isEnabled":        llx.NilData,
		"expiryTime":       llx.NilData,
		"lastInvokedTime":  llx.NilData,
		"description":      llx.NilData,
		"creationTime":     llx.NilData,
		"lastModifiedTime": llx.NilData,
		"lastModifiedBy":   llx.NilData,
	}
	if p := wh.Properties; p != nil {
		args["isEnabled"] = llx.BoolDataPtr(p.IsEnabled)
		args["expiryTime"] = llx.TimeDataPtr(p.ExpiryTime)
		args["lastInvokedTime"] = llx.TimeDataPtr(p.LastInvokedTime)
		args["description"] = llx.StringDataPtr(p.Description)
		args["creationTime"] = llx.TimeDataPtr(p.CreationTime)
		args["lastModifiedTime"] = llx.TimeDataPtr(p.LastModifiedTime)
		args["lastModifiedBy"] = llx.StringDataPtr(p.LastModifiedBy)
	}
	return args
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) webhooks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, name, err := a.accountScope()
	if err != nil {
		return nil, err
	}
	client, err := armautomation.NewWebhookClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByAutomationAccountPager(rg, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Automation/automationAccounts/webhooks/read")
		}
		for _, wh := range page.Value {
			if wh == nil || wh.ID == nil {
				continue
			}
			mqlWh, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionAutomationServiceAccountWebhook, webhookArgs(wh))
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(wh.SystemData)
			if err != nil {
				return nil, err
			}
			webhook := mqlWh.(*mqlAzureSubscriptionAutomationServiceAccountWebhook)
			webhook.cacheSystemData = sysData
			webhook.cacheAccount = a
			if p := wh.Properties; p != nil {
				webhook.cacheHybridGroupName = convert.ToValue(p.RunOn)
				if p.Runbook != nil {
					webhook.cacheRunbookName = convert.ToValue(p.Runbook.Name)
				}
			}
			res = append(res, webhook)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccount) hybridWorkerGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, name, err := a.accountScope()
	if err != nil {
		return nil, err
	}
	client, err := armautomation.NewHybridRunbookWorkerGroupClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByAutomationAccountPager(rg, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/read")
		}
		for _, g := range page.Value {
			if g == nil || g.ID == nil {
				continue
			}
			var groupType *string
			var credentialName string
			if p := g.Properties; p != nil {
				groupType = stringEnumPtr(p.GroupType)
				if p.Credential != nil {
					credentialName = convert.ToValue(p.Credential.Name)
				}
			}
			mqlG, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionAutomationServiceAccountHybridWorkerGroup,
				map[string]*llx.RawData{
					"id":        llx.StringDataPtr(g.ID),
					"name":      llx.StringDataPtr(g.Name),
					"groupType": llx.StringDataPtr(groupType),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(g.SystemData)
			if err != nil {
				return nil, err
			}
			group := mqlG.(*mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroup)
			group.cacheSystemData = sysData
			group.cacheAccount = a
			group.cacheCredentialName = credentialName
			res = append(res, group)
		}
	}
	return res, nil
}

// findByName returns the entry of an account's child list whose name matches,
// case-insensitively as ARM treats names. getName reads the entry's name.
func findByName[T plugin.Resource](list []any, name string, getName func(T) string) (T, bool) {
	var zero T
	if name == "" {
		return zero, false
	}
	for _, entry := range list {
		item, ok := entry.(T)
		if !ok {
			continue
		}
		if strings.EqualFold(getName(item), name) {
			return item, true
		}
	}
	return zero, false
}

func (a *mqlAzureSubscriptionAutomationServiceAccountWebhook) runbook() (*mqlAzureSubscriptionAutomationServiceAccountRunbook, error) {
	if a.cacheRunbookName == "" || a.cacheAccount == nil {
		a.Runbook.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account := a.cacheAccount
	runbooks := account.GetRunbooks()
	if runbooks.Error != nil {
		return nil, runbooks.Error
	}
	rb, ok := findByName(runbooks.Data, a.cacheRunbookName, func(r *mqlAzureSubscriptionAutomationServiceAccountRunbook) string { return r.Name.Data })
	if !ok {
		a.Runbook.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return rb, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountWebhook) hybridWorkerGroup() (*mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroup, error) {
	if a.cacheHybridGroupName == "" || a.cacheAccount == nil {
		a.HybridWorkerGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account := a.cacheAccount
	groups := account.GetHybridWorkerGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	g, ok := findByName(groups.Data, a.cacheHybridGroupName, func(r *mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroup) string { return r.Name.Data })
	if !ok {
		a.HybridWorkerGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return g, nil
}

func (a *mqlAzureSubscriptionAutomationServiceAccountHybridWorkerGroup) credential() (*mqlAzureSubscriptionAutomationServiceAccountCredential, error) {
	if a.cacheCredentialName == "" || a.cacheAccount == nil {
		a.Credential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account := a.cacheAccount
	creds := account.GetCredentials()
	if creds.Error != nil {
		return nil, creds.Error
	}
	c, ok := findByName(creds.Data, a.cacheCredentialName, func(r *mqlAzureSubscriptionAutomationServiceAccountCredential) string { return r.Name.Data })
	if !ok {
		a.Credential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return c, nil
}
