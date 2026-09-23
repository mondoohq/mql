// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
	"golang.org/x/sync/errgroup"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
)

func (a *mqlAzureSubscriptionNetworkService) id() (string, error) {
	return "azure.subscription.network/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionNetworkService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionNetworkService) interfaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewInterfacesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.InterfacesClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, iface := range page.Value {
			if iface == nil {
				continue
			}
			mqlAzure, err := azureInterfaceToMql(a.MqlRuntime, *iface)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) securityGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewSecurityGroupsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.SecurityGroupsClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, secgrp := range page.Value {
			if secgrp == nil {
				continue
			}
			mqlAzure, err := azureSecGroupToMql(a.MqlRuntime, *secgrp)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) watchers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewWatchersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.WatchersClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, watcher := range page.Value {
			if watcher == nil {
				continue
			}
			properties, err := convert.JsonToDict(watcher.Properties)
			if err != nil {
				return nil, err
			}
			// Properties is nullable on a transient or failed watcher; the
			// provisioning-state read below would deref it bare.
			var watcherProvisioningState *string
			if watcher.Properties != nil {
				watcherProvisioningState = (*string)(watcher.Properties.ProvisioningState)
			}

			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.watcher",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(watcher.ID),
					"name":              llx.StringDataPtr(watcher.Name),
					"location":          llx.StringDataPtr(watcher.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(watcher.Tags), types.String),
					"type":              llx.StringDataPtr(watcher.Type),
					"etag":              llx.StringDataPtr(watcher.Etag),
					"properties":        llx.DictData(properties),
					"provisioningState": llx.StringDataPtr(watcherProvisioningState),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) publicIpAddresses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewPublicIPAddressesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.PublicIPAddressesClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ip := range page.Value {
			if ip == nil {
				continue
			}
			mqlAzure, err := azureIpToMql(a.MqlRuntime, *ip)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) bastionHosts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewBastionHostsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&network.BastionHostsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, bh := range page.Value {
			if bh == nil {
				continue
			}
			properties, err := convert.JsonToDict(bh.Properties)
			if err != nil {
				return nil, err
			}
			sku, err := convert.JsonToDict(bh.SKU)
			if err != nil {
				return nil, err
			}
			var skuName string
			if bh.SKU != nil && bh.SKU.Name != nil {
				skuName = string(*bh.SKU.Name)
			}
			var disableCopyPaste, enableFileCopy, enableIPConnect, enableKerberos, enablePrivateOnlyBastion, enableSessionRecording, enableShareableLink, enableTunneling *bool
			var scaleUnits *int64
			allowedIPRules := []any{}
			if p := bh.Properties; p != nil {
				disableCopyPaste = p.DisableCopyPaste
				enableFileCopy = p.EnableFileCopy
				enableIPConnect = p.EnableIPConnect
				enableKerberos = p.EnableKerberos
				enablePrivateOnlyBastion = p.EnablePrivateOnlyBastion
				enableSessionRecording = p.EnableSessionRecording
				enableShareableLink = p.EnableShareableLink
				enableTunneling = p.EnableTunneling
				if p.ScaleUnits != nil {
					su := int64(*p.ScaleUnits)
					scaleUnits = &su
				}
				if p.NetworkACLs != nil {
					for _, rule := range p.NetworkACLs.IPRules {
						if rule != nil && rule.AddressPrefix != nil {
							allowedIPRules = append(allowedIPRules, *rule.AddressPrefix)
						}
					}
				}
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.bastionHost",
				map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(bh.ID),
					"name":                     llx.StringDataPtr(bh.Name),
					"location":                 llx.StringDataPtr(bh.Location),
					"tags":                     llx.MapData(convert.PtrMapStrToInterface(bh.Tags), types.String),
					"type":                     llx.StringDataPtr(bh.Type),
					"properties":               llx.DictData(properties),
					"sku":                      llx.DictData(sku),
					"skuName":                  llx.StringData(skuName),
					"disableCopyPaste":         llx.BoolDataPtr(disableCopyPaste),
					"enableFileCopy":           llx.BoolDataPtr(enableFileCopy),
					"enableIpConnect":          llx.BoolDataPtr(enableIPConnect),
					"enableKerberos":           llx.BoolDataPtr(enableKerberos),
					"enablePrivateOnlyBastion": llx.BoolDataPtr(enablePrivateOnlyBastion),
					"enableSessionRecording":   llx.BoolDataPtr(enableSessionRecording),
					"enableShareableLink":      llx.BoolDataPtr(enableShareableLink),
					"enableTunneling":          llx.BoolDataPtr(enableTunneling),
					"scaleUnits":               llx.IntDataPtr(scaleUnits),
					"allowedIpRules":           llx.ArrayData(allowedIPRules, types.String),
				})
			if err != nil {
				return nil, err
			}
			if bh.Properties != nil {
				mqlAzure.(*mqlAzureSubscriptionNetworkServiceBastionHost).cacheIPConfigurations = bh.Properties.IPConfigurations
			}
			res = append(res, mqlAzure)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceInterface) vm() (*mqlAzureSubscriptionComputeServiceVm, error) {
	props := a.Properties.Data
	if props == nil {
		a.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	propsMap, ok := props.(map[string]any)
	if !ok {
		a.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	vmRef, ok := propsMap["virtualMachine"]
	if !ok || vmRef == nil {
		a.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	vmMap, ok := vmRef.(map[string]any)
	if !ok {
		a.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	vmID, ok := vmMap["id"].(string)
	if !ok || vmID == "" {
		a.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.vm", map[string]*llx.RawData{
		"id": llx.StringData(strings.ToLower(vmID)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceVm), nil
}

// effectiveNsgGroup is one network security group in a NIC's effective-NSG
// chain, paired with the effective rules Azure computed for it. Inbound traffic
// must be admitted by every group in the chain (subnet-level NSG then NIC-level
// NSG) to reach the interface, so exposure evaluation is per-group rather than
// over a flattened rule set.
type effectiveNsgGroup struct {
	nsgID string
	rules []map[string]any
}

// effectiveNsgGroupsCached fetches the NIC's effective NSGs, memoizing the
// result for reuse by both the effectiveSecurityRules field and the VM exposure
// computation. Only successful fetches are cached: the effective-NSG call is a
// bounded Azure long-poll that can fail transiently (timeout), so an error is
// returned without being memoized, letting a later caller retry.
// The second return value reports whether Azure answered authoritatively. It
// is false when the effective-rules call degraded (denied, unavailable, or the
// NIC is not attached to a running VM), which must not be confused with an
// authoritative "this NIC has no NSG attached" — the latter means every inbound
// flow is admitted.
func (a *mqlAzureSubscriptionNetworkServiceInterface) effectiveNsgGroupsCached() ([]effectiveNsgGroup, bool, error) {
	a.effNsgMu.Lock()
	defer a.effNsgMu.Unlock()
	if a.effNsgLoaded {
		return a.effNsgGroups, a.effNsgEvaluated, nil
	}
	groups, evaluated, err := a.fetchEffectiveNsgGroups()
	if err != nil {
		return nil, false, err
	}
	a.effNsgGroups = groups
	a.effNsgEvaluated = evaluated
	a.effNsgLoaded = true
	return a.effNsgGroups, a.effNsgEvaluated, nil
}

// effectiveSecurityRules computes the merged NSG rules effective on this NIC
// (NSG attached to NIC + ASG + NSG attached to subnet), flattened across the
// effective-NSG chain. Lazily called per NIC.
//
// When Azure did not answer authoritatively -- a NIC on a deallocated VM, or a
// caller without the effectiveNetworkSecurityGroups action -- this reports null
// rather than an empty list. An empty list is a claim: it says this NIC has no
// effective rules, so a check of the form
// `.none(access == "Allow" && sourceAddressPrefix == "*")` passes over every
// stopped machine and every subscription the scanner cannot read the rules in.
func (a *mqlAzureSubscriptionNetworkServiceInterface) effectiveSecurityRules() ([]any, error) {
	groups, evaluated, err := a.effectiveNsgGroupsCached()
	if err != nil {
		return nil, err
	}
	if !evaluated {
		a.EffectiveSecurityRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := []any{}
	for _, g := range groups {
		for _, rule := range g.rules {
			res = append(res, rule)
		}
	}
	return res, nil
}

// azureAsyncPollInterval is how long to wait between polls of a long-running
// ARM operation. A variable so tests do not have to sleep through it.
var azureAsyncPollInterval = 2 * time.Second

// drainAndClose reads a response body to EOF and closes it, which is what
// returns the connection to the pool. Closing without draining makes net/http
// discard the connection instead of reusing it.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}

// pollAzureAsyncOperation follows the Location header of a 202 Accepted response
// until the operation reports its result, and returns that final response with
// its body still open for the caller to read and close.
//
// Every response the loop moves past is drained and closed here, on the success
// path and on every error path. That used to be a leak: the caller's
// `defer httpResp.Body.Close()` evaluates httpResp.Body when the defer statement
// runs rather than when the function returns, so it bound the very first
// response, which the loop had already closed on its way past, and the final
// response -- the one actually decoded -- was never closed at all. Azure answers
// 202 for any NIC attached to a running VM, so this fired on the success path,
// once per interface.
func pollAzureAsyncOperation(ctx context.Context, client *http.Client, resp *http.Response, bearer string) (*http.Response, error) {
	for resp.StatusCode == http.StatusAccepted {
		loc := resp.Header.Get("Location")
		if loc == "" {
			drainAndClose(resp.Body)
			return nil, errors.New("azure long-running operation returned 202 without a Location header")
		}
		select {
		case <-ctx.Done():
			drainAndClose(resp.Body)
			return nil, ctx.Err()
		case <-time.After(azureAsyncPollInterval):
		}
		pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
		if err != nil {
			drainAndClose(resp.Body)
			return nil, err
		}
		pollReq.Header.Set("Authorization", "Bearer "+bearer)
		pollReq.Header.Set("Accept", "application/json")
		next, err := client.Do(pollReq)
		if err != nil {
			drainAndClose(resp.Body)
			return nil, err
		}
		drainAndClose(resp.Body)
		resp = next
	}
	return resp, nil
}

// fetchEffectiveNsgGroups computes the effective NSGs on this NIC, one group per
// NSG in the effective chain. Azure only computes effective rules for NICs
// attached to a running VM; for detached or stopped NICs the API returns
// NicNotAssociatedWithVm or similar 400/404 errors. We treat those as "no
// effective NSGs" rather than failing the whole interfaces query.
func (a *mqlAzureSubscriptionNetworkServiceInterface) fetchEffectiveNsgGroups() ([]effectiveNsgGroup, bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	// Bound the long-poll so a stuck operation doesn't hang the interfaces query.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, false, err
	}
	nicName, err := resourceID.Component("networkInterfaces")
	if err != nil {
		return nil, false, err
	}

	// armnetwork v9 misshaped EffectiveNetworkSecurityGroup.TagMap (declared *string
	// while the API returns an object), so SDK unmarshalling failed and we fetch via
	// REST, plucking effectiveSecurityRules out as raw JSON. armnetwork v10 corrected
	// TagMap to map[string][]*string, so this could be switched back to the SDK client
	// (BeginGetEffectiveNetworkSecurityGroups) in a follow-up once verified live.
	tok, err := conn.Token().GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return nil, false, err
	}

	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces/%s/effectiveNetworkSecurityGroups?api-version=2024-05-01",
		resourceID.SubscriptionID, resourceID.ResourceGroup, nicName,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 60 * time.Second}
	httpResp, err := httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}

	// 202 Accepted → poll the Location header until the result is ready. We don't
	// fall back to Azure-AsyncOperation: that endpoint returns a status envelope
	// (`{"status": "InProgress"|"Succeeded"|"Failed"}`), not the effective-rules
	// payload, so a 200 from it would just be the loop exiting onto the wrong body.
	httpResp, err = pollAzureAsyncOperation(ctx, httpClient, httpResp, tok.Token)
	if err != nil {
		return nil, false, err
	}
	// Deferred after the poll, so it binds the body actually being read below.
	defer drainAndClose(httpResp.Body)

	if httpResp.StatusCode == http.StatusBadRequest ||
		httpResp.StatusCode == http.StatusNotFound ||
		httpResp.StatusCode == http.StatusForbidden {
		log.Warn().Str("nic", nicName).Int("status", httpResp.StatusCode).Msg("effective security rules unavailable for NIC")
		return nil, false, nil
	}
	if httpResp.StatusCode >= 400 {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, false, fmt.Errorf("effective NSG list returned %d: %s", httpResp.StatusCode, string(body))
	}

	var payload struct {
		Value []struct {
			NetworkSecurityGroup struct {
				ID string `json:"id"`
			} `json:"networkSecurityGroup"`
			EffectiveSecurityRules []map[string]any `json:"effectiveSecurityRules"`
		} `json:"value"`
	}
	if err := json.NewDecoder(httpResp.Body).Decode(&payload); err != nil {
		return nil, false, err
	}

	groups := make([]effectiveNsgGroup, 0, len(payload.Value))
	for _, ensg := range payload.Value {
		rules := make([]map[string]any, 0, len(ensg.EffectiveSecurityRules))
		for _, rule := range ensg.EffectiveSecurityRules {
			if rule == nil {
				continue
			}
			rules = append(rules, rule)
		}
		groups = append(groups, effectiveNsgGroup{nsgID: ensg.NetworkSecurityGroup.ID, rules: rules})
	}
	return groups, true, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWatcher) flowLogs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	name := a.Name.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	subId := resourceID.SubscriptionID
	client, err := network.NewFlowLogsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(resourceID.ResourceGroup, name, &network.FlowLogsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, flowLog := range page.Value {
			if flowLog == nil {
				continue
			}
			mqlFlowLog, err := flowLogToMql(a.MqlRuntime, *flowLog)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFlowLog)
		}
	}

	return res, nil
}

// flowLogRetentionPolicy and flowLogAnalyticsConfig mirror the Azure flow-log
// sub-objects, carrying the JSON tags used to build the resource's dict fields.
// They are package-level (not function-local) so the tag mapping can be
// unit-tested — the tags were previously scrambled, serializing values under
// the wrong keys.
type flowLogRetentionPolicy struct {
	Enabled       bool `json:"enabled"`
	RetentionDays int  `json:"retentionDays"`
}

type flowLogAnalyticsConfig struct {
	Enabled             bool   `json:"enabled"`
	AnalyticsInterval   int    `json:"analyticsInterval"`
	WorkspaceId         string `json:"workspaceId"`
	WorkspaceResourceId string `json:"workspaceResourceId"`
	WorkspaceRegion     string `json:"workspaceRegion"`
}

func flowLogToMql(runtime *plugin.Runtime, flowLog network.FlowLog) (*mqlAzureSubscriptionNetworkServiceWatcherFlowlog, error) {
	args := map[string]*llx.RawData{
		"id":       llx.StringDataPtr(flowLog.ID),
		"name":     llx.StringDataPtr(flowLog.Name),
		"location": llx.StringDataPtr(flowLog.Location),
		"tags":     llx.MapData(convert.PtrMapStrToInterface(flowLog.Tags), types.String),
		"type":     llx.StringDataPtr(flowLog.Type),
		"etag":     llx.StringDataPtr(flowLog.Etag),
	}

	if props := flowLog.Properties; props != nil {
		var retentionPolicy flowLogRetentionPolicy
		if rp := props.RetentionPolicy; rp != nil {
			retentionPolicy = flowLogRetentionPolicy{
				Enabled:       convert.ToValue(rp.Enabled),
				RetentionDays: int(convert.ToValue(rp.Days)),
			}
		}
		var flowLogAnalytics flowLogAnalyticsConfig
		if fac := props.FlowAnalyticsConfiguration; fac != nil && fac.NetworkWatcherFlowAnalyticsConfiguration != nil {
			nwfac := fac.NetworkWatcherFlowAnalyticsConfiguration
			flowLogAnalytics = flowLogAnalyticsConfig{
				Enabled:             convert.ToValue(nwfac.Enabled),
				AnalyticsInterval:   int(convert.ToValue(nwfac.TrafficAnalyticsInterval)),
				WorkspaceRegion:     convert.ToValue(nwfac.WorkspaceRegion),
				WorkspaceResourceId: convert.ToValue(nwfac.WorkspaceResourceID),
				WorkspaceId:         convert.ToValue(nwfac.WorkspaceID),
			}
		}
		var formatType *string
		var formatVersion *int32
		if f := props.Format; f != nil {
			formatType = (*string)(f.Type)
			formatVersion = f.Version
		}
		args["retentionEnabled"] = llx.BoolData(retentionPolicy.Enabled)
		args["retentionDays"] = llx.IntData(int64(retentionPolicy.RetentionDays))
		args["format"] = llx.StringDataPtr(formatType)
		args["version"] = llx.IntDataDefault(formatVersion, 0)
		args["enabled"] = llx.BoolDataPtr(props.Enabled)
		args["storageAccountId"] = llx.StringDataPtr(props.StorageID)
		args["targetResourceId"] = llx.StringDataPtr(props.TargetResourceID)
		args["targetResourceGuid"] = llx.StringDataPtr(props.TargetResourceGUID)
		args["provisioningState"] = llx.StringDataPtr((*string)(props.ProvisioningState))
		args["trafficAnalyticsEnabled"] = llx.BoolData(flowLogAnalytics.Enabled)
		args["trafficAnalyticsInterval"] = llx.IntData(int64(flowLogAnalytics.AnalyticsInterval))
		args["trafficAnalyticsWorkspaceId"] = llx.StringData(flowLogAnalytics.WorkspaceResourceId)
	}

	mqlFlowLog, err := CreateResource(runtime, "azure.subscription.networkService.watcher.flowlog", args)
	if err != nil {
		return nil, err
	}
	return mqlFlowLog.(*mqlAzureSubscriptionNetworkServiceWatcherFlowlog), nil
}

func (a *mqlAzureSubscriptionNetworkService) loadBalancers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewLoadBalancersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.LoadBalancersClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lb := range page.Value {
			if lb == nil {
				continue
			}
			lbProps, err := convert.JsonToDict(lb.Properties)
			if err != nil {
				return nil, err
			}
			var lbSkuName, lbSkuTier *string
			if lb.SKU != nil {
				lbSkuName = (*string)(lb.SKU.Name)
				lbSkuTier = (*string)(lb.SKU.Tier)
			}
			var lbMode string
			if lb.Properties != nil && lb.Properties.Mode != nil {
				lbMode = string(*lb.Properties.Mode)
			}
			mqlAzure, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.loadBalancer",
				map[string]*llx.RawData{
					"id":         llx.StringDataPtr(lb.ID),
					"name":       llx.StringDataPtr(lb.Name),
					"location":   llx.StringDataPtr(lb.Location),
					"etag":       llx.StringDataPtr(lb.Etag),
					"sku":        llx.StringDataPtr(lbSkuName),
					"skuTier":    llx.StringDataPtr(lbSkuTier),
					"mode":       llx.StringData(lbMode),
					"tags":       llx.MapData(convert.PtrMapStrToInterface(lb.Tags), types.String),
					"type":       llx.StringDataPtr(lb.Type),
					"properties": llx.DictData(lbProps),
				})
			if err != nil {
				return nil, err
			}
			mqlLb := mqlAzure.(*mqlAzureSubscriptionNetworkServiceLoadBalancer)
			mqlLb.cacheProperties = lb.Properties
			res = append(res, mqlLb)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceLoadBalancerInternal struct {
	cacheProperties *network.LoadBalancerPropertiesFormat
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) probes() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, p := range a.cacheProperties.Probes {
		if p == nil {
			continue
		}
		props, err := convert.JsonToDict(p.Properties)
		if err != nil {
			return nil, err
		}
		pp := orZero(p.Properties)
		mqlProbe, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.probe",
			map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(p.ID),
				"type":                      llx.StringDataPtr(p.Type),
				"name":                      llx.StringDataPtr(p.Name),
				"etag":                      llx.StringDataPtr(p.Etag),
				"properties":                llx.DictData(props),
				"port":                      llx.IntDataPtr(pp.Port),
				"protocol":                  llx.StringDataPtr(stringEnumPtr(pp.Protocol)),
				"intervalInSeconds":         llx.IntDataPtr(pp.IntervalInSeconds),
				"numberOfProbes":            llx.IntDataPtr(pp.NumberOfProbes),
				"probeThreshold":            llx.IntDataPtr(pp.ProbeThreshold),
				"requestPath":               llx.StringDataPtr(pp.RequestPath),
				"noHealthyBackendsBehavior": llx.StringDataPtr(stringEnumPtr(pp.NoHealthyBackendsBehavior)),
				"provisioningState":         llx.StringDataPtr(stringEnumPtr(pp.ProvisioningState)),
			})
		if err != nil {
			return nil, err
		}
		probe := mqlProbe.(*mqlAzureSubscriptionNetworkServiceProbe)
		probe.cacheLoadBalancer = a
		probe.cacheLoadBalancerRules = subResourceIDs(pp.LoadBalancingRules)
		res = append(res, probe)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) backendPools() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, bap := range a.cacheProperties.BackendAddressPools {
		if bap == nil {
			continue
		}
		props, err := convert.JsonToDict(bap.Properties)
		if err != nil {
			return nil, err
		}
		bp := orZero(bap.Properties)
		mqlBap, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.backendAddressPool",
			map[string]*llx.RawData{
				"id":                   llx.StringDataPtr(bap.ID),
				"type":                 llx.StringDataPtr(bap.Type),
				"name":                 llx.StringDataPtr(bap.Name),
				"etag":                 llx.StringDataPtr(bap.Etag),
				"properties":           llx.DictData(props),
				"drainPeriodInSeconds": llx.IntDataPtr(bp.DrainPeriodInSeconds),
				"location":             llx.StringDataPtr(bp.Location),
				"syncMode":             llx.StringDataPtr(stringEnumPtr(bp.SyncMode)),
				"provisioningState":    llx.StringDataPtr(stringEnumPtr(bp.ProvisioningState)),
			})
		if err != nil {
			return nil, err
		}
		pool := mqlBap.(*mqlAzureSubscriptionNetworkServiceBackendAddressPool)
		pool.cacheLoadBalancer = a
		pool.cacheLoadBalancerRules = subResourceIDs(bp.LoadBalancingRules)
		pool.cacheInboundNatRules = subResourceIDs(bp.InboundNatRules)
		pool.cacheOutboundRules = subResourceIDs(bp.OutboundRules)
		res = append(res, pool)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) frontendIpConfigs() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, ipConfig := range a.cacheProperties.FrontendIPConfigurations {
		if ipConfig == nil {
			continue
		}
		props, err := convert.JsonToDict(ipConfig.Properties)
		if err != nil {
			return nil, err
		}
		isPublic := false
		var privateIpAddress string
		var ddosCustomPolicyId string
		var publicIpAddressIDPtr, subnetIDPtr *string
		var enableConnectionTracking *bool
		if ipConfig.Properties != nil {
			enableConnectionTracking = ipConfig.Properties.EnableConnectionTracking
			if ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
				isPublic = true
				publicIpAddressIDPtr = ipConfig.Properties.PublicIPAddress.ID
			}
			if ipConfig.Properties.Subnet != nil {
				subnetIDPtr = ipConfig.Properties.Subnet.ID
			}
			if ipConfig.Properties.PrivateIPAddress != nil {
				privateIpAddress = *ipConfig.Properties.PrivateIPAddress
			}
			if ds := ipConfig.Properties.DdosSettings; ds != nil && ds.DdosCustomPolicy != nil {
				ddosCustomPolicyId = convert.ToValue(ds.DdosCustomPolicy.ID)
			}
		}

		mqlIpConfig, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.frontendIpConfig",
			map[string]*llx.RawData{
				"id":                 llx.StringDataPtr(ipConfig.ID),
				"type":               llx.StringDataPtr(ipConfig.Type),
				"name":               llx.StringDataPtr(ipConfig.Name),
				"etag":               llx.StringDataPtr(ipConfig.Etag),
				"zones":              llx.ArrayData(strPtrsToAny(ipConfig.Zones), types.String),
				"properties":         llx.DictData(props),
				"isPublic":           llx.BoolData(isPublic),
				"privateIpAddress":   llx.StringData(privateIpAddress),
				"ddosCustomPolicyId": llx.StringData(ddosCustomPolicyId),

				"enableConnectionTracking": llx.BoolDataPtr(enableConnectionTracking),
			})
		if err != nil {
			return nil, err
		}
		fic := mqlIpConfig.(*mqlAzureSubscriptionNetworkServiceFrontendIpConfig)
		fic.cachePublicIpAddressID = publicIpAddressIDPtr
		fic.cacheSubnetID = subnetIDPtr
		res = append(res, mqlIpConfig)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) inboundNatPools() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, natPool := range a.cacheProperties.InboundNatPools {
		if natPool == nil {
			continue
		}
		props, err := convert.JsonToDict(natPool.Properties)
		if err != nil {
			return nil, err
		}
		np := orZero(natPool.Properties)
		mqlNatPool, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.inboundNatPool",
			map[string]*llx.RawData{
				"id":                     llx.StringDataPtr(natPool.ID),
				"type":                   llx.StringDataPtr(natPool.Type),
				"name":                   llx.StringDataPtr(natPool.Name),
				"etag":                   llx.StringDataPtr(natPool.Etag),
				"properties":             llx.DictData(props),
				"backendPort":            llx.IntDataPtr(np.BackendPort),
				"frontendPortRangeStart": llx.IntDataPtr(np.FrontendPortRangeStart),
				"frontendPortRangeEnd":   llx.IntDataPtr(np.FrontendPortRangeEnd),
				"protocol":               llx.StringDataPtr(stringEnumPtr(np.Protocol)),
				"enableFloatingIp":       llx.BoolDataPtr(np.EnableFloatingIP),
				"enableTcpReset":         llx.BoolDataPtr(np.EnableTCPReset),
				"idleTimeoutInMinutes":   llx.IntDataPtr(np.IdleTimeoutInMinutes),
				"provisioningState":      llx.StringDataPtr(stringEnumPtr(np.ProvisioningState)),
			})
		if err != nil {
			return nil, err
		}
		pool := mqlNatPool.(*mqlAzureSubscriptionNetworkServiceInboundNatPool)
		pool.cacheLoadBalancer = a
		pool.cacheFrontendIpConfig = subResourceID(np.FrontendIPConfiguration)
		res = append(res, pool)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) inboundNatRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, natRule := range a.cacheProperties.InboundNatRules {
		if natRule == nil {
			continue
		}
		props, err := convert.JsonToDict(natRule.Properties)
		if err != nil {
			return nil, err
		}
		nr := orZero(natRule.Properties)
		mqlNatRule, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.inboundNatRule",
			map[string]*llx.RawData{
				"id":                     llx.StringDataPtr(natRule.ID),
				"type":                   llx.StringDataPtr(natRule.Type),
				"name":                   llx.StringDataPtr(natRule.Name),
				"etag":                   llx.StringDataPtr(natRule.Etag),
				"properties":             llx.DictData(props),
				"frontendPort":           llx.IntDataPtr(nr.FrontendPort),
				"frontendPortRangeStart": llx.IntDataPtr(nr.FrontendPortRangeStart),
				"frontendPortRangeEnd":   llx.IntDataPtr(nr.FrontendPortRangeEnd),
				"backendPort":            llx.IntDataPtr(nr.BackendPort),
				"protocol":               llx.StringDataPtr(stringEnumPtr(nr.Protocol)),
				"enableFloatingIp":       llx.BoolDataPtr(nr.EnableFloatingIP),
				"enableTcpReset":         llx.BoolDataPtr(nr.EnableTCPReset),
				"idleTimeoutInMinutes":   llx.IntDataPtr(nr.IdleTimeoutInMinutes),
				"provisioningState":      llx.StringDataPtr(stringEnumPtr(nr.ProvisioningState)),
			})
		if err != nil {
			return nil, err
		}
		rule := mqlNatRule.(*mqlAzureSubscriptionNetworkServiceInboundNatRule)
		rule.cacheLoadBalancer = a
		rule.cacheFrontendIpConfig = subResourceID(nr.FrontendIPConfiguration)
		rule.cacheBackendAddressPol = subResourceID(nr.BackendAddressPool)
		res = append(res, rule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) outboundRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, outboundRule := range a.cacheProperties.OutboundRules {
		if outboundRule == nil {
			continue
		}
		props, err := convert.JsonToDict(outboundRule.Properties)
		if err != nil {
			return nil, err
		}
		or := orZero(outboundRule.Properties)
		mqlOutbound, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.outboundRule",
			map[string]*llx.RawData{
				"__id":                   llx.StringData(subResourceCacheID(outboundRule.ID, a.Id.Data, "outboundRules", convert.ToValue(outboundRule.Name))),
				"id":                     llx.StringDataPtr(outboundRule.ID),
				"type":                   llx.StringDataPtr(outboundRule.Type),
				"name":                   llx.StringDataPtr(outboundRule.Name),
				"etag":                   llx.StringDataPtr(outboundRule.Etag),
				"properties":             llx.DictData(props),
				"protocol":               llx.StringDataPtr(stringEnumPtr(or.Protocol)),
				"allocatedOutboundPorts": llx.IntDataPtr(or.AllocatedOutboundPorts),
				"enableTcpReset":         llx.BoolDataPtr(or.EnableTCPReset),
				"idleTimeoutInMinutes":   llx.IntDataPtr(or.IdleTimeoutInMinutes),
				"provisioningState":      llx.StringDataPtr(stringEnumPtr(or.ProvisioningState)),
			})
		if err != nil {
			return nil, err
		}
		rule := mqlOutbound.(*mqlAzureSubscriptionNetworkServiceOutboundRule)
		rule.cacheLoadBalancer = a
		rule.cacheBackendAddressPol = subResourceID(or.BackendAddressPool)
		rule.cacheFrontendIpConfigs = subResourceIDs(or.FrontendIPConfigurations)
		res = append(res, rule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) loadBalancerRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, lbRule := range a.cacheProperties.LoadBalancingRules {
		if lbRule == nil {
			continue
		}
		props, err := convert.JsonToDict(lbRule.Properties)
		if err != nil {
			return nil, err
		}
		lr := orZero(lbRule.Properties)
		mqlLbRule, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.loadBalancerRule",
			map[string]*llx.RawData{
				"__id":                     llx.StringData(subResourceCacheID(lbRule.ID, a.Id.Data, "loadBalancingRules", convert.ToValue(lbRule.Name))),
				"id":                       llx.StringDataPtr(lbRule.ID),
				"type":                     llx.StringDataPtr(lbRule.Type),
				"name":                     llx.StringDataPtr(lbRule.Name),
				"etag":                     llx.StringDataPtr(lbRule.Etag),
				"properties":               llx.DictData(props),
				"frontendPort":             llx.IntDataPtr(lr.FrontendPort),
				"backendPort":              llx.IntDataPtr(lr.BackendPort),
				"protocol":                 llx.StringDataPtr(stringEnumPtr(lr.Protocol)),
				"disableOutboundSnat":      llx.BoolDataPtr(lr.DisableOutboundSnat),
				"enableConnectionTracking": llx.BoolDataPtr(lr.EnableConnectionTracking),
				"enableFloatingIp":         llx.BoolDataPtr(lr.EnableFloatingIP),
				"enableTcpReset":           llx.BoolDataPtr(lr.EnableTCPReset),
				"idleTimeoutInMinutes":     llx.IntDataPtr(lr.IdleTimeoutInMinutes),
				"loadDistribution":         llx.StringDataPtr(stringEnumPtr(lr.LoadDistribution)),
				"provisioningState":        llx.StringDataPtr(stringEnumPtr(lr.ProvisioningState)),
			})
		if err != nil {
			return nil, err
		}
		rule := mqlLbRule.(*mqlAzureSubscriptionNetworkServiceLoadBalancerRule)
		rule.cacheLoadBalancer = a
		rule.cacheFrontendIpConfig = subResourceID(lr.FrontendIPConfiguration)
		rule.cacheBackendAddressPol = subResourceID(lr.BackendAddressPool)
		rule.cacheBackendAddressPols = subResourceIDs(lr.BackendAddressPools)
		rule.cacheProbe = subResourceID(lr.Probe)
		res = append(res, rule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) natGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewNatGatewaysClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.NatGatewaysClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ng := range page.Value {
			if ng == nil {
				continue
			}
			mqlNg, err := azureNatGatewayToMql(a.MqlRuntime, *ng)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlNg)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) firewalls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := network.NewAzureFirewallsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.AzureFirewallsClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fw := range page.Value {
			if fw == nil {
				continue
			}
			mqlFw, err := azureFirewallToMql(a.MqlRuntime, *fw)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFw)
		}
	}
	return res, nil
}

// nestedResourceID extracts a nested ARM reference's id from a resource's
// decoded properties dict, e.g. properties.firewallPolicy.id.
//
// Returns "" when the reference is absent or the dict has an unexpected shape.
// Callers must treat that as a legitimate null: these references are optional
// on most resources (a firewall with classic rules has no policy, a
// forced-tunneling gateway ipconfig has no public IP), so an absent reference
// is the common case rather than an error. Every lookup is comma-ok because
// this walks JSON-decoded runtime data, where a bare assertion would panic and
// take the whole scan down with it.
func nestedResourceID(props any, key string) string {
	propsDict, ok := props.(map[string]any)
	if !ok {
		return ""
	}
	ref, ok := propsDict[key].(map[string]any)
	if !ok {
		return ""
	}
	id, _ := ref["id"].(string)
	return id
}

// nestedResourceIDs is the list counterpart of nestedResourceID: it pulls the
// ids out of a JSON-decoded array of resource references, skipping anything
// that is not shaped like one.
//
// Same reasoning as its sibling, and the same hazard. Several accessors used to
// walk these arrays with bare assertions -- props.Data.(map[string]any),
// value.([]any), entry.(map[string]any)["id"].(string) -- and an entry whose
// "id" the service omitted (populate() drops nil pointers, so a SubResource
// with no ID marshals without the key) made the last one panic on a nil. A
// panic in an accessor is unrecoverable: the executor runs blocks in
// goroutines, so it takes down the entire scan rather than one query.
func nestedResourceIDs(props any, key string) []string {
	propsDict, ok := props.(map[string]any)
	if !ok {
		return nil
	}
	entries, ok := propsDict[key].([]any)
	if !ok {
		return nil
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ref, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := ref["id"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) policy() (*mqlAzureSubscriptionNetworkServiceFirewallPolicy, error) {
	// A firewall using classic rule collections has no policy attached; that
	// is the normal state, not an error.
	strId := nestedResourceID(a.Properties.Data, "firewallPolicy")
	if strId == "" {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceFirewallPolicy,
		map[string]*llx.RawData{"id": llx.StringData(strId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceFirewallPolicy), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallIpConfig) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	// Management-only and forced-tunneling ip configurations carry no public
	// IP; report null rather than failing the field.
	strId := nestedResourceID(a.Properties.Data, "publicIPAddress")
	if strId == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceIpAddress,
		map[string]*llx.RawData{"id": llx.StringData(strId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayIpConfig) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	// Management-only and forced-tunneling ip configurations carry no public
	// IP; report null rather than failing the field.
	strId := nestedResourceID(a.Properties.Data, "publicIPAddress")
	if strId == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceIpAddress,
		map[string]*llx.RawData{"id": llx.StringData(strId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallIpConfig) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	strId := nestedResourceID(a.Properties.Data, "subnet")
	if strId == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the subnet's own init rather than fetched here, so a
	// subnet several resources sit on is fetched once for the scan instead of
	// once per resource pointing at it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceSubnet,
		map[string]*llx.RawData{"id": llx.StringData(strId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func (a *mqlAzureSubscriptionNetworkService) firewallPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := network.NewFirewallPoliciesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.FirewallPoliciesClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fwp := range page.Value {
			if fwp == nil {
				continue
			}
			mqlFw, err := azureFirewallPolicyToMql(a.MqlRuntime, *fwp)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFw)
		}
	}
	return res, nil
}

func azureVirtualNetworkToMql(runtime *plugin.Runtime, vn network.VirtualNetwork) (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	props, err := convert.JsonToDict(vn.Properties)
	if err != nil {
		return nil, err
	}
	subnets := []any{}
	if vn.Properties != nil {
		for _, s := range vn.Properties.Subnets {
			if s != nil {
				mqlSubnet, err := azureSubnetToMql(runtime, *s)
				if err != nil {
					return nil, err
				}
				subnets = append(subnets, mqlSubnet)
			}
		}
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(vn.ID),
		"name":       llx.StringDataPtr(vn.Name),
		"type":       llx.StringDataPtr(vn.Type),
		"location":   llx.StringDataPtr(vn.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(vn.Tags), types.String),
		"etag":       llx.StringDataPtr(vn.Etag),
		"properties": llx.DictData(props),
		"subnets":    llx.ArrayData(subnets, types.ResourceLike),
	}
	if vn.Properties != nil {
		args["enableDdosProtection"] = llx.BoolDataPtr(vn.Properties.EnableDdosProtection)
		args["enableVmProtection"] = llx.BoolDataPtr(vn.Properties.EnableVMProtection)
		args["provisioningState"] = llx.StringDataPtr((*string)(vn.Properties.ProvisioningState))
		args["flowTimeoutInMinutes"] = llx.IntDataPtr(vn.Properties.FlowTimeoutInMinutes)
		args["privateEndpointVNetPolicies"] = llx.StringDataPtr((*string)(vn.Properties.PrivateEndpointVNetPolicies))
		args["resourceGuid"] = llx.StringDataPtr(vn.Properties.ResourceGUID)
		bgpCommunities, err := convert.JsonToDict(vn.Properties.BgpCommunities)
		if err != nil {
			return nil, err
		}
		args["bgpCommunities"] = llx.DictData(bgpCommunities)
		if sgp := vn.Properties.SummarizedGatewayPrefixes; sgp != nil {
			args["summarizedGatewayPrefixes"] = llx.ArrayData(strPtrsToAny(sgp.AddressPrefixes), types.String)
		} else {
			args["summarizedGatewayPrefixes"] = llx.ArrayData([]any{}, types.String)
		}
		if vn.Properties.AddressSpace != nil {
			args["addressPrefixes"] = llx.ArrayData(strPtrsToAny(vn.Properties.AddressSpace.AddressPrefixes), types.String)
		} else {
			args["addressPrefixes"] = llx.ArrayData([]any{}, types.String)
		}
		if vn.Properties.Encryption != nil {
			args["encryptionEnabled"] = llx.BoolDataPtr(vn.Properties.Encryption.Enabled)
			args["encryptionEnforcement"] = llx.StringDataPtr((*string)(vn.Properties.Encryption.Enforcement))
		} else {
			args["encryptionEnabled"] = llx.BoolData(false)
			args["encryptionEnforcement"] = llx.StringData("")
		}
		if vn.Properties.DhcpOptions != nil {
			id := convert.ToValue(vn.ID) + "/dhcpOptions"
			dhcpOpts, err := CreateResource(runtime, "azure.subscription.networkService.virtualNetwork.dhcpOptions",
				map[string]*llx.RawData{
					"id":         llx.StringData(id),
					"dnsServers": llx.ArrayData(strPtrsToAny(vn.Properties.DhcpOptions.DNSServers), types.String),
				})
			if err != nil {
				return nil, err
			}
			args["dhcpOptions"] = llx.ResourceData(dhcpOpts, dhcpOpts.MqlName())
		} else {
			args["dhcpOptions"] = llx.NilData
		}
	} else {
		args["enableDdosProtection"] = llx.BoolData(false)
		args["enableVmProtection"] = llx.BoolData(false)
		args["provisioningState"] = llx.StringData("")
		args["flowTimeoutInMinutes"] = llx.IntData(0)
		args["addressPrefixes"] = llx.ArrayData([]any{}, types.String)
		args["encryptionEnabled"] = llx.BoolData(false)
		args["encryptionEnforcement"] = llx.StringData("")
		args["dhcpOptions"] = llx.NilData
		args["privateEndpointVNetPolicies"] = llx.StringData("")
		args["resourceGuid"] = llx.StringData("")
		args["bgpCommunities"] = llx.NilData
		args["summarizedGatewayPrefixes"] = llx.ArrayData([]any{}, types.String)
	}

	mqlVn, err := CreateResource(runtime, ResourceAzureSubscriptionNetworkServiceVirtualNetwork, args)
	if err != nil {
		return nil, err
	}
	res := mqlVn.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork)
	if vn.Properties != nil {
		if ng := vn.Properties.DefaultPublicNatGateway; ng != nil {
			res.cacheDefaultNatGatewayId = ng.ID
		}
		if plan := vn.Properties.DdosProtectionPlan; plan != nil {
			res.cacheDdosProtectionPlanId = plan.ID
		}
		res.cacheFlowLogs = vn.Properties.FlowLogs
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceVirtualNetworkInternal struct {
	cacheDefaultNatGatewayId  *string
	cacheDdosProtectionPlanId *string
	cacheFlowLogs             []*network.FlowLog
}

// defaultNatGateway resolves the typed default public NAT gateway that provides
// outbound SNAT for subnets in the virtual network that do not have their own
// NAT gateway. Returns null when no default NAT gateway is configured.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetwork) defaultNatGateway() (*mqlAzureSubscriptionNetworkServiceNatGateway, error) {
	if a.cacheDefaultNatGatewayId == nil || *a.cacheDefaultNatGatewayId == "" {
		a.DefaultNatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceNatGateway,
		map[string]*llx.RawData{"id": llx.StringData(*a.cacheDefaultNatGatewayId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceNatGateway), nil
}

// ddosProtectionPlan resolves the DDoS protection plan attached to the virtual
// network. Returns null when the network relies on the platform's basic
// protection, and when the attached plan lives in a subscription this
// credential cannot read.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetwork) ddosProtectionPlan() (*mqlAzureSubscriptionNetworkServiceDdosProtectionPlan, error) {
	id := convert.ToValue(a.cacheDdosProtectionPlanId)
	if id == "" {
		a.DdosProtectionPlan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceDdosProtectionPlan,
		map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		// A plan attached from another subscription is a supported
		// configuration and reads as forbidden or not-found here. Report the
		// absence rather than failing the virtual network.
		log.Warn().Err(err).Str("id", id).Msg("could not resolve DDoS protection plan")
		a.DdosProtectionPlan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlAzureSubscriptionNetworkServiceDdosProtectionPlan), nil
}

func initAzureSubscriptionNetworkServiceDdosProtectionPlan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	planName, err := azureId.Component("ddosProtectionPlans")
	if err != nil {
		return nil, nil, err
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	// Already fetched by an earlier reference: NewResource consults the cache
	// only after this init returns, so without this a plan shared by many
	// virtual networks is fetched once per network.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceDdosProtectionPlan, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewDdosProtectionPlansClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	plan, err := client.Get(context.Background(), azureId.ResourceGroup, planName, nil)
	if err != nil {
		return nil, nil, err
	}

	var provisioningState string
	if plan.Properties != nil && plan.Properties.ProvisioningState != nil {
		provisioningState = string(*plan.Properties.ProvisioningState)
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionNetworkServiceDdosProtectionPlan,
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(plan.ID),
			"name":              llx.StringDataPtr(plan.Name),
			"location":          llx.StringDataPtr(plan.Location),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(plan.Tags), types.String),
			"type":              llx.StringDataPtr(plan.Type),
			"etag":              llx.StringDataPtr(plan.Etag),
			"provisioningState": llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// flowLogs resolves the flow logs that target this virtual network. Returns an
// empty list when none are configured.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetwork) flowLogs() ([]any, error) {
	res := []any{}
	if len(a.cacheFlowLogs) == 0 {
		return res, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	for _, flowLog := range a.cacheFlowLogs {
		if flowLog == nil || flowLog.ID == nil {
			continue
		}
		// The flow logs embedded on the virtual network are ID-only
		// references (their Properties are nil), so resolve each by ID to
		// populate enabled, targetResourceId, retention, analytics, etc.
		resourceID, err := ParseResourceID(*flowLog.ID)
		if err != nil {
			return nil, err
		}
		watcherName, err := resourceID.Component("networkWatchers")
		if err != nil {
			return nil, err
		}
		flowLogName, err := resourceID.Component("flowLogs")
		if err != nil {
			return nil, err
		}
		client, err := network.NewFlowLogsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			return nil, err
		}
		flowLogRes, err := client.Get(ctx, resourceID.ResourceGroup, watcherName, flowLogName, &network.FlowLogsClientGetOptions{})
		if err != nil {
			return nil, err
		}
		mqlFlowLog, err := flowLogToMql(a.MqlRuntime, flowLogRes.FlowLog)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFlowLog)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) virtualNetworks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewVirtualNetworksClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.VirtualNetworksClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vn := range page.Value {
			if vn == nil {
				continue
			}
			mqlVn, err := azureVirtualNetworkToMql(a.MqlRuntime, *vn)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVn)
		}
	}
	return res, nil
}

func initAzureSubscriptionNetworkServiceVirtualNetwork(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure virtual network")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.networkService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	networkSvc := res.(*mqlAzureSubscriptionNetworkService)
	vnets := networkSvc.GetVirtualNetworks()
	if vnets.Error != nil {
		return nil, nil, vnets.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range vnets.Data {
		vnet := entry.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork)
		if vnet.Id.Data == id {
			return args, vnet, nil
		}
	}

	return nil, nil, errors.New("azure virtual network does not exist")
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetwork) peerings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := conn.SubId()

	client, err := network.NewVirtualNetworkPeeringsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// Extract resource group and vnet name from the ID
	// Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{name}
	id := a.Id.Data
	parts := strings.Split(id, "/")
	var rgName, vnetName string
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			rgName = parts[i+1]
		}
		if strings.EqualFold(p, "virtualNetworks") && i+1 < len(parts) {
			vnetName = parts[i+1]
		}
	}
	if rgName == "" || vnetName == "" {
		return nil, fmt.Errorf("could not parse resource group and vnet name from id: %s", id)
	}

	pager := client.NewListPager(rgName, vnetName, &network.VirtualNetworkPeeringsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Value {
			if p == nil {
				continue
			}
			if p.Properties == nil {
				continue
			}
			var remoteVnetId string
			if p.Properties.RemoteVirtualNetwork != nil && p.Properties.RemoteVirtualNetwork.ID != nil {
				remoteVnetId = *p.Properties.RemoteVirtualNetwork.ID
			}
			var remoteEncEnabled bool
			var remoteEncEnforcement string
			if p.Properties.RemoteVirtualNetworkEncryption != nil {
				if p.Properties.RemoteVirtualNetworkEncryption.Enabled != nil {
					remoteEncEnabled = *p.Properties.RemoteVirtualNetworkEncryption.Enabled
				}
				if p.Properties.RemoteVirtualNetworkEncryption.Enforcement != nil {
					remoteEncEnforcement = string(*p.Properties.RemoteVirtualNetworkEncryption.Enforcement)
				}
			}
			mqlPeering, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetwork.peering",
				map[string]*llx.RawData{
					"id":                                    llx.StringDataPtr(p.ID),
					"name":                                  llx.StringDataPtr(p.Name),
					"allowForwardedTraffic":                 llx.BoolDataPtr(p.Properties.AllowForwardedTraffic),
					"allowGatewayTransit":                   llx.BoolDataPtr(p.Properties.AllowGatewayTransit),
					"allowVirtualNetworkAccess":             llx.BoolDataPtr(p.Properties.AllowVirtualNetworkAccess),
					"useRemoteGateways":                     llx.BoolDataPtr(p.Properties.UseRemoteGateways),
					"peeringState":                          llx.StringDataPtr((*string)(p.Properties.PeeringState)),
					"peeringSyncLevel":                      llx.StringDataPtr((*string)(p.Properties.PeeringSyncLevel)),
					"provisioningState":                     llx.StringDataPtr((*string)(p.Properties.ProvisioningState)),
					"remoteVirtualNetworkEncryptionEnabled": llx.BoolData(remoteEncEnabled),
					"remoteVirtualNetworkEncryptionEnforcement": llx.StringData(remoteEncEnforcement),
				})
			if err != nil {
				return nil, err
			}
			mqlPeering.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkPeering).cacheRemoteVirtualNetworkId = remoteVnetId
			res = append(res, mqlPeering)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceVirtualNetworkPeeringInternal struct {
	cacheRemoteVirtualNetworkId string
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkPeering) id() (string, error) {
	return a.Id.Data, nil
}

// remoteVirtualNetwork resolves the typed remote virtual network on the far end
// of the peering from the cached remoteVirtualNetworkId. The remote network is
// fetched directly by its ARM resource ID so cross-subscription peerings resolve
// correctly. Returns null when the peering has no remote virtual network
// reference.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkPeering) remoteVirtualNetwork() (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	if a.cacheRemoteVirtualNetworkId == "" {
		a.RemoteVirtualNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Answer a repeated reference from the cache; the fetch below stays,
	// because a peer often lives in another subscription, which this subscription's vnet
	// list cannot answer for.
	if cached := cachedResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceVirtualNetwork, a.cacheRemoteVirtualNetworkId); cached != nil {
		return cached.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	resourceID, err := ParseResourceID(a.cacheRemoteVirtualNetworkId)
	if err != nil {
		return nil, err
	}
	vnetName, err := resourceID.Component("virtualNetworks")
	if err != nil {
		return nil, err
	}
	client, err := network.NewVirtualNetworksClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	vnetRes, err := client.Get(ctx, resourceID.ResourceGroup, vnetName, &network.VirtualNetworksClientGetOptions{})
	if err != nil {
		return nil, err
	}
	return azureVirtualNetworkToMql(a.MqlRuntime, vnetRes.VirtualNetwork)
}

func (a *mqlAzureSubscriptionNetworkService) applicationSecurityGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewApplicationSecurityGroupsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.ApplicationSecurityGroupsClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, asg := range page.Value {
			if asg == nil {
				continue
			}
			mqlAppSecGroup, err := azureAppSecurityGroupToMql(a.MqlRuntime, *asg)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAppSecGroup)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) virtualNetworkGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewVirtualNetworkGatewaysClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// the virtual network gateways API works on resource-group level. therefore, we need to fetch all RGs first
	// __id has to be explicit: azure.subscription.id() reads the `id` field,
	// which these args do not carry, so without it every such reference shares
	// the empty cache key and resolves to whichever subscription got there first.
	sub, err := CreateResource(a.MqlRuntime, "azure.subscription", map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + subId),
		"subscriptionId": llx.StringData(subId),
	})
	if err != nil {
		return nil, err
	}
	azureSub := sub.(*mqlAzureSubscription)
	rgs := azureSub.GetResourceGroups()
	if rgs.Error != nil {
		return nil, rgs.Error
	}
	res := []any{}
	for _, rg := range rgs.Data {
		mqlRg := rg.(*mqlAzureSubscriptionResourcegroup)
		pager := client.NewListPager(mqlRg.Name.Data, &network.VirtualNetworkGatewaysClientListOptions{})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, vng := range page.Value {
				if vng == nil {
					continue
				}
				// Properties and the nested SKU are nullable pointers; a gateway
				// in a transient/failed state can return either as nil. The args
				// map below dereferences them throughout, so normalize to empty
				// structs to avoid a scan-killing panic.
				if vng.Properties == nil {
					vng.Properties = &network.VirtualNetworkGatewayPropertiesFormat{}
				}
				if vng.Properties.SKU == nil {
					vng.Properties.SKU = &network.VirtualNetworkGatewaySKU{}
				}
				props, err := convert.JsonToDict(vng.Properties)
				if err != nil {
					return nil, err
				}
				args := map[string]*llx.RawData{
					"id":                              llx.StringDataPtr(vng.ID),
					"name":                            llx.StringDataPtr(vng.Name),
					"type":                            llx.StringDataPtr(vng.Type),
					"location":                        llx.StringDataPtr(vng.Location),
					"tags":                            llx.MapData(convert.PtrMapStrToInterface(vng.Tags), types.String),
					"etag":                            llx.StringDataPtr(vng.Etag),
					"active":                          llx.BoolDataPtr(vng.Properties.Active),
					"enableBgp":                       llx.BoolDataPtr(vng.Properties.EnableBgp),
					"enableBgpRouteTranslationForNat": llx.BoolDataPtr(vng.Properties.EnableBgpRouteTranslationForNat),
					"enableDNSForwarding":             llx.BoolDataPtr(vng.Properties.EnableDNSForwarding),
					"enablePrivateIPAddress":          llx.BoolDataPtr(vng.Properties.EnablePrivateIPAddress),
					"disableIPSecReplayProtection":    llx.BoolDataPtr(vng.Properties.DisableIPSecReplayProtection),
					"inboundDNSForwardingEndpoint":    llx.StringDataPtr(vng.Properties.InboundDNSForwardingEndpoint),
					"skuName":                         llx.StringDataPtr((*string)(vng.Properties.SKU.Name)),
					"skuCapacity":                     llx.IntDataDefault(vng.Properties.SKU.Capacity, 0),
					"provisioningState":               llx.StringDataPtr((*string)(vng.Properties.ProvisioningState)),
					"properties":                      llx.DictData(props),
					"vpnType":                         llx.StringDataPtr((*string)(vng.Properties.VPNType)),
					"vpnGatewayGeneration":            llx.StringDataPtr((*string)(vng.Properties.VPNGatewayGeneration)),
					"gatewayType":                     llx.StringDataPtr((*string)(vng.Properties.GatewayType)),
				}
				if vng.Properties.CustomRoutes != nil {
					args["addressPrefixes"] = llx.ArrayData(strPtrsToAny(vng.Properties.CustomRoutes.AddressPrefixes), types.String)
				} else {
					args["addressPrefixes"] = llx.ArrayData([]any{}, types.String)
				}
				vpnClientAuthTypes := []any{}
				vpnClientAddressPool := []any{}
				var aadTenant, aadAudience, aadIssuer string
				radiusConfigured := false
				if vc := vng.Properties.VPNClientConfiguration; vc != nil {
					for _, at := range vc.VPNAuthenticationTypes {
						if at != nil {
							vpnClientAuthTypes = append(vpnClientAuthTypes, string(*at))
						}
					}
					if vc.VPNClientAddressPool != nil {
						vpnClientAddressPool = strPtrsToAny(vc.VPNClientAddressPool.AddressPrefixes)
					}
					aadTenant = convert.ToValue(vc.AADTenant)
					aadAudience = convert.ToValue(vc.AADAudience)
					aadIssuer = convert.ToValue(vc.AADIssuer)
					radiusConfigured = (vc.RadiusServerAddress != nil && *vc.RadiusServerAddress != "") || len(vc.RadiusServers) > 0
				}
				args["vpnClientAuthenticationTypes"] = llx.ArrayData(vpnClientAuthTypes, types.String)
				args["vpnClientAddressPool"] = llx.ArrayData(vpnClientAddressPool, types.String)
				args["aadTenant"] = llx.StringData(aadTenant)
				args["aadAudience"] = llx.StringData(aadAudience)
				args["aadIssuer"] = llx.StringData(aadIssuer)
				args["radiusAuthenticationConfigured"] = llx.BoolData(radiusConfigured)
				mqlVn, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkGateway", args)
				if err != nil {
					return nil, err
				}
				mqlGw := mqlVn.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway)
				mqlGw.cacheProperties = vng.Properties
				res = append(res, mqlGw)
			}
		}
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayInternal struct {
	cacheProperties *network.VirtualNetworkGatewayPropertiesFormat
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) bgpSettings() (*mqlAzureSubscriptionNetworkServiceBgpSettings, error) {
	if a.cacheProperties == nil || a.cacheProperties.BgpSettings == nil {
		a.BgpSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlBgpSettingsFromSdk(a.MqlRuntime, a.Id.Data, a.cacheProperties.BgpSettings)
}

func mqlBgpSettingsFromSdk(runtime *plugin.Runtime, parentId string, bgp *network.BgpSettings) (*mqlAzureSubscriptionNetworkServiceBgpSettings, error) {
	bgpSettingsId := parentId + "/bgpSettings"
	bgpPeeringAddresses := []any{}
	for i, bpa := range bgp.BgpPeeringAddresses {
		// ARM models every element of this slice as an optional pointer. A nil
		// one panics on the first field read, and a panic here kills the scan
		// rather than this gateway.
		if bpa == nil {
			continue
		}
		bpaId := fmt.Sprintf("%s/%s/%d", bgpSettingsId, "bgpPeeringAddresses", i)
		mqlBpa, err := CreateResource(runtime, "azure.subscription.networkService.bgpSettings.ipConfigurationBgpPeeringAddress",
			map[string]*llx.RawData{
				"id":                    llx.StringData(bpaId),
				"customBgpIpAddresses":  llx.ArrayData(strPtrsToAny(bpa.CustomBgpIPAddresses), types.String),
				"defaultBgpIpAddresses": llx.ArrayData(strPtrsToAny(bpa.DefaultBgpIPAddresses), types.String),
				"tunnelIpAddresses":     llx.ArrayData(strPtrsToAny(bpa.TunnelIPAddresses), types.String),
				"ipConfigurationId":     llx.StringDataPtr(bpa.IPConfigurationID),
			})
		if err != nil {
			return nil, err
		}
		bgpPeeringAddresses = append(bgpPeeringAddresses, mqlBpa)
	}
	mqlBgp, err := CreateResource(runtime, "azure.subscription.networkService.bgpSettings",
		map[string]*llx.RawData{
			"id":                        llx.StringData(bgpSettingsId),
			"asn":                       llx.IntDataPtr(bgp.Asn),
			"bgpPeeringAddress":         llx.StringDataPtr(bgp.BgpPeeringAddress),
			"peerWeight":                llx.IntDataDefault(bgp.PeerWeight, 0),
			"bgpPeeringAddressesConfig": llx.ArrayData(bgpPeeringAddresses, types.ResourceLike),
		})
	if err != nil {
		return nil, err
	}
	return mqlBgp.(*mqlAzureSubscriptionNetworkServiceBgpSettings), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) ipConfigurations() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, ipc := range a.cacheProperties.IPConfigurations {
		if ipc == nil {
			continue
		}
		props, err := convert.JsonToDict(ipc.Properties)
		if err != nil {
			return nil, err
		}
		var privateIP *string
		if ipc.Properties != nil {
			privateIP = ipc.Properties.PrivateIPAddress
		}
		mqlIpc, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkGateway.ipConfig", map[string]*llx.RawData{
			"id":               llx.StringDataPtr(ipc.ID),
			"name":             llx.StringDataPtr(ipc.Name),
			"etag":             llx.StringDataPtr(ipc.Etag),
			"properties":       llx.DictData(props),
			"privateIpAddress": llx.StringDataPtr(privateIP),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIpc)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) natRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, nr := range a.cacheProperties.NatRules {
		if nr == nil {
			continue
		}
		props, err := convert.JsonToDict(nr.Properties)
		if err != nil {
			return nil, err
		}

		var mode, natRuleType, ipConfigurationID, provisioningState *string
		internalMappings := []any{}
		externalMappings := []any{}
		if p := nr.Properties; p != nil {
			mode = stringEnumPtr(p.Mode)
			natRuleType = stringEnumPtr(p.Type)
			provisioningState = stringEnumPtr(p.ProvisioningState)
			ipConfigurationID = p.IPConfigurationID
			internalMappings, err = vpnNatRuleMappingsToDict(p.InternalMappings)
			if err != nil {
				return nil, err
			}
			externalMappings, err = vpnNatRuleMappingsToDict(p.ExternalMappings)
			if err != nil {
				return nil, err
			}
		}

		mqlNr, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceVirtualNetworkGatewayNatRule, map[string]*llx.RawData{
			"id":                llx.StringDataPtr(nr.ID),
			"name":              llx.StringDataPtr(nr.Name),
			"etag":              llx.StringDataPtr(nr.Etag),
			"properties":        llx.DictData(props),
			"mode":              llx.StringDataPtr(mode),
			"natRuleType":       llx.StringDataPtr(natRuleType),
			"internalMappings":  llx.ArrayData(internalMappings, types.Dict),
			"externalMappings":  llx.ArrayData(externalMappings, types.Dict),
			"ipConfigurationId": llx.StringDataPtr(ipConfigurationID),
			"provisioningState": llx.StringDataPtr(provisioningState),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNr)
	}
	return res, nil
}

// vpnNatRuleMappingsToDict converts VPN NAT rule address-space/port-range
// mappings into dicts, skipping nil entries.
func vpnNatRuleMappingsToDict(mappings []*network.VPNNatRuleMapping) ([]any, error) {
	res := []any{}
	for _, m := range mappings {
		if m == nil {
			continue
		}
		d, err := convert.JsonToDict(m)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayNatRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkService) applicationGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewApplicationGatewaysClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListAllPager(&network.ApplicationGatewaysClientListAllOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ag := range page.Value {
			if ag == nil {
				continue
			}
			mqlAg, err := azureAppGatewayToMql(a.MqlRuntime, *ag)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAg)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWafConfig) id() (string, error) {
	return a.Id.Data, nil
}

// wafConfiguration returns the legacy WAF configuration attached directly to
// the application gateway (v1 SKUs). The configuration is an inline block on
// the gateway itself, so at most one entry is ever returned; gateways using a
// standalone WAF policy return an empty list and expose it through policy()
// instead.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGateway) wafConfiguration() ([]any, error) {
	res := []any{}
	if a.cacheWafConfiguration == nil {
		return res, nil
	}

	props, err := convert.JsonToDict(a.cacheWafConfiguration)
	if err != nil {
		return nil, err
	}
	cfg := a.cacheWafConfiguration
	// The WAF configuration is an inline block with no ARM identity of its
	// own; key it and its rule groups off the parent gateway.
	configID := a.Id.Data + "/webApplicationFirewallConfiguration"

	disabledRuleGroups := []any{}
	for i, g := range cfg.DisabledRuleGroups {
		if g == nil {
			continue
		}
		rules := []any{}
		for _, r := range g.Rules {
			if r != nil {
				rules = append(rules, int64(*r))
			}
		}
		key := convert.ToValue(g.RuleGroupName)
		if key == "" {
			key = strconv.Itoa(i)
		}
		mqlGroup, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.wafConfig.disabledRuleGroup",
			map[string]*llx.RawData{
				"__id":          llx.StringData(subResourceCacheID(nil, configID, "disabledRuleGroups", key)),
				"ruleGroupName": llx.StringDataPtr(g.RuleGroupName),
				"rules":         llx.ArrayData(rules, types.Int),
			})
		if err != nil {
			return nil, err
		}
		disabledRuleGroups = append(disabledRuleGroups, mqlGroup)
	}

	mqlAzure, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceWafConfig,
		map[string]*llx.RawData{
			"id":         llx.StringData(configID),
			"name":       llx.NilData,
			"type":       llx.NilData,
			"kind":       llx.NilData,
			"properties": llx.DictData(props),
			// MaxRequestBodySize is the deprecated byte-valued sibling of
			// MaxRequestBodySizeInKb and is deliberately not modeled.
			"enabled":                llx.BoolDataPtr(cfg.Enabled),
			"firewallMode":           llx.StringDataPtr(stringEnumPtr(cfg.FirewallMode)),
			"ruleSetType":            llx.StringDataPtr(cfg.RuleSetType),
			"ruleSetVersion":         llx.StringDataPtr(cfg.RuleSetVersion),
			"requestBodyCheck":       llx.BoolDataPtr(cfg.RequestBodyCheck),
			"maxRequestBodySizeInKb": llx.IntDataPtr(cfg.MaxRequestBodySizeInKb),
			"fileUploadLimitInMb":    llx.IntDataPtr(cfg.FileUploadLimitInMb),
			"disabledRuleGroups":     llx.ArrayData(disabledRuleGroups, types.Resource("azure.subscription.networkService.wafConfig.disabledRuleGroup")),
		})
	if err != nil {
		return nil, err
	}
	res = append(res, mqlAzure)
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) applicationFirewallPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewWebApplicationFirewallPoliciesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListAllPager(&network.WebApplicationFirewallPoliciesClientListAllOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, waf := range page.Value {
			if waf == nil {
				continue
			}
			mqlWaf, err := azureAppFirewallPolicyToMql(a.MqlRuntime, *waf)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlWaf)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkService) privateEndpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewPrivateEndpointsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(&network.PrivateEndpointsClientListBySubscriptionOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pe := range page.Value {
			mqlPe, err := privateEndpointToMql(a.MqlRuntime, pe)
			if err != nil {
				return nil, err
			}
			if mqlPe == nil {
				continue
			}
			res = append(res, mqlPe)
		}
	}
	return res, nil
}

func privateEndpointToMql(runtime *plugin.Runtime, pe *network.PrivateEndpoint) (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	if pe == nil {
		return nil, nil
	}

	var provisioningState, subnetId, customNicName, billingSku string
	var plsConns, manualPlsConns []any
	var nicIDs []string

	if pe.Properties != nil {
		if pe.Properties.ProvisioningState != nil {
			provisioningState = string(*pe.Properties.ProvisioningState)
		}
		if pe.Properties.Subnet != nil {
			subnetId = convert.ToValue(pe.Properties.Subnet.ID)
		}
		customNicName = convert.ToValue(pe.Properties.CustomNetworkInterfaceName)
		if pe.Properties.BillingSKU != nil {
			billingSku = string(*pe.Properties.BillingSKU)
		}
		for _, nic := range pe.Properties.NetworkInterfaces {
			if nic != nil && nic.ID != nil {
				nicIDs = append(nicIDs, *nic.ID)
			}
		}

		peID := convert.ToValue(pe.ID)
		// the two collections can hold connections of the same name, so the
		// collection segment has to be part of the fallback cache key
		for _, c := range pe.Properties.PrivateLinkServiceConnections {
			mqlConn, err := privateLinkServiceConnectionToMql(runtime, c, peID, "privateLinkServiceConnections")
			if err != nil {
				return nil, err
			}
			plsConns = append(plsConns, mqlConn)
		}
		for _, c := range pe.Properties.ManualPrivateLinkServiceConnections {
			mqlConn, err := privateLinkServiceConnectionToMql(runtime, c, peID, "manualPrivateLinkServiceConnections")
			if err != nil {
				return nil, err
			}
			manualPlsConns = append(manualPlsConns, mqlConn)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.privateEndpoint",
		map[string]*llx.RawData{
			"__id":                                llx.StringDataPtr(pe.ID),
			"id":                                  llx.StringDataPtr(pe.ID),
			"name":                                llx.StringDataPtr(pe.Name),
			"location":                            llx.StringDataPtr(pe.Location),
			"tags":                                llx.MapData(convert.PtrMapStrToInterface(pe.Tags), types.String),
			"type":                                llx.StringDataPtr(pe.Type),
			"provisioningState":                   llx.StringData(provisioningState),
			"customNetworkInterfaceName":          llx.StringData(customNicName),
			"billingSku":                          llx.StringData(billingSku),
			"privateLinkServiceConnections":       llx.ArrayData(plsConns, types.ResourceLike),
			"manualPrivateLinkServiceConnections": llx.ArrayData(manualPlsConns, types.ResourceLike),
		})
	if err != nil {
		return nil, err
	}
	mqlPe := res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint)
	mqlPe.cacheNetworkInterfaceIDs = nicIDs
	mqlPe.cacheSubnetId = subnetId
	return mqlPe, nil
}

type mqlAzureSubscriptionNetworkServicePrivateEndpointInternal struct {
	cacheNetworkInterfaceIDs []string
	cacheSubnetId            string
}

// subnet resolves the subnet the private endpoint's network interface is
// allocated in, the network location from which the linked resource is
// privately reachable.
func (a *mqlAzureSubscriptionNetworkServicePrivateEndpoint) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetId == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheSubnetId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

// networkInterfaces resolves the interfaces holding the private endpoint's
// private IPs so their effective security rules and routes can be examined.
func (a *mqlAzureSubscriptionNetworkServicePrivateEndpoint) networkInterfaces() ([]any, error) {
	res := make([]any, 0, len(a.cacheNetworkInterfaceIDs))
	for _, id := range a.cacheNetworkInterfaceIDs {
		if id == "" {
			continue
		}
		nic, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.interface",
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		res = append(res, nic)
	}
	return res, nil
}

// initAzureSubscriptionNetworkServiceInterface resolves a network interface
// referenced only by its resource ID (e.g. from a private endpoint) by fetching
// it on demand. When the interface was already listed by interfaces() the
// runtime cache short-circuits this and the init never runs.
func initAzureSubscriptionNetworkServiceInterface(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return args, nil, nil
	}
	name, err := resourceID.Component("networkInterfaces")
	if err != nil {
		return args, nil, nil
	}

	// The subscription's interface list already holds this one, and holds it
	// for every other reference to it too. Only pay for a Get when the list
	// cannot answer -- an interface in another subscription, or one since
	// deleted.
	if iface := lookupInServiceList(runtime, ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] { return s.GetInterfaces() },
		id); iface != nil {
		return args, iface, nil
	}

	client, err := network.NewInterfacesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), resourceID.ResourceGroup, name, nil)
	if err != nil {
		// The interface may be inaccessible (deleted, cross-subscription, or
		// access denied); fall back to the bare reference rather than failing
		// the surrounding query.
		return args, nil, nil
	}
	mqlIface, err := azureInterfaceToMql(runtime, resp.Interface)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlIface, nil
}

func initAzureSubscriptionNetworkServicePrivateEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := resourceID.Component("privateEndpoints")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServicePrivateEndpoint, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewPrivateEndpointsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), resourceID.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mqlPe, err := privateEndpointToMql(runtime, &resp.PrivateEndpoint)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlPe, nil
}

// privateDnsZoneGroups fetches the Private DNS Zone Groups attached to this PE.
// Each group lists which Private DNS zones records will be auto-registered into.
func (a *mqlAzureSubscriptionNetworkServicePrivateEndpoint) privateDnsZoneGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	peName, err := resourceID.Component("privateEndpoints")
	if err != nil {
		return nil, err
	}

	client, err := network.NewPrivateDNSZoneGroupsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(peName, resourceID.ResourceGroup, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, g := range page.Value {
			if g == nil {
				continue
			}
			entry := map[string]any{
				"id":   convert.ToValue(g.ID),
				"name": convert.ToValue(g.Name),
			}
			if g.Properties != nil {
				var zoneIds []any
				var configs []any
				for _, c := range g.Properties.PrivateDNSZoneConfigs {
					if c == nil {
						continue
					}
					ce := map[string]any{
						"name": convert.ToValue(c.Name),
					}
					if c.Properties != nil && c.Properties.PrivateDNSZoneID != nil {
						ce["privateDnsZoneId"] = *c.Properties.PrivateDNSZoneID
						zoneIds = append(zoneIds, *c.Properties.PrivateDNSZoneID)
					}
					configs = append(configs, ce)
				}
				entry["privateDnsZoneIds"] = zoneIds
				entry["configs"] = configs
				if g.Properties.ProvisioningState != nil {
					entry["provisioningState"] = string(*g.Properties.ProvisioningState)
				}
			}
			res = append(res, entry)
		}
	}
	return res, nil
}

func privateLinkServiceConnectionToMql(runtime *plugin.Runtime, c *network.PrivateLinkServiceConnection, parentID, collection string) (*mqlAzureSubscriptionNetworkServicePrivateEndpointServiceconnection, error) {
	if c == nil {
		return nil, errors.New("private link service connection is nil")
	}

	var plsId, connectionStatus, requestMessage string
	var groupIds []any

	if c.Properties != nil {
		plsId = convert.ToValue(c.Properties.PrivateLinkServiceID)
		requestMessage = convert.ToValue(c.Properties.RequestMessage)
		if c.Properties.PrivateLinkServiceConnectionState != nil {
			connectionStatus = convert.ToValue(c.Properties.PrivateLinkServiceConnectionState.Status)
		}
		for _, gid := range c.Properties.GroupIDs {
			if gid != nil {
				groupIds = append(groupIds, *gid)
			}
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.privateEndpoint.serviceconnection",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(subResourceCacheID(c.ID, parentID, collection, convert.ToValue(c.Name))),
			"id":                   llx.StringDataPtr(c.ID),
			"name":                 llx.StringDataPtr(c.Name),
			"privateLinkServiceId": llx.StringData(plsId),
			"groupIds":             llx.ArrayData(groupIds, types.String),
			"connectionStatus":     llx.StringData(connectionStatus),
			"requestMessage":       llx.StringData(requestMessage),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpointServiceconnection), nil
}

func (a *mqlAzureSubscriptionNetworkServicePrivateEndpointServiceconnection) privateLinkService() (*mqlAzureSubscriptionNetworkServicePrivateLinkService, error) {
	// A connection to a first-party PaaS resource puts that resource's own ARM
	// id in privateLinkServiceId, so there is no private link service to
	// resolve. privateLinkServiceId still reports the target.
	if _, ok := parsePrivateLinkServiceID(a.PrivateLinkServiceId.Data); !ok {
		a.PrivateLinkService.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.privateLinkService", map[string]*llx.RawData{
		"id": llx.StringData(a.PrivateLinkServiceId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateLinkService), nil
}

func (a *mqlAzureSubscriptionNetworkServicePrivateLinkService) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServicePrivateLinkServicePrivateEndpointConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkService) privateLinkServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewPrivateLinkServicesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pls := range page.Value {
			mqlPls, err := privateLinkServiceToMql(a.MqlRuntime, pls)
			if err != nil {
				return nil, err
			}
			if mqlPls == nil {
				continue
			}
			res = append(res, mqlPls)
		}
	}
	return res, nil
}

func privateLinkServiceToMql(runtime *plugin.Runtime, pls *network.PrivateLinkService) (*mqlAzureSubscriptionNetworkServicePrivateLinkService, error) {
	if pls == nil {
		return nil, nil
	}

	var (
		provisioningState, accessMode string
		enableProxyPtr                *bool
		fqdns                         []any
		visibility                    []any
		autoApproval                  []any
		ipConfigs                     []any
		lbFrontendIds                 []any
		nicIds                        []any
	)

	var aliasPtr, destIPPtr *string
	if pls.Properties != nil {
		if pls.Properties.ProvisioningState != nil {
			provisioningState = string(*pls.Properties.ProvisioningState)
		}
		aliasPtr = pls.Properties.Alias
		if pls.Properties.AccessMode != nil {
			accessMode = string(*pls.Properties.AccessMode)
		}
		destIPPtr = pls.Properties.DestinationIPAddress
		enableProxyPtr = pls.Properties.EnableProxyProtocol

		for _, f := range pls.Properties.Fqdns {
			if f != nil {
				fqdns = append(fqdns, *f)
			}
		}
		if pls.Properties.Visibility != nil {
			for _, s := range pls.Properties.Visibility.Subscriptions {
				if s != nil {
					visibility = append(visibility, *s)
				}
			}
		}
		if pls.Properties.AutoApproval != nil {
			for _, s := range pls.Properties.AutoApproval.Subscriptions {
				if s != nil {
					autoApproval = append(autoApproval, *s)
				}
			}
		}
		for _, ipc := range pls.Properties.IPConfigurations {
			if ipc == nil {
				continue
			}
			entry := map[string]any{
				"id":   convert.ToValue(ipc.ID),
				"name": convert.ToValue(ipc.Name),
			}
			if ipc.Properties != nil {
				if ipc.Properties.Primary != nil {
					entry["primary"] = *ipc.Properties.Primary
				}
				entry["privateIPAddress"] = convert.ToValue(ipc.Properties.PrivateIPAddress)
				if ipc.Properties.PrivateIPAddressVersion != nil {
					entry["privateIPAddressVersion"] = string(*ipc.Properties.PrivateIPAddressVersion)
				}
				if ipc.Properties.PrivateIPAllocationMethod != nil {
					entry["privateIPAllocationMethod"] = string(*ipc.Properties.PrivateIPAllocationMethod)
				}
				if ipc.Properties.Subnet != nil {
					entry["subnetId"] = convert.ToValue(ipc.Properties.Subnet.ID)
				}
				if ipc.Properties.ProvisioningState != nil {
					entry["provisioningState"] = string(*ipc.Properties.ProvisioningState)
				}
			}
			ipConfigs = append(ipConfigs, entry)
		}
		for _, lb := range pls.Properties.LoadBalancerFrontendIPConfigurations {
			if lb != nil && lb.ID != nil {
				lbFrontendIds = append(lbFrontendIds, *lb.ID)
			}
		}
		for _, nic := range pls.Properties.NetworkInterfaces {
			if nic != nil && nic.ID != nil {
				nicIds = append(nicIds, *nic.ID)
			}
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.privateLinkService",
		map[string]*llx.RawData{
			"id":                                     llx.StringDataPtr(pls.ID),
			"name":                                   llx.StringDataPtr(pls.Name),
			"location":                               llx.StringDataPtr(pls.Location),
			"tags":                                   llx.MapData(convert.PtrMapStrToInterface(pls.Tags), types.String),
			"type":                                   llx.StringDataPtr(pls.Type),
			"etag":                                   llx.StringDataPtr(pls.Etag),
			"provisioningState":                      llx.StringData(provisioningState),
			"alias":                                  llx.StringDataPtr(aliasPtr),
			"accessMode":                             llx.StringData(accessMode),
			"enableProxyProtocol":                    llx.BoolDataPtr(enableProxyPtr),
			"destinationIPAddress":                   llx.StringDataPtr(destIPPtr),
			"fqdns":                                  llx.ArrayData(fqdns, types.String),
			"visibilitySubscriptions":                llx.ArrayData(visibility, types.String),
			"autoApprovalSubscriptions":              llx.ArrayData(autoApproval, types.String),
			"ipConfigurations":                       llx.ArrayData(ipConfigs, types.Dict),
			"loadBalancerFrontendIpConfigurationIds": llx.ArrayData(lbFrontendIds, types.String),
			"networkInterfaceIds":                    llx.ArrayData(nicIds, types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateLinkService), nil
}

// privateLinkServiceTarget names the private link service an ARM resource id
// refers to, split into the parts the private-link-services API needs.
type privateLinkServiceTarget struct {
	SubscriptionID string
	ResourceGroup  string
	Name           string
}

// parsePrivateLinkServiceID reports whether an ARM resource id names a
// Microsoft.Network/privateLinkServices resource, and returns its parts when it
// does.
//
// A private endpoint's properties.privateLinkServiceId carries either shape the
// endpoint can take: a private link service somebody built to expose their own
// service, or, far more commonly, the first-party PaaS resource the endpoint
// connects to, whose own ARM id goes in that same field. Callers have to
// discriminate before asking the private-link-services API for it, because a
// storage account id has no privateLinkServices component to read a name from.
func parsePrivateLinkServiceID(id string) (privateLinkServiceTarget, bool) {
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return privateLinkServiceTarget{}, false
	}
	if !strings.EqualFold(resourceID.Provider, "Microsoft.Network") || resourceID.ResourceGroup == "" {
		return privateLinkServiceTarget{}, false
	}
	name, err := resourceID.Component("privateLinkServices")
	if err != nil {
		return privateLinkServiceTarget{}, false
	}
	// A child of a private link service is not the service: an ip
	// configuration's id also carries a privateLinkServices component, and
	// reading the name out of it would silently return the parent instead.
	if len(resourceID.Path) != 1 {
		return privateLinkServiceTarget{}, false
	}
	return privateLinkServiceTarget{
		SubscriptionID: resourceID.SubscriptionID,
		ResourceGroup:  resourceID.ResourceGroup,
		Name:           name,
	}, true
}

func initAzureSubscriptionNetworkServicePrivateLinkService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	target, ok := parsePrivateLinkServiceID(id)
	if !ok {
		return nil, nil, fmt.Errorf("%q is not a private link service id", id)
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServicePrivateLinkService, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewPrivateLinkServicesClient(target.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), target.ResourceGroup, target.Name, nil)
	if err != nil {
		return nil, nil, err
	}
	mqlPls, err := privateLinkServiceToMql(runtime, &resp.PrivateLinkService)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlPls, nil
}

func (a *mqlAzureSubscriptionNetworkServicePrivateLinkService) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	name, err := resourceID.Component("privateLinkServices")
	if err != nil {
		return nil, err
	}

	client, err := network.NewPrivateLinkServicesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPrivateEndpointConnectionsPager(resourceID.ResourceGroup, name, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pec := range page.Value {
			mqlPec, err := plsEndpointConnectionToMql(a.MqlRuntime, pec)
			if err != nil {
				return nil, err
			}
			if mqlPec == nil {
				continue
			}
			res = append(res, mqlPec)
		}
	}
	return res, nil
}

func plsEndpointConnectionToMql(runtime *plugin.Runtime, pec *network.PrivateEndpointConnection) (*mqlAzureSubscriptionNetworkServicePrivateLinkServicePrivateEndpointConnection, error) {
	if pec == nil {
		return nil, nil
	}

	var (
		linkID, peID, peLocation, status, description, actions, provState string
	)
	if pec.Properties != nil {
		linkID = convert.ToValue(pec.Properties.LinkIdentifier)
		if pec.Properties.PrivateEndpoint != nil {
			peID = convert.ToValue(pec.Properties.PrivateEndpoint.ID)
		}
		peLocation = convert.ToValue(pec.Properties.PrivateEndpointLocation)
		if pec.Properties.PrivateLinkServiceConnectionState != nil {
			status = convert.ToValue(pec.Properties.PrivateLinkServiceConnectionState.Status)
			description = convert.ToValue(pec.Properties.PrivateLinkServiceConnectionState.Description)
			actions = convert.ToValue(pec.Properties.PrivateLinkServiceConnectionState.ActionsRequired)
		}
		if pec.Properties.ProvisioningState != nil {
			provState = string(*pec.Properties.ProvisioningState)
		}
	}

	var etag string
	if pec.Etag != nil {
		etag = *pec.Etag
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.privateLinkService.privateEndpointConnection",
		map[string]*llx.RawData{
			"id":                      llx.StringDataPtr(pec.ID),
			"name":                    llx.StringDataPtr(pec.Name),
			"type":                    llx.StringDataPtr(pec.Type),
			"etag":                    llx.StringData(etag),
			"linkIdentifier":          llx.StringData(linkID),
			"privateEndpointId":       llx.StringData(peID),
			"privateEndpointLocation": llx.StringData(peLocation),
			"connectionStatus":        llx.StringData(status),
			"connectionDescription":   llx.StringData(description),
			"actionsRequired":         llx.StringData(actions),
			"provisioningState":       llx.StringData(provState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateLinkServicePrivateEndpointConnection), nil
}

func (a *mqlAzureSubscriptionNetworkServicePrivateLinkServicePrivateEndpointConnection) privateEndpoint() (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	peId := a.PrivateEndpointId.Data
	if peId == "" {
		a.PrivateEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.privateEndpoint", map[string]*llx.RawData{
		"id": llx.StringData(peId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint), nil
}

func (a *mqlAzureSubscriptionPrivateEndpointConnection) privateEndpoint() (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	peId := a.cachePrivateEndpointId
	if peId == "" {
		a.PrivateEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.privateEndpoint", map[string]*llx.RawData{
		"id": llx.StringData(peId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint), nil
}

func (a *mqlAzureSubscriptionNetworkService) routeTables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewRouteTablesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(&network.RouteTablesClientListAllOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rt := range page.Value {
			if rt == nil {
				continue
			}

			var disableBgp bool
			var provisioningState string
			var routes []any

			if rt.Properties != nil {
				disableBgp = convert.ToValue(rt.Properties.DisableBgpRoutePropagation)
				if rt.Properties.ProvisioningState != nil {
					provisioningState = string(*rt.Properties.ProvisioningState)
				}
				for _, route := range rt.Properties.Routes {
					if route == nil {
						continue
					}
					mqlRoute, err := azureRouteToMql(a.MqlRuntime, route, convert.ToValue(rt.ID))
					if err != nil {
						return nil, err
					}
					routes = append(routes, mqlRoute)
				}
			}

			mqlRt, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.routeTable",
				map[string]*llx.RawData{
					"__id":                       llx.StringData(subResourceCacheID(rt.ID, "/subscriptions/"+subId, "routeTables", convert.ToValue(rt.Name))),
					"id":                         llx.StringDataPtr(rt.ID),
					"name":                       llx.StringDataPtr(rt.Name),
					"location":                   llx.StringDataPtr(rt.Location),
					"tags":                       llx.MapData(convert.PtrMapStrToInterface(rt.Tags), types.String),
					"type":                       llx.StringDataPtr(rt.Type),
					"etag":                       llx.StringDataPtr(rt.Etag),
					"disableBgpRoutePropagation": llx.BoolData(disableBgp),
					"provisioningState":          llx.StringData(provisioningState),
					"routes":                     llx.ArrayData(routes, types.ResourceLike),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRt)
		}
	}
	return res, nil
}

func azureRouteToMql(runtime *plugin.Runtime, route *network.Route, routeTableID string) (*mqlAzureSubscriptionNetworkServiceRoute, error) {
	var addressPrefix, nextHopType, nextHopIpAddress, provisioningState string
	var hasBgpOverride bool
	ecmpNextHopIpAddresses := []any{}

	if route.Properties != nil {
		addressPrefix = convert.ToValue(route.Properties.AddressPrefix)
		nextHopIpAddress = convert.ToValue(route.Properties.NextHopIPAddress)
		hasBgpOverride = convert.ToValue(route.Properties.HasBgpOverride)
		if route.Properties.NextHopType != nil {
			nextHopType = string(*route.Properties.NextHopType)
		}
		if route.Properties.ProvisioningState != nil {
			provisioningState = string(*route.Properties.ProvisioningState)
		}
		if route.Properties.NextHop != nil {
			ecmpNextHopIpAddresses = strPtrsToAny(route.Properties.NextHop.NextHopIPAddresses)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.route",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(subResourceCacheID(route.ID, routeTableID, "routes", convert.ToValue(route.Name))),
			"id":                     llx.StringDataPtr(route.ID),
			"name":                   llx.StringDataPtr(route.Name),
			"addressPrefix":          llx.StringData(addressPrefix),
			"nextHopType":            llx.StringData(nextHopType),
			"nextHopIpAddress":       llx.StringData(nextHopIpAddress),
			"ecmpNextHopIpAddresses": llx.ArrayData(ecmpNextHopIpAddresses, types.String),
			"hasBgpOverride":         llx.BoolData(hasBgpOverride),
			"provisioningState":      llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceRoute), nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGateway) policy() (*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy, error) {
	props := a.Properties
	if props.Error != nil {
		return nil, props.Error
	}
	// Gateways that are not WAF-enabled, or that use the legacy inline
	// wafConfiguration, have no standalone policy attached.
	strId := nestedResourceID(props.Data, "firewallPolicy")
	if strId == "" {
		a.Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Answer a repeated reference from the cache; the fetch below stays,
	// because this resource has no init to route through.
	if cached := cachedResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceApplicationFirewallPolicy, strId); cached != nil {
		return cached.(*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy), nil
	}
	azureId, err := ParseResourceID(strId)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	client, err := network.NewWebApplicationFirewallPoliciesClient(azureId.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	policyName, err := azureId.Component("ApplicationGatewayWebApplicationFirewallPolicies")
	if err != nil {
		return nil, err
	}
	policy, err := client.Get(ctx, azureId.ResourceGroup, policyName, &network.WebApplicationFirewallPoliciesClientGetOptions{})
	if err != nil {
		return nil, err
	}
	return azureAppFirewallPolicyToMql(a.MqlRuntime, policy.WebApplicationFirewallPolicy)
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy) gateways() ([]any, error) {
	props := a.Properties
	if props.Error != nil {
		return nil, props.Error
	}
	gatewayIDs := nestedResourceIDs(props.Data, "applicationGateways")
	if len(gatewayIDs) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	client, err := network.NewApplicationGatewaysClient(conn.SubId(), token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// Pre-validate all gateway IDs before launching any goroutines so that an
	// early parse error can't leak in-flight workers.
	type gwFetch struct {
		rg   string
		name string
	}
	fetches := make([]gwFetch, 0, len(gatewayIDs))
	for _, strId := range gatewayIDs {
		azureId, err := ParseResourceID(strId)
		if err != nil {
			return nil, err
		}
		gatewayName, err := azureId.Component("applicationGateways")
		if err != nil {
			return nil, err
		}
		fetches = append(fetches, gwFetch{rg: azureId.ResourceGroup, name: gatewayName})
	}

	// Fetch the referenced application gateways in parallel; there is no
	// batch endpoint, so a bounded errgroup is the cheapest fix.
	results := make([]network.ApplicationGateway, len(fetches))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	for i, f := range fetches {
		g.Go(func() error {
			resp, err := client.Get(gctx, f.rg, f.name, &network.ApplicationGatewaysClientGetOptions{})
			if err != nil {
				return err
			}
			results[i] = resp.ApplicationGateway
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	res := []any{}
	for _, gw := range results {
		if gw.ID == nil {
			continue
		}
		mqlGateway, err := azureAppGatewayToMql(a.MqlRuntime, gw)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGateway)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNatGateway) publicIpAddresses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	// if we have no present public ip addresses ids, we can just return nil
	publicIpIDs := nestedResourceIDs(a.Properties.Data, "publicIpAddresses")
	if len(publicIpIDs) == 0 {
		return nil, nil
	}

	res := []any{}
	client, err := network.NewPublicIPAddressesClient(azureId.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	for _, pId := range publicIpIDs {
		resourceID, err := ParseResourceID(pId)
		if err != nil {
			return nil, err
		}
		publicIpName, err := resourceID.Component("publicIPAddresses")
		if err != nil {
			return nil, err
		}
		publicIp, err := client.Get(ctx, resourceID.ResourceGroup, publicIpName, &network.PublicIPAddressesClientGetOptions{})
		if err != nil {
			return nil, err
		}
		mqlPublicIp, err := azureIpToMql(a.MqlRuntime, publicIp.PublicIPAddress)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPublicIp)
	}

	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) connections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	client, err := network.NewVirtualNetworkGatewayConnectionsClient(azureId.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, &network.VirtualNetworkGatewayConnectionsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			if c.Properties == nil {
				continue
			}
			// the API does not let us get connections, applicable to a given gateway.
			// Therefore we filter them manually here.
			filter := []string{}
			// primary gateway
			if c.Properties.VirtualNetworkGateway1 != nil && c.Properties.VirtualNetworkGateway1.ID != nil {
				filter = append(filter, *c.Properties.VirtualNetworkGateway1.ID)
			}
			// secondary, optional (only if Vnet2Vnet connection)
			if c.Properties.VirtualNetworkGateway2 != nil && c.Properties.VirtualNetworkGateway2.ID != nil {
				filter = append(filter, *c.Properties.VirtualNetworkGateway2.ID)
			}
			if !stringx.Contains(filter, id) {
				continue
			}
			if c.ID == nil || c.Name == nil {
				continue
			}
			// LIST omits runtime fields like connectionStatus, ingressBytesTransferred,
			// and egressBytesTransferred — they only land in GET responses. Fetch
			// the full record so audits like `connections.where(connectionStatus == "NotConnected")`
			// see real values rather than nulls. Connections-per-gateway is typically
			// small (1–5) so the extra N+1 GETs are bounded.
			//
			// Resolve the connection's own resource group from its ARM id rather
			// than reusing the gateway's. While the ListPager is scoped to the
			// gateway's RG, a Vnet2Vnet connection can reference a peer gateway
			// that lives elsewhere, and parsing the connection's id keeps the
			// GET correct regardless of any future cross-RG list semantics.
			connId, err := ParseResourceID(*c.ID)
			if err != nil {
				return nil, err
			}
			full, err := client.Get(ctx, connId.ResourceGroup, *c.Name, &network.VirtualNetworkGatewayConnectionsClientGetOptions{})
			if err != nil {
				return nil, err
			}
			cn := full.VirtualNetworkGatewayConnection
			props, err := convert.JsonToDict(cn.Properties)
			if err != nil {
				return nil, err
			}
			args := map[string]*llx.RawData{
				"id":         llx.StringDataPtr(cn.ID),
				"type":       llx.StringDataPtr(cn.Type),
				"name":       llx.StringDataPtr(cn.Name),
				"etag":       llx.StringDataPtr(cn.Etag),
				"location":   llx.StringDataPtr(cn.Location),
				"tags":       llx.MapData(convert.PtrMapStrToInterface(cn.Tags), types.String),
				"properties": llx.DictData(props),
			}
			if cn.Properties != nil {
				args["connectionType"] = llx.StringDataPtr((*string)(cn.Properties.ConnectionType))
				args["connectionStatus"] = llx.StringDataPtr((*string)(cn.Properties.ConnectionStatus))
				args["connectionMode"] = llx.StringDataPtr((*string)(cn.Properties.ConnectionMode))
				args["connectionProtocol"] = llx.StringDataPtr((*string)(cn.Properties.ConnectionProtocol))
				args["provisioningState"] = llx.StringDataPtr((*string)(cn.Properties.ProvisioningState))
				args["enableBgp"] = llx.BoolDataPtr(cn.Properties.EnableBgp)
				args["usePolicyBasedTrafficSelectors"] = llx.BoolDataPtr(cn.Properties.UsePolicyBasedTrafficSelectors)
				args["useLocalAzureIpAddress"] = llx.BoolDataPtr(cn.Properties.UseLocalAzureIPAddress)
				args["dpdTimeoutSeconds"] = llx.IntDataDefault(cn.Properties.DpdTimeoutSeconds, 0)
				args["routingWeight"] = llx.IntDataDefault(cn.Properties.RoutingWeight, 0)
				args["ingressBytesTransferred"] = llx.IntDataDefault(cn.Properties.IngressBytesTransferred, 0)
				args["egressBytesTransferred"] = llx.IntDataDefault(cn.Properties.EgressBytesTransferred, 0)
				routingConfig, err := convert.JsonToDict(cn.Properties.RoutingConfiguration)
				if err != nil {
					return nil, err
				}
				args["routingConfiguration"] = llx.DictData(routingConfig)
			}
			mqlConnection, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkGateway.connection", args)
			if err != nil {
				return nil, err
			}
			mqlConn := mqlConnection.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnection)
			mqlConn.cacheProperties = cn.Properties
			res = append(res, mqlConn)

		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNatGateway) subnets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	// if we have no present subnets in the dict, we can just return nil
	subnetIDs := nestedResourceIDs(a.Properties.Data, "subnets")
	if len(subnetIDs) == 0 {
		return nil, nil
	}
	res := []any{}
	client, err := network.NewSubnetsClient(azureId.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	for _, sId := range subnetIDs {
		resourceID, err := ParseResourceID(sId)
		if err != nil {
			return nil, err
		}
		virtualNetworkName, err := resourceID.Component("virtualNetworks")
		if err != nil {
			return nil, err
		}
		subnetName, err := resourceID.Component("subnets")
		if err != nil {
			return nil, err
		}
		subnet, err := client.Get(ctx, resourceID.ResourceGroup, virtualNetworkName, subnetName, &network.SubnetsClientGetOptions{})
		if err != nil {
			return nil, err
		}
		mqlSubnet, err := azureSubnetToMql(a.MqlRuntime, subnet.Subnet)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) natGateway() (*mqlAzureSubscriptionNetworkServiceNatGateway, error) {
	// NAT gateways are opt-in, so the overwhelming majority of subnets have
	// none. That is a null, not an error.
	natGatewayId := nestedResourceID(a.Properties.Data, "natGateway")
	if natGatewayId == "" {
		a.NatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceNatGateway,
		map[string]*llx.RawData{"id": llx.StringData(natGatewayId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceNatGateway), nil
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) ipConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	subId := conn.SubId()
	rawIpConfigIds := nestedResourceIDs(a.Properties.Data, "ipConfigurations")
	if len(rawIpConfigIds) == 0 {
		return nil, nil
	}
	res := []any{}
	ipConfigIds := make([]string, 0, len(rawIpConfigIds))
	for _, ipcId := range rawIpConfigIds {
		ipConfigIds = append(ipConfigIds, strings.ToLower(ipcId))
	}

	network, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(subId),
	})
	if err != nil {
		return nil, err
	}
	mqlNetwork := network.(*mqlAzureSubscriptionNetworkService)
	// the subnet ip configs are referencing the virtual network gateways ip config. There seems to be no
	// no API to fetch this so we fetch the gateways and iterate through them
	gateways := mqlNetwork.GetVirtualNetworkGateways()
	if gateways.Error != nil {
		return nil, gateways.Error
	}
	for _, gw := range gateways.Data {
		mqlGw := gw.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway)
		// we need to check if the gateway has the ip configuration
		for _, ipc := range mqlGw.IpConfigurations.Data {
			mqlIpc := ipc.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayIpConfig)
			// Note: for some reason, the azure API returns the resource id capitalized, e.g.
			// .../ipConfigurations/MY-IP-CONFIGURATION whereas those are all lower case in the virtual network gateways
			// object. To make this work, we make sure everything's lower case
			if stringx.Contains(ipConfigIds, strings.ToLower(mqlIpc.Id.Data)) {
				res = append(res, mqlIpc)
			}
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) basePolicy() (*mqlAzureSubscriptionNetworkServiceFirewallPolicy, error) {
	// Only child policies have a base policy; a standalone or root policy
	// legitimately has none.
	basePolicyId := nestedResourceID(a.Properties.Data, "basePolicy")
	if basePolicyId == "" {
		a.BasePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceFirewallPolicy,
		map[string]*llx.RawData{"id": llx.StringData(basePolicyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceFirewallPolicy), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) childPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	childPolicyIDs := nestedResourceIDs(a.Properties.Data, "childPolicies")
	if len(childPolicyIDs) == 0 {
		return nil, nil
	}
	baseResourceId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := network.NewFirewallPoliciesClient(baseResourceId.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, cpId := range childPolicyIDs {
		resourceID, err := ParseResourceID(cpId)
		if err != nil {
			return nil, err
		}
		polName, err := resourceID.Component("firewallPolicies")
		if err != nil {
			return nil, err
		}
		polRes, err := client.Get(ctx, resourceID.ResourceGroup, polName, &network.FirewallPoliciesClientGetOptions{})
		if err != nil {
			return nil, err
		}
		mqlFw, err := azureFirewallPolicyToMql(a.MqlRuntime, polRes.FirewallPolicy)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFw)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) firewalls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	firewallIDs := nestedResourceIDs(a.Properties.Data, "firewalls")
	if len(firewallIDs) == 0 {
		return nil, nil
	}
	baseResourceId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := network.NewAzureFirewallsClient(baseResourceId.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, fwId := range firewallIDs {
		resourceID, err := ParseResourceID(fwId)
		if err != nil {
			return nil, err
		}
		firewallName, err := resourceID.Component("azureFirewalls")
		if err != nil {
			return nil, err
		}
		fwRes, err := client.Get(ctx, resourceID.ResourceGroup, firewallName, &network.AzureFirewallsClientGetOptions{})
		if err != nil {
			return nil, err
		}
		mqlFw, err := azureFirewallToMql(a.MqlRuntime, fwRes.AzureFirewall)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFw)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceInterface) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceIpAddress) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceBastionHost) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWatcher) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWatcherFlowlog) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityrule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceLoadBalancer) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceBackendAddressPool) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFrontendIpConfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceInboundNatPool) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceInboundNatRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceProbe) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceNatGateway) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetwork) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceBgpSettings) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceBgpSettingsIpConfigurationBgpPeeringAddress) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayIpConfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallApplicationRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallNetworkRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallNatRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallIpConfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceAppSecurityGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkDhcpOptions) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGateway) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy) id() (string, error) {
	return a.Id.Data, nil
}

// wafPolicyEnabled reports whether the WAF policy is enabled. The SDK models
// this as an Enabled/Disabled enum; we collapse it to a bool where only the
// explicit Enabled state (and, matching Azure's default for an unset value)
// is true.
func wafPolicyEnabled(ps *network.PolicySettings) bool {
	return ps == nil || ps.State == nil || *ps.State == network.WebApplicationFirewallEnabledStateEnabled
}

func azureAppFirewallPolicyToMql(runtime *plugin.Runtime, waf network.WebApplicationFirewallPolicy) (*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy, error) {
	props, err := convert.JsonToDict(waf.Properties)
	if err != nil {
		return nil, err
	}
	var mode string
	enabled := true
	var requestBodyCheck *bool
	var maxRequestBodySizeInKb, fileUploadLimitInMb *int64
	customRulesCount := int64(0)
	managedRuleSets := []any{}
	exclusions, err := wafExclusionsToDicts(policyManagedRules(waf))
	if err != nil {
		return nil, err
	}
	if p := waf.Properties; p != nil {
		enabled = wafPolicyEnabled(p.PolicySettings)
		if ps := p.PolicySettings; ps != nil {
			if ps.Mode != nil {
				mode = string(*ps.Mode)
			}
			if ps.State != nil {
			}
			requestBodyCheck = ps.RequestBodyCheck
			if ps.MaxRequestBodySizeInKb != nil {
				v := int64(*ps.MaxRequestBodySizeInKb)
				maxRequestBodySizeInKb = &v
			}
			if ps.FileUploadLimitInMb != nil {
				v := int64(*ps.FileUploadLimitInMb)
				fileUploadLimitInMb = &v
			}
		}
		customRulesCount = int64(len(p.CustomRules))
		if p.ManagedRules != nil {
			for _, rs := range p.ManagedRules.ManagedRuleSets {
				if rs == nil {
					continue
				}
				entry := map[string]any{}
				if rs.RuleSetType != nil {
					entry["ruleSetType"] = *rs.RuleSetType
				}
				if rs.RuleSetVersion != nil {
					entry["ruleSetVersion"] = *rs.RuleSetVersion
				}
				managedRuleSets = append(managedRuleSets, entry)
			}
		}
	}
	args := map[string]*llx.RawData{
		"id":                     llx.StringDataPtr(waf.ID),
		"name":                   llx.StringDataPtr(waf.Name),
		"type":                   llx.StringDataPtr(waf.Type),
		"location":               llx.StringDataPtr(waf.Location),
		"tags":                   llx.MapData(convert.PtrMapStrToInterface(waf.Tags), types.String),
		"etag":                   llx.StringDataPtr(waf.Etag),
		"properties":             llx.DictData(props),
		"mode":                   llx.StringData(mode),
		"enabled":                llx.BoolData(enabled),
		"requestBodyCheck":       llx.BoolDataPtr(requestBodyCheck),
		"maxRequestBodySizeInKb": llx.IntDataPtr(maxRequestBodySizeInKb),
		"fileUploadLimitInMb":    llx.IntDataPtr(fileUploadLimitInMb),
		"customRulesCount":       llx.IntData(customRulesCount),
		"managedRuleSets":        llx.ArrayData(managedRuleSets, types.Dict),
		"exclusions":             llx.ArrayData(exclusions, types.Dict),
	}

	mqlWaf, err := CreateResource(runtime, "azure.subscription.networkService.applicationFirewallPolicy", args)
	if err != nil {
		return nil, err
	}

	// Hold the rule documents so the typed customRules() and managedRules()
	// trees can be built without re-fetching the policy.
	policy := mqlWaf.(*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy)
	if p := waf.Properties; p != nil {
		policy.cacheCustomRules = p.CustomRules
		if p.ManagedRules != nil {
			policy.cacheManagedRuleSets = p.ManagedRules.ManagedRuleSets
		}
	}

	return policy, nil
}

func azureAppGatewayToMql(runtime *plugin.Runtime, ag network.ApplicationGateway) (*mqlAzureSubscriptionNetworkServiceApplicationGateway, error) {
	props, err := convert.JsonToDict(ag.Properties)
	if err != nil {
		return nil, err
	}
	var sslPolicyType, sslMinProtocolVersion string
	sslCipherSuites := []any{}
	if ag.Properties != nil {
		sslPolicyType, _, sslMinProtocolVersion, sslCipherSuites = azureAppGatewaySSLPolicyFields(ag.Properties.SSLPolicy)
	}

	// Build frontend-port lookup so listeners can resolve their bound port,
	// and cert/profile name lookups so listeners and settings can resolve
	// their references.
	frontendPorts := map[string]int64{}
	sslCertNames := map[string]string{}
	sslProfileNames := map[string]string{}
	trustedRootCertNames := map[string]string{}
	trustedClientCertNames := map[string]string{}
	if ag.Properties != nil {
		for _, fp := range ag.Properties.FrontendPorts {
			if fp == nil || fp.ID == nil || fp.Properties == nil || fp.Properties.Port == nil {
				continue
			}
			frontendPorts[*fp.ID] = int64(*fp.Properties.Port)
		}
		for _, c := range ag.Properties.SSLCertificates {
			if c == nil || c.ID == nil || c.Name == nil {
				continue
			}
			sslCertNames[*c.ID] = *c.Name
		}
		for _, p := range ag.Properties.SSLProfiles {
			if p == nil || p.ID == nil || p.Name == nil {
				continue
			}
			sslProfileNames[*p.ID] = *p.Name
		}
		for _, c := range ag.Properties.TrustedRootCertificates {
			if c == nil || c.ID == nil || c.Name == nil {
				continue
			}
			trustedRootCertNames[*c.ID] = *c.Name
		}
		for _, c := range ag.Properties.TrustedClientCertificates {
			if c == nil || c.ID == nil || c.Name == nil {
				continue
			}
			trustedClientCertNames[*c.ID] = *c.Name
		}
	}

	sslCertificates := []any{}
	if ag.Properties != nil {
		for _, c := range ag.Properties.SSLCertificates {
			if c == nil {
				continue
			}
			mqlCert, err := azureAppGatewaySSLCertToMql(runtime, c)
			if err != nil {
				return nil, err
			}
			sslCertificates = append(sslCertificates, mqlCert)
		}
	}

	listeners := []any{}
	if ag.Properties != nil {
		for _, l := range ag.Properties.HTTPListeners {
			if l == nil {
				continue
			}
			mqlListener, err := azureAppGatewayListenerToMql(runtime, l, frontendPorts, sslCertNames, sslProfileNames)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, mqlListener)
		}
	}

	frontendIpConfigs := []any{}
	if ag.Properties != nil {
		for _, fc := range ag.Properties.FrontendIPConfigurations {
			if fc == nil {
				continue
			}
			mqlFc, err := azureAppGatewayFrontendIpConfigToMql(runtime, fc)
			if err != nil {
				return nil, err
			}
			frontendIpConfigs = append(frontendIpConfigs, mqlFc)
		}
	}

	backendHttpSettings := []any{}
	sslProfiles := []any{}
	trustedRootCertificates := []any{}
	trustedClientCertificates := []any{}
	if ag.Properties != nil {
		for _, s := range ag.Properties.BackendHTTPSettingsCollection {
			if s == nil {
				continue
			}
			mqlSettings, err := azureAppGatewayBackendHttpSettingsToMql(runtime, s, trustedRootCertNames)
			if err != nil {
				return nil, err
			}
			backendHttpSettings = append(backendHttpSettings, mqlSettings)
		}
		for _, p := range ag.Properties.SSLProfiles {
			if p == nil {
				continue
			}
			mqlProfile, err := azureAppGatewaySSLProfileToMql(runtime, p, trustedClientCertNames)
			if err != nil {
				return nil, err
			}
			sslProfiles = append(sslProfiles, mqlProfile)
		}
		for _, c := range ag.Properties.TrustedRootCertificates {
			if c == nil {
				continue
			}
			mqlCert, err := azureAppGatewayTrustedRootCertToMql(runtime, c)
			if err != nil {
				return nil, err
			}
			trustedRootCertificates = append(trustedRootCertificates, mqlCert)
		}
		for _, c := range ag.Properties.TrustedClientCertificates {
			if c == nil {
				continue
			}
			mqlCert, err := azureAppGatewayTrustedClientCertToMql(runtime, c)
			if err != nil {
				return nil, err
			}
			trustedClientCertificates = append(trustedClientCertificates, mqlCert)
		}
	}

	// The gateway's managed identity lives on the top-level ag.Identity, not in
	// ag.Properties, so it is captured separately here.
	var principalId, tenantId, identityType *string
	var userAssignedIdentityIds []string
	if ag.Identity != nil {
		principalId = ag.Identity.PrincipalID
		tenantId = ag.Identity.TenantID
		identityType = (*string)(ag.Identity.Type)
		userAssignedIdentityIds = sortedUserAssignedIdentityIDs(ag.Identity.UserAssignedIdentities)
	}

	// The default Server header suppression lives on the gateway's global
	// configuration block, which is absent on gateways that never set one.
	var disableDefaultServerHeaderInResponse *bool
	if ag.Properties != nil && ag.Properties.GlobalConfiguration != nil {
		disableDefaultServerHeaderInResponse = ag.Properties.GlobalConfiguration.DisableDefaultServerHeaderInResponse
	}

	var enableHttp2, enableFips, forceFirewallPolicyAssociation *bool
	var defaultPredefinedSslPolicy, operationalState, resourceGuid *string
	var autoscaleMinCapacity, autoscaleMaxCapacity *int32
	if ag.Properties != nil {
		enableHttp2 = ag.Properties.EnableHTTP2
		enableFips = ag.Properties.EnableFips
		forceFirewallPolicyAssociation = ag.Properties.ForceFirewallPolicyAssociation
		defaultPredefinedSslPolicy = stringEnumPtr(ag.Properties.DefaultPredefinedSSLPolicy)
		operationalState = stringEnumPtr(ag.Properties.OperationalState)
		resourceGuid = ag.Properties.ResourceGUID
		if asc := ag.Properties.AutoscaleConfiguration; asc != nil {
			autoscaleMinCapacity = asc.MinCapacity
			autoscaleMaxCapacity = asc.MaxCapacity
		}
	}

	args := map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(ag.ID),
		"name":                      llx.StringDataPtr(ag.Name),
		"type":                      llx.StringDataPtr(ag.Type),
		"location":                  llx.StringDataPtr(ag.Location),
		"tags":                      llx.MapData(convert.PtrMapStrToInterface(ag.Tags), types.String),
		"etag":                      llx.StringDataPtr(ag.Etag),
		"properties":                llx.DictData(props),
		"sslPolicyType":             llx.StringData(sslPolicyType),
		"sslMinProtocolVersion":     llx.StringData(sslMinProtocolVersion),
		"sslCipherSuites":           llx.ArrayData(sslCipherSuites, types.String),
		"listeners":                 llx.ArrayData(listeners, types.Resource("azure.subscription.networkService.applicationGateway.listener")),
		"sslCertificates":           llx.ArrayData(sslCertificates, types.Resource("azure.subscription.networkService.applicationGateway.sslCertificate")),
		"frontendIpConfigs":         llx.ArrayData(frontendIpConfigs, types.Resource("azure.subscription.networkService.applicationGateway.frontendIpConfig")),
		"backendHttpSettings":       llx.ArrayData(backendHttpSettings, types.Resource("azure.subscription.networkService.applicationGateway.backendHttpSettings")),
		"sslProfiles":               llx.ArrayData(sslProfiles, types.Resource("azure.subscription.networkService.applicationGateway.sslProfile")),
		"trustedRootCertificates":   llx.ArrayData(trustedRootCertificates, types.Resource("azure.subscription.networkService.applicationGateway.trustedRootCertificate")),
		"trustedClientCertificates": llx.ArrayData(trustedClientCertificates, types.Resource("azure.subscription.networkService.applicationGateway.trustedClientCertificate")),
		"principalId":               llx.StringDataPtr(principalId),
		"tenantId":                  llx.StringDataPtr(tenantId),
		"identityType":              llx.StringDataPtr(identityType),

		"disableDefaultServerHeaderInResponse": llx.BoolDataPtr(disableDefaultServerHeaderInResponse),

		"enableHttp2":                    llx.BoolDataPtr(enableHttp2),
		"enableFips":                     llx.BoolDataPtr(enableFips),
		"forceFirewallPolicyAssociation": llx.BoolDataPtr(forceFirewallPolicyAssociation),
		"defaultPredefinedSslPolicy":     llx.StringDataPtr(defaultPredefinedSslPolicy),
		"operationalState":               llx.StringDataPtr(operationalState),
		"autoscaleMinCapacity":           llx.IntDataPtr(autoscaleMinCapacity),
		"autoscaleMaxCapacity":           llx.IntDataPtr(autoscaleMaxCapacity),
		"resourceGuid":                   llx.StringDataPtr(resourceGuid),
	}

	mqlAg, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway", args)
	if err != nil {
		return nil, err
	}

	res := mqlAg.(*mqlAzureSubscriptionNetworkServiceApplicationGateway)
	res.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	if ag.Properties != nil {
		res.cacheGatewayIPConfigs = ag.Properties.GatewayIPConfigurations
		res.cacheWafConfiguration = ag.Properties.WebApplicationFirewallConfiguration
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceApplicationGatewayInternal struct {
	cacheUserAssignedIdentityIds []string
	cacheGatewayIPConfigs        []*network.ApplicationGatewayIPConfiguration
	cacheWafConfiguration        *network.ApplicationGatewayWebApplicationFirewallConfiguration
}

// userAssignedIdentities resolves the typed user-assigned managed identities
// associated with the application gateway. Returns an empty list when none are
// assigned.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGateway) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

// gatewayIpConfigs resolves the gateway IP configurations that bind the
// application gateway into a subnet. Returns an empty list when none are set.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGateway) gatewayIpConfigs() ([]any, error) {
	res := []any{}
	for _, gc := range a.cacheGatewayIPConfigs {
		if gc == nil {
			continue
		}
		mqlGc, err := azureAppGatewayIpConfigToMql(a.MqlRuntime, gc)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGc)
	}
	return res, nil
}

func azureAppGatewayIpConfigToMql(runtime *plugin.Runtime, gc *network.ApplicationGatewayIPConfiguration) (*mqlAzureSubscriptionNetworkServiceApplicationGatewayGatewayIpConfig, error) {
	id := ""
	if gc.ID != nil {
		id = *gc.ID
	}
	name := ""
	if gc.Name != nil {
		name = *gc.Name
	}
	subnetId := ""
	if gc.Properties != nil && gc.Properties.Subnet != nil && gc.Properties.Subnet.ID != nil {
		subnetId = *gc.Properties.Subnet.ID
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.gatewayIpConfig", map[string]*llx.RawData{
		"id":       llx.StringData(id),
		"name":     llx.StringData(name),
		"subnetId": llx.StringData(subnetId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewayGatewayIpConfig), nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayGatewayIpConfig) id() (string, error) {
	return a.Id.Data, nil
}

// subnet resolves the typed subnet the application gateway is deployed into from
// the cached subnetId. Returns null when the configuration is not bound to a
// subnet.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayGatewayIpConfig) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.SubnetId.Data == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.SubnetId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func azureAppGatewayListenerToMql(runtime *plugin.Runtime, l *network.ApplicationGatewayHTTPListener, frontendPorts map[string]int64, sslCertNames map[string]string, sslProfileNames map[string]string) (*mqlAzureSubscriptionNetworkServiceApplicationGatewayListener, error) {
	id := ""
	if l.ID != nil {
		id = *l.ID
	}
	name := ""
	if l.Name != nil {
		name = *l.Name
	}
	protocol := ""
	hostName := ""
	hostNames := []any{}
	requireSNI := false
	var port int64
	provisioningState := ""
	sslCertID := ""
	sslCertName := ""
	sslProfileID := ""
	sslProfileName := ""
	if l.Properties != nil {
		if l.Properties.Protocol != nil {
			protocol = string(*l.Properties.Protocol)
		}
		if l.Properties.HostName != nil {
			hostName = *l.Properties.HostName
		}
		for _, h := range l.Properties.HostNames {
			if h != nil {
				hostNames = append(hostNames, *h)
			}
		}
		if l.Properties.RequireServerNameIndication != nil {
			requireSNI = *l.Properties.RequireServerNameIndication
		}
		if l.Properties.FrontendPort != nil && l.Properties.FrontendPort.ID != nil {
			port = frontendPorts[*l.Properties.FrontendPort.ID]
		}
		if l.Properties.ProvisioningState != nil {
			provisioningState = string(*l.Properties.ProvisioningState)
		}
		if l.Properties.SSLCertificate != nil && l.Properties.SSLCertificate.ID != nil {
			sslCertID = *l.Properties.SSLCertificate.ID
			sslCertName = sslCertNames[sslCertID]
		}
		if l.Properties.SSLProfile != nil && l.Properties.SSLProfile.ID != nil {
			sslProfileID = *l.Properties.SSLProfile.ID
			sslProfileName = sslProfileNames[sslProfileID]
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.listener", map[string]*llx.RawData{
		"id":                          llx.StringData(id),
		"name":                        llx.StringData(name),
		"protocol":                    llx.StringData(protocol),
		"port":                        llx.IntData(port),
		"hostName":                    llx.StringData(hostName),
		"hostNames":                   llx.ArrayData(hostNames, types.String),
		"requireServerNameIndication": llx.BoolData(requireSNI),
		"sslCertificateId":            llx.StringData(sslCertID),
		"sslCertificateName":          llx.StringData(sslCertName),
		"sslProfileId":                llx.StringData(sslProfileID),
		"sslProfileName":              llx.StringData(sslProfileName),
		"provisioningState":           llx.StringData(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewayListener), nil
}

func azureAppGatewaySSLCertToMql(runtime *plugin.Runtime, c *network.ApplicationGatewaySSLCertificate) (*mqlAzureSubscriptionNetworkServiceApplicationGatewaySslCertificate, error) {
	id := ""
	if c.ID != nil {
		id = *c.ID
	}
	name := ""
	if c.Name != nil {
		name = *c.Name
	}
	keyVaultSecretId := ""
	publicCertData := ""
	provisioningState := ""
	hsmKeyId := ""
	if c.Properties != nil {
		if c.Properties.KeyVaultSecretID != nil {
			keyVaultSecretId = *c.Properties.KeyVaultSecretID
		}
		if c.Properties.PublicCertData != nil {
			publicCertData = *c.Properties.PublicCertData
		}
		if c.Properties.ProvisioningState != nil {
			provisioningState = string(*c.Properties.ProvisioningState)
		}
		if c.Properties.Hsm != nil {
			hsmKeyId = convert.ToValue(c.Properties.Hsm.KeyID)
		}
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.sslCertificate", map[string]*llx.RawData{
		"id":                llx.StringData(id),
		"name":              llx.StringData(name),
		"publicCertData":    llx.StringData(publicCertData),
		"provisioningState": llx.StringData(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	sslCert := res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewaySslCertificate)
	sslCert.cacheHsmKeyId = hsmKeyId
	sslCert.cacheKeyVaultSecretId = keyVaultSecretId
	return sslCert, nil
}

type mqlAzureSubscriptionNetworkServiceApplicationGatewaySslCertificateInternal struct {
	cacheHsmKeyId         string
	cacheKeyVaultSecretId string
}

// keyVaultSecret resolves the typed Key Vault secret backing this certificate
// from its secret URI. Returns null for certificates uploaded directly.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewaySslCertificate) keyVaultSecret() (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	if a.cacheKeyVaultSecretId == "" {
		a.KeyVaultSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultSecretResource(a.MqlRuntime, a.cacheKeyVaultSecretId)
}

// hsmKey resolves the typed Managed HSM key backing this certificate from its
// key identifier. Returns null for Key Vault- or PFX-backed certificates.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewaySslCertificate) hsmKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheHsmKeyId == "" {
		a.HsmKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheHsmKeyId)
}

// azureAppGatewaySSLPolicyFields flattens an application gateway SSL policy into
// its scalar fields. Returns an empty cipher-suite slice when the policy is nil.
func azureAppGatewaySSLPolicyFields(sp *network.ApplicationGatewaySSLPolicy) (policyType, policyName, minProto string, ciphers []any) {
	ciphers = []any{}
	if sp == nil {
		return
	}
	if sp.PolicyType != nil {
		policyType = string(*sp.PolicyType)
	}
	if sp.PolicyName != nil {
		policyName = string(*sp.PolicyName)
	}
	if sp.MinProtocolVersion != nil {
		minProto = string(*sp.MinProtocolVersion)
	}
	for _, cs := range sp.CipherSuites {
		if cs != nil {
			ciphers = append(ciphers, string(*cs))
		}
	}
	return
}

func azureAppGatewayBackendHttpSettingsToMql(runtime *plugin.Runtime, s *network.ApplicationGatewayBackendHTTPSettings, trustedRootCertNames map[string]string) (*mqlAzureSubscriptionNetworkServiceApplicationGatewayBackendHttpSettings, error) {
	protocol := ""
	hostName := ""
	sniName := ""
	cookieBasedAffinity := ""
	provisioningState := ""
	pickHostName := false
	validateCertChainAndExpiry := false
	validateSNI := false
	var port, requestTimeout int64
	trustedRootCertIds := []any{}
	trustedRootCertNamesList := []any{}
	if s.Properties != nil {
		p := s.Properties
		if p.Protocol != nil {
			protocol = string(*p.Protocol)
		}
		if p.Port != nil {
			port = int64(*p.Port)
		}
		if p.HostName != nil {
			hostName = *p.HostName
		}
		if p.PickHostNameFromBackendAddress != nil {
			pickHostName = *p.PickHostNameFromBackendAddress
		}
		if p.SniName != nil {
			sniName = *p.SniName
		}
		if p.ValidateCertChainAndExpiry != nil {
			validateCertChainAndExpiry = *p.ValidateCertChainAndExpiry
		}
		if p.ValidateSNI != nil {
			validateSNI = *p.ValidateSNI
		}
		if p.CookieBasedAffinity != nil {
			cookieBasedAffinity = string(*p.CookieBasedAffinity)
		}
		if p.RequestTimeout != nil {
			requestTimeout = int64(*p.RequestTimeout)
		}
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		for _, c := range p.TrustedRootCertificates {
			if c == nil || c.ID == nil {
				continue
			}
			trustedRootCertIds = append(trustedRootCertIds, *c.ID)
			if name, ok := trustedRootCertNames[*c.ID]; ok {
				trustedRootCertNamesList = append(trustedRootCertNamesList, name)
			}
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.backendHttpSettings", map[string]*llx.RawData{
		"id":                             llx.StringData(convert.ToValue(s.ID)),
		"name":                           llx.StringData(convert.ToValue(s.Name)),
		"protocol":                       llx.StringData(protocol),
		"port":                           llx.IntData(port),
		"hostName":                       llx.StringData(hostName),
		"pickHostNameFromBackendAddress": llx.BoolData(pickHostName),
		"sniName":                        llx.StringData(sniName),
		"validateCertChainAndExpiry":     llx.BoolData(validateCertChainAndExpiry),
		"validateSNI":                    llx.BoolData(validateSNI),
		"trustedRootCertificateNames":    llx.ArrayData(trustedRootCertNamesList, types.String),
		"trustedRootCertificateIds":      llx.ArrayData(trustedRootCertIds, types.String),
		"cookieBasedAffinity":            llx.StringData(cookieBasedAffinity),
		"requestTimeout":                 llx.IntData(requestTimeout),
		"provisioningState":              llx.StringData(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewayBackendHttpSettings), nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayBackendHttpSettings) id() (string, error) {
	return a.Id.Data, nil
}

func azureAppGatewaySSLProfileToMql(runtime *plugin.Runtime, p *network.ApplicationGatewaySSLProfile, trustedClientCertNames map[string]string) (*mqlAzureSubscriptionNetworkServiceApplicationGatewaySslProfile, error) {
	provisioningState := ""
	verifyClientAuthMode := ""
	verifyClientRevocation := ""
	verifyClientCertIssuerDN := false
	policyType, policyName, minProto, ciphers := "", "", "", []any{}
	trustedClientCertIds := []any{}
	trustedClientCertNamesList := []any{}
	if p.Properties != nil {
		props := p.Properties
		policyType, policyName, minProto, ciphers = azureAppGatewaySSLPolicyFields(props.SSLPolicy)
		if props.ClientAuthConfiguration != nil {
			cac := props.ClientAuthConfiguration
			if cac.VerifyClientAuthMode != nil {
				verifyClientAuthMode = string(*cac.VerifyClientAuthMode)
			}
			if cac.VerifyClientCertIssuerDN != nil {
				verifyClientCertIssuerDN = *cac.VerifyClientCertIssuerDN
			}
			if cac.VerifyClientRevocation != nil {
				verifyClientRevocation = string(*cac.VerifyClientRevocation)
			}
		}
		if props.ProvisioningState != nil {
			provisioningState = string(*props.ProvisioningState)
		}
		for _, c := range props.TrustedClientCertificates {
			if c == nil || c.ID == nil {
				continue
			}
			trustedClientCertIds = append(trustedClientCertIds, *c.ID)
			if name, ok := trustedClientCertNames[*c.ID]; ok {
				trustedClientCertNamesList = append(trustedClientCertNamesList, name)
			}
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.sslProfile", map[string]*llx.RawData{
		"id":                            llx.StringData(convert.ToValue(p.ID)),
		"name":                          llx.StringData(convert.ToValue(p.Name)),
		"sslPolicyType":                 llx.StringData(policyType),
		"sslPolicyName":                 llx.StringData(policyName),
		"sslMinProtocolVersion":         llx.StringData(minProto),
		"sslCipherSuites":               llx.ArrayData(ciphers, types.String),
		"verifyClientAuthMode":          llx.StringData(verifyClientAuthMode),
		"verifyClientCertIssuerDN":      llx.BoolData(verifyClientCertIssuerDN),
		"verifyClientRevocation":        llx.StringData(verifyClientRevocation),
		"trustedClientCertificateNames": llx.ArrayData(trustedClientCertNamesList, types.String),
		"trustedClientCertificateIds":   llx.ArrayData(trustedClientCertIds, types.String),
		"provisioningState":             llx.StringData(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewaySslProfile), nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewaySslProfile) id() (string, error) {
	return a.Id.Data, nil
}

func azureAppGatewayTrustedRootCertToMql(runtime *plugin.Runtime, c *network.ApplicationGatewayTrustedRootCertificate) (*mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedRootCertificate, error) {
	data := ""
	keyVaultSecretId := ""
	provisioningState := ""
	if c.Properties != nil {
		if c.Properties.Data != nil {
			data = *c.Properties.Data
		}
		if c.Properties.KeyVaultSecretID != nil {
			keyVaultSecretId = *c.Properties.KeyVaultSecretID
		}
		if c.Properties.ProvisioningState != nil {
			provisioningState = string(*c.Properties.ProvisioningState)
		}
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.trustedRootCertificate", map[string]*llx.RawData{
		"id":                llx.StringData(convert.ToValue(c.ID)),
		"name":              llx.StringData(convert.ToValue(c.Name)),
		"data":              llx.StringData(data),
		"provisioningState": llx.StringData(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	cert := res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedRootCertificate)
	cert.cacheKeyVaultSecretId = keyVaultSecretId
	return cert, nil
}

type mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedRootCertificateInternal struct {
	cacheKeyVaultSecretId string
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedRootCertificate) id() (string, error) {
	return a.Id.Data, nil
}

// keyVaultSecret resolves the typed Key Vault secret backing this trusted root
// certificate from its secret URI. Returns null for certificates uploaded
// directly.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedRootCertificate) keyVaultSecret() (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	if a.cacheKeyVaultSecretId == "" {
		a.KeyVaultSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultSecretResource(a.MqlRuntime, a.cacheKeyVaultSecretId)
}

func azureAppGatewayTrustedClientCertToMql(runtime *plugin.Runtime, c *network.ApplicationGatewayTrustedClientCertificate) (*mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedClientCertificate, error) {
	data := ""
	clientCertIssuerDN := ""
	validatedCertData := ""
	provisioningState := ""
	if c.Properties != nil {
		if c.Properties.Data != nil {
			data = *c.Properties.Data
		}
		if c.Properties.ClientCertIssuerDN != nil {
			clientCertIssuerDN = *c.Properties.ClientCertIssuerDN
		}
		if c.Properties.ValidatedCertData != nil {
			validatedCertData = *c.Properties.ValidatedCertData
		}
		if c.Properties.ProvisioningState != nil {
			provisioningState = string(*c.Properties.ProvisioningState)
		}
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.trustedClientCertificate", map[string]*llx.RawData{
		"id":                 llx.StringData(convert.ToValue(c.ID)),
		"name":               llx.StringData(convert.ToValue(c.Name)),
		"data":               llx.StringData(data),
		"clientCertIssuerDN": llx.StringData(clientCertIssuerDN),
		"validatedCertData":  llx.StringData(validatedCertData),
		"provisioningState":  llx.StringData(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedClientCertificate), nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayTrustedClientCertificate) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayListener) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayFrontendIpConfig) id() (string, error) {
	return a.Id.Data, nil
}

// subnet resolves the typed subnet bound to an internal (private) frontend IP
// configuration from the cached subnetId. Returns null for internet-facing
// frontends that are not bound to a subnet.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayFrontendIpConfig) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.SubnetId.Data == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.SubnetId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

// publicIpAddress resolves the typed public IP address bound to an
// internet-facing frontend IP configuration from the cached publicIpAddressId.
// Returns null for internal frontends that have no public IP.
func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewayFrontendIpConfig) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	if a.PublicIpAddressId.Data == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolved through the target's own init rather than fetched here, so a
	// resource several things point at is fetched once for the scan instead
	// of once per reference to it.
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceIpAddress,
		map[string]*llx.RawData{"id": llx.StringData(a.PublicIpAddressId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}

// frontendIpConfigFields extracts the displayable fields from an application
// gateway frontend IP configuration. subnetId is set for internal (private)
// frontends; publicIpAddressId is set for internet-facing ones.
func frontendIpConfigFields(fc *network.ApplicationGatewayFrontendIPConfiguration) (id, name, subnetId, publicIpAddressId, privateIPAddress, privateIPAllocationMethod string) {
	if fc == nil {
		return
	}
	if fc.ID != nil {
		id = *fc.ID
	}
	if fc.Name != nil {
		name = *fc.Name
	}
	if p := fc.Properties; p != nil {
		if p.Subnet != nil && p.Subnet.ID != nil {
			subnetId = *p.Subnet.ID
		}
		if p.PublicIPAddress != nil && p.PublicIPAddress.ID != nil {
			publicIpAddressId = *p.PublicIPAddress.ID
		}
		if p.PrivateIPAddress != nil {
			privateIPAddress = *p.PrivateIPAddress
		}
		if p.PrivateIPAllocationMethod != nil {
			privateIPAllocationMethod = string(*p.PrivateIPAllocationMethod)
		}
	}
	return id, name, subnetId, publicIpAddressId, privateIPAddress, privateIPAllocationMethod
}

func azureAppGatewayFrontendIpConfigToMql(runtime *plugin.Runtime, fc *network.ApplicationGatewayFrontendIPConfiguration) (*mqlAzureSubscriptionNetworkServiceApplicationGatewayFrontendIpConfig, error) {
	id, name, subnetId, publicIpAddressId, privateIPAddress, privateIPAllocationMethod := frontendIpConfigFields(fc)
	res, err := CreateResource(runtime, "azure.subscription.networkService.applicationGateway.frontendIpConfig", map[string]*llx.RawData{
		"id":                        llx.StringData(id),
		"name":                      llx.StringData(name),
		"subnetId":                  llx.StringData(subnetId),
		"publicIpAddressId":         llx.StringData(publicIpAddressId),
		"privateIPAddress":          llx.StringData(privateIPAddress),
		"privateIPAllocationMethod": llx.StringData(privateIPAllocationMethod),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceApplicationGatewayFrontendIpConfig), nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationGatewaySslCertificate) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionNetworkServiceFirewallInternal struct {
	cacheProperties *network.AzureFirewallPropertiesFormat
}

func azureFirewallToMql(runtime *plugin.Runtime, fw network.AzureFirewall) (*mqlAzureSubscriptionNetworkServiceFirewall, error) {
	props, err := convert.JsonToDict(fw.Properties)
	if err != nil {
		return nil, err
	}
	var fwSkuTier, fwSkuName, fwProvisioningState, fwThreatIntelMode, fwAfcServiceEndpoint *string
	var fwAiSecurityAddOn *bool
	if fw.Properties != nil {
		fwAiSecurityAddOn = fw.Properties.AiSecurityAddOn
		fwProvisioningState = (*string)(fw.Properties.ProvisioningState)
		fwThreatIntelMode = (*string)(fw.Properties.ThreatIntelMode)
		if fw.Properties.SKU != nil {
			fwSkuTier = (*string)(fw.Properties.SKU.Tier)
			fwSkuName = (*string)(fw.Properties.SKU.Name)
		}
		if fw.Properties.AfcConfiguration != nil {
			fwAfcServiceEndpoint = fw.Properties.AfcConfiguration.ServiceEndpoint
		}
	}
	args := map[string]*llx.RawData{
		"id":                 llx.StringDataPtr(fw.ID),
		"name":               llx.StringDataPtr(fw.Name),
		"type":               llx.StringDataPtr(fw.Type),
		"location":           llx.StringDataPtr(fw.Location),
		"tags":               llx.MapData(convert.PtrMapStrToInterface(fw.Tags), types.String),
		"etag":               llx.StringDataPtr(fw.Etag),
		"properties":         llx.DictData(props),
		"skuTier":            llx.StringDataPtr(fwSkuTier),
		"skuName":            llx.StringDataPtr(fwSkuName),
		"provisioningState":  llx.StringDataPtr(fwProvisioningState),
		"threatIntelMode":    llx.StringDataPtr(fwThreatIntelMode),
		"afcServiceEndpoint": llx.StringDataPtr(fwAfcServiceEndpoint),
		"aiSecurityAddOn":    llx.BoolDataPtr(fwAiSecurityAddOn),
	}
	mqlFw, err := CreateResource(runtime, "azure.subscription.networkService.firewall", args)
	if err != nil {
		return nil, err
	}
	fwRes := mqlFw.(*mqlAzureSubscriptionNetworkServiceFirewall)
	fwRes.cacheProperties = fw.Properties
	return fwRes, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) ipConfigurations() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, ipConfig := range a.cacheProperties.IPConfigurations {
		if ipConfig == nil {
			continue
		}
		props, err := convert.JsonToDict(ipConfig.Properties)
		if err != nil {
			return nil, err
		}
		var privateIP *string
		if ipConfig.Properties != nil {
			privateIP = ipConfig.Properties.PrivateIPAddress
		}
		mqlIpConfig, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.firewall.ipConfig",
			map[string]*llx.RawData{
				"id":               llx.StringDataPtr(ipConfig.ID),
				"name":             llx.StringDataPtr(ipConfig.Name),
				"etag":             llx.StringDataPtr(ipConfig.Etag),
				"privateIpAddress": llx.StringDataPtr(privateIP),
				"properties":       llx.DictData(props),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIpConfig)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) managementIpConfiguration() (*mqlAzureSubscriptionNetworkServiceFirewallIpConfig, error) {
	if a.cacheProperties == nil || a.cacheProperties.ManagementIPConfiguration == nil {
		a.ManagementIpConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ipConfig := a.cacheProperties.ManagementIPConfiguration
	props, err := convert.JsonToDict(ipConfig.Properties)
	if err != nil {
		return nil, err
	}
	var privateIP *string
	if ipConfig.Properties != nil {
		privateIP = ipConfig.Properties.PrivateIPAddress
	}
	mqlIpConfig, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.firewall.ipConfig",
		map[string]*llx.RawData{
			"id":               llx.StringDataPtr(ipConfig.ID),
			"name":             llx.StringDataPtr(ipConfig.Name),
			"etag":             llx.StringDataPtr(ipConfig.Etag),
			"privateIpAddress": llx.StringDataPtr(privateIP),
			"properties":       llx.DictData(props),
		})
	if err != nil {
		return nil, err
	}
	return mqlIpConfig.(*mqlAzureSubscriptionNetworkServiceFirewallIpConfig), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) natRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, natRule := range a.cacheProperties.NatRuleCollections {
		if natRule == nil {
			continue
		}
		var action string
		var priority *int64
		rules := []any{}
		if p := natRule.Properties; p != nil {
			if p.Action != nil && p.Action.Type != nil {
				action = string(*p.Action.Type)
			}
			if p.Priority != nil {
				v := int64(*p.Priority)
				priority = &v
			}
			r, err := convert.JsonToDictSlice(p.Rules)
			if err != nil {
				return nil, err
			}
			rules = r
		}
		mqlNatRule, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.firewall.natRule",
			map[string]*llx.RawData{
				"id":       llx.StringDataPtr(natRule.ID),
				"name":     llx.StringDataPtr(natRule.Name),
				"etag":     llx.StringDataPtr(natRule.Etag),
				"action":   llx.StringData(action),
				"priority": llx.IntDataPtr(priority),
				"rules":    llx.ArrayData(rules, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNatRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) networkRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, networkRule := range a.cacheProperties.NetworkRuleCollections {
		if networkRule == nil {
			continue
		}
		var action string
		var priority *int64
		rules := []any{}
		if p := networkRule.Properties; p != nil {
			if p.Action != nil && p.Action.Type != nil {
				action = string(*p.Action.Type)
			}
			if p.Priority != nil {
				v := int64(*p.Priority)
				priority = &v
			}
			r, err := convert.JsonToDictSlice(p.Rules)
			if err != nil {
				return nil, err
			}
			rules = r
		}
		mqlNetworkRule, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.firewall.networkRule",
			map[string]*llx.RawData{
				"id":       llx.StringDataPtr(networkRule.ID),
				"name":     llx.StringDataPtr(networkRule.Name),
				"etag":     llx.StringDataPtr(networkRule.Etag),
				"action":   llx.StringData(action),
				"priority": llx.IntDataPtr(priority),
				"rules":    llx.ArrayData(rules, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNetworkRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewall) applicationRules() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, appRule := range a.cacheProperties.ApplicationRuleCollections {
		if appRule == nil {
			continue
		}
		var action string
		var priority *int64
		rules := []any{}
		if p := appRule.Properties; p != nil {
			if p.Action != nil && p.Action.Type != nil {
				action = string(*p.Action.Type)
			}
			if p.Priority != nil {
				v := int64(*p.Priority)
				priority = &v
			}
			r, err := convert.JsonToDictSlice(p.Rules)
			if err != nil {
				return nil, err
			}
			rules = r
		}
		mqlAppRule, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.firewall.applicationRule",
			map[string]*llx.RawData{
				"id":       llx.StringDataPtr(appRule.ID),
				"name":     llx.StringDataPtr(appRule.Name),
				"etag":     llx.StringDataPtr(appRule.Etag),
				"action":   llx.StringData(action),
				"priority": llx.IntDataPtr(priority),
				"rules":    llx.ArrayData(rules, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAppRule)
	}
	return res, nil
}

func azureFirewallPolicyToMql(runtime *plugin.Runtime, fwp network.FirewallPolicy) (*mqlAzureSubscriptionNetworkServiceFirewallPolicy, error) {
	props, err := convert.JsonToDict(fwp.Properties)
	if err != nil {
		return nil, err
	}
	// Properties can be nil on a minimal API response (e.g. a by-ID Get from
	// the firewallPolicy init), so guard before dereferencing.
	var provisioningState *string
	if fwp.Properties != nil {
		provisioningState = (*string)(fwp.Properties.ProvisioningState)
	}

	var threatIntelMode, transportSecurityCertName, transportSecurityKvSecretId *string
	var explicitProxyPacFile *string
	var dnsProxyEnabled, dnsRequireProxy, explicitProxyEnabled, explicitProxyPacFileEnabled, insightsEnabled *bool
	var explicitProxyHttpPort, explicitProxyHttpsPort, explicitProxyPacFilePort, insightsRetentionDays *int32
	threatIntelAllowedFqdns := []any{}
	threatIntelAllowedIps := []any{}
	dnsServers := []any{}
	snatPrivateRanges := []any{}
	if p := fwp.Properties; p != nil {
		threatIntelMode = stringEnumPtr(p.ThreatIntelMode)
		if w := p.ThreatIntelWhitelist; w != nil {
			threatIntelAllowedFqdns = strPtrsToAny(w.Fqdns)
			threatIntelAllowedIps = strPtrsToAny(w.IPAddresses)
		}
		if ts := p.TransportSecurity; ts != nil && ts.CertificateAuthority != nil {
			transportSecurityCertName = ts.CertificateAuthority.Name
			transportSecurityKvSecretId = ts.CertificateAuthority.KeyVaultSecretID
		}
		if d := p.DNSSettings; d != nil {
			dnsProxyEnabled = d.EnableProxy
			dnsRequireProxy = d.RequireProxyForNetworkRules
			dnsServers = strPtrsToAny(d.Servers)
		}
		if e := p.ExplicitProxySettings; e != nil {
			explicitProxyEnabled = e.EnableExplicitProxy
			explicitProxyPacFileEnabled = e.EnablePacFile
			explicitProxyHttpPort = e.HTTPPort
			explicitProxyHttpsPort = e.HTTPSPort
			explicitProxyPacFile = e.PacFile
			explicitProxyPacFilePort = e.PacFilePort
		}
		if i := p.Insights; i != nil {
			insightsEnabled = i.IsEnabled
			insightsRetentionDays = i.RetentionDays
		}
		if s := p.Snat; s != nil {
			snatPrivateRanges = strPtrsToAny(s.PrivateRanges)
		}
	}

	mqlFw, err := CreateResource(runtime, "azure.subscription.networkService.firewallPolicy",
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(fwp.ID),
			"name":              llx.StringDataPtr(fwp.Name),
			"type":              llx.StringDataPtr(fwp.Type),
			"location":          llx.StringDataPtr(fwp.Location),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(fwp.Tags), types.String),
			"etag":              llx.StringDataPtr(fwp.Etag),
			"properties":        llx.DictData(props),
			"provisioningState": llx.StringDataPtr(provisioningState),

			"threatIntelMode":                   llx.StringDataPtr(threatIntelMode),
			"threatIntelAllowedFqdns":           llx.ArrayData(threatIntelAllowedFqdns, types.String),
			"threatIntelAllowedIpAddresses":     llx.ArrayData(threatIntelAllowedIps, types.String),
			"transportSecurityCertificateName":  llx.StringDataPtr(transportSecurityCertName),
			"transportSecurityKeyVaultSecretId": llx.StringDataPtr(transportSecurityKvSecretId),
			"dnsProxyEnabled":                   llx.BoolDataPtr(dnsProxyEnabled),
			"dnsRequireProxyForNetworkRules":    llx.BoolDataPtr(dnsRequireProxy),
			"dnsServers":                        llx.ArrayData(dnsServers, types.String),
			"explicitProxyEnabled":              llx.BoolDataPtr(explicitProxyEnabled),
			"explicitProxyHttpPort":             llx.IntDataPtr(explicitProxyHttpPort),
			"explicitProxyHttpsPort":            llx.IntDataPtr(explicitProxyHttpsPort),
			"explicitProxyPacFileEnabled":       llx.BoolDataPtr(explicitProxyPacFileEnabled),
			"explicitProxyPacFile":              llx.StringDataPtr(explicitProxyPacFile),
			"explicitProxyPacFilePort":          llx.IntDataPtr(explicitProxyPacFilePort),
			"insightsEnabled":                   llx.BoolDataPtr(insightsEnabled),
			"insightsRetentionDays":             llx.IntDataPtr(insightsRetentionDays),
			"snatPrivateRanges":                 llx.ArrayData(snatPrivateRanges, types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlFwPolicy := mqlFw.(*mqlAzureSubscriptionNetworkServiceFirewallPolicy)
	if fwp.Properties != nil {
		mqlFwPolicy.cacheIntrusionDetection = fwp.Properties.IntrusionDetection
	}

	return mqlFwPolicy, nil
}

func azureIpToMql(runtime *plugin.Runtime, ip network.PublicIPAddress) (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	var ipAllocationMethod, ipVersion, ddosProtectionMode, associatedResourceId string
	var ipAddr, publicIpPrefixId, natGatewayId *string
	var upgradedToV2 *bool
	var idleTimeoutInMinutes int64
	ipTags := []any{}
	if ip.Properties != nil {
		ipAddr = ip.Properties.IPAddress
		upgradedToV2 = ip.Properties.UpgradedToV2
		if ip.Properties.PublicIPAllocationMethod != nil {
			ipAllocationMethod = string(*ip.Properties.PublicIPAllocationMethod)
		}
		if ip.Properties.PublicIPAddressVersion != nil {
			ipVersion = string(*ip.Properties.PublicIPAddressVersion)
		}
		if ip.Properties.DdosSettings != nil && ip.Properties.DdosSettings.ProtectionMode != nil {
			ddosProtectionMode = string(*ip.Properties.DdosSettings.ProtectionMode)
		}
		if ip.Properties.IPConfiguration != nil && ip.Properties.IPConfiguration.ID != nil {
			associatedResourceId = *ip.Properties.IPConfiguration.ID
		}
		if ip.Properties.PublicIPPrefix != nil {
			publicIpPrefixId = ip.Properties.PublicIPPrefix.ID
		}
		if ip.Properties.NatGateway != nil {
			natGatewayId = ip.Properties.NatGateway.ID
		}
		if ip.Properties.IdleTimeoutInMinutes != nil {
			idleTimeoutInMinutes = int64(*ip.Properties.IdleTimeoutInMinutes)
		}
		tags, err := convert.JsonToDictSlice(ip.Properties.IPTags)
		if err != nil {
			return nil, err
		}
		ipTags = tags
	}
	var skuName, skuTier string
	if ip.SKU != nil {
		if ip.SKU.Name != nil {
			skuName = string(*ip.SKU.Name)
		}
		if ip.SKU.Tier != nil {
			skuTier = string(*ip.SKU.Tier)
		}
	}
	zones := []any{}
	for _, z := range ip.Zones {
		if z != nil {
			zones = append(zones, *z)
		}
	}
	mqlAzure, err := CreateResource(runtime, "azure.subscription.networkService.ipAddress",
		map[string]*llx.RawData{
			"id":                   llx.StringDataPtr(ip.ID),
			"name":                 llx.StringDataPtr(ip.Name),
			"location":             llx.StringDataPtr(ip.Location),
			"tags":                 llx.MapData(convert.PtrMapStrToInterface(ip.Tags), types.String),
			"type":                 llx.StringDataPtr(ip.Type),
			"ipAddress":            llx.StringDataPtr(ipAddr),
			"ipAllocationMethod":   llx.StringData(ipAllocationMethod),
			"ipVersion":            llx.StringData(ipVersion),
			"zones":                llx.ArrayData(zones, types.String),
			"ddosProtectionMode":   llx.StringData(ddosProtectionMode),
			"associatedResourceId": llx.StringData(associatedResourceId),
			"skuName":              llx.StringData(skuName),
			"skuTier":              llx.StringData(skuTier),
			"idleTimeoutInMinutes": llx.IntData(idleTimeoutInMinutes),
			"ipTags":               llx.ArrayData(ipTags, types.Dict),
			"upgradedToV2":         llx.BoolDataPtr(upgradedToV2),
		})
	if err != nil {
		return nil, err
	}
	mqlIp := mqlAzure.(*mqlAzureSubscriptionNetworkServiceIpAddress)
	mqlIp.cachePublicIpPrefixID = publicIpPrefixId
	mqlIp.cacheNatGatewayID = natGatewayId
	return mqlIp, nil
}

type mqlAzureSubscriptionNetworkServiceIpAddressInternal struct {
	cachePublicIpPrefixID *string
	cacheNatGatewayID     *string
}

func (a *mqlAzureSubscriptionNetworkServiceIpAddress) natGateway() (*mqlAzureSubscriptionNetworkServiceNatGateway, error) {
	if a.cacheNatGatewayID == nil || *a.cacheNatGatewayID == "" {
		a.NatGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.natGateway", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheNatGatewayID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceNatGateway), nil
}

func (a *mqlAzureSubscriptionNetworkServiceIpAddress) publicIpPrefix() (*mqlAzureSubscriptionNetworkServicePublicIpPrefix, error) {
	if a.cachePublicIpPrefixID == nil || *a.cachePublicIpPrefixID == "" {
		a.PublicIpPrefix.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.publicIpPrefix", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cachePublicIpPrefixID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServicePublicIpPrefix), nil
}

// natGatewayNat64Enabled reports whether NAT64 translation is switched on for
// the NAT gateway. The SDK models this as a tri-state (Enabled/Disabled/None);
// we collapse it to a bool where only the explicit Enabled state is true, so an
// unset ("None") or nil value reads as "not enabled".
func natGatewayNat64Enabled(props *network.NatGatewayPropertiesFormat) bool {
	return props != nil && props.Nat64 != nil && *props.Nat64 == network.Nat64StateEnabled
}

// initAzureSubscriptionNetworkServiceNatGateway resolves a NAT gateway by its
// ARM ID so typed references to it (e.g. from a public IP address) populate
// fully.
func initAzureSubscriptionNetworkServiceNatGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("natGateways")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceNatGateway, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewNatGatewaysClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureNatGatewayToMql(runtime, resp.NatGateway)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

func azureNatGatewayToMql(runtime *plugin.Runtime, ng network.NatGateway) (*mqlAzureSubscriptionNetworkServiceNatGateway, error) {
	props, err := convert.JsonToDict(ng.Properties)
	if err != nil {
		return nil, err
	}
	nat64Enabled := natGatewayNat64Enabled(ng.Properties)
	mqlNg, err := CreateResource(runtime, "azure.subscription.networkService.natGateway",
		map[string]*llx.RawData{
			"id":           llx.StringDataPtr(ng.ID),
			"name":         llx.StringDataPtr(ng.Name),
			"type":         llx.StringDataPtr(ng.Type),
			"location":     llx.StringDataPtr(ng.Location),
			"tags":         llx.MapData(convert.PtrMapStrToInterface(ng.Tags), types.String),
			"etag":         llx.StringDataPtr(ng.Etag),
			"zones":        llx.ArrayData(strPtrsToAny(ng.Zones), types.String),
			"nat64Enabled": llx.BoolData(nat64Enabled),
			"properties":   llx.DictData(props),
		})
	if err != nil {
		return nil, err
	}
	return mqlNg.(*mqlAzureSubscriptionNetworkServiceNatGateway), nil
}

func initAzureSubscriptionNetworkServiceSubnet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	azureId, err := ParseResourceID(id)
	if err != nil {
		return args, nil, nil
	}
	vnName, err := azureId.Component("virtualNetworks")
	if err != nil {
		return args, nil, nil
	}
	subnetName, err := azureId.Component("subnets")
	if err != nil {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceSubnet, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewSubnetsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, vnName, subnetName, &network.SubnetsClientGetOptions{})
	if err != nil {
		// Not `return args, nil, nil`: that has the runtime build a subnet from
		// the id alone, every other field unset rather than null, which reaches
		// the client as an untyped null with nothing naming the cause. Callers
		// resolving a subnet reference through here need the failure reported.
		return nil, nil, err
	}

	mqlSubnet, err := azureSubnetToMql(runtime, resp.Subnet)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlSubnet, nil
}

func azureSubnetToMql(runtime *plugin.Runtime, subnet network.Subnet) (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	props, err := convert.JsonToDict(subnet.Properties)
	if err != nil {
		return nil, err
	}

	var addressPrefix *llx.RawData
	var privateEndpointNetworkPolicies, privateLinkServiceNetworkPolicies *llx.RawData
	var defaultOutboundAccess *llx.RawData
	var sharingScope *llx.RawData
	addressPrefixes := []any{}
	serviceEndpoints := []any{}
	delegations := []any{}
	var nsgID, routeTableID string
	subnetID := ""
	if subnet.ID != nil {
		subnetID = *subnet.ID
	}
	if subnet.Properties != nil {
		addressPrefix = llx.StringDataPtr(subnet.Properties.AddressPrefix)
		if subnet.Properties.PrivateEndpointNetworkPolicies != nil {
			privateEndpointNetworkPolicies = llx.StringData(string(*subnet.Properties.PrivateEndpointNetworkPolicies))
		} else {
			privateEndpointNetworkPolicies = llx.StringData("")
		}
		if subnet.Properties.PrivateLinkServiceNetworkPolicies != nil {
			privateLinkServiceNetworkPolicies = llx.StringData(string(*subnet.Properties.PrivateLinkServiceNetworkPolicies))
		} else {
			privateLinkServiceNetworkPolicies = llx.StringData("")
		}
		defaultOutboundAccess = llx.BoolDataPtr(subnet.Properties.DefaultOutboundAccess)
		sharingScope = llx.StringDataPtr(stringEnumPtr(subnet.Properties.SharingScope))

		for _, p := range subnet.Properties.AddressPrefixes {
			if p != nil {
				addressPrefixes = append(addressPrefixes, *p)
			}
		}
		if subnet.Properties.NetworkSecurityGroup != nil && subnet.Properties.NetworkSecurityGroup.ID != nil {
			nsgID = *subnet.Properties.NetworkSecurityGroup.ID
		}
		if subnet.Properties.RouteTable != nil && subnet.Properties.RouteTable.ID != nil {
			routeTableID = *subnet.Properties.RouteTable.ID
		}
		for i, se := range subnet.Properties.ServiceEndpoints {
			if se == nil {
				continue
			}
			mqlSE, err := azureSubnetServiceEndpointToMql(runtime, subnetID, i, se)
			if err != nil {
				return nil, err
			}
			serviceEndpoints = append(serviceEndpoints, mqlSE)
		}
		for _, d := range subnet.Properties.Delegations {
			if d == nil {
				continue
			}
			mqlDel, err := azureSubnetDelegationToMql(runtime, subnetID, d)
			if err != nil {
				return nil, err
			}
			delegations = append(delegations, mqlDel)
		}
	} else {
		addressPrefix = llx.StringData("")
		privateEndpointNetworkPolicies = llx.StringData("")
		privateLinkServiceNetworkPolicies = llx.StringData("")
		defaultOutboundAccess = llx.BoolData(false)
		sharingScope = llx.StringData("")
	}

	mqlAzure, err := CreateResource(runtime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{
			"id":                                llx.StringDataPtr(subnet.ID),
			"name":                              llx.StringDataPtr(subnet.Name),
			"type":                              llx.StringDataPtr(subnet.Type),
			"etag":                              llx.StringDataPtr(subnet.Etag),
			"addressPrefix":                     addressPrefix,
			"addressPrefixes":                   llx.ArrayData(addressPrefixes, types.String),
			"properties":                        llx.DictData(props),
			"privateEndpointNetworkPolicies":    privateEndpointNetworkPolicies,
			"privateLinkServiceNetworkPolicies": privateLinkServiceNetworkPolicies,
			"defaultOutboundAccess":             defaultOutboundAccess,
			"sharingScope":                      sharingScope,
			"serviceEndpoints":                  llx.ArrayData(serviceEndpoints, types.Resource("azure.subscription.networkService.subnet.serviceEndpoint")),
			"delegations":                       llx.ArrayData(delegations, types.Resource("azure.subscription.networkService.subnet.delegation")),
		})
	if err != nil {
		return nil, err
	}
	mqlSubnet := mqlAzure.(*mqlAzureSubscriptionNetworkServiceSubnet)
	// see azureInterfaceToMql: a reference-shaped payload must not clear values
	// a full read already stored on the cached instance
	if subnet.Properties != nil {
		mqlSubnet.cacheNetworkSecurityGroupID = nsgID
		mqlSubnet.cacheRouteTableID = routeTableID
		for _, pe := range subnet.Properties.PrivateEndpoints {
			if pe != nil && pe.ID != nil {
				mqlSubnet.cachePrivateEndpointIDs = append(mqlSubnet.cachePrivateEndpointIDs, *pe.ID)
			}
		}
		mqlSubnet.cacheIPAllocationIDs = azureNetworkSubResourceIDs(subnet.Properties.IPAllocations)
		for _, ipConfig := range subnet.Properties.IPConfigurations {
			if ipConfig != nil && ipConfig.ID != nil {
				mqlSubnet.cacheIPConfigurationIDs = append(mqlSubnet.cacheIPConfigurationIDs, *ipConfig.ID)
			}
		}
	}
	return mqlSubnet, nil
}

type mqlAzureSubscriptionNetworkServiceSubnetInternal struct {
	cacheNetworkSecurityGroupID string
	cacheRouteTableID           string
	cachePrivateEndpointIDs     []string
	cacheIPAllocationIDs        []string
	cacheIPConfigurationIDs     []string
}

// subnetIPConfigIDSet lowercases a subnet's ipConfigurations ids so they can be
// matched against the same ids as the owning resource reports them.
//
// ARM upper-cases these inside the subnet --
// .../networkInterfaces/MY-NIC/ipConfigurations/INTERNAL -- while the interface
// itself reports the identical id in the casing it was created with, so a direct
// comparison finds nothing. ARM resource ids are case-insensitive, so folding both
// sides is the correct comparison rather than a workaround.
func subnetIPConfigIDSet(ids []string) map[string]struct{} {
	if len(ids) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			set[id] = struct{}{}
		}
	}
	return set
}

// interfaceIpConfigurations resolves the network interface IP configurations that
// hold an address from this subnet.
//
// A subnet's properties.ipConfigurations is where ARM reports them, and in
// practice it is almost entirely interface configurations: virtual machine
// interfaces, private endpoint interfaces, load balancer backend members. Nothing
// exposed them, because the only accessor over that list matched virtual network
// gateway configurations, which exist on a gateway subnet and nowhere else.
//
// Resolved by walking the interface list rather than fetching per id: there is no
// API for an IP configuration on its own, and the interfaces are fetched once for
// the whole scan.
func (a *mqlAzureSubscriptionNetworkServiceSubnet) interfaceIpConfigurations() ([]any, error) {
	wanted := subnetIPConfigIDSet(a.cacheIPConfigurationIDs)
	res := []any{}
	if len(wanted) == 0 {
		return res, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	svc, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	interfaces := svc.(*mqlAzureSubscriptionNetworkService).GetInterfaces()
	if interfaces.Error != nil {
		return nil, interfaces.Error
	}

	for _, iface := range interfaces.Data {
		mqlIface, ok := iface.(*mqlAzureSubscriptionNetworkServiceInterface)
		if !ok {
			continue
		}
		ipConfigs := mqlIface.GetIpConfigs()
		if ipConfigs.Error != nil {
			// One unreadable interface should not hide every address in the
			// subnet; the rest are still reported.
			log.Warn().Err(ipConfigs.Error).Str("interface", mqlIface.Id.Data).
				Msg("could not read ip configurations while resolving a subnet's")
			continue
		}
		for _, ipConfig := range ipConfigs.Data {
			mqlIPConfig, ok := ipConfig.(*mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration)
			if !ok {
				continue
			}
			if _, ok := wanted[strings.ToLower(mqlIPConfig.Id.Data)]; ok {
				res = append(res, mqlIPConfig)
			}
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) privateEndpoints() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.privateEndpoint", a.cachePrivateEndpointIDs)
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) ipAllocations() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.ipAllocation", a.cacheIPAllocationIDs)
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) networkSecurityGroup() (*mqlAzureSubscriptionNetworkServiceSecurityGroup, error) {
	if a.cacheNetworkSecurityGroupID == "" {
		a.NetworkSecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.securityGroup",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheNetworkSecurityGroupID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSecurityGroup), nil
}

func (a *mqlAzureSubscriptionNetworkServiceSubnet) routeTable() (*mqlAzureSubscriptionNetworkServiceRouteTable, error) {
	if a.cacheRouteTableID == "" {
		a.RouteTable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.routeTable",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheRouteTableID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceRouteTable), nil
}

// virtualNetworkIDFromSubnetID derives the parent virtual network's resource ID
// from a subnet resource ID by trimming the trailing "/subnets/<name>" segment.
// It returns "" when the ID has no "/subnets/" segment.
func virtualNetworkIDFromSubnetID(subnetID string) string {
	idx := strings.Index(strings.ToLower(subnetID), "/subnets/")
	if idx < 0 {
		return ""
	}
	return subnetID[:idx]
}

// virtualNetwork resolves the parent virtual network of the subnet so its
// peerings and address space can be traversed, extending a reachability path to
// networks peered with the one hosting the subnet.
func (a *mqlAzureSubscriptionNetworkServiceSubnet) virtualNetwork() (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	vnetID := virtualNetworkIDFromSubnetID(a.Id.Data)
	if vnetID == "" {
		a.VirtualNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetwork",
		map[string]*llx.RawData{"id": llx.StringData(vnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
}

func azureSubnetServiceEndpointToMql(runtime *plugin.Runtime, subnetID string, idx int, se *network.ServiceEndpointPropertiesFormat) (*mqlAzureSubscriptionNetworkServiceSubnetServiceEndpoint, error) {
	service := ""
	if se.Service != nil {
		service = *se.Service
	}
	provisioningState := ""
	if se.ProvisioningState != nil {
		provisioningState = string(*se.ProvisioningState)
	}
	locations := []any{}
	for _, l := range se.Locations {
		if l != nil {
			locations = append(locations, *l)
		}
	}
	id := fmt.Sprintf("%s/serviceEndpoints/%s/%d", subnetID, service, idx)
	res, err := CreateResource(runtime, "azure.subscription.networkService.subnet.serviceEndpoint",
		map[string]*llx.RawData{
			"__id":              llx.StringData(id),
			"service":           llx.StringData(service),
			"locations":         llx.ArrayData(locations, types.String),
			"provisioningState": llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnetServiceEndpoint), nil
}

func azureSubnetDelegationToMql(runtime *plugin.Runtime, subnetID string, d *network.Delegation) (*mqlAzureSubscriptionNetworkServiceSubnetDelegation, error) {
	name := ""
	if d.Name != nil {
		name = *d.Name
	}
	id := ""
	if d.ID != nil {
		id = *d.ID
	} else {
		id = fmt.Sprintf("%s/delegations/%s", subnetID, name)
	}
	serviceName := ""
	provisioningState := ""
	actions := []any{}
	if d.Properties != nil {
		if d.Properties.ServiceName != nil {
			serviceName = *d.Properties.ServiceName
		}
		if d.Properties.ProvisioningState != nil {
			provisioningState = string(*d.Properties.ProvisioningState)
		}
		for _, a := range d.Properties.Actions {
			if a != nil {
				actions = append(actions, *a)
			}
		}
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.subnet.delegation",
		map[string]*llx.RawData{
			"__id":              llx.StringData(id),
			"name":              llx.StringData(name),
			"serviceName":       llx.StringData(serviceName),
			"actions":           llx.ArrayData(actions, types.String),
			"provisioningState": llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnetDelegation), nil
}

func azureInterfaceToMql(runtime *plugin.Runtime, iface network.Interface) (*mqlAzureSubscriptionNetworkServiceInterface, error) {
	properties, err := convert.JsonToDict(iface.Properties)
	if err != nil {
		return nil, err
	}

	var enableIPForwarding, enableAcceleratedNetworking, primary *llx.RawData
	var disableTcpStateTracking *llx.RawData
	var networkSecurityGroupId, internalDnsNameLabel string
	var nicType, auxiliaryMode, auxiliarySku, migrationPhase string
	var privateEndpointId, privateLinkServiceId, resourceGuid string
	hostedWorkloads := []any{}
	dnsServers := []any{}
	appliedDnsServers := []any{}
	ipConfigs := []any{}
	if iface.Properties != nil {
		enableIPForwarding = llx.BoolDataPtr(iface.Properties.EnableIPForwarding)
		enableAcceleratedNetworking = llx.BoolDataPtr(iface.Properties.EnableAcceleratedNetworking)
		primary = llx.BoolDataPtr(iface.Properties.Primary)
		disableTcpStateTracking = llx.BoolDataPtr(iface.Properties.DisableTCPStateTracking)
		nicType = convert.ToValue(stringEnumPtr(iface.Properties.NicType))
		auxiliaryMode = convert.ToValue(stringEnumPtr(iface.Properties.AuxiliaryMode))
		auxiliarySku = convert.ToValue(stringEnumPtr(iface.Properties.AuxiliarySKU))
		migrationPhase = convert.ToValue(stringEnumPtr(iface.Properties.MigrationPhase))
		if iface.Properties.ResourceGUID != nil {
			resourceGuid = *iface.Properties.ResourceGUID
		}
		if pe := iface.Properties.PrivateEndpoint; pe != nil && pe.ID != nil {
			privateEndpointId = *pe.ID
		}
		if pls := iface.Properties.PrivateLinkService; pls != nil && pls.ID != nil {
			privateLinkServiceId = *pls.ID
		}
		for _, hw := range iface.Properties.HostedWorkloads {
			if hw != nil {
				hostedWorkloads = append(hostedWorkloads, *hw)
			}
		}
		if iface.Properties.NetworkSecurityGroup != nil && iface.Properties.NetworkSecurityGroup.ID != nil {
			networkSecurityGroupId = *iface.Properties.NetworkSecurityGroup.ID
		}
		if iface.Properties.DNSSettings != nil {
			for _, s := range iface.Properties.DNSSettings.DNSServers {
				if s != nil {
					dnsServers = append(dnsServers, *s)
				}
			}
			for _, s := range iface.Properties.DNSSettings.AppliedDNSServers {
				if s != nil {
					appliedDnsServers = append(appliedDnsServers, *s)
				}
			}
			if iface.Properties.DNSSettings.InternalDNSNameLabel != nil {
				internalDnsNameLabel = *iface.Properties.DNSSettings.InternalDNSNameLabel
			}
		}
		for _, ipConfig := range iface.Properties.IPConfigurations {
			if ipConfig == nil {
				continue
			}
			configDict := map[string]any{}
			if ipConfig.Name != nil {
				configDict["name"] = *ipConfig.Name
			}
			if ipConfig.ID != nil {
				configDict["id"] = *ipConfig.ID
			}
			if ipConfig.Properties != nil {
				if ipConfig.Properties.PrivateIPAddress != nil {
					configDict["privateIpAddress"] = *ipConfig.Properties.PrivateIPAddress
				}
				if ipConfig.Properties.PrivateIPAllocationMethod != nil {
					configDict["privateIpAllocationMethod"] = string(*ipConfig.Properties.PrivateIPAllocationMethod)
				}
				if ipConfig.Properties.Primary != nil {
					configDict["primary"] = *ipConfig.Properties.Primary
				}
				if ipConfig.Properties.PublicIPAddress != nil && ipConfig.Properties.PublicIPAddress.ID != nil {
					configDict["publicIpAddressId"] = *ipConfig.Properties.PublicIPAddress.ID
				}
				if ipConfig.Properties.Subnet != nil && ipConfig.Properties.Subnet.ID != nil {
					configDict["subnetId"] = *ipConfig.Properties.Subnet.ID
				}
			}
			ipConfigs = append(ipConfigs, configDict)
		}
	} else {
		enableIPForwarding = llx.BoolData(false)
		enableAcceleratedNetworking = llx.BoolData(false)
		primary = llx.BoolData(false)
		disableTcpStateTracking = llx.BoolData(false)
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.interface",
		map[string]*llx.RawData{
			"id":                          llx.StringDataPtr(iface.ID),
			"name":                        llx.StringDataPtr(iface.Name),
			"location":                    llx.StringDataPtr(iface.Location),
			"tags":                        llx.MapData(convert.PtrMapStrToInterface(iface.Tags), types.String),
			"type":                        llx.StringDataPtr(iface.Type),
			"etag":                        llx.StringDataPtr(iface.Etag),
			"properties":                  llx.DictData(properties),
			"enableIPForwarding":          enableIPForwarding,
			"enableAcceleratedNetworking": enableAcceleratedNetworking,
			"primary":                     primary,
			"dnsServers":                  llx.ArrayData(dnsServers, types.String),
			"appliedDnsServers":           llx.ArrayData(appliedDnsServers, types.String),
			"internalDnsNameLabel":        llx.StringData(internalDnsNameLabel),
			"disableTcpStateTracking":     disableTcpStateTracking,
			"nicType":                     llx.StringData(nicType),
			"auxiliaryMode":               llx.StringData(auxiliaryMode),
			"auxiliarySku":                llx.StringData(auxiliarySku),
			"migrationPhase":              llx.StringData(migrationPhase),
			"hostedWorkloads":             llx.ArrayData(hostedWorkloads, types.String),
			"resourceGuid":                llx.StringData(resourceGuid),
		})
	if err != nil {
		return nil, err
	}
	mqlIface := res.(*mqlAzureSubscriptionNetworkServiceInterface)
	// Only seed the cache fields from a response that actually carried
	// properties. CreateResource returns the already-cached instance on a known
	// __id, so writing unconditionally let a reference-shaped payload clear the
	// values a full read had already stored.
	if iface.Properties != nil {
		mqlIface.cacheNetworkSecurityGroupID = networkSecurityGroupId
		mqlIface.cachePrivateEndpointID = privateEndpointId
		mqlIface.cachePrivateLinkServiceID = privateLinkServiceId
		mqlIface.cacheIPConfigurations = iface.Properties.IPConfigurations
	}
	return mqlIface, nil
}

type mqlAzureSubscriptionNetworkServiceInterfaceInternal struct {
	cacheNetworkSecurityGroupID string
	cachePrivateEndpointID      string
	cachePrivateLinkServiceID   string
	cacheIPConfigurations       []*network.InterfaceIPConfiguration

	// effNsgMu guards a memoized fetch of the NIC's effective NSGs, shared by
	// the effectiveSecurityRules field and the VM exposure computation so the
	// live Azure call is paid at most once per interface. Only a successful
	// fetch is memoized (effNsgLoaded), so a transient error can be retried.
	effNsgMu     sync.Mutex
	effNsgLoaded bool
	effNsgGroups []effectiveNsgGroup
	// effNsgEvaluated records whether Azure answered authoritatively. An
	// authoritative empty group list means the NIC has no NSG at all (every
	// inbound flow is admitted); a degraded fetch also yields an empty list
	// but proves nothing, and the two must not be conflated.
	effNsgEvaluated bool

	// effRouteMu guards a memoized fetch of the NIC's effective routes, shared
	// by the deprecated effectiveRouteTable field and the typed effectiveRoutes
	// field. BeginGetEffectiveRouteTable is a long-running operation bounded at
	// 60 seconds, so a query naming both fields would otherwise pay for it
	// twice. As with the NSG fetch, only a successful call is memoized
	// (effRouteLoaded), leaving a transient failure retryable.
	effRouteMu     sync.Mutex
	effRouteLoaded bool
	effRoutes      []*network.EffectiveRoute
}

func (a *mqlAzureSubscriptionNetworkServiceInterface) networkSecurityGroup() (*mqlAzureSubscriptionNetworkServiceSecurityGroup, error) {
	if a.cacheNetworkSecurityGroupID == "" {
		a.NetworkSecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.securityGroup",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheNetworkSecurityGroupID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSecurityGroup), nil
}

// privateEndpoint resolves the private endpoint a NIC belongs to. Null on an
// ordinary virtual machine NIC, which is the common case.
func (a *mqlAzureSubscriptionNetworkServiceInterface) privateEndpoint() (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	if a.cachePrivateEndpointID == "" {
		a.PrivateEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServicePrivateEndpoint,
		map[string]*llx.RawData{"id": llx.StringData(a.cachePrivateEndpointID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint), nil
}

// privateLinkService resolves the private link service a NIC forms part of the
// frontend for. Null on an ordinary virtual machine NIC.
func (a *mqlAzureSubscriptionNetworkServiceInterface) privateLinkService() (*mqlAzureSubscriptionNetworkServicePrivateLinkService, error) {
	if a.cachePrivateLinkServiceID == "" {
		a.PrivateLinkService.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServicePrivateLinkService,
		map[string]*llx.RawData{"id": llx.StringData(a.cachePrivateLinkServiceID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateLinkService), nil
}

// see https://github.com/Azure/azure-sdk-for-go/issues/8224
type AzureSecurityGroupPropertiesFormat network.SecurityGroupPropertiesFormat

type mqlAzureSubscriptionNetworkServiceSecurityGroupInternal struct {
	cacheProperties *network.SecurityGroupPropertiesFormat
}

func azureSecGroupToMql(runtime *plugin.Runtime, secGroup network.SecurityGroup) (*mqlAzureSubscriptionNetworkServiceSecurityGroup, error) {
	var properties map[string]any
	var err error
	if secGroup.Properties != nil {
		// avoid using the azure sdk SecurityGroupPropertiesFormat MarshalJSON
		var j AzureSecurityGroupPropertiesFormat
		j = AzureSecurityGroupPropertiesFormat(*secGroup.Properties)

		properties, err = convert.JsonToDict(j)
		if err != nil {
			return nil, err
		}
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.securityGroup",
		map[string]*llx.RawData{
			"id":         llx.StringDataPtr(secGroup.ID),
			"name":       llx.StringDataPtr(secGroup.Name),
			"location":   llx.StringDataPtr(secGroup.Location),
			"tags":       llx.MapData(convert.PtrMapStrToInterface(secGroup.Tags), types.String),
			"type":       llx.StringDataPtr(secGroup.Type),
			"etag":       llx.StringDataPtr(secGroup.Etag),
			"properties": llx.DictData(properties),
		})
	if err != nil {
		return nil, err
	}
	mqlSecGroup := res.(*mqlAzureSubscriptionNetworkServiceSecurityGroup)
	mqlSecGroup.cacheProperties = secGroup.Properties
	return mqlSecGroup, nil
}

// flowLog resolves the Network Watcher flow log whose target resource is this
// NSG. Flow logs are child resources of Network Watchers, so rather than
// enumerating every watcher for each NSG (an N+1 problem when querying
// `securityGroups { flowLog }`), it resolves the per-subscription
// networkService singleton and reuses its cached watcher→flow-log index.
// Returns null when no flow log targets the NSG.
func (a *mqlAzureSubscriptionNetworkServiceSecurityGroup) flowLog() (*mqlAzureSubscriptionNetworkServiceWatcherFlowlog, error) {
	nsgID := a.Id.Data
	resourceID, err := ParseResourceID(nsgID)
	if err != nil {
		return nil, err
	}

	netRes, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(resourceID.SubscriptionID),
	})
	if err != nil {
		return nil, err
	}
	netService := netRes.(*mqlAzureSubscriptionNetworkService)

	index, err := netService.flowLogIndexByTargetResourceId()
	if err != nil {
		return nil, err
	}
	if flowLog, ok := index[strings.ToLower(nsgID)]; ok {
		return flowLog, nil
	}

	// no flow log targets this NSG
	a.FlowLog.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

type mqlAzureSubscriptionNetworkServiceInternal struct {
	flowLogIndexOnce sync.Once
	flowLogIndex     map[string]*mqlAzureSubscriptionNetworkServiceWatcherFlowlog
	flowLogIndexErr  error
}

// flowLogIndexByTargetResourceId lazily builds, once per networkService
// instance, a map from a (lowercased) target resource id to the Network Watcher
// flow log that targets it. The subscription's watchers and their flow logs are
// enumerated a single time so that per-NSG lookups are in-memory.
func (a *mqlAzureSubscriptionNetworkService) flowLogIndexByTargetResourceId() (map[string]*mqlAzureSubscriptionNetworkServiceWatcherFlowlog, error) {
	a.flowLogIndexOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		ctx := context.Background()
		token := conn.Token()
		subId := a.SubscriptionId.Data

		index := map[string]*mqlAzureSubscriptionNetworkServiceWatcherFlowlog{}

		watchersClient, err := network.NewWatchersClient(subId, token, &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.flowLogIndexErr = err
			return
		}
		flowLogsClient, err := network.NewFlowLogsClient(subId, token, &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.flowLogIndexErr = err
			return
		}

		watcherPager := watchersClient.NewListAllPager(&network.WatchersClientListAllOptions{})
		for watcherPager.More() {
			page, err := watcherPager.NextPage(ctx)
			if err != nil {
				a.flowLogIndexErr = err
				return
			}
			for _, watcher := range page.Value {
				if watcher == nil || watcher.ID == nil || watcher.Name == nil {
					continue
				}
				watcherID, err := ParseResourceID(*watcher.ID)
				if err != nil {
					a.flowLogIndexErr = err
					return
				}
				flowLogPager := flowLogsClient.NewListPager(watcherID.ResourceGroup, *watcher.Name, &network.FlowLogsClientListOptions{})
				for flowLogPager.More() {
					flowLogPage, err := flowLogPager.NextPage(ctx)
					if err != nil {
						a.flowLogIndexErr = err
						return
					}
					for _, flowLog := range flowLogPage.Value {
						if flowLog == nil || flowLog.Properties == nil || flowLog.Properties.TargetResourceID == nil {
							continue
						}
						mqlFlowLog, err := flowLogToMql(a.MqlRuntime, *flowLog)
						if err != nil {
							a.flowLogIndexErr = err
							return
						}
						index[strings.ToLower(*flowLog.Properties.TargetResourceID)] = mqlFlowLog
					}
				}
			}
		}
		a.flowLogIndex = index
	})
	return a.flowLogIndex, a.flowLogIndexErr
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityGroup) interfaces() ([]any, error) {
	if a.cacheProperties == nil || a.cacheProperties.NetworkInterfaces == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, iface := range a.cacheProperties.NetworkInterfaces {
		// Resolve by id rather than mapping the embedded value. The SDK marks
		// SecurityGroupPropertiesFormat.NetworkInterfaces as "a collection of
		// references": ARM returns {"id": ...} with no properties. Mapping that
		// through azureInterfaceToMql invented enableIPForwarding: false and an
		// empty ipConfigurations list, and -- because CreateResource returns the
		// already-cached instance for a known __id while the mapper then wrote
		// its cache fields onto it -- wiped the NSG reference of a NIC that had
		// been read properly, so nic.networkSecurityGroup() answered null for
		// the rest of the scan. subnets() below has always done it this way.
		if iface == nil || iface.ID == nil {
			continue
		}
		mqlIface, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.interface",
			map[string]*llx.RawData{"id": llx.StringDataPtr(iface.ID)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIface)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityGroup) subnets() ([]any, error) {
	if a.cacheProperties == nil || a.cacheProperties.Subnets == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, subnet := range a.cacheProperties.Subnets {
		if subnet == nil || subnet.ID == nil {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
			map[string]*llx.RawData{"id": llx.StringDataPtr(subnet.ID)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityGroup) securityRules() ([]any, error) {
	if a.cacheProperties == nil || a.cacheProperties.SecurityRules == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, secRule := range a.cacheProperties.SecurityRules {
		if secRule == nil {
			continue
		}
		mqlRule, err := azureSecurityRuleToMql(a.MqlRuntime, *secRule)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityGroup) defaultSecurityRules() ([]any, error) {
	if a.cacheProperties == nil || a.cacheProperties.DefaultSecurityRules == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, secRule := range a.cacheProperties.DefaultSecurityRules {
		if secRule == nil {
			continue
		}
		mqlRule, err := azureSecurityRuleToMql(a.MqlRuntime, *secRule)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func azureSecurityRuleToMql(runtime *plugin.Runtime, secRule network.SecurityRule) (*mqlAzureSubscriptionNetworkServiceSecurityrule, error) {
	properties, err := convert.JsonToDict(secRule.Properties)
	if err != nil {
		return nil, err
	}

	destinationPortRange := []any{}

	if secRule.Properties != nil && secRule.Properties.DestinationPortRange != nil {
		dPortRange := parseAzureSecurityRulePortRange(*secRule.Properties.DestinationPortRange)
		for i := range dPortRange {
			destinationPortRange = append(destinationPortRange, map[string]any{
				"fromPort": dPortRange[i].FromPort,
				"toPort":   dPortRange[i].ToPort,
			})
		}
	}

	if secRule.Properties != nil && secRule.Properties.DestinationPortRanges != nil {
		for _, r := range secRule.Properties.DestinationPortRanges {
			// The same slice is walked again below with a nil guard. Without one
			// here a nil element panics, and a panic in an accessor is
			// unrecoverable: the executor runs blocks in goroutines, so it takes
			// down the whole scan rather than this one rule.
			if r == nil {
				continue
			}
			dPortRange := parseAzureSecurityRulePortRange(*r)
			for i := range dPortRange {
				destinationPortRange = append(destinationPortRange, map[string]any{
					"fromPort": dPortRange[i].FromPort,
					"toPort":   dPortRange[i].ToPort,
				})
			}
		}
	}

	var direction, protocol, access, sourcePortRange, sourceAddressPrefix, destinationAddressPrefix, description, provisioningState *llx.RawData
	var priority *llx.RawData
	sourcePortRanges := []any{}
	destinationPortRanges := []any{}
	sourceAddressPrefixes := []any{}
	destinationAddressPrefixes := []any{}
	if secRule.Properties != nil {
		direction = llx.StringDataPtr((*string)(secRule.Properties.Direction))
		if secRule.Properties.Protocol != nil {
			protocol = llx.StringData(string(*secRule.Properties.Protocol))
		} else {
			protocol = llx.StringData("")
		}
		if secRule.Properties.Access != nil {
			access = llx.StringData(string(*secRule.Properties.Access))
		} else {
			access = llx.StringData("")
		}
		priority = llx.IntDataDefault(secRule.Properties.Priority, 0)
		sourcePortRange = llx.StringDataPtr(secRule.Properties.SourcePortRange)
		sourceAddressPrefix = llx.StringDataPtr(secRule.Properties.SourceAddressPrefix)
		destinationAddressPrefix = llx.StringDataPtr(secRule.Properties.DestinationAddressPrefix)
		description = llx.StringDataPtr(secRule.Properties.Description)
		provisioningState = llx.StringDataPtr((*string)(secRule.Properties.ProvisioningState))
		for _, p := range secRule.Properties.SourcePortRanges {
			if p != nil {
				sourcePortRanges = append(sourcePortRanges, *p)
			}
		}
		for _, p := range secRule.Properties.DestinationPortRanges {
			if p != nil {
				destinationPortRanges = append(destinationPortRanges, *p)
			}
		}
		for _, p := range secRule.Properties.SourceAddressPrefixes {
			if p != nil {
				sourceAddressPrefixes = append(sourceAddressPrefixes, *p)
			}
		}
		for _, p := range secRule.Properties.DestinationAddressPrefixes {
			if p != nil {
				destinationAddressPrefixes = append(destinationAddressPrefixes, *p)
			}
		}
	} else {
		direction = llx.StringData("")
		protocol = llx.StringData("")
		access = llx.StringData("")
		priority = llx.IntData(0)
		sourcePortRange = llx.StringData("")
		sourceAddressPrefix = llx.StringData("")
		destinationAddressPrefix = llx.StringData("")
		description = llx.StringData("")
		provisioningState = llx.StringData("")
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.securityrule",
		map[string]*llx.RawData{
			"id":                         llx.StringDataPtr(secRule.ID),
			"name":                       llx.StringDataPtr(secRule.Name),
			"etag":                       llx.StringDataPtr(secRule.Etag),
			"direction":                  direction,
			"properties":                 llx.DictData(properties),
			"destinationPortRange":       llx.ArrayData(destinationPortRange, types.Dict),
			"protocol":                   protocol,
			"access":                     access,
			"priority":                   priority,
			"sourcePortRange":            sourcePortRange,
			"sourceAddressPrefix":        sourceAddressPrefix,
			"destinationAddressPrefix":   destinationAddressPrefix,
			"sourcePortRanges":           llx.ArrayData(sourcePortRanges, types.String),
			"destinationPortRanges":      llx.ArrayData(destinationPortRanges, types.String),
			"sourceAddressPrefixes":      llx.ArrayData(sourceAddressPrefixes, types.String),
			"destinationAddressPrefixes": llx.ArrayData(destinationAddressPrefixes, types.String),
			"description":                description,
			"provisioningState":          provisioningState,
		})
	if err != nil {
		return nil, err
	}
	mqlRule := res.(*mqlAzureSubscriptionNetworkServiceSecurityrule)
	mqlRule.cacheProperties = secRule.Properties
	return mqlRule, nil
}

type mqlAzureSubscriptionNetworkServiceSecurityruleInternal struct {
	cacheProperties *network.SecurityRulePropertiesFormat
}

func azureAppSecurityGroupToMql(runtime *plugin.Runtime, asg network.ApplicationSecurityGroup) (*mqlAzureSubscriptionNetworkServiceAppSecurityGroup, error) {
	props, err := convert.JsonToDict(asg.Properties)
	if err != nil {
		return nil, err
	}
	// When the ASG is referenced from a security rule, the Azure API returns
	// only the ARM resource ID. Recover the name from the ID's final segment
	// so consumers don't see name=null on otherwise-valid typed references.
	name := asg.Name
	if (name == nil || *name == "") && asg.ID != nil {
		if i := strings.LastIndex(*asg.ID, "/"); i >= 0 && i+1 < len(*asg.ID) {
			n := (*asg.ID)[i+1:]
			name = &n
		}
	}
	res, err := CreateResource(runtime, "azure.subscription.networkService.appSecurityGroup",
		map[string]*llx.RawData{
			"id":         llx.StringDataPtr(asg.ID),
			"name":       llx.StringDataPtr(name),
			"type":       llx.StringDataPtr(asg.Type),
			"location":   llx.StringDataPtr(asg.Location),
			"tags":       llx.MapData(convert.PtrMapStrToInterface(asg.Tags), types.String),
			"etag":       llx.StringDataPtr(asg.Etag),
			"properties": llx.DictData(props),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceAppSecurityGroup), nil
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityrule) sourceApplicationSecurityGroups() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	return azureAsgListToMql(a.MqlRuntime, a.cacheProperties.SourceApplicationSecurityGroups)
}

func (a *mqlAzureSubscriptionNetworkServiceSecurityrule) destinationApplicationSecurityGroups() ([]any, error) {
	if a.cacheProperties == nil {
		return []any{}, nil
	}
	return azureAsgListToMql(a.MqlRuntime, a.cacheProperties.DestinationApplicationSecurityGroups)
}

func azureAsgListToMql(runtime *plugin.Runtime, asgs []*network.ApplicationSecurityGroup) ([]any, error) {
	res := []any{}
	for _, asg := range asgs {
		if asg == nil {
			continue
		}
		mqlAsg, err := azureAppSecurityGroupToMql(runtime, *asg)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAsg)
	}
	return res, nil
}

type AzureSecurityRulePortRange struct {
	FromPort string
	ToPort   string
}

func parseAzureSecurityRulePortRange(portRange string) []AzureSecurityRulePortRange {
	res := []AzureSecurityRulePortRange{}
	entries := strings.Split(portRange, ",")
	for i := range entries {
		entry := strings.TrimSpace(entries[i])
		if strings.Contains(entry, "-") {
			entryRange := strings.Split(entry, "-")
			res = append(res, AzureSecurityRulePortRange{FromPort: entryRange[0], ToPort: entryRange[1]})
		} else {
			res = append(res, AzureSecurityRulePortRange{FromPort: entry, ToPort: entry})
		}
	}
	return res
}

func initAzureSubscriptionNetworkServiceSecurityGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure network security group")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.networkService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	network := res.(*mqlAzureSubscriptionNetworkService)
	secGrps := network.GetSecurityGroups()
	if secGrps.Error != nil {
		return nil, nil, secGrps.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range secGrps.Data {
		secGrp := entry.(*mqlAzureSubscriptionNetworkServiceSecurityGroup)
		if secGrp.Id.Data == id {
			return args, secGrp, nil
		}
	}

	return nil, nil, errors.New("azure network security group does not exist")
}

func initAzureSubscriptionNetworkServiceRouteTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if args["id"] == nil {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.networkService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	network := res.(*mqlAzureSubscriptionNetworkService)
	tables := network.GetRouteTables()
	if tables.Error != nil {
		return nil, nil, tables.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range tables.Data {
		rt := entry.(*mqlAzureSubscriptionNetworkServiceRouteTable)
		if rt.Id.Data == id {
			return args, rt, nil
		}
	}

	return nil, nil, errors.New("azure route table does not exist")
}

// --- DDoS Protection Plans ---

type mqlAzureSubscriptionNetworkServiceDdosProtectionPlanInternal struct {
	cacheVnetIds     []string
	cachePublicIpIds []string
}

func (a *mqlAzureSubscriptionNetworkService) ddosProtectionPlans() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewDdosProtectionPlansClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list DDoS protection plans due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, plan := range page.Value {
			if plan == nil {
				continue
			}

			var provisioningState string
			var vnetIds []string
			var publicIpIds []string
			if plan.Properties != nil {
				if plan.Properties.ProvisioningState != nil {
					provisioningState = string(*plan.Properties.ProvisioningState)
				}
				for _, vn := range plan.Properties.VirtualNetworks {
					if vn != nil && vn.ID != nil {
						vnetIds = append(vnetIds, *vn.ID)
					}
				}
				for _, pip := range plan.Properties.PublicIPAddresses {
					if pip != nil && pip.ID != nil {
						publicIpIds = append(publicIpIds, *pip.ID)
					}
				}
			}

			mqlPlan, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceDdosProtectionPlan,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(plan.ID),
					"name":              llx.StringDataPtr(plan.Name),
					"location":          llx.StringDataPtr(plan.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(plan.Tags), types.String),
					"type":              llx.StringDataPtr(plan.Type),
					"etag":              llx.StringDataPtr(plan.Etag),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			mqlDdos := mqlPlan.(*mqlAzureSubscriptionNetworkServiceDdosProtectionPlan)
			mqlDdos.cacheVnetIds = vnetIds
			mqlDdos.cachePublicIpIds = publicIpIds
			res = append(res, mqlDdos)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceDdosProtectionPlan) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceDdosProtectionPlan) virtualNetworks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	// Group VNet IDs by subscription to reuse clients.
	type vnetRef struct {
		rgName   string
		vnetName string
		id       string
	}
	bySubscription := map[string][]vnetRef{}
	for _, vnetId := range a.cacheVnetIds {
		resourceID, err := ParseResourceID(vnetId)
		if err != nil {
			log.Warn().Err(err).Str("id", vnetId).Msg("could not parse virtual network resource ID")
			continue
		}
		bySubscription[resourceID.SubscriptionID] = append(bySubscription[resourceID.SubscriptionID], vnetRef{
			rgName:   resourceID.ResourceGroup,
			vnetName: resourceID.Path["virtualnetworks"],
			id:       vnetId,
		})
	}

	res := []any{}
	for subId, refs := range bySubscription {
		client, err := network.NewVirtualNetworksClient(subId, token, &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			return nil, err
		}

		for _, ref := range refs {
			resp, err := client.Get(ctx, ref.rgName, ref.vnetName, nil)
			if err != nil {
				log.Warn().Err(err).Str("id", ref.id).Msg("could not get virtual network for DDoS protection plan")
				continue
			}

			mqlVn, err := azureVirtualNetworkToMql(a.MqlRuntime, resp.VirtualNetwork)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVn)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceDdosProtectionPlan) publicIpAddresses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	res := []any{}
	for _, pipId := range a.cachePublicIpIds {
		resourceID, err := ParseResourceID(pipId)
		if err != nil {
			log.Warn().Err(err).Str("id", pipId).Msg("could not parse public IP address resource ID")
			continue
		}
		rgName := resourceID.ResourceGroup
		ipName := resourceID.Path["publicipaddresses"]

		client, err := network.NewPublicIPAddressesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			return nil, err
		}

		resp, err := client.Get(ctx, rgName, ipName, nil)
		if err != nil {
			log.Warn().Err(err).Str("id", pipId).Msg("could not get public IP address for DDoS protection plan")
			continue
		}

		mqlIp, err := azureIpToMql(a.MqlRuntime, resp.PublicIPAddress)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIp)
	}
	return res, nil
}

// --- Service Endpoint Policies ---

type mqlAzureSubscriptionNetworkServiceServiceEndpointPolicyInternal struct {
	cacheSubnets []network.Subnet
}

func (a *mqlAzureSubscriptionNetworkService) serviceEndpointPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewServiceEndpointPoliciesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list service endpoint policies due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, policy := range page.Value {
			if policy == nil {
				continue
			}

			var provisioningState, serviceAlias string
			definitions := []any{}
			var cachedSubnets []network.Subnet
			if policy.Properties != nil {
				if policy.Properties.ProvisioningState != nil {
					provisioningState = string(*policy.Properties.ProvisioningState)
				}
				if policy.Properties.ServiceAlias != nil {
					serviceAlias = *policy.Properties.ServiceAlias
				}
				for _, def := range policy.Properties.ServiceEndpointPolicyDefinitions {
					if def == nil {
						continue
					}
					var defDescription, defService, defProvisioningState string
					var defServiceResources []any
					if def.Properties != nil {
						if def.Properties.Description != nil {
							defDescription = *def.Properties.Description
						}
						if def.Properties.Service != nil {
							defService = *def.Properties.Service
						}
						if def.Properties.ProvisioningState != nil {
							defProvisioningState = string(*def.Properties.ProvisioningState)
						}
						defServiceResources = strPtrsToAny(def.Properties.ServiceResources)
					}
					mqlDef, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceServiceEndpointPolicyDefinition,
						map[string]*llx.RawData{
							"id":                llx.StringDataPtr(def.ID),
							"name":              llx.StringDataPtr(def.Name),
							"type":              llx.StringDataPtr(def.Type),
							"etag":              llx.StringDataPtr(def.Etag),
							"description":       llx.StringData(defDescription),
							"service":           llx.StringData(defService),
							"serviceResources":  llx.ArrayData(defServiceResources, types.String),
							"provisioningState": llx.StringData(defProvisioningState),
						})
					if err != nil {
						return nil, err
					}
					definitions = append(definitions, mqlDef)
				}
				for _, subnet := range policy.Properties.Subnets {
					if subnet != nil {
						cachedSubnets = append(cachedSubnets, *subnet)
					}
				}
			}

			mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceServiceEndpointPolicy,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(policy.ID),
					"name":              llx.StringDataPtr(policy.Name),
					"location":          llx.StringDataPtr(policy.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(policy.Tags), types.String),
					"type":              llx.StringDataPtr(policy.Type),
					"etag":              llx.StringDataPtr(policy.Etag),
					"kind":              llx.StringDataPtr(policy.Kind),
					"provisioningState": llx.StringData(provisioningState),
					"serviceAlias":      llx.StringData(serviceAlias),
					"definitions":       llx.ArrayData(definitions, types.ResourceLike),
				})
			if err != nil {
				return nil, err
			}
			mqlSep := mqlPolicy.(*mqlAzureSubscriptionNetworkServiceServiceEndpointPolicy)
			mqlSep.cacheSubnets = cachedSubnets
			res = append(res, mqlSep)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceServiceEndpointPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceServiceEndpointPolicyDefinition) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceServiceEndpointPolicy) subnets() ([]any, error) {
	res := []any{}
	for _, subnet := range a.cacheSubnets {
		// Same shape as securityGroup.interfaces(): the SDK marks
		// ServiceEndpointPolicyPropertiesFormat.Subnets as "a collection of
		// references", so these carry an id and nothing else. Mapping them
		// invented an empty addressPrefix and cleared the cached subnet's NSG
		// and route-table references, which made subnet.networkSecurityGroup()
		// answer null -- "this subnet has no NSG" -- for the rest of the scan.
		if subnet.ID == nil {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
			map[string]*llx.RawData{"id": llx.StringDataPtr(subnet.ID)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

// --- Firewall Policy IDPS ---

type mqlAzureSubscriptionNetworkServiceFirewallPolicyInternal struct {
	cacheIntrusionDetection *network.FirewallPolicyIntrusionDetection
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) intrusionDetectionMode() (string, error) {
	if a.cacheIntrusionDetection == nil || a.cacheIntrusionDetection.Mode == nil {
		return "", nil
	}
	return string(*a.cacheIntrusionDetection.Mode), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) intrusionDetectionProfile() (string, error) {
	if a.cacheIntrusionDetection == nil || a.cacheIntrusionDetection.Profile == nil {
		return "", nil
	}
	return string(*a.cacheIntrusionDetection.Profile), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) intrusionDetectionSignatureOverrides() ([]any, error) {
	if a.cacheIntrusionDetection == nil || a.cacheIntrusionDetection.Configuration == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, sig := range a.cacheIntrusionDetection.Configuration.SignatureOverrides {
		if sig == nil {
			continue
		}
		entry := map[string]any{}
		if sig.ID != nil {
			entry["id"] = *sig.ID
		}
		if sig.Mode != nil {
			entry["mode"] = string(*sig.Mode)
		}
		res = append(res, entry)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) intrusionDetectionBypassRules() ([]any, error) {
	if a.cacheIntrusionDetection == nil || a.cacheIntrusionDetection.Configuration == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, rule := range a.cacheIntrusionDetection.Configuration.BypassTrafficSettings {
		if rule == nil {
			continue
		}
		var protocol string
		if rule.Protocol != nil {
			protocol = string(*rule.Protocol)
		}

		id := a.Id.Data + "/intrusionDetection/bypassRules/" + convert.ToValue(rule.Name)
		mqlRule, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceFirewallPolicyIdpsBypassRule,
			map[string]*llx.RawData{
				"id":                   llx.StringData(id),
				"name":                 llx.StringDataPtr(rule.Name),
				"description":          llx.StringDataPtr(rule.Description),
				"protocol":             llx.StringData(protocol),
				"sourceAddresses":      llx.ArrayData(strPtrsToAny(rule.SourceAddresses), types.String),
				"destinationAddresses": llx.ArrayData(strPtrsToAny(rule.DestinationAddresses), types.String),
				"destinationPorts":     llx.ArrayData(strPtrsToAny(rule.DestinationPorts), types.String),
			})
		if err != nil {
			return nil, err
		}
		mqlBypassRule := mqlRule.(*mqlAzureSubscriptionNetworkServiceFirewallPolicyIdpsBypassRule)
		mqlBypassRule.cacheSourceIpGroupIds = azureStrPtrsToStr(rule.SourceIPGroups)
		mqlBypassRule.cacheDestinationIpGroupIds = azureStrPtrsToStr(rule.DestinationIPGroups)
		res = append(res, mqlRule)
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceFirewallPolicyIdpsBypassRuleInternal struct {
	cacheSourceIpGroupIds      []string
	cacheDestinationIpGroupIds []string
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicyIdpsBypassRule) id() (string, error) {
	return a.Id.Data, nil
}

// sourceIpGroupRefs resolves the bypass rule's source IP groups to their typed
// resources from the cached ARM IDs.
func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicyIdpsBypassRule) sourceIpGroupRefs() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.ipGroup", a.cacheSourceIpGroupIds)
}

// destinationIpGroupRefs resolves the bypass rule's destination IP groups to
// their typed resources from the cached ARM IDs.
func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicyIdpsBypassRule) destinationIpGroupRefs() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.ipGroup", a.cacheDestinationIpGroupIds)
}

// ruleCollectionGroups resolves the priority-ordered rule collection groups
// that hold the firewall policy's network, NAT, and application rules. The
// list API is scoped to the policy, so we parse the resource group and policy
// name out of the policy's own resource ID.
func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicy) ruleCollectionGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	policyName, err := resourceID.Component("firewallPolicies")
	if err != nil {
		return nil, err
	}
	client, err := network.NewFirewallPolicyRuleCollectionGroupsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, policyName, &network.FirewallPolicyRuleCollectionGroupsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rcg := range page.Value {
			if rcg == nil {
				continue
			}
			var priority int64
			var provisioningState string
			ruleCollections := []any{}
			if rcg.Properties != nil {
				if rcg.Properties.Priority != nil {
					priority = int64(*rcg.Properties.Priority)
				}
				if rcg.Properties.ProvisioningState != nil {
					provisioningState = string(*rcg.Properties.ProvisioningState)
				}
				ruleCollections, err = convert.JsonToDictSlice(rcg.Properties.RuleCollections)
				if err != nil {
					return nil, err
				}
			}
			mqlRcg, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceFirewallPolicyRuleCollectionGroup,
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(rcg.ID),
					"name":              llx.StringDataPtr(rcg.Name),
					"etag":              llx.StringDataPtr(rcg.Etag),
					"priority":          llx.IntData(priority),
					"provisioningState": llx.StringData(provisioningState),
					"ruleCollections":   llx.ArrayData(ruleCollections, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRcg)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceFirewallPolicyRuleCollectionGroup) id() (string, error) {
	return a.Id.Data, nil
}

// --- Local Network Gateway / VNet Gateway Connection enhancements ---

type mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnectionInternal struct {
	cacheProperties *network.VirtualNetworkGatewayConnectionPropertiesFormat
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnection) localNetworkGateway2() (*mqlAzureSubscriptionNetworkServiceLocalNetworkGateway, error) {
	if a.cacheProperties == nil || a.cacheProperties.LocalNetworkGateway2 == nil || a.cacheProperties.LocalNetworkGateway2.ID == nil {
		a.LocalNetworkGateway2.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.localNetworkGateway", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheProperties.LocalNetworkGateway2.ID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceLocalNetworkGateway), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnection) virtualNetworkGateway2() (*mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway, error) {
	if a.cacheProperties == nil || a.cacheProperties.VirtualNetworkGateway2 == nil || a.cacheProperties.VirtualNetworkGateway2.ID == nil {
		a.VirtualNetworkGateway2.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkGateway", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheProperties.VirtualNetworkGateway2.ID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnectionIpsecPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGatewayConnection) ipsecPolicies() ([]any, error) {
	res := []any{}
	if a.cacheProperties == nil {
		return res, nil
	}
	for i, policy := range a.cacheProperties.IPSecPolicies {
		if policy == nil {
			continue
		}
		var saLifeTimeSeconds, saDataSizeKilobytes int64
		if policy.SaLifeTimeSeconds != nil {
			saLifeTimeSeconds = int64(*policy.SaLifeTimeSeconds)
		}
		if policy.SaDataSizeKilobytes != nil {
			saDataSizeKilobytes = int64(*policy.SaDataSizeKilobytes)
		}
		mqlPolicy, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkGateway.connection.ipsecPolicy", map[string]*llx.RawData{
			"id":                  llx.StringData(fmt.Sprintf("%s/ipsecPolicies/%d", a.Id.Data, i)),
			"ikeEncryption":       llx.StringDataPtr((*string)(policy.IkeEncryption)),
			"ikeIntegrity":        llx.StringDataPtr((*string)(policy.IkeIntegrity)),
			"ipsecEncryption":     llx.StringDataPtr((*string)(policy.IPSecEncryption)),
			"ipsecIntegrity":      llx.StringDataPtr((*string)(policy.IPSecIntegrity)),
			"dhGroup":             llx.StringDataPtr((*string)(policy.DhGroup)),
			"pfsGroup":            llx.StringDataPtr((*string)(policy.PfsGroup)),
			"saLifeTimeSeconds":   llx.IntData(saLifeTimeSeconds),
			"saDataSizeKilobytes": llx.IntData(saDataSizeKilobytes),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// vpnClientIpsecPolicies maps the custom IPsec/IKE policies negotiated for
// point-to-site VPN clients. Returns an empty list when the gateway has no
// point-to-site configuration or uses Azure default cryptography.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) vpnClientIpsecPolicies() ([]any, error) {
	res := []any{}
	if a.cacheProperties == nil || a.cacheProperties.VPNClientConfiguration == nil {
		return res, nil
	}
	for i, policy := range a.cacheProperties.VPNClientConfiguration.VPNClientIPSecPolicies {
		if policy == nil {
			continue
		}
		var saLifeTimeSeconds, saDataSizeKilobytes int64
		if policy.SaLifeTimeSeconds != nil {
			saLifeTimeSeconds = int64(*policy.SaLifeTimeSeconds)
		}
		if policy.SaDataSizeKilobytes != nil {
			saDataSizeKilobytes = int64(*policy.SaDataSizeKilobytes)
		}
		mqlPolicy, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkGateway.connection.ipsecPolicy", map[string]*llx.RawData{
			"id":                  llx.StringData(fmt.Sprintf("%s/vpnClientIpsecPolicies/%d", a.Id.Data, i)),
			"ikeEncryption":       llx.StringDataPtr((*string)(policy.IkeEncryption)),
			"ikeIntegrity":        llx.StringDataPtr((*string)(policy.IkeIntegrity)),
			"ipsecEncryption":     llx.StringDataPtr((*string)(policy.IPSecEncryption)),
			"ipsecIntegrity":      llx.StringDataPtr((*string)(policy.IPSecIntegrity)),
			"dhGroup":             llx.StringDataPtr((*string)(policy.DhGroup)),
			"pfsGroup":            llx.StringDataPtr((*string)(policy.PfsGroup)),
			"saLifeTimeSeconds":   llx.IntData(saLifeTimeSeconds),
			"saDataSizeKilobytes": llx.IntData(saDataSizeKilobytes),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkGateway) gatewayDefaultSite() (*mqlAzureSubscriptionNetworkServiceLocalNetworkGateway, error) {
	if a.cacheProperties == nil || a.cacheProperties.GatewayDefaultSite == nil || a.cacheProperties.GatewayDefaultSite.ID == nil {
		a.GatewayDefaultSite.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.localNetworkGateway", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheProperties.GatewayDefaultSite.ID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceLocalNetworkGateway), nil
}

func (a *mqlAzureSubscriptionNetworkService) localNetworkGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewLocalNetworkGatewaysClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// the local network gateways API works on resource-group level, so we fetch all RGs first
	// __id has to be explicit: azure.subscription.id() reads the `id` field,
	// which these args do not carry, so without it every such reference shares
	// the empty cache key and resolves to whichever subscription got there first.
	sub, err := CreateResource(a.MqlRuntime, "azure.subscription", map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + subId),
		"subscriptionId": llx.StringData(subId),
	})
	if err != nil {
		return nil, err
	}
	azureSub := sub.(*mqlAzureSubscription)
	rgs := azureSub.GetResourceGroups()
	if rgs.Error != nil {
		return nil, rgs.Error
	}
	res := []any{}
	for _, rg := range rgs.Data {
		mqlRg := rg.(*mqlAzureSubscriptionResourcegroup)
		pager := client.NewListPager(mqlRg.Name.Data, &network.LocalNetworkGatewaysClientListOptions{})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
					log.Warn().Err(err).Str("resourceGroup", mqlRg.Name.Data).Msg("could not list local network gateways due to access denied")
					break
				}
				return nil, err
			}
			for _, lng := range page.Value {
				if lng == nil {
					continue
				}
				mqlLng, err := newMqlLocalNetworkGateway(a.MqlRuntime, lng)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlLng)
			}
		}
	}
	return res, nil
}

func newMqlLocalNetworkGateway(runtime *plugin.Runtime, lng *network.LocalNetworkGateway) (*mqlAzureSubscriptionNetworkServiceLocalNetworkGateway, error) {
	args := map[string]*llx.RawData{
		"id":       llx.StringDataPtr(lng.ID),
		"name":     llx.StringDataPtr(lng.Name),
		"type":     llx.StringDataPtr(lng.Type),
		"location": llx.StringDataPtr(lng.Location),
		"tags":     llx.MapData(convert.PtrMapStrToInterface(lng.Tags), types.String),
		"etag":     llx.StringDataPtr(lng.Etag),
	}
	addressPrefixes := []any{}
	if lng.Properties != nil {
		args["gatewayIpAddress"] = llx.StringDataPtr(lng.Properties.GatewayIPAddress)
		args["fqdn"] = llx.StringDataPtr(lng.Properties.Fqdn)
		args["provisioningState"] = llx.StringDataPtr((*string)(lng.Properties.ProvisioningState))
		args["resourceGuid"] = llx.StringDataPtr(lng.Properties.ResourceGUID)
		if lng.Properties.LocalNetworkAddressSpace != nil {
			addressPrefixes = strPtrsToAny(lng.Properties.LocalNetworkAddressSpace.AddressPrefixes)
		}
	}
	args["localNetworkAddressSpacePrefixes"] = llx.ArrayData(addressPrefixes, types.String)
	res, err := CreateResource(runtime, "azure.subscription.networkService.localNetworkGateway", args)
	if err != nil {
		return nil, err
	}
	mqlLng := res.(*mqlAzureSubscriptionNetworkServiceLocalNetworkGateway)
	if lng.Properties != nil {
		mqlLng.cacheBgpSettings = lng.Properties.BgpSettings
	}
	return mqlLng, nil
}

type mqlAzureSubscriptionNetworkServiceLocalNetworkGatewayInternal struct {
	cacheBgpSettings *network.BgpSettings
}

func (a *mqlAzureSubscriptionNetworkServiceLocalNetworkGateway) bgpSettings() (*mqlAzureSubscriptionNetworkServiceBgpSettings, error) {
	if a.cacheBgpSettings == nil {
		a.BgpSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlBgpSettingsFromSdk(a.MqlRuntime, a.Id.Data, a.cacheBgpSettings)
}

func (a *mqlAzureSubscriptionNetworkServiceLocalNetworkGateway) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionNetworkServiceLocalNetworkGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("localNetworkGateways")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceLocalNetworkGateway, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewLocalNetworkGatewaysClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, &network.LocalNetworkGatewaysClientGetOptions{})
	if err != nil {
		return nil, nil, err
	}
	mqlLng, err := newMqlLocalNetworkGateway(runtime, &resp.LocalNetworkGateway)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlLng, nil
}

// initAzureSubscriptionNetworkServiceApplicationGateway resolves a single
// application gateway by its ARM resource ID so platform-discovered assets
// can be queried directly without re-listing every gateway in the
// subscription.
func initAzureSubscriptionNetworkServiceApplicationGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] { return s.GetApplicationGateways() },
		ResourceAzureSubscriptionNetworkServiceApplicationGateway)
}
