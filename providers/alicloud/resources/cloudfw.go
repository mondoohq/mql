// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"
	"sync/atomic"

	cloudfwclient "github.com/alibabacloud-go/cloudfw-20171207/v11/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// mqlAlicloudCloudFirewallInternal memoizes the center region the account's
// Cloud Firewall answers at (cn-hangzhou or ap-southeast-1) and the edition
// probe, so enabled/edition/controlPolicies share one lookup.
type mqlAlicloudCloudFirewallInternal struct {
	lock    sync.Mutex
	fetched atomic.Bool
	region  string
	version *cloudfwclient.DescribeUserBuyVersionResponseBody

	logLock sync.Mutex
	logDone bool
	log     *cloudfwclient.DescribeLogStoreInfoResponseBody
}

func (r *mqlAlicloudCloudFirewall) id() (string, error) {
	return "alicloud.cloudFirewall", nil
}

// buyVersion probes the two centers for the account's Cloud Firewall edition and
// caches the working center. It returns the last error when NEITHER center
// responds, so a transient outage is surfaced rather than masked as "not
// provisioned". A success is cached; a total failure is not, so a later call
// retries.
func (r *mqlAlicloudCloudFirewall) buyVersion() (string, *cloudfwclient.DescribeUserBuyVersionResponseBody, error) {
	if r.fetched.Load() {
		return r.region, r.version, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.region, r.version, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	var lastErr error
	for _, region := range alicloudCenterRegions {
		client, err := conn.CloudfwClient(region)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.DescribeUserBuyVersion(&cloudfwclient.DescribeUserBuyVersionRequest{})
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil || resp.Body == nil {
			continue
		}
		r.region = region
		r.version = resp.Body
		r.fetched.Store(true)
		return r.region, r.version, nil
	}
	return "", nil, lastErr
}

func (r *mqlAlicloudCloudFirewall) enabled() (bool, error) {
	_, v, err := r.buyVersion()
	if err != nil || v == nil {
		return false, err
	}
	return tea.BoolValue(v.UserStatus), nil
}

func (r *mqlAlicloudCloudFirewall) edition() (int64, error) {
	_, v, err := r.buyVersion()
	if err != nil || v == nil {
		return 0, err
	}
	return int64(tea.Int32Value(v.Version)), nil
}

// cloudfwLogDelivering reports whether a log store info response describes a
// provisioned log store. Cloud Firewall has no boolean for the log-analysis
// feature: switching it on provisions a Log Service project and logstore, so
// their presence is the signal. A response naming neither means log analysis
// was never switched on.
func cloudfwLogDelivering(info *cloudfwclient.DescribeLogStoreInfoResponseBody) bool {
	if info == nil {
		return false
	}
	return tea.StringValue(info.ProjectName) != "" && tea.StringValue(info.LogStoreName) != ""
}

// logStoreInfo lazily reads the account's Cloud Firewall log store detail and
// memoizes it, so the six log fields share one call. Returns nil when Cloud
// Firewall is not provisioned or the call fails, which reads as log analysis
// off rather than claiming an audit trail nobody confirmed.
func (r *mqlAlicloudCloudFirewall) logStoreInfo() *cloudfwclient.DescribeLogStoreInfoResponseBody {
	r.logLock.Lock()
	defer r.logLock.Unlock()
	if r.logDone {
		return r.log
	}
	r.logDone = true

	region, _, err := r.buyVersion()
	if err != nil || region == "" {
		return nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudfwClient(region)
	if err != nil {
		return nil
	}
	// DescribeLogStoreInfo is account-scoped and takes no request parameters.
	resp, err := client.DescribeLogStoreInfo()
	if err != nil || resp == nil || resp.Body == nil {
		return nil
	}
	r.log = resp.Body
	return r.log
}

func (r *mqlAlicloudCloudFirewall) logDeliveryEnabled() (bool, error) {
	return cloudfwLogDelivering(r.logStoreInfo()), nil
}

func (r *mqlAlicloudCloudFirewall) logProjectName() (string, error) {
	info := r.logStoreInfo()
	if info == nil {
		return "", nil
	}
	return tea.StringValue(info.ProjectName), nil
}

func (r *mqlAlicloudCloudFirewall) logStoreName() (string, error) {
	info := r.logStoreInfo()
	if info == nil {
		return "", nil
	}
	return tea.StringValue(info.LogStoreName), nil
}

func (r *mqlAlicloudCloudFirewall) logRegionId() (string, error) {
	info := r.logStoreInfo()
	if info == nil {
		return "", nil
	}
	return tea.StringValue(info.RegionId), nil
}

func (r *mqlAlicloudCloudFirewall) logRetentionDays() (int64, error) {
	info := r.logStoreInfo()
	if info == nil {
		return 0, nil
	}
	return int64(tea.Int32Value(info.Ttl)), nil
}

// logProject resolves the project holding the firewall logs. The response names
// the region logs are delivered to, so the ref is built from that rather than
// from the center the firewall answers at, which need not be the same.
func (r *mqlAlicloudCloudFirewall) logProject() (*mqlAlicloudLogProject, error) {
	info := r.logStoreInfo()
	if !cloudfwLogDelivering(info) {
		r.LogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveLogProject(r.MqlRuntime, tea.StringValue(info.RegionId), tea.StringValue(info.ProjectName))
	if err != nil || project == nil {
		r.LogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

func (r *mqlAlicloudCloudFirewall) controlPolicies() ([]any, error) {
	region, v, err := r.buyVersion()
	if err != nil {
		return nil, err
	}
	if region == "" || v == nil {
		// Cloud Firewall is not provisioned for this account
		return []any{}, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudfwClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, direction := range []string{"in", "out"} {
		currentPage := 1
		collected := 0
		for {
			resp, err := client.DescribeControlPolicy(&cloudfwclient.DescribeControlPolicyRequest{
				Direction:   new(direction),
				CurrentPage: new(strconv.Itoa(currentPage)),
				// The API caps PageSize server-side (documented example is 10),
				// so use a conservative page and terminate on the accumulated
				// count vs TotalCount below — robust to whatever the server caps
				// the page at, rather than assuming a full page means "more".
				PageSize: new("50"),
			})
			if err != nil {
				return nil, err
			}
			if resp == nil || resp.Body == nil {
				break
			}
			items := resp.Body.Policys
			for _, p := range items {
				if p == nil || p.AclUuid == nil {
					continue
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudFirewall.controlPolicy", map[string]*llx.RawData{
					"__id":            llx.StringDataPtr(p.AclUuid),
					"aclUuid":         llx.StringDataPtr(p.AclUuid),
					"direction":       llx.StringDataPtr(p.Direction),
					"action":          llx.StringDataPtr(p.AclAction),
					"source":          llx.StringDataPtr(p.Source),
					"sourceType":      llx.StringDataPtr(p.SourceType),
					"destination":     llx.StringDataPtr(p.Destination),
					"destinationType": llx.StringDataPtr(p.DestinationType),
					"destPort":        llx.StringDataPtr(p.DestPort),
					"proto":           llx.StringDataPtr(p.Proto),
					"applicationName": llx.StringDataPtr(p.ApplicationName),
					"description":     llx.StringDataPtr(p.Description),
					"enabled":         llx.BoolData(tea.StringValue(p.Release) == "true"),
					"order":           llx.IntData(int64(tea.Int32Value(p.Order))),
					"hitTimes":        llx.IntData(tea.Int64Value(p.HitTimes)),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			collected += len(items)
			total, _ := strconv.Atoi(tea.StringValue(resp.Body.TotalCount))
			if len(items) == 0 || collected >= total {
				break
			}
			currentPage++
		}
	}
	return res, nil
}

func (r *mqlAlicloudCloudFirewallControlPolicy) id() (string, error) {
	return r.AclUuid.Data, nil
}
