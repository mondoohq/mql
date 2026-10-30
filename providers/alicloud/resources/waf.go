// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/alibabacloud-go/tea/tea"
	wafclient "github.com/alibabacloud-go/waf-openapi-20211001/v7/client"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlAlicloudWaf) id() (string, error) {
	return "alicloud.waf", nil
}

func (r *mqlAlicloudWaf) instances() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)

	res := []any{}
	// WAF is a center service; an account lives in one partition, so a call
	// against the other center errors. Try both and skip a failing center, but
	// remember the error and surface it only if NEITHER center responded, so a
	// transient outage is not silently reported as "no WAF".
	var lastErr error
	succeeded := 0
	for _, region := range alicloudCenterRegions {
		client, err := conn.WafClient(region)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.DescribeInstance(&wafclient.DescribeInstanceRequest{
			RegionId: new(region),
		})
		if err != nil {
			lastErr = err
			continue
		}
		succeeded++
		if resp == nil || resp.Body == nil || resp.Body.InstanceId == nil || *resp.Body.InstanceId == "" {
			// this center responded but the account has no WAF instance here
			continue
		}
		mqlInstance, err := newWafInstance(r.MqlRuntime, region, resp.Body)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}
	if succeeded == 0 && lastErr != nil {
		return nil, lastErr
	}
	return res, nil
}

// mqlAlicloudWafInstanceInternal caches the center region and instance id used
// by the child accessors.
type mqlAlicloudWafInstanceInternal struct {
	region     string
	instanceId string

	logLock sync.Mutex
	logDone bool
	log     *wafclient.DescribeUserWafLogStatusResponseBody

	resourceLogLock sync.Mutex
	resourceLogDone bool
	resourceLog     map[string]bool
}

func newWafInstance(runtime *plugin.Runtime, region string, body *wafclient.DescribeInstanceResponseBody) (*mqlAlicloudWafInstance, error) {
	instanceID := tea.StringValue(body.InstanceId)
	resource, err := CreateResource(runtime, "alicloud.waf.instance", map[string]*llx.RawData{
		"__id":       llx.StringData(region + "/" + instanceID),
		"regionId":   llx.StringData(region),
		"instanceId": llx.StringData(instanceID),
		"status":     llx.IntData(int64(tea.Int32Value(body.Status))),
		"edition":    llx.StringDataPtr(body.Edition),
		"payType":    llx.StringDataPtr(body.PayType),
		"inDebt":     llx.StringDataPtr(body.InDebt),
		"startTime":  llx.TimeDataPtr(configEpochMillis(body.StartTime)),
		"endTime":    llx.TimeDataPtr(configEpochMillis(body.EndTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlInstance := resource.(*mqlAlicloudWafInstance)
	mqlInstance.region = region
	mqlInstance.instanceId = instanceID
	return mqlInstance, nil
}

// initAlicloudWafInstance resolves the WAF instance for a discovered
// alicloud-waf-instance asset when the resource is invoked bare. WAF exposes one
// instance per region and DescribeInstance takes no instance id, so the lookup
// is keyed solely on the scoped region; there is no by-id form. On any other
// asset the resource is only constructed from the alicloud.waf.instances list.
func initAlicloudWafInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 0 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	instanceID, region, ok := conn.ScopedObject(connection.OptionWafInstanceID)
	if !ok {
		return nil, nil, errors.New("alicloud.waf.instance is only available on a discovered WAF instance asset; use alicloud.waf.instances to enumerate them")
	}

	if x, ok := runtime.Resources.Get("alicloud.waf.instance\x00" + region + "/" + instanceID); ok {
		return nil, x, nil
	}

	client, err := conn.WafClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeInstance(&wafclient.DescribeInstanceRequest{
		RegionId: new(region),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || tea.StringValue(resp.Body.InstanceId) == "" {
		return nil, nil, fmt.Errorf("alicloud.waf.instance %q not found in region %q", instanceID, region)
	}
	// DescribeInstance returns whichever instance the region hosts rather than
	// looking up by id, so confirm it is the scoped instance; a stale scope or a
	// replaced instance would otherwise resolve silently to the wrong resource.
	if got := tea.StringValue(resp.Body.InstanceId); got != instanceID {
		return nil, nil, fmt.Errorf("alicloud.waf.instance %q not found in region %q (region hosts %q)", instanceID, region, got)
	}
	res, err := newWafInstance(runtime, region, resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudWafInstance) id() (string, error) {
	return r.region + "/" + r.instanceId, nil
}

func (r *mqlAlicloudWafInstance) defenseResources() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	pageSize := int32(100)
	for {
		resp, err := client.DescribeDefenseResources(&wafclient.DescribeDefenseResourcesRequest{
			InstanceId: new(r.instanceId),
			RegionId:   new(r.region),
			PageNumber: new(pageNumber),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Resources
		for _, dr := range items {
			if dr == nil || dr.Resource == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.waf.defenseResource", map[string]*llx.RawData{
				"__id":           llx.StringData(r.region + "/" + r.instanceId + "/" + tea.StringValue(dr.Resource)),
				"regionId":       llx.StringData(r.region),
				"instanceId":     llx.StringData(r.instanceId),
				"resource":       llx.StringDataPtr(dr.Resource),
				"product":        llx.StringDataPtr(dr.Product),
				"pattern":        llx.StringDataPtr(dr.Pattern),
				"resourceStatus": llx.StringDataPtr(dr.ResourceStatus),
				"resourceGroup":  llx.StringDataPtr(dr.ResourceGroup),
				"createTime":     llx.TimeDataPtr(configEpochMillis(dr.GmtCreate)),
			})
			if err != nil {
				return nil, err
			}
			mqlResource := resource.(*mqlAlicloudWafDefenseResource)
			mqlResource.parentInstance = r
			res = append(res, mqlResource)
		}
		if len(items) < int(pageSize) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// wafResourceLogBatch is the number of protected objects asked about per
// DescribeResourceLogStatus call. The API takes a comma-separated list, so the
// per-object status for a whole instance costs a handful of calls rather than
// one per object.
const wafResourceLogBatch = 50

// mqlAlicloudWafDefenseResourceInternal carries a pointer to the instance the
// protected object was listed from. The per-object log status is a batch call
// keyed on the instance, so every object on one instance shares a single read
// instead of making one call each.
type mqlAlicloudWafDefenseResourceInternal struct {
	parentInstance *mqlAlicloudWafInstance
}

// logDeliveryEnabled reports whether this protected object's logs reach Log
// Service. It reads the instance-wide batch, which is fetched once. False when
// the object was reached without its parent instance or the batch could not be
// read: claiming delivery is on would assert an audit trail that may not exist.
func (r *mqlAlicloudWafDefenseResource) logDeliveryEnabled() (bool, error) {
	if r.parentInstance == nil {
		log.Debug().Str("resource", r.Resource.Data).
			Msg("alicloud> WAF protected object reached without its instance, reporting log delivery off")
		return false, nil
	}
	statuses, err := r.parentInstance.resourceLogStatuses()
	if err != nil || statuses == nil {
		// The false is deliberate (an unread status must not read as an audit
		// trail nobody confirmed), but it is indistinguishable from a genuine
		// "delivery is off", so the cause is logged rather than dropped.
		log.Debug().Err(err).Str("resource", r.Resource.Data).
			Msg("alicloud> could not read WAF per-resource log status, reporting log delivery off")
		return false, nil
	}
	return statuses[r.Resource.Data], nil
}

// resourceLogStatuses reads the per-object log-delivery status for every
// protected object on the instance and memoizes it, so N objects cost
// ceil(N/wafResourceLogBatch) calls rather than N.
func (r *mqlAlicloudWafInstance) resourceLogStatuses() (map[string]bool, error) {
	r.resourceLogLock.Lock()
	defer r.resourceLogLock.Unlock()
	if r.resourceLogDone {
		return r.resourceLog, nil
	}
	r.resourceLogDone = true

	resources := r.GetDefenseResources()
	if resources.Error != nil {
		return nil, resources.Error
	}
	names := []string{}
	for _, entry := range resources.Data {
		dr, ok := entry.(*mqlAlicloudWafDefenseResource)
		if !ok || dr.Resource.Data == "" {
			continue
		}
		names = append(names, dr.Resource.Data)
	}
	if len(names) == 0 {
		r.resourceLog = map[string]bool{}
		return r.resourceLog, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil, err
	}

	statuses := map[string]bool{}
	for start := 0; start < len(names); start += wafResourceLogBatch {
		end := min(start+wafResourceLogBatch, len(names))
		resp, err := client.DescribeResourceLogStatus(&wafclient.DescribeResourceLogStatusRequest{
			InstanceId: new(r.instanceId),
			RegionId:   new(r.region),
			Resources:  new(strings.Join(names[start:end], ",")),
		})
		if err != nil {
			// A batch that fails leaves its objects absent from the map, which
			// reads as delivery off. Recording them as on would be worse: it
			// would report an audit trail nobody confirmed.
			log.Debug().Err(err).Str("instance", r.instanceId).
				Msg("alicloud> could not read WAF per-resource log status")
			continue
		}
		if resp == nil || resp.Body == nil {
			continue
		}
		for _, entry := range resp.Body.Result {
			if entry == nil || entry.Resource == nil {
				continue
			}
			statuses[*entry.Resource] = tea.BoolValue(entry.Status)
		}
	}
	r.resourceLog = statuses
	return r.resourceLog, nil
}

// fetchLogStatus lazily reads the instance-wide Log Service delivery state and
// memoizes it, so the three log fields share one call.
func (r *mqlAlicloudWafInstance) fetchLogStatus() *wafclient.DescribeUserWafLogStatusResponseBody {
	r.logLock.Lock()
	defer r.logLock.Unlock()
	if r.logDone {
		return r.log
	}
	r.logDone = true

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil
	}
	resp, err := client.DescribeUserWafLogStatus(&wafclient.DescribeUserWafLogStatusRequest{
		InstanceId: new(r.instanceId),
		RegionId:   new(r.region),
	})
	if err != nil || resp == nil || resp.Body == nil {
		return nil
	}
	r.log = resp.Body
	return r.log
}

// wafLogDelivering reports whether a WAF log status means logs are actually
// reaching Log Service. Only normal counts: initializing and releasing are
// transitional, and both failure states mean nothing is being delivered.
func wafLogDelivering(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "normal")
}

func (r *mqlAlicloudWafInstance) logDeliveryEnabled() (bool, error) {
	status := r.fetchLogStatus()
	if status == nil {
		return false, nil
	}
	return wafLogDelivering(status.LogStatus), nil
}

func (r *mqlAlicloudWafInstance) logStatus() (string, error) {
	status := r.fetchLogStatus()
	if status == nil {
		return "", nil
	}
	return tea.StringValue(status.LogStatus), nil
}

func (r *mqlAlicloudWafInstance) logRegionId() (string, error) {
	status := r.fetchLogStatus()
	if status == nil {
		return "", nil
	}
	return tea.StringValue(status.LogRegionId), nil
}

func (r *mqlAlicloudWafInstance) domains() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int64(1)
	pageSize := int64(100)
	for {
		resp, err := client.DescribeDomains(&wafclient.DescribeDomainsRequest{
			InstanceId: new(r.instanceId),
			RegionId:   new(r.region),
			PageNumber: new(pageNumber),
			PageSize:   new(pageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Domains
		for _, d := range items {
			if d == nil || d.Domain == nil {
				continue
			}
			mqlDomain, err := newWafDomain(r.MqlRuntime, r.region, r.instanceId, d)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDomain)
		}
		if len(items) < int(pageSize) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// mqlAlicloudWafDomainInternal caches the keys needed to fetch the per-domain
// TLS detail and memoizes it.
type mqlAlicloudWafDomainInternal struct {
	region     string
	instanceId string
	domain     string

	detailLock    sync.Mutex
	detailFetched atomic.Bool
	detail        *wafclient.DescribeDomainDetailResponseBody
}

func newWafDomain(runtime *plugin.Runtime, region, instanceID string, d *wafclient.DescribeDomainsResponseBodyDomains) (*mqlAlicloudWafDomain, error) {
	httpPorts := []any{}
	httpsPorts := []any{}
	if d.ListenPorts != nil {
		httpPorts = int64PtrsToInts(d.ListenPorts.Http)
		httpsPorts = int64PtrsToInts(d.ListenPorts.Https)
	}

	resource, err := CreateResource(runtime, "alicloud.waf.domain", map[string]*llx.RawData{
		"__id":         llx.StringData(region + "/" + instanceID + "/" + tea.StringValue(d.Domain)),
		"regionId":     llx.StringData(region),
		"instanceId":   llx.StringData(instanceID),
		"domain":       llx.StringDataPtr(d.Domain),
		"cname":        llx.StringDataPtr(d.Cname),
		"status":       llx.IntData(int64(tea.Int32Value(d.Status))),
		"httpPorts":    llx.ArrayData(httpPorts, types.Int),
		"httpsPorts":   llx.ArrayData(httpsPorts, types.Int),
		"httpsEnabled": llx.BoolData(len(httpsPorts) > 0),
	})
	if err != nil {
		return nil, err
	}
	mqlDomain := resource.(*mqlAlicloudWafDomain)
	mqlDomain.region = region
	mqlDomain.instanceId = instanceID
	mqlDomain.domain = tea.StringValue(d.Domain)
	return mqlDomain, nil
}

func (r *mqlAlicloudWafDomain) id() (string, error) {
	return r.region + "/" + r.instanceId + "/" + r.domain, nil
}

// domainDetail lazily fetches DescribeDomainDetail for the TLS configuration. A
// transient error is not cached and is returned.
func (r *mqlAlicloudWafDomain) domainDetail() (*wafclient.DescribeDomainDetailResponseBody, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.WafClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeDomainDetail(&wafclient.DescribeDomainDetailRequest{
		InstanceId: new(r.instanceId),
		RegionId:   new(r.region),
		Domain:     new(r.domain),
	})
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.detail = resp.Body
	}
	r.detailFetched.Store(true)
	return r.detail, nil
}

func (r *mqlAlicloudWafDomain) certId() (string, error) {
	d, err := r.domainDetail()
	if err != nil || d == nil || d.Listen == nil {
		return "", err
	}
	return tea.StringValue(d.Listen.CertId), nil
}

func (r *mqlAlicloudWafDomain) tlsVersion() (string, error) {
	d, err := r.domainDetail()
	if err != nil || d == nil || d.Listen == nil {
		return "", err
	}
	return tea.StringValue(d.Listen.TLSVersion), nil
}

func (r *mqlAlicloudWafDomain) tls13Enabled() (bool, error) {
	d, err := r.domainDetail()
	if err != nil || d == nil || d.Listen == nil {
		return false, err
	}
	return tea.BoolValue(d.Listen.EnableTLSv3), nil
}

func (r *mqlAlicloudWafDomain) certExpireTime() (*time.Time, error) {
	d, err := r.domainDetail()
	if err != nil || d == nil || d.CertDetail == nil {
		return nil, err
	}
	return configEpochMillis(d.CertDetail.EndTime), nil
}
