// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	esclient "github.com/alibabacloud-go/elasticsearch-20170613/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// esParseTime parses an Elasticsearch timestamp, which the API returns as an
// ISO 8601 string. A nil, empty, or unparseable value yields nil rather than a
// fabricated date.
func esParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return &t
		}
	}
	return nil
}

// esRegionUnavailable reports whether a first-page ListInstance error means the
// region simply does not offer Elasticsearch, or that the credential has no
// access to it there. Both are ordinary on an account whose enabled regions
// outnumber the ones running a cluster, so they are logged at debug rather than
// emitting a warning per region on every healthy scan. Anything else, including
// throttling and server faults, is a real failure and is warned about, so a
// region skipped because the API was unhappy is distinguishable from a region
// that legitimately has nothing.
func esRegionUnavailable(err error) bool {
	var sdkErr *tea.SDKError
	if !errors.As(err, &sdkErr) || sdkErr.StatusCode == nil {
		return false
	}
	switch *sdkErr.StatusCode {
	case http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

// esStrings flattens a slice of string pointers, dropping nil and empty
// entries so an address list never carries a blank entry that would read as a
// configured rule.
func esStrings(in []*string) []any {
	res := []any{}
	for _, s := range in {
		if s == nil || *s == "" {
			continue
		}
		res = append(res, *s)
	}
	return res
}

func (r *mqlAlicloudEs) id() (string, error) {
	return "alicloud.es", nil
}

func (r *mqlAlicloudEs) instances() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.ElasticsearchClient(region)
		if err != nil {
			return nil, err
		}

		page := int32(1)
		size := int32(100)
		firstPage := true
		for {
			resp, err := client.ListInstance(&esclient.ListInstanceRequest{
				Page: tea.Int32(page),
				Size: tea.Int32(size),
			})
			if err != nil {
				// A first-page error means the region has no Elasticsearch or the
				// credential lacks access there; skip it. A later-page error is
				// real, so surface it rather than truncating the list.
				if firstPage {
					if esRegionUnavailable(err) {
						log.Debug().Err(err).Str("region", region).
							Msg("alicloud> skipping region with no Elasticsearch access")
					} else {
						log.Warn().Err(err).Str("region", region).
							Msg("alicloud> skipping Elasticsearch region after an unexpected error")
					}
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}

			items := resp.Body.Result
			for _, inst := range items {
				if inst == nil || inst.InstanceId == nil {
					continue
				}
				mqlInst, err := newEsInstance(r.MqlRuntime, region, inst)
				if err != nil {
					return nil, err
				}
				// ListInstance returns tags inline, so the filter costs nothing
				// beyond the listing already made
				if filteredOutByTags(conn, mqlInst.Tags.Data) {
					continue
				}
				res = append(res, mqlInst)
			}

			if len(items) < int(size) {
				break
			}
			page++
		}
	}
	return res, nil
}

// mqlAlicloudEsInstanceInternal caches the region needed to rebuild a
// region-scoped client, the network ids the VPC references resolve through, and
// memoizes the cluster detail so the public-endpoint accessors share one read.
type mqlAlicloudEsInstanceInternal struct {
	region         string
	cacheVpcID     string
	cacheVswitchID string

	detailLock    sync.Mutex
	detailFetched atomic.Bool
	detail        *esclient.DescribeInstanceResponseBodyResult

	snapshotLock    sync.Mutex
	snapshotFetched atomic.Bool
	snapshot        *esclient.DescribeSnapshotSettingResponseBodyResult
}

// newEsInstance builds an alicloud.es.instance from a ListInstance item. The
// public-endpoint fields are not in this response and load lazily.
func newEsInstance(runtime *plugin.Runtime, region string, inst *esclient.ListInstanceResponseBodyResult) (*mqlAlicloudEsInstance, error) {
	tags := map[string]any{}
	for _, t := range inst.Tags {
		if t == nil || tea.StringValue(t.TagKey) == "" {
			continue
		}
		tags[tea.StringValue(t.TagKey)] = tea.StringValue(t.TagValue)
	}

	diskEncrypted := false
	if inst.NodeSpec != nil {
		diskEncrypted = tea.BoolValue(inst.NodeSpec.DiskEncryption)
	}

	vpcID, vswitchID := "", ""
	if inst.NetworkConfig != nil {
		vpcID = tea.StringValue(inst.NetworkConfig.VpcId)
		vswitchID = tea.StringValue(inst.NetworkConfig.VswitchId)
	}

	// the list response carries the port as a string while the detail response
	// carries it as an int, so it is parsed here rather than assumed
	port := int64(0)
	if p := tea.StringValue(inst.Port); p != "" {
		if v, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
			port = v
		}
	}

	resource, err := CreateResource(runtime, "alicloud.es.instance", map[string]*llx.RawData{
		// region-qualified so two clusters can never share a cache key, matching
		// the RDS and PolarDB keys; instanceId stays the user-facing field
		"__id":            llx.StringData(region + "/" + tea.StringValue(inst.InstanceId)),
		"instanceId":      llx.StringDataPtr(inst.InstanceId),
		"description":     llx.StringDataPtr(inst.Description),
		"esVersion":       llx.StringDataPtr(inst.EsVersion),
		"status":          llx.StringDataPtr(inst.Status),
		"regionId":        llx.StringData(region),
		"paymentType":     llx.StringDataPtr(inst.PaymentType),
		"nodeAmount":      llx.IntData(int64(tea.Int32Value(inst.NodeAmount))),
		"zoneCount":       llx.IntData(int64(tea.Int32Value(inst.ZoneCount))),
		"dedicatedMaster": llx.BoolData(tea.BoolValue(inst.DedicateMaster)),
		"protocol":        llx.StringDataPtr(inst.Protocol),
		"domain":          llx.StringDataPtr(inst.Domain),
		"port":            llx.IntData(port),
		"diskEncrypted":   llx.BoolData(diskEncrypted),
		"resourceGroupId": llx.StringDataPtr(inst.ResourceGroupId),
		"tags":            llx.MapData(tags, types.String),
		"createdAt":       llx.TimeDataPtr(esParseTime(inst.CreatedAt)),
		"updatedAt":       llx.TimeDataPtr(esParseTime(inst.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	mqlInst := resource.(*mqlAlicloudEsInstance)
	mqlInst.region = region
	mqlInst.cacheVpcID = vpcID
	mqlInst.cacheVswitchID = vswitchID
	return mqlInst, nil
}

// initAlicloudEsInstance resolves an Elasticsearch cluster by its instance id
// within a region, reusing an already-listed cluster from the resource cache. It
// also backs the discovered es-cluster asset, which scopes the connection to one
// cluster.
func initAlicloudEsInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// on a discovered cluster asset, resolve the cluster the asset is scoped to
	args = scopedInitArgs(runtime, args, connection.OptionEsInstanceID, "instanceId")

	instanceID, err := requiredStringArg(args, "instanceId", "alicloud.es.instance")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.es.instance")
	if err != nil {
		return nil, nil, err
	}

	// Matches the cluster __id: region + "/" + instanceId.
	if x, ok := runtime.Resources.Get("alicloud.es.instance\x00" + region + "/" + instanceID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ElasticsearchClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.ListInstance(&esclient.ListInstanceRequest{
		InstanceId: tea.String(instanceID),
		Page:       tea.Int32(1),
		Size:       tea.Int32(100),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil {
		for _, inst := range resp.Body.Result {
			if inst == nil || tea.StringValue(inst.InstanceId) != instanceID {
				continue
			}
			res, err := newEsInstance(runtime, region, inst)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.es.instance %q not found in region %q", instanceID, region)
}

func (r *mqlAlicloudEsInstance) id() (string, error) {
	// Read the public RegionId rather than the Internal region cache: the cache
	// field is set after CreateResource, so reading it here would build the key
	// from an empty region and collapse every cluster onto "/<id>".
	return r.RegionId.Data + "/" + r.InstanceId.Data, nil
}

func (r *mqlAlicloudEsInstance) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// vpc resolves the VPC the cluster is attached to. A cluster cannot outlive its
// network, so a failure to read it propagates.
func (r *mqlAlicloudEsInstance) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcID)
}

func (r *mqlAlicloudEsInstance) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.region, r.cacheVswitchID)
}

// detailFor lazily loads and memoizes the cluster detail, which is where the
// public-endpoint and address-list fields live. A transient error is not cached,
// so a later access retries rather than permanently reporting a cluster with an
// unread detail as private.
func (r *mqlAlicloudEsInstance) detailFor() (*esclient.DescribeInstanceResponseBodyResult, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ElasticsearchClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeInstance(tea.String(r.InstanceId.Data))
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		r.detail = resp.Body.Result
	}
	r.detailFetched.Store(true)
	return r.detail, nil
}

// instanceCategory reads the cluster edition, which ListInstance omits and only
// the detail carries. It shares the memoized detail, so it costs no extra call
// alongside the public-endpoint accessors.
func (r *mqlAlicloudEsInstance) instanceCategory() (string, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.InstanceCategory), nil
}

func (r *mqlAlicloudEsInstance) publicNetworkEnabled() (bool, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.EnablePublic), nil
}

func (r *mqlAlicloudEsInstance) publicDomain() (string, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.PublicDomain), nil
}

func (r *mqlAlicloudEsInstance) publicPort() (int64, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(tea.Int32Value(d.PublicPort)), nil
}

func (r *mqlAlicloudEsInstance) publicIpWhitelist() ([]any, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return nil, err
	}
	return esStrings(d.PublicIpWhitelist), nil
}

func (r *mqlAlicloudEsInstance) privateIpWhitelist() ([]any, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return nil, err
	}
	return esStrings(d.EsIPWhitelist), nil
}

func (r *mqlAlicloudEsInstance) kibanaPublicNetworkEnabled() (bool, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.EnableKibanaPublicNetwork), nil
}

func (r *mqlAlicloudEsInstance) kibanaDomain() (string, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.KibanaDomain), nil
}

func (r *mqlAlicloudEsInstance) kibanaIpWhitelist() ([]any, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return nil, err
	}
	return esStrings(d.KibanaIPWhitelist), nil
}

// esInternetExposed reports whether either published endpoint reaches the
// internet. Kibana counts on its own: the console reads everything the cluster
// holds, so a public console exposes the data even when the cluster endpoint
// stays inside the VPC.
func esInternetExposed(publicEnabled, kibanaPublicEnabled bool) bool {
	return publicEnabled || kibanaPublicEnabled
}

func (r *mqlAlicloudEsInstance) internetExposed() (bool, error) {
	d, err := r.detailFor()
	if err != nil || d == nil {
		return false, err
	}
	return esInternetExposed(tea.BoolValue(d.EnablePublic), tea.BoolValue(d.EnableKibanaPublicNetwork)), nil
}

// esClassifyError maps a refused Elasticsearch API call to its ADR 046 kind,
// naming the permission the call needs. An error the target did not refuse,
// such as a transport failure or a server fault, is returned unchanged.
func esClassifyError(err error, permission string) error {
	var sdkErr *tea.SDKError
	if !errors.As(err, &sdkErr) || sdkErr.StatusCode == nil {
		return err
	}
	switch *sdkErr.StatusCode {
	case http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case http.StatusForbidden:
		return llx.Forbidden(err, llx.WithPermissions(permission))
	}
	return err
}

// snapshotSettingFor loads and memoizes the automatic snapshot setting, so the
// snapshot accessors share one DescribeSnapshotSetting call. An error is not
// cached, so a later access retries.
func (r *mqlAlicloudEsInstance) snapshotSettingFor() (*esclient.DescribeSnapshotSettingResponseBodyResult, error) {
	if r.snapshotFetched.Load() {
		return r.snapshot, nil
	}
	r.snapshotLock.Lock()
	defer r.snapshotLock.Unlock()
	if r.snapshotFetched.Load() {
		return r.snapshot, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ElasticsearchClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeSnapshotSetting(tea.String(r.InstanceId.Data))
	if err != nil {
		return nil, esClassifyError(err, "elasticsearch:DescribeSnapshotSetting")
	}
	if resp != nil && resp.Body != nil {
		r.snapshot = resp.Body.Result
	}
	r.snapshotFetched.Store(true)
	return r.snapshot, nil
}

// esSnapshotIndices flattens the index list of a snapshot setting. A setting
// that carries no list at all yields nil, so the field reads null rather than
// an empty list that would claim no index is covered.
func esSnapshotIndices(s *esclient.DescribeSnapshotSettingResponseBodyResult) []any {
	if s == nil || s.Indices == nil {
		return nil
	}
	return esStrings(s.Indices)
}

func (r *mqlAlicloudEsInstance) autoSnapshotEnabled() (bool, error) {
	s, err := r.snapshotSettingFor()
	if err != nil {
		return false, err
	}
	if s == nil || s.Enable == nil {
		r.AutoSnapshotEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.Enable, nil
}

func (r *mqlAlicloudEsInstance) autoSnapshotSchedule() (string, error) {
	s, err := r.snapshotSettingFor()
	if err != nil {
		return "", err
	}
	if s == nil || s.QuartzRegex == nil {
		r.AutoSnapshotSchedule.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.QuartzRegex, nil
}

func (r *mqlAlicloudEsInstance) snapshotIndices() ([]any, error) {
	s, err := r.snapshotSettingFor()
	if err != nil {
		return nil, err
	}
	indices := esSnapshotIndices(s)
	if indices == nil {
		r.SnapshotIndices.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return indices, nil
}
