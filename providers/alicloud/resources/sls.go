// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	slsclient "github.com/alibabacloud-go/sls-20201230/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// slsParseTime parses an SLS ISO-8601 project timestamp, returning nil on a nil
// or unparseable input.
func slsParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(layout, *s); err == nil {
			return &t
		}
	}
	return nil
}

// slsEpochTime converts an SLS epoch-seconds timestamp into a *time.Time,
// returning nil when the value is nil or zero.
func slsEpochTime(v *int32) *time.Time {
	if v == nil || *v == 0 {
		return nil
	}
	t := time.Unix(int64(*v), 0).UTC()
	return &t
}

func (r *mqlAlicloudLog) id() (string, error) {
	return "alicloud.log", nil
}

func (r *mqlAlicloudLog) projects() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.SlsClient(region)
		if err != nil {
			return nil, err
		}

		offset := int32(0)
		size := int32(100)
		firstPage := true
		for {
			resp, err := client.ListProject(&slsclient.ListProjectRequest{
				Offset: new(offset),
				Size:   new(size),
			})
			if err != nil {
				// A first-page error means the region has no SLS or the
				// credential lacks access there; skip it. A later-page error is
				// real — surface it rather than silently truncating the project
				// list.
				if firstPage {
					break
				}
				return nil, err
			}
			firstPage = false
			if resp == nil || resp.Body == nil {
				break
			}

			items := resp.Body.Projects
			for _, p := range items {
				if p == nil || p.ProjectName == nil {
					continue
				}
				mqlProject, err := newLogProject(r.MqlRuntime, region, p)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProject)
			}

			total := tea.Int64Value(resp.Body.Total)
			offset += int32(len(items))
			if len(items) < int(size) || (total > 0 && int64(offset) >= total) {
				break
			}
		}
	}
	return res, nil
}

// mqlAlicloudLogProjectInternal caches the region needed to build the SLS client
// for listing the project's logstores, and memoizes the project's resource
// policy so the policy and isPublic accessors share one read.
type mqlAlicloudLogProjectInternal struct {
	region string

	policyLock    sync.Mutex
	policyFetched atomic.Bool
	policyDoc     string
}

// newLogProject builds a fully populated alicloud.log.project from an SLS
// project record. It is shared by the projects list accessor and the by-name
// init so both produce identical resources.
func newLogProject(runtime *plugin.Runtime, region string, p *slsclient.Project) (*mqlAlicloudLogProject, error) {
	name := tea.StringValue(p.ProjectName)
	resource, err := CreateResource(runtime, "alicloud.log.project", map[string]*llx.RawData{
		"__id":               llx.StringData(region + "/" + name),
		"regionId":           llx.StringData(region),
		"name":               llx.StringData(name),
		"description":        llx.StringDataPtr(p.Description),
		"status":             llx.StringDataPtr(p.Status),
		"owner":              llx.StringDataPtr(p.Owner),
		"resourceGroupId":    llx.StringDataPtr(p.ResourceGroupId),
		"dataRedundancyType": llx.StringDataPtr(p.DataRedundancyType),
		"recycleBinEnabled":  llx.BoolDataPtr(p.RecycleBinEnabled),
		"internalEndpoint":   llx.StringDataPtr(p.InternalEndpoint),
		"internetEndpoint":   llx.StringDataPtr(p.InternetEndpoint),
		"createTime":         llx.TimeDataPtr(slsParseTime(p.CreateTime)),
		"lastModifyTime":     llx.TimeDataPtr(slsParseTime(p.LastModifyTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlProject := resource.(*mqlAlicloudLogProject)
	mqlProject.region = region
	return mqlProject, nil
}

// resolveLogProject returns the typed SLS project for a name within a region, or
// (nil, nil) when name is empty. It backs the ActionTrail slsProject() ref.
func resolveLogProject(runtime *plugin.Runtime, region, name string) (*mqlAlicloudLogProject, error) {
	if name == "" || region == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.log.project", map[string]*llx.RawData{
		"name":     llx.StringData(name),
		"regionId": llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudLogProject), nil
}

// initAlicloudLogProject resolves an SLS project by name within a region,
// reusing an already-listed project from the resource cache and otherwise
// fetching it via GetProject.
func initAlicloudLogProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	name, err := requiredStringArg(args, "name", "alicloud.log.project")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.log.project")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.log.project\x00" + region + "/" + name); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetProject(new(name), &slsclient.GetProjectRequest{})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.ProjectName == nil {
		return nil, nil, fmt.Errorf("alicloud.log.project %q not found in region %q", name, region)
	}
	res, err := newLogProject(runtime, region, resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudLogProject) id() (string, error) {
	return r.region + "/" + r.Name.Data, nil
}

func (r *mqlAlicloudLogProject) logstores() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(r.region)
	if err != nil {
		return nil, err
	}
	projectName := r.Name.Data

	res := []any{}
	offset := int32(0)
	size := int32(200)
	firstPage := true
	for {
		resp, err := client.ListLogStores(new(projectName), &slsclient.ListLogStoresRequest{
			Offset: new(offset),
			Size:   new(size),
		})
		if err != nil {
			// First-page error = can't read this project's stores (skip);
			// later-page error is real — surface rather than truncate.
			if firstPage {
				break
			}
			return nil, err
		}
		firstPage = false
		if resp == nil || resp.Body == nil {
			break
		}
		items := resp.Body.Logstores
		for _, name := range items {
			if name == nil {
				continue
			}
			mqlStore, err := newLogLogstore(r.MqlRuntime, r.region, projectName, tea.StringValue(name))
			if err != nil {
				return nil, err
			}
			res = append(res, mqlStore)
		}
		total := tea.Int32Value(resp.Body.Total)
		offset += int32(len(items))
		if len(items) < int(size) || (total > 0 && offset >= total) {
			break
		}
	}
	return res, nil
}

// slsPolicyAbsent reports whether a GetProjectPolicy error means the project has
// no resource policy attached rather than that the read failed. SLS answers a
// project without a policy with a 404, so the check is on the API's own error
// envelope. A transport failure carries no SDKError and is deliberately not
// matched: degrading a network blip to "no policy attached" would report the
// project as not public without ever having read the policy.
func slsPolicyAbsent(err error) bool {
	var sdkErr *tea.SDKError
	if !errors.As(err, &sdkErr) {
		return false
	}
	return sdkErr.StatusCode != nil && *sdkErr.StatusCode == http.StatusNotFound
}

// fetchPolicy lazily loads and memoizes the project's resource policy. A
// transient error is not cached, so a later access retries instead of
// permanently reporting a project with an unread policy as having none.
func (r *mqlAlicloudLogProject) fetchPolicy() (string, error) {
	if r.policyFetched.Load() {
		return r.policyDoc, nil
	}
	r.policyLock.Lock()
	defer r.policyLock.Unlock()
	if r.policyFetched.Load() {
		return r.policyDoc, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(r.region)
	if err != nil {
		return "", err
	}
	resp, err := client.GetProjectPolicy(new(r.Name.Data))
	if err != nil {
		if !slsPolicyAbsent(err) {
			return "", err
		}
		// no policy attached is the common case, and is not a failure
		r.policyFetched.Store(true)
		return "", nil
	}
	if resp != nil {
		r.policyDoc = tea.StringValue(resp.Body)
	}
	r.policyFetched.Store(true)
	return r.policyDoc, nil
}

func (r *mqlAlicloudLogProject) policy() (string, error) {
	return r.fetchPolicy()
}

// isPublic reports whether the project's resource policy grants any principal
// access. An unparseable document is warned about and treated as not public,
// because the alternative is failing every project in the account on one
// malformed policy; the raw document stays readable through policy.
func (r *mqlAlicloudLogProject) isPublic() (bool, error) {
	doc, err := r.fetchPolicy()
	if err != nil {
		return false, err
	}
	statements, err := parsePolicyDocument(doc)
	if err != nil {
		log.Warn().Err(err).Str("project", r.Name.Data).
			Msg("alicloud> unable to parse the log project resource policy")
		return false, nil
	}
	return policyGrantsAnonymousAccess(statements), nil
}

// mqlAlicloudLogLogstoreInternal caches the keys needed to fetch the logstore
// detail and holds the cached detail so the several detail-derived accessors
// each trigger at most one GetLogStore call.
type mqlAlicloudLogLogstoreInternal struct {
	region      string
	projectName string
	name        string

	detailLock    sync.Mutex
	detailFetched atomic.Bool
	detail        *slsclient.Logstore
}

// newLogLogstore builds an alicloud.log.logstore husk keyed by region, project,
// and name. All detail fields load lazily via GetLogStore.
func newLogLogstore(runtime *plugin.Runtime, region, projectName, name string) (*mqlAlicloudLogLogstore, error) {
	resource, err := CreateResource(runtime, "alicloud.log.logstore", map[string]*llx.RawData{
		"__id":        llx.StringData(region + "/" + projectName + "/" + name),
		"regionId":    llx.StringData(region),
		"projectName": llx.StringData(projectName),
		"name":        llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	mqlStore := resource.(*mqlAlicloudLogLogstore)
	mqlStore.region = region
	mqlStore.projectName = projectName
	mqlStore.name = name
	return mqlStore, nil
}

// resolveLogStore returns the typed logstore for a project/name within a region,
// or (nil, nil) when either name is empty. It backs the VPC flow-log logstore()
// reference.
func resolveLogStore(runtime *plugin.Runtime, region, projectName, name string) (*mqlAlicloudLogLogstore, error) {
	if region == "" || projectName == "" || name == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.log.logstore", map[string]*llx.RawData{
		"regionId":    llx.StringData(region),
		"projectName": llx.StringData(projectName),
		"name":        llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudLogLogstore), nil
}

// initAlicloudLogLogstore resolves a logstore by region/project/name. The
// logstore's own detail loads lazily, so a cache miss simply builds the husk
// after confirming the logstore exists via GetLogStore.
func initAlicloudLogLogstore(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	name, err := requiredStringArg(args, "name", "alicloud.log.logstore")
	if err != nil {
		return nil, nil, err
	}
	projectName, err := requiredStringArg(args, "projectName", "alicloud.log.logstore")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.log.logstore")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.log.logstore\x00" + region + "/" + projectName + "/" + name); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetLogStore(new(projectName), new(name))
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil {
		return nil, nil, fmt.Errorf("alicloud.log.logstore %q not found in project %q", name, projectName)
	}
	res, err := newLogLogstore(runtime, region, projectName, name)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// project resolves the Log Service project that contains the logstore. A
// logstore cannot outlive its project, so a failure to read it is a real error.
func (r *mqlAlicloudLogLogstore) project() (*mqlAlicloudLogProject, error) {
	project, err := resolveLogProject(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

func (r *mqlAlicloudLogLogstore) id() (string, error) {
	return r.region + "/" + r.projectName + "/" + r.name, nil
}

// fetchDetail lazily loads and caches the GetLogStore detail, shared by every
// detail-derived accessor. A transient error is not cached (detailFetched is
// set only on success), so a later access retries rather than permanently
// reporting fabricated defaults; the error is returned so the field surfaces as
// an error instead of a misleading zero value.
func (r *mqlAlicloudLogLogstore) fetchDetail() (*slsclient.Logstore, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.SlsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetLogStore(new(r.projectName), new(r.name))
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.detail = resp.Body
	}
	r.detailFetched.Store(true)
	return r.detail, nil
}

func (r *mqlAlicloudLogLogstore) ttl() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(tea.Int32Value(d.Ttl)), nil
}

func (r *mqlAlicloudLogLogstore) hotTtl() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(tea.Int32Value(d.HotTtl)), nil
}

func (r *mqlAlicloudLogLogstore) shardCount() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(tea.Int32Value(d.ShardCount)), nil
}

func (r *mqlAlicloudLogLogstore) autoSplit() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.AutoSplit), nil
}

func (r *mqlAlicloudLogLogstore) maxSplitShard() (int64, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return 0, err
	}
	return int64(tea.Int32Value(d.MaxSplitShard)), nil
}

func (r *mqlAlicloudLogLogstore) appendMeta() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.AppendMeta), nil
}

func (r *mqlAlicloudLogLogstore) enableTracking() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return false, err
	}
	return tea.BoolValue(d.EnableTracking), nil
}

func (r *mqlAlicloudLogLogstore) telemetryType() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.TelemetryType), nil
}

func (r *mqlAlicloudLogLogstore) mode() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return "", err
	}
	return tea.StringValue(d.Mode), nil
}

func (r *mqlAlicloudLogLogstore) encryptionEnabled() (bool, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil || d.EncryptConf == nil {
		return false, err
	}
	return tea.BoolValue(d.EncryptConf.Enable), nil
}

func (r *mqlAlicloudLogLogstore) encryptionType() (string, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil || d.EncryptConf == nil {
		return "", err
	}
	return tea.StringValue(d.EncryptConf.EncryptType), nil
}

func (r *mqlAlicloudLogLogstore) encryptionKey() (*mqlAlicloudKmsKey, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	if d == nil || d.EncryptConf == nil || d.EncryptConf.UserCmkInfo == nil {
		r.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	cmk := d.EncryptConf.UserCmkInfo
	keyID := tea.StringValue(cmk.CmkKeyId)
	region := tea.StringValue(cmk.RegionId)
	if region == "" {
		region = r.region
	}
	if keyID == "" {
		r.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	key, err := resolveKmsKey(r.MqlRuntime, region, keyID)
	if err != nil || key == nil {
		r.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return key, nil
}

func (r *mqlAlicloudLogLogstore) createTime() (*time.Time, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return slsEpochTime(d.CreateTime), nil
}

func (r *mqlAlicloudLogLogstore) lastModifyTime() (*time.Time, error) {
	d, err := r.fetchDetail()
	if err != nil || d == nil {
		return nil, err
	}
	return slsEpochTime(d.LastModifyTime), nil
}
