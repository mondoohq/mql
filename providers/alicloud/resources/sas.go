// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"sync"
	"time"

	sasclient "github.com/alibabacloud-go/sas-20181203/v10/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// sasPageSize is the per-request item count for the page-numbered Security
// Center list APIs.
const sasPageSize int32 = 100

// sasParseTime parses a Security Center timestamp string. The APIs return a
// space-separated local form rather than RFC3339, so both are attempted.
func sasParseTime(s *string) *time.Time {
	v := tea.StringValue(s)
	if v == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t
		}
	}
	return nil
}

func (r *mqlAlicloudSas) id() (string, error) {
	return "alicloud.sas", nil
}

// mqlAlicloudSasInternal caches the result of the one-time center probe: the
// client for the center that owns the account, and the DescribeVersionConfig
// response that probe already paid for.
type mqlAlicloudSasInternal struct {
	resolveOnce  sync.Once
	centerClient *sasclient.Client
	versionCfg   *sasclient.DescribeVersionConfigResponseBody
	resolveErr   error
}

// resolveCenter probes both centers once and keeps what it learned.
//
// DescribeVersionConfig is both the cheapest call that proves a center owns the
// account and the source of every scalar field on this resource, so the probe's
// response is kept rather than discarded. Without this, a query for the whole
// resource would issue one DescribeVersionConfig for the probe plus one per
// field.
//
// A failure in both centers is reported as an error rather than swallowed. An
// account that has never subscribed still answers DescribeVersionConfig in its
// own center, with version 0, so "no center answered" means the call genuinely
// failed. Swallowing it would render an unreachable Security Center as one that
// is switched off, with no findings, which is the wrong direction for the
// question this resource exists to answer.
func (r *mqlAlicloudSas) resolveCenter() (client *sasclient.Client, cfg *sasclient.DescribeVersionConfigResponseBody, ok bool, err error) {
	r.resolveOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)

		var lastErr error
		for _, region := range alicloudCenterRegions {
			c, err := conn.SasClient(region)
			if err != nil {
				lastErr = err
				continue
			}
			resp, err := c.DescribeVersionConfig(&sasclient.DescribeVersionConfigRequest{})
			if err != nil {
				// the other center owns this account, or the call failed
				lastErr = err
				continue
			}
			r.centerClient = c
			if resp != nil {
				r.versionCfg = resp.Body
			}
			return
		}

		r.resolveErr = lastErr
	})

	if r.resolveErr != nil {
		return nil, nil, false, r.resolveErr
	}
	return r.centerClient, r.versionCfg, r.centerClient != nil, nil
}

// sasClient returns a client for the center that owns this account.
func (r *mqlAlicloudSas) sasClient() (*sasclient.Client, bool, error) {
	client, _, ok, err := r.resolveCenter()
	return client, ok, err
}

// versionConfig returns the subscription details backing every scalar field on
// the service resource, read once during the center probe.
func (r *mqlAlicloudSas) versionConfig() (*sasclient.DescribeVersionConfigResponseBody, error) {
	_, cfg, _, err := r.resolveCenter()
	return cfg, err
}

func (r *mqlAlicloudSas) enabled() (bool, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return false, err
	}
	return tea.Int32Value(cfg.Version) > 0, nil
}

func (r *mqlAlicloudSas) version() (int64, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return 0, err
	}
	return int64(tea.Int32Value(cfg.Version)), nil
}

func (r *mqlAlicloudSas) assetLevel() (int64, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return 0, err
	}
	return int64(tea.Int32Value(cfg.AssetLevel)), nil
}

func (r *mqlAlicloudSas) trialVersion() (bool, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return false, err
	}
	return tea.Int32Value(cfg.IsTrialVersion) == 1, nil
}

func (r *mqlAlicloudSas) postPay() (bool, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return false, err
	}
	return tea.BoolValue(cfg.IsPostpay), nil
}

func (r *mqlAlicloudSas) openTime() (*time.Time, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return nil, err
	}
	return configEpochMillis(cfg.OpenTime), nil
}

func (r *mqlAlicloudSas) expireTime() (*time.Time, error) {
	cfg, err := r.versionConfig()
	if err != nil || cfg == nil {
		return nil, err
	}
	return configEpochMillis(cfg.ReleaseTime), nil
}

// ---------------------------------------------------------------------------
// alicloud.sas.logDelivery
// ---------------------------------------------------------------------------

// sasLogEnabled reports whether a Security Center log-analysis entry is
// switched on. The API spells the states enabled/disabled; anything else,
// including an absent status, reads as off so a category nobody could read
// fails a "log analysis is on" check rather than passing it.
func sasLogEnabled(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "enabled")
}

// logDeliveries enumerates the per-log-type analysis configuration. Security
// Center switches host, network and security logs on separately, so this is a
// list rather than a single boolean.
func (r *mqlAlicloudSas) logDeliveries() ([]any, error) {
	client, ok, err := r.sasClient()
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}

	resp, err := client.DescribeLogMeta(&sasclient.DescribeLogMetaRequest{})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, meta := range resp.Body.LogMetaList {
		if meta == nil {
			continue
		}
		topic := tea.StringValue(meta.Topic)
		if topic == "" {
			// the topic is the cache key; an entry without one would collide
			// with every other unnamed entry and report the first one's values
			log.Debug().Msg("alicloud> skipping Security Center log meta entry with no topic")
			continue
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.sas.logDelivery", map[string]*llx.RawData{
			"__id":         llx.StringData(topic),
			"topic":        llx.StringData(topic),
			"category":     llx.StringDataPtr(meta.Category),
			"description":  llx.StringDataPtr(meta.LogDesc),
			"enabled":      llx.BoolData(sasLogEnabled(meta.Status)),
			"ttlDays":      llx.IntData(int64(tea.Int32Value(meta.Ttl))),
			"projectName":  llx.StringDataPtr(meta.UserProject),
			"logstoreName": llx.StringDataPtr(meta.UserLogStore),
			"regionId":     llx.StringDataPtr(meta.UserRegion),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (r *mqlAlicloudSasLogDelivery) id() (string, error) {
	return r.Topic.Data, nil
}

// logProject resolves the project the logs are delivered to. A project that
// cannot be resolved degrades to null rather than failing the query, and
// projectName still carries the name it reported.
func (r *mqlAlicloudSasLogDelivery) logProject() (*mqlAlicloudLogProject, error) {
	if r.ProjectName.Data == "" || r.RegionId.Data == "" {
		r.LogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveLogProject(r.MqlRuntime, r.RegionId.Data, r.ProjectName.Data)
	if err != nil || project == nil {
		r.LogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

// ---------------------------------------------------------------------------
// alicloud.sas.machine
// ---------------------------------------------------------------------------

func (r *mqlAlicloudSasMachine) id() (string, error) {
	return r.Uuid.Data, nil
}

// mqlAlicloudSasMachineInternal caches the identifiers needed to resolve the
// machine's typed ECS instance reference.
type mqlAlicloudSasMachineInternal struct {
	cacheRegion     string
	cacheInstanceID string
	cacheIsEcs      bool
}

func (r *mqlAlicloudSas) machines() ([]any, error) {
	client, ok, err := r.sasClient()
	if err != nil || !ok {
		return []any{}, err
	}

	res := []any{}
	currentPage := int32(1)
	for {
		resp, err := client.DescribeCloudCenterInstances(&sasclient.DescribeCloudCenterInstancesRequest{
			CurrentPage: tea.Int32(currentPage),
			PageSize:    tea.Int32(sasPageSize),
			// the console's own default: exclude group metadata we do not model
			NoGroupTrace: tea.Bool(true),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, m := range resp.Body.Instances {
			if m == nil || m.Uuid == nil {
				continue
			}
			machine, err := newSasMachine(r.MqlRuntime, m)
			if err != nil {
				return nil, err
			}
			res = append(res, machine)
		}

		if resp.Body.PageInfo == nil {
			break
		}
		total := tea.Int32Value(resp.Body.PageInfo.TotalCount)
		if total == 0 || currentPage*sasPageSize >= total {
			break
		}
		currentPage++
	}
	return res, nil
}

func newSasMachine(runtime *plugin.Runtime, m *sasclient.DescribeCloudCenterInstancesResponseBodyInstances) (*mqlAlicloudSasMachine, error) {
	resource, err := CreateResource(runtime, "alicloud.sas.machine", map[string]*llx.RawData{
		"__id":             llx.StringDataPtr(m.Uuid),
		"uuid":             llx.StringDataPtr(m.Uuid),
		"instanceId":       llx.StringDataPtr(m.InstanceId),
		"instanceName":     llx.StringDataPtr(m.InstanceName),
		"regionId":         llx.StringDataPtr(m.RegionId),
		"os":               llx.StringDataPtr(m.Os),
		"osName":           llx.StringDataPtr(m.OsName),
		"internetIp":       llx.StringDataPtr(m.InternetIp),
		"intranetIp":       llx.StringDataPtr(m.IntranetIp),
		"clientStatus":     llx.StringDataPtr(m.ClientStatus),
		"bind":             llx.BoolDataPtr(m.Bind),
		"vulCount":         llx.IntDataPtr(m.VulCount),
		"vulStatus":        llx.StringDataPtr(m.VulStatus),
		"riskCount":        llx.StringDataPtr(m.RiskCount),
		"riskStatus":       llx.StringDataPtr(m.RiskStatus),
		"alarmStatus":      llx.StringDataPtr(m.AlarmStatus),
		"safeEventCount":   llx.IntDataPtr(m.SafeEventCount),
		"healthCheckCount": llx.IntDataPtr(m.HealthCheckCount),
		"exposedStatus":    llx.IntDataPtr(m.ExposedStatus),
		"importance":       llx.IntDataPtr(m.Importance),
		"authVersionName":  llx.StringDataPtr(m.AuthVersionName),
		"assetTypeName":    llx.StringDataPtr(m.AssetTypeName),
		"vendorName":       llx.StringDataPtr(m.VendorName),
		"clusterId":        llx.StringDataPtr(m.ClusterId),
		"groupTrace":       llx.StringDataPtr(m.GroupTrace),
		"createdTime":      llx.TimeDataPtr(configEpochMillis(m.CreatedTime)),
		"lastLoginTime":    llx.TimeDataPtr(configEpochMillis(m.LastLoginTimestamp)),
	})
	if err != nil {
		return nil, err
	}

	mqlMachine := resource.(*mqlAlicloudSasMachine)
	mqlMachine.cacheRegion = tea.StringValue(m.RegionId)
	mqlMachine.cacheInstanceID = tea.StringValue(m.InstanceId)
	// Vendor 0 is Alibaba Cloud; anything else is a server onboarded from
	// another cloud or from on-premises, which has no ECS instance behind it.
	mqlMachine.cacheIsEcs = tea.Int32Value(m.Vendor) == 0 && tea.StringValue(m.AssetType) == "ecs"
	return mqlMachine, nil
}

// ecsInstance resolves the ECS instance behind an Alibaba Cloud machine.
func (r *mqlAlicloudSasMachine) ecsInstance() (*mqlAlicloudEcsInstance, error) {
	if !r.cacheIsEcs || r.cacheInstanceID == "" || r.cacheRegion == "" {
		r.EcsInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	instance, err := resolveEcsInstance(r.MqlRuntime, r.cacheRegion, r.cacheInstanceID)
	if err != nil {
		// the instance may have been terminated while still listed in the
		// Security Center inventory
		log.Debug().Err(err).Str("instance", r.cacheInstanceID).
			Msg("alicloud: could not resolve ECS instance behind Security Center machine")
		r.EcsInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return instance, nil
}

// ---------------------------------------------------------------------------
// alicloud.sas.vulnerability
// ---------------------------------------------------------------------------

func (r *mqlAlicloudSasVulnerability) id() (string, error) {
	return r.Type.Data + "/" + r.Name.Data, nil
}

// sasVulnerabilityTypes are the vulnerability categories DescribeGroupedVul
// reports on. The API requires a type per request, so every category is walked.
var sasVulnerabilityTypes = []string{"cve", "sys", "cms", "app", "emg", "sca"}

func (r *mqlAlicloudSas) vulnerabilities() ([]any, error) {
	client, ok, err := r.sasClient()
	if err != nil || !ok {
		return []any{}, err
	}

	res := []any{}
	for _, vulType := range sasVulnerabilityTypes {
		currentPage := int32(1)
		for {
			resp, err := client.DescribeGroupedVul(&sasclient.DescribeGroupedVulRequest{
				Type:        tea.String(vulType),
				CurrentPage: tea.Int32(currentPage),
				PageSize:    tea.Int32(sasPageSize),
			})
			if err != nil {
				// a category the subscription does not cover answers with an
				// error; skip it rather than failing the whole list
				log.Debug().Err(err).Str("type", vulType).
					Msg("alicloud: could not read Security Center vulnerabilities")
				break
			}
			if resp == nil || resp.Body == nil {
				break
			}

			for _, v := range resp.Body.GroupedVulItems {
				if v == nil || v.Name == nil {
					continue
				}
				vuln, err := CreateResource(r.MqlRuntime, "alicloud.sas.vulnerability", map[string]*llx.RawData{
					"__id":          llx.StringData(vulType + "/" + tea.StringValue(v.Name)),
					"name":          llx.StringDataPtr(v.Name),
					"aliasName":     llx.StringDataPtr(v.AliasName),
					"type":          llx.StringData(vulType),
					"asapCount":     llx.IntDataPtr(v.AsapCount),
					"laterCount":    llx.IntDataPtr(v.LaterCount),
					"nntfCount":     llx.IntDataPtr(v.NntfCount),
					"handledCount":  llx.IntDataPtr(v.HandledCount),
					"totalFixCount": llx.IntDataPtr(v.TotalFixCount),
					"lastFoundTime": llx.TimeDataPtr(configEpochMillis(v.GmtLast)),
					"tags":          llx.StringDataPtr(v.Tags),
					"related":       llx.StringDataPtr(v.Related),
					"raspDefend":    llx.IntDataPtr(v.RaspDefend),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, vuln)
			}

			total := tea.Int32Value(resp.Body.TotalCount)
			if total == 0 || currentPage*sasPageSize >= total {
				break
			}
			currentPage++
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.sas.baselineCheck
// ---------------------------------------------------------------------------

func (r *mqlAlicloudSasBaselineCheck) id() (string, error) {
	return strconv.FormatInt(r.RiskId.Data, 10), nil
}

func (r *mqlAlicloudSas) baselineChecks() ([]any, error) {
	client, ok, err := r.sasClient()
	if err != nil || !ok {
		return []any{}, err
	}

	res := []any{}
	currentPage := int32(1)
	for {
		resp, err := client.DescribeCheckWarningSummary(&sasclient.DescribeCheckWarningSummaryRequest{
			CurrentPage: tea.Int32(currentPage),
			PageSize:    tea.Int32(sasPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, w := range resp.Body.WarningSummarys {
			if w == nil || w.RiskId == nil {
				continue
			}
			check, err := CreateResource(r.MqlRuntime, "alicloud.sas.baselineCheck", map[string]*llx.RawData{
				"__id":                llx.StringData(strconv.FormatInt(tea.Int64Value(w.RiskId), 10)),
				"riskId":              llx.IntDataPtr(w.RiskId),
				"riskName":            llx.StringDataPtr(w.RiskName),
				"typeAlias":           llx.StringDataPtr(w.TypeAlias),
				"subTypeAlias":        llx.StringDataPtr(w.SubTypeAlias),
				"level":               llx.StringDataPtr(w.Level),
				"checkCount":          llx.IntDataPtr(w.CheckCount),
				"highWarningCount":    llx.IntDataPtr(w.HighWarningCount),
				"mediumWarningCount":  llx.IntDataPtr(w.MediumWarningCount),
				"lowWarningCount":     llx.IntDataPtr(w.LowWarningCount),
				"warningMachineCount": llx.IntDataPtr(w.WarningMachineCount),
				"lastFoundTime":       llx.TimeDataPtr(sasParseTime(w.LastFoundTime)),
				"checkExploit":        llx.BoolDataPtr(w.CheckExploit),
				"containerRisk":       llx.BoolDataPtr(w.ContainerRisk),
				"databaseRisk":        llx.BoolDataPtr(w.DatabaseRisk),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, check)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if total == 0 || currentPage*sasPageSize >= total {
			break
		}
		currentPage++
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.sas.alarmEvent
// ---------------------------------------------------------------------------

func (r *mqlAlicloudSasAlarmEvent) id() (string, error) {
	return strconv.FormatInt(r.Id.Data, 10), nil
}

func (r *mqlAlicloudSas) alarmEvents() ([]any, error) {
	client, ok, err := r.sasClient()
	if err != nil || !ok {
		return []any{}, err
	}

	res := []any{}
	currentPage := int32(1)
	for {
		// DescribeSuspEvents takes its paging parameters as strings
		resp, err := client.DescribeSuspEvents(&sasclient.DescribeSuspEventsRequest{
			CurrentPage: tea.String(strconv.Itoa(int(currentPage))),
			PageSize:    tea.String(strconv.Itoa(int(sasPageSize))),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		for _, e := range resp.Body.SuspEvents {
			if e == nil || e.Id == nil {
				continue
			}
			event, err := newSasAlarmEvent(r.MqlRuntime, e)
			if err != nil {
				return nil, err
			}
			res = append(res, event)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if total == 0 || currentPage*sasPageSize >= total {
			break
		}
		currentPage++
	}
	return res, nil
}

func newSasAlarmEvent(runtime *plugin.Runtime, e *sasclient.DescribeSuspEventsResponseBodySuspEvents) (*mqlAlicloudSasAlarmEvent, error) {
	resource, err := CreateResource(runtime, "alicloud.sas.alarmEvent", map[string]*llx.RawData{
		"__id":               llx.StringData(strconv.FormatInt(tea.Int64Value(e.Id), 10)),
		"id":                 llx.IntDataPtr(e.Id),
		"alarmEventName":     llx.StringDataPtr(e.AlarmEventName),
		"alarmEventType":     llx.StringDataPtr(e.AlarmEventType),
		"level":              llx.StringDataPtr(e.Level),
		"eventStatus":        llx.IntDataPtr(e.EventStatus),
		"description":        llx.StringDataPtr(e.Desc),
		"stages":             llx.StringDataPtr(e.Stages),
		"dataSource":         llx.StringDataPtr(e.DataSource),
		"uuid":               llx.StringDataPtr(e.Uuid),
		"instanceId":         llx.StringDataPtr(e.InstanceId),
		"instanceName":       llx.StringDataPtr(e.InstanceName),
		"internetIp":         llx.StringDataPtr(e.InternetIp),
		"intranetIp":         llx.StringDataPtr(e.IntranetIp),
		"containerId":        llx.StringDataPtr(e.ContainerId),
		"containerImageName": llx.StringDataPtr(e.ContainerImageName),
		"k8sClusterId":       llx.StringDataPtr(e.K8sClusterId),
		"k8sNamespace":       llx.StringDataPtr(e.K8sNamespace),
		"k8sPodName":         llx.StringDataPtr(e.K8sPodName),
		"occurrenceTime":     llx.TimeDataPtr(sasParseTime(e.OccurrenceTime)),
		"lastTime":           llx.TimeDataPtr(sasParseTime(e.LastTime)),
		"canBeDealOnLine":    llx.BoolDataPtr(e.CanBeDealOnLine),
		"autoBreaking":       llx.BoolDataPtr(e.AutoBreaking),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudSasAlarmEvent), nil
}

// machine resolves the Security Center machine the alert was raised against.
func (r *mqlAlicloudSasAlarmEvent) machine() (*mqlAlicloudSasMachine, error) {
	uuid := r.Uuid.Data
	if uuid == "" {
		r.Machine.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// the machine listing materializes every machine, so the alert's machine is
	// found in the cache rather than fetched one at a time
	if x, ok := r.MqlRuntime.Resources.Get("alicloud.sas.machine\x00" + uuid); ok {
		return x.(*mqlAlicloudSasMachine), nil
	}

	svc, err := CreateResource(r.MqlRuntime, "alicloud.sas", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	machines := svc.(*mqlAlicloudSas).GetMachines()
	if machines.Error != nil {
		return nil, machines.Error
	}
	for _, im := range machines.Data {
		machine, ok := im.(*mqlAlicloudSasMachine)
		if ok && machine.Uuid.Data == uuid {
			return machine, nil
		}
	}

	// an alert can outlive the machine it was raised against
	r.Machine.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
