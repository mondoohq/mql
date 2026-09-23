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
	"go.mondoo.com/mql/types"
)

// sasPropertyScheduleTypes are the asset fingerprint kinds Security Center
// collects. GetPropertyScheduleConfig answers for one kind per request, so the
// schedule for the account is assembled by walking the documented set, the same
// way DescribeGroupedVul is walked per vulnerability type.
var sasPropertyScheduleTypes = []string{
	"scheduler_software_period",
	"scheduler_cron_period",
	"scheduler_sca_period",
	"scheduler_autorun_period",
	"scheduler_lkm_period",
	"scheduler_sca_proxy_period",
}

// sasNoticeChannels decodes the notification route bit field into channel
// names. The API reports a single integer where 1 is text message, 2 is email
// and 4 is internal message, so 7 means all three and 0 means the event type
// raises no notification anywhere.
func sasNoticeChannels(route *int32) []any {
	v := tea.Int32Value(route)
	res := []any{}
	if v&1 != 0 {
		res = append(res, "sms")
	}
	if v&2 != 0 {
		res = append(res, "email")
	}
	if v&4 != 0 {
		res = append(res, "internal")
	}
	return res
}

// sasSwitchEnabled reads the on/off switch the vulnerability scan settings use.
// Only "on" counts; an absent or unrecognised value reads as off so a type
// nobody could read fails a "scanning is enabled" check rather than passing it.
func sasSwitchEnabled(value *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(value)), "on")
}

// sasScheduleHours converts the fingerprint collection interval, which the API
// returns as a string, to hours. An absent or unparseable value is 0, which
// reads as "not scheduled" rather than as an invented frequency.
func sasScheduleHours(value *string) int64 {
	v := strings.TrimSpace(tea.StringValue(value))
	if v == "" {
		return 0
	}
	hours, err := strconv.Atoi(v)
	if err != nil || hours < 0 {
		return 0
	}
	return int64(hours)
}

// mqlAlicloudSasConfigInternal memoizes each settings call, so a query touching
// several fields backed by one API pays for it once.
type mqlAlicloudSasConfigInternal struct {
	client *sasclient.Client

	virusLock sync.Mutex
	virusDone bool
	virus     *sasclient.GetVirusScanConfigResponseBodyData

	checkLock sync.Mutex
	checkDone bool
	check     *sasclient.GetCheckConfigResponseBody
}

// config exposes the account's Security Center settings. It is reached through
// the center that owns the account, which the service resource has already
// probed.
func (r *mqlAlicloudSas) config() (*mqlAlicloudSasConfig, error) {
	client, ok, err := r.sasClient()
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Config.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resource, err := CreateResource(r.MqlRuntime, "alicloud.sas.config", map[string]*llx.RawData{
		"__id": llx.StringData("alicloud.sas.config"),
	})
	if err != nil {
		return nil, err
	}
	cfg := resource.(*mqlAlicloudSasConfig)
	cfg.client = client
	return cfg, nil
}

func (r *mqlAlicloudSasConfig) id() (string, error) {
	return "alicloud.sas.config", nil
}

// virusScanConfig lazily reads the scheduled antivirus scan settings and
// memoizes them, so the five virus scan fields share one call.
func (r *mqlAlicloudSasConfig) virusScanConfig() *sasclient.GetVirusScanConfigResponseBodyData {
	r.virusLock.Lock()
	defer r.virusLock.Unlock()
	if r.virusDone {
		return r.virus
	}
	r.virusDone = true

	if r.client == nil {
		return nil
	}
	resp, err := r.client.GetVirusScanConfig(&sasclient.GetVirusScanConfigRequest{})
	if err != nil || resp == nil || resp.Body == nil {
		return nil
	}
	r.virus = resp.Body.Data
	return r.virus
}

func (r *mqlAlicloudSasConfig) virusScanEnabled() (bool, error) {
	cfg := r.virusScanConfig()
	if cfg == nil {
		return false, nil
	}
	return tea.Int32Value(cfg.Enable) == 1, nil
}

func (r *mqlAlicloudSasConfig) virusScanInterval() (int64, error) {
	cfg := r.virusScanConfig()
	if cfg == nil {
		return 0, nil
	}
	return int64(tea.Int32Value(cfg.IntervalPeriod)), nil
}

func (r *mqlAlicloudSasConfig) virusScanPeriodUnit() (string, error) {
	cfg := r.virusScanConfig()
	if cfg == nil {
		return "", nil
	}
	return tea.StringValue(cfg.PeriodUnit), nil
}

func (r *mqlAlicloudSasConfig) virusScanPaths() ([]any, error) {
	cfg := r.virusScanConfig()
	if cfg == nil {
		return []any{}, nil
	}
	return sasStrings(cfg.ScanPath), nil
}

func (r *mqlAlicloudSasConfig) virusScanType() (string, error) {
	cfg := r.virusScanConfig()
	if cfg == nil {
		return "", nil
	}
	return tea.StringValue(cfg.ScanType), nil
}

// checkConfig lazily reads the configuration assessment schedule and memoizes
// it, so the four assessment fields share one call.
func (r *mqlAlicloudSasConfig) checkConfig() *sasclient.GetCheckConfigResponseBody {
	r.checkLock.Lock()
	defer r.checkLock.Unlock()
	if r.checkDone {
		return r.check
	}
	r.checkDone = true

	if r.client == nil {
		return nil
	}
	resp, err := r.client.GetCheckConfig(&sasclient.GetCheckConfigRequest{})
	if err != nil || resp == nil || resp.Body == nil {
		return nil
	}
	r.check = resp.Body
	return r.check
}

func (r *mqlAlicloudSasConfig) configAssessmentEnabled() (bool, error) {
	cfg := r.checkConfig()
	if cfg == nil {
		return false, nil
	}
	return tea.BoolValue(cfg.EnableAutoCheck), nil
}

func (r *mqlAlicloudSasConfig) configAssessmentAutoAddEnabled() (bool, error) {
	cfg := r.checkConfig()
	if cfg == nil {
		return false, nil
	}
	return tea.BoolValue(cfg.EnableAddCheck), nil
}

func (r *mqlAlicloudSasConfig) configAssessmentCycleDays() ([]any, error) {
	cfg := r.checkConfig()
	if cfg == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, day := range cfg.CycleDays {
		if day == nil {
			continue
		}
		res = append(res, int64(*day))
	}
	return res, nil
}

func (r *mqlAlicloudSasConfig) configAssessmentStandards() ([]any, error) {
	cfg := r.checkConfig()
	if cfg == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, standard := range cfg.Standards {
		if standard == nil {
			continue
		}
		name := tea.StringValue(standard.ShowName)
		if name == "" {
			continue
		}
		res = append(res, name)
	}
	return res, nil
}

// webPaths lists the directories webshell detection covers. The listing is
// page-numbered, so it is walked to the end rather than reporting the first
// page as the whole scope.
func (r *mqlAlicloudSasConfig) webPaths() ([]any, error) {
	if r.client == nil {
		return []any{}, nil
	}

	res := []any{}
	currentPage := int32(1)
	for {
		resp, err := r.client.DescribeWebPath(&sasclient.DescribeWebPathRequest{
			CurrentPage: tea.Int32(currentPage),
			PageSize:    tea.Int32(sasPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}

		items := resp.Body.ConfigList
		for _, item := range items {
			if item == nil {
				continue
			}
			path := tea.StringValue(item.WebPath)
			if path == "" {
				// the path is the cache key; an entry without one would collide
				// with every other unnamed entry and report the first's values
				log.Debug().Msg("alicloud> skipping Security Center web path with no path")
				continue
			}
			targets := map[string]any{}
			for _, target := range item.TargetList {
				if target == nil || target.Target == nil || *target.Target == "" {
					continue
				}
				targets[*target.Target] = tea.StringValue(target.TargetType)
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.sas.webPath", map[string]*llx.RawData{
				"__id":        llx.StringData(path),
				"webPath":     llx.StringData(path),
				"webPathType": llx.StringDataPtr(item.WebPathType),
				"targets":     llx.MapData(targets, types.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}

		if len(items) < int(sasPageSize) {
			break
		}
		currentPage++
	}
	return res, nil
}

// noticeConfigs lists where each kind of Security Center event is notified.
func (r *mqlAlicloudSasConfig) noticeConfigs() ([]any, error) {
	if r.client == nil {
		return []any{}, nil
	}

	resp, err := r.client.DescribeNoticeConfig(&sasclient.DescribeNoticeConfigRequest{})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, notice := range resp.Body.NoticeConfigList {
		if notice == nil {
			continue
		}
		project := tea.StringValue(notice.Project)
		if project == "" {
			log.Debug().Msg("alicloud> skipping Security Center notice config with no project")
			continue
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.sas.noticeConfig", map[string]*llx.RawData{
			"__id":      llx.StringData(project),
			"project":   llx.StringData(project),
			"category":  llx.StringDataPtr(notice.Category),
			"channels":  llx.ArrayData(sasNoticeChannels(notice.Route), types.String),
			"route":     llx.IntData(int64(tea.Int32Value(notice.Route))),
			"timeLimit": llx.IntData(int64(tea.Int32Value(notice.TimeLimit))),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

// vulnerabilityConfigs lists the scan setting for each vulnerability type.
func (r *mqlAlicloudSasConfig) vulnerabilityConfigs() ([]any, error) {
	if r.client == nil {
		return []any{}, nil
	}

	resp, err := r.client.DescribeVulConfig(&sasclient.DescribeVulConfigRequest{})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, target := range resp.Body.TargetConfigs {
		if target == nil {
			continue
		}
		vulType := tea.StringValue(target.Type)
		if vulType == "" {
			log.Debug().Msg("alicloud> skipping Security Center vulnerability config with no type")
			continue
		}
		resource, err := CreateResource(r.MqlRuntime, "alicloud.sas.vulnerabilityConfig", map[string]*llx.RawData{
			"__id":    llx.StringData(vulType),
			"type":    llx.StringData(vulType),
			"enabled": llx.BoolData(sasSwitchEnabled(target.OverAllConfig)),
			"config":  llx.StringDataPtr(target.Config),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

// propertySchedules lists how often each kind of asset fingerprint is
// collected. GetPropertyScheduleConfig answers for one kind per request, so the
// documented set is walked; a kind the account has not configured is skipped
// rather than reported with an invented frequency.
func (r *mqlAlicloudSasConfig) propertySchedules() ([]any, error) {
	if r.client == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, scheduleType := range sasPropertyScheduleTypes {
		resp, err := r.client.GetPropertyScheduleConfig(&sasclient.GetPropertyScheduleConfigRequest{
			Type: tea.String(scheduleType),
		})
		if err != nil {
			// one fingerprint kind that cannot be read must not drop the rest
			log.Debug().Err(err).Str("type", scheduleType).
				Msg("alicloud> could not read Security Center fingerprint schedule")
			continue
		}
		if resp == nil || resp.Body == nil || resp.Body.PropertyScheduleConfig == nil {
			continue
		}
		cfg := resp.Body.PropertyScheduleConfig

		var nextSchedule *time.Time
		if next := tea.Int64Value(cfg.NextScheduleTime); next > 0 {
			t := time.UnixMilli(next).UTC()
			nextSchedule = &t
		}

		resource, err := CreateResource(r.MqlRuntime, "alicloud.sas.propertySchedule", map[string]*llx.RawData{
			"__id":             llx.StringData(scheduleType),
			"type":             llx.StringData(scheduleType),
			"scheduleHours":    llx.IntData(sasScheduleHours(cfg.ScheduleTime)),
			"nextScheduleTime": llx.TimeDataPtr(nextSchedule),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, resource)
	}
	return res, nil
}

func (r *mqlAlicloudSasWebPath) id() (string, error) {
	return r.WebPath.Data, nil
}

func (r *mqlAlicloudSasNoticeConfig) id() (string, error) {
	return r.Project.Data, nil
}

func (r *mqlAlicloudSasVulnerabilityConfig) id() (string, error) {
	return r.Type.Data, nil
}

func (r *mqlAlicloudSasPropertySchedule) id() (string, error) {
	return r.Type.Data, nil
}

// sasStrings flattens a pointer-string slice, dropping nil and empty entries so
// a blank does not surface as a configured path.
func sasStrings(in []*string) []any {
	res := []any{}
	for _, v := range in {
		if v == nil || *v == "" {
			continue
		}
		res = append(res, *v)
	}
	return res
}
