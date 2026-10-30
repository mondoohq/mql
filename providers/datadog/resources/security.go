// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/datadog/connection"
)

// --- Sensitive Data Scanner Groups ---

func (r *mqlDatadog) sensitiveDataScannerGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewSensitiveDataScannerApi(conn.ApiClient())

	resp, httpResp, err := api.ListScanningGroups(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> sensitive data scanner not available (403 Forbidden). Your Datadog plan may not include this feature")
			return nil, nil
		}
		return nil, err
	}

	// Groups are in the Included array as SensitiveDataScannerGroup items
	var all []any
	for _, item := range resp.GetIncluded() {
		group := item.SensitiveDataScannerGroupIncludedItem
		if group == nil {
			continue
		}
		attrs := group.GetAttributes()

		productList := make([]any, 0)
		for _, p := range attrs.GetProductList() {
			productList = append(productList, string(p))
		}

		filterQuery := ""
		if f, ok := attrs.GetFilterOk(); ok && f != nil {
			filterQuery = f.GetQuery()
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.sensitiveDataScannerGroup", map[string]*llx.RawData{
			"id":          llx.StringData(group.GetId()),
			"name":        llx.StringData(attrs.GetName()),
			"description": llx.StringData(attrs.GetDescription()),
			"isEnabled":   llx.BoolData(attrs.GetIsEnabled()),
			"productList": llx.ArrayData(productList, "\x02"),
			"filter":      llx.StringData(filterQuery),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogSensitiveDataScannerGroup) id() (string, error) {
	return "datadog.sensitiveDataScannerGroup/" + r.Id.Data, nil
}

// --- Security Monitoring Filters ---

func (r *mqlDatadog) securityFilters() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewSecurityMonitoringApi(conn.ApiClient())

	resp, httpResp, err := api.ListSecurityFilters(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> security filters not available (403 Forbidden). Your Datadog plan may not include Cloud SIEM")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, f := range resp.GetData() {
		attrs := f.GetAttributes()
		res, err := CreateResource(r.MqlRuntime, "datadog.securityFilter", map[string]*llx.RawData{
			"id":               llx.StringData(f.GetId()),
			"name":             llx.StringData(attrs.GetName()),
			"query":            llx.StringData(attrs.GetQuery()),
			"isEnabled":        llx.BoolData(attrs.GetIsEnabled()),
			"filteredDataType": llx.StringData(string(attrs.GetFilteredDataType())),
			"version":          llx.IntData(int64(attrs.GetVersion())),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogSecurityFilter) id() (string, error) {
	return "datadog.securityFilter/" + r.Id.Data, nil
}

// --- Security Monitoring Suppressions ---

func (r *mqlDatadog) securitySuppressions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewSecurityMonitoringApi(conn.ApiClient())

	resp, httpResp, err := api.ListSecurityMonitoringSuppressions(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> security suppressions not available (403 Forbidden). Your Datadog plan may not include Cloud SIEM")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, s := range resp.GetData() {
		attrs := s.GetAttributes()

		// expiration_date is a Unix millisecond timestamp.
		var expirationDate *time.Time
		if v, ok := attrs.GetExpirationDateOk(); ok && v != nil {
			expirationDate = epochMillisToTimePtr(*v)
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.securitySuppression", map[string]*llx.RawData{
			"id":                 llx.StringData(s.GetId()),
			"name":               llx.StringData(attrs.GetName()),
			"description":        llx.StringData(attrs.GetDescription()),
			"enabled":            llx.BoolData(attrs.GetEnabled()),
			"ruleQuery":          llx.StringData(attrs.GetRuleQuery()),
			"suppressionQuery":   llx.StringData(attrs.GetSuppressionQuery()),
			"dataExclusionQuery": llx.StringData(attrs.GetDataExclusionQuery()),
			"expirationDate":     llx.TimeDataPtr(expirationDate),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogSecuritySuppression) id() (string, error) {
	return "datadog.securitySuppression/" + r.Id.Data, nil
}

// --- Service Accounts ---

func (r *mqlDatadog) serviceAccounts() ([]any, error) {
	usersList, err := r.fetchUsers()
	if err != nil {
		return nil, err
	}

	var all []any
	for _, u := range usersList {
		attrs := u.GetAttributes()
		if !attrs.GetServiceAccount() {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "datadog.serviceAccount", map[string]*llx.RawData{
			"id":        llx.StringData(u.GetId()),
			"email":     llx.StringData(attrs.GetEmail()),
			"name":      llx.StringData(attrs.GetName()),
			"handle":    llx.StringData(attrs.GetHandle()),
			"status":    llx.StringData(attrs.GetStatus()),
			"disabled":  llx.BoolData(attrs.GetDisabled()),
			"createdAt": llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogServiceAccount) id() (string, error) {
	return "datadog.serviceAccount/" + r.Id.Data, nil
}

// --- Logs Archives ---

func (r *mqlDatadog) logsArchives() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewLogsArchivesApi(conn.ApiClient())

	resp, httpResp, err := api.ListLogsArchives(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> logs archives not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, a := range resp.GetData() {
		attrs := a.GetAttributes()

		query := ""
		if q, ok := attrs.GetQueryOk(); ok {
			query = *q
		}

		state := ""
		if s, ok := attrs.GetStateOk(); ok {
			state = string(*s)
		}

		includeTags := false
		if v, ok := attrs.GetIncludeTagsOk(); ok {
			includeTags = *v
		}

		rehydrationMaxScan := int64(0)
		if v, ok := attrs.GetRehydrationMaxScanSizeInGbOk(); ok && v != nil {
			rehydrationMaxScan = *v
		}

		rehydrationTags := make([]any, 0)
		for _, t := range attrs.GetRehydrationTags() {
			rehydrationTags = append(rehydrationTags, t)
		}

		destType := ""
		dest := map[string]any{}
		if d := attrs.GetDestination(); d.LogsArchiveDestinationS3 != nil {
			destType = "s3"
			s3 := d.LogsArchiveDestinationS3
			dest["bucket"] = s3.GetBucket()
			dest["path"] = s3.GetPath()
		} else if d.LogsArchiveDestinationGCS != nil {
			destType = "gcs"
			gcs := d.LogsArchiveDestinationGCS
			dest["bucket"] = gcs.GetBucket()
			dest["path"] = gcs.GetPath()
		} else if d.LogsArchiveDestinationAzure != nil {
			destType = "azure"
			az := d.LogsArchiveDestinationAzure
			dest["container"] = az.GetContainer()
			dest["storageAccount"] = az.GetStorageAccount()
			dest["path"] = az.GetPath()
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.logsArchive", map[string]*llx.RawData{
			"id":                         llx.StringData(a.GetId()),
			"name":                       llx.StringData(attrs.GetName()),
			"query":                      llx.StringData(query),
			"state":                      llx.StringData(state),
			"includeTags":                llx.BoolData(includeTags),
			"rehydrationMaxScanSizeInGb": llx.IntData(rehydrationMaxScan),
			"rehydrationTags":            llx.ArrayData(rehydrationTags, "\x02"),
			"destinationType":            llx.StringData(destType),
			"destination":                llx.DictData(dest),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogLogsArchive) id() (string, error) {
	return "datadog.logsArchive/" + r.Id.Data, nil
}

// --- RUM Applications ---

func (r *mqlDatadog) rumApplications() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewRUMApi(conn.ApiClient())

	resp, httpResp, err := api.GetRUMApplications(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> RUM applications not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, app := range resp.GetData() {
		attrs := app.GetAttributes()
		res, err := CreateResource(r.MqlRuntime, "datadog.rumApplication", map[string]*llx.RawData{
			"id":   llx.StringData(app.GetId()),
			"name": llx.StringData(attrs.GetName()),
			"type": llx.StringData(attrs.GetType()),
			// clientToken is not available on the list API response (only the create response)
			"clientToken": llx.StringData(""),
			// created_at and updated_at are Unix millisecond timestamps.
			"createdAt": llx.TimeDataPtr(epochMillisToTimePtr(attrs.GetCreatedAt())),
			"updatedAt": llx.TimeDataPtr(epochMillisToTimePtr(attrs.GetUpdatedAt())),
			"orgId":     llx.StringData(strconv.FormatInt(int64(attrs.GetOrgId()), 10)),
			"isActive":  llx.BoolData(attrs.GetIsActive()),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogRumApplication) id() (string, error) {
	return "datadog.rumApplication/" + r.Id.Data, nil
}

// --- Synthetics Global Variables ---

func (r *mqlDatadog) syntheticsGlobalVariables() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV1.NewSyntheticsApi(conn.ApiClient())

	resp, httpResp, err := api.ListGlobalVariables(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> synthetics global variables not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, v := range resp.GetVariables() {
		tags := toAnyStrings(v.GetTags())

		parseTestId := ""
		if pt, ok := v.GetParseTestPublicIdOk(); ok && pt != nil {
			parseTestId = *pt
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.syntheticsGlobalVariable", map[string]*llx.RawData{
			"id":                llx.StringData(v.GetId()),
			"name":              llx.StringData(v.GetName()),
			"description":       llx.StringData(v.GetDescription()),
			"tags":              llx.ArrayData(tags, "\x02"),
			"isTotp":            llx.BoolData(v.GetIsTotp()),
			"isFido":            llx.BoolData(v.GetIsFido()),
			"parseTestPublicId": llx.StringData(parseTestId),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogSyntheticsGlobalVariable) id() (string, error) {
	return "datadog.syntheticsGlobalVariable/" + r.Id.Data, nil
}

// --- Synthetics Private Locations ---

func (r *mqlDatadog) syntheticsPrivateLocations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV1.NewSyntheticsApi(conn.ApiClient())

	resp, httpResp, err := api.ListLocations(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> synthetics private locations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, loc := range resp.GetLocations() {
		id := loc.GetId()
		// Private locations have IDs starting with "pl:"
		if !strings.HasPrefix(id, "pl:") {
			continue
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.syntheticsPrivateLocation", map[string]*llx.RawData{
			"id":   llx.StringData(id),
			"name": llx.StringData(loc.GetName()),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogSyntheticsPrivateLocation) id() (string, error) {
	return "datadog.syntheticsPrivateLocation/" + r.Id.Data, nil
}

type mqlDatadogSyntheticsPrivateLocationInternal struct {
	fetched        atomic.Bool
	cachedDesc     string
	cachedTags     []string
	cachedMetadata map[string]any
	lock           sync.Mutex
}

func (r *mqlDatadogSyntheticsPrivateLocation) fetchDetails() error {
	if r.fetched.Load() {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return nil
	}

	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV1.NewSyntheticsApi(conn.ApiClient())

	loc, _, err := api.GetPrivateLocation(conn.AuthCtx(), r.Id.Data)
	if err != nil {
		return err
	}

	r.cachedDesc = loc.GetDescription()
	r.cachedTags = loc.GetTags()
	r.cachedMetadata = map[string]any{}
	if m, ok := loc.GetMetadataOk(); ok && m != nil {
		// Extract available metadata fields
		if v, ok := m.GetRestrictedRolesOk(); ok {
			r.cachedMetadata["restrictedRoles"] = v
		}
	}
	r.fetched.Store(true)
	return nil
}

func (r *mqlDatadogSyntheticsPrivateLocation) description() (string, error) {
	if err := r.fetchDetails(); err != nil {
		return "", err
	}
	return r.cachedDesc, nil
}

func (r *mqlDatadogSyntheticsPrivateLocation) tags() ([]any, error) {
	if err := r.fetchDetails(); err != nil {
		return nil, err
	}
	return toAnyStrings(r.cachedTags), nil
}

func (r *mqlDatadogSyntheticsPrivateLocation) metadata() (map[string]any, error) {
	if err := r.fetchDetails(); err != nil {
		return nil, err
	}
	return r.cachedMetadata, nil
}
