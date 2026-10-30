// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
	"sync"

	polardbclient "github.com/alibabacloud-go/polardb-20170801/v10/client"
	rkvclient "github.com/alibabacloud-go/r-kvstore-20150101/v8/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers/alicloud/connection"
)

// redisAuditEnabled reads the audit switch of a Redis instance, which the API
// returns as the string "true" or "false" rather than as a boolean. An absent
// or unparseable value reads as off, so an "auditing is on" check fails rather
// than passing on an instance nobody could read.
func redisAuditEnabled(dbAudit *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(dbAudit)), "true")
}

// redisAuditRetentionDays reads the audit retention window, which the API
// returns as a string. An absent or unparseable value is 0, which fails a
// minimum-retention check rather than satisfying it, matching how RDS handles
// the same shape.
func redisAuditRetentionDays(retention *string) int64 {
	value := strings.TrimSpace(tea.StringValue(retention))
	if value == "" {
		return 0
	}
	days, err := strconv.Atoi(value)
	if err != nil || days < 0 {
		return 0
	}
	return int64(days)
}

// polardbAuditCollecting reports whether a PolarDB SQL audit collector is
// recording statements now. Enabling and Disabling are transitional, and only
// Enable means statements are being recorded.
func polardbAuditCollecting(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "Enable")
}

// redisAuditState memoizes the instance's audit configuration, which both the
// enabled and the retention field read.
type redisAuditState struct {
	auditOnce sync.Once
	audit     *rkvclient.DescribeAuditLogConfigResponseBody
}

// auditLogConfig reads the instance's audit configuration once. An instance
// whose configuration cannot be read yields nil, which both fields report as
// auditing off rather than as a scan failure: one unreadable instance must not
// fail a query over the whole fleet.
func (r *mqlAlicloudRedisInstance) auditLogConfig() *rkvclient.DescribeAuditLogConfigResponseBody {
	r.auditOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RedisClient(r.region)
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach Redis to read the audit log config")
			return
		}
		resp, err := client.DescribeAuditLogConfig(&rkvclient.DescribeAuditLogConfigRequest{
			RegionId:   new(r.region),
			InstanceId: new(r.InstanceId.Data),
		})
		if err != nil {
			log.Debug().Err(err).Str("instance", r.InstanceId.Data).
				Msg("alicloud> could not read the Redis audit log config")
			return
		}
		if resp == nil {
			return
		}
		r.audit = resp.Body
	})
	return r.audit
}

func (r *mqlAlicloudRedisInstance) auditLogEnabled() (bool, error) {
	config := r.auditLogConfig()
	if config == nil {
		return false, nil
	}
	return redisAuditEnabled(config.DbAudit), nil
}

func (r *mqlAlicloudRedisInstance) auditLogRetentionDays() (int64, error) {
	config := r.auditLogConfig()
	if config == nil {
		return 0, nil
	}
	return redisAuditRetentionDays(config.Retention), nil
}

// polardbAuditState memoizes the cluster's SQL audit collector state, which
// both PolarDB audit fields read.
type polardbAuditState struct {
	auditOnce   sync.Once
	auditStatus string
}

// auditCollectorStatus reads the cluster's SQL audit collector state once. A
// cluster whose state cannot be read yields an empty status, which reads as not
// collecting.
func (r *mqlAlicloudPolardbCluster) auditCollectorStatus() string {
	r.auditOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.PolarDBClient(r.region)
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach PolarDB to read the audit collector")
			return
		}
		resp, err := client.DescribeDBClusterAuditLogCollector(&polardbclient.DescribeDBClusterAuditLogCollectorRequest{
			DBClusterId: new(r.dbClusterId),
		})
		if err != nil {
			log.Debug().Err(err).Str("cluster", r.dbClusterId).
				Msg("alicloud> could not read the PolarDB audit log collector")
			return
		}
		if resp == nil || resp.Body == nil {
			return
		}
		r.auditStatus = tea.StringValue(resp.Body.CollectorStatus)
	})
	return r.auditStatus
}

func (r *mqlAlicloudPolardbCluster) auditLogEnabled() (bool, error) {
	status := r.auditCollectorStatus()
	return polardbAuditCollecting(&status), nil
}

func (r *mqlAlicloudPolardbCluster) auditLogCollectorStatus() (string, error) {
	return r.auditCollectorStatus(), nil
}
