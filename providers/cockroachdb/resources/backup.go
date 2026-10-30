// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
)

type mqlCockroachdbBackupScheduleInternal struct {
	cacheOwner string
}

// encryptedBackupOption matches the BACKUP options that encrypt a backup.
var encryptedBackupOption = regexp.MustCompile(`(?i)\b(encryption_passphrase|kms)\s*=`)

// isEncryptedBackup reports whether a BACKUP statement writes encrypted
// backups.
func isEncryptedBackup(statement string) bool {
	return encryptedBackupOption.MatchString(statement)
}

func (r *mqlCockroachdbCluster) backupSchedules() ([]any, error) {
	rows, err := query(r.MqlRuntime, `SELECT id, label, schedule_status, recurrence, owner,
		command->>'backup_statement', next_run, created
		FROM [SHOW SCHEDULES] WHERE command->>'backup_statement' IS NOT NULL ORDER BY id`)
	if err != nil {
		return nil, refused(err, "admin role (SELECT ON system.scheduled_jobs)")
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var id int64
		var label, status, recurrence, owner, statement string
		var nextRun, created *time.Time
		if err := rows.Scan(&id, &label, &status, &recurrence, &owner, &statement, &nextRun, &created); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.backupSchedule", map[string]*llx.RawData{
			"__id":       llx.StringData("cockroachdb.backupSchedule/" + strconv.FormatInt(id, 10)),
			"id":         llx.StringData(strconv.FormatInt(id, 10)),
			"label":      llx.StringData(label),
			"status":     llx.StringData(status),
			"recurrence": llx.StringData(recurrence),
			"statement":  llx.StringData(statement),
			"encrypted":  llx.BoolData(isEncryptedBackup(statement)),
			"nextRun":    llx.TimeDataPtr(utc(nextRun)),
			"createdAt":  llx.TimeDataPtr(utc(created)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlCockroachdbBackupSchedule).cacheOwner = owner
		list = append(list, res)
	}
	if err := rows.Err(); err != nil {
		return nil, refused(err, "admin role (SELECT ON system.scheduled_jobs)")
	}
	return list, nil
}

func (r *mqlCockroachdbBackupSchedule) owner() (*mqlCockroachdbRole, error) {
	return resolveRole(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

// utc returns t in UTC, or nil for nil.
func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
