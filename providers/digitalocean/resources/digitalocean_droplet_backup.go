// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// dropletBackupPolicy is the normalized automated-backup schedule for one
// droplet. weekday is empty on the daily plan, where DigitalOcean returns no
// day of the week.
type dropletBackupPolicy struct {
	plan                string
	weekday             string
	hour                int64
	windowLengthHours   int64
	retentionPeriodDays int64
}

// indexBackupPolicies normalizes one page of the account-wide backup-policy
// response and adds it to the given index.
//
// Droplets whose backups are disabled come back with no schedule attached.
// They are left out of the index entirely rather than stored as a zero value,
// so their fields resolve to null. Storing zeros instead would report a
// never-configured droplet as having a zero-day retention policy.
func indexBackupPolicies(policies map[int]*godo.DropletBackupPolicy, into map[int64]dropletBackupPolicy) {
	for id, p := range policies {
		if p == nil || p.BackupPolicy == nil {
			continue
		}
		into[int64(id)] = dropletBackupPolicy{
			plan:                p.BackupPolicy.Plan,
			weekday:             p.BackupPolicy.Weekday,
			hour:                int64(p.BackupPolicy.Hour),
			windowLengthHours:   int64(p.BackupPolicy.WindowLengthHours),
			retentionPeriodDays: int64(p.BackupPolicy.RetentionPeriodDays),
		}
	}
}

// backupPolicyByDropletID resolves a droplet's backup schedule from an
// account-wide index, returning nil when the droplet has no policy.
//
// DigitalOcean exposes both a per-droplet policy endpoint and an account-wide
// one. Reading the account-wide list once and indexing it keeps a query over
// every droplet at a single (paginated) call instead of one call per droplet.
func (r *mqlDigitalocean) backupPolicyByDropletID(dropletID int64) (*dropletBackupPolicy, error) {
	r.backupPolicyIndexOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
		client := conn.Client()

		idx := map[int64]dropletBackupPolicy{}
		opt := &godo.ListOptions{PerPage: 200}
		for {
			policies, resp, err := client.Droplets.ListBackupPolicies(context.Background(), opt)
			if err != nil {
				r.backupPolicyIndexErr = err
				return
			}
			indexBackupPolicies(policies, idx)
			if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
				break
			}
			page, err := resp.Links.CurrentPage()
			if err != nil {
				r.backupPolicyIndexErr = err
				return
			}
			opt.Page = page + 1
		}
		r.backupPolicyIndex = idx
	})
	if r.backupPolicyIndexErr != nil {
		return nil, r.backupPolicyIndexErr
	}
	policy, ok := r.backupPolicyIndex[dropletID]
	if !ok {
		return nil, nil
	}
	return &policy, nil
}

// backupPolicy fetches this droplet's schedule from the parent's index. All
// five backup* accessors share it, so the account-wide list is read once no
// matter how many of them a query touches.
func (r *mqlDigitaloceanDroplet) backupPolicy() (*dropletBackupPolicy, error) {
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return parent.backupPolicyByDropletID(r.Id.Data)
}

func (r *mqlDigitaloceanDroplet) backupPlan() (string, error) {
	policy, err := r.backupPolicy()
	if err != nil {
		return "", err
	}
	if policy == nil {
		r.BackupPlan.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return policy.plan, nil
}

// backupWeekday resolves to null on the daily plan, which has no day of the
// week, so `where(backupWeekday != null)` selects the weekly-plan droplets.
func (r *mqlDigitaloceanDroplet) backupWeekday() (string, error) {
	policy, err := r.backupPolicy()
	if err != nil {
		return "", err
	}
	if policy == nil || policy.weekday == "" {
		r.BackupWeekday.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return policy.weekday, nil
}

func (r *mqlDigitaloceanDroplet) backupHour() (int64, error) {
	policy, err := r.backupPolicy()
	if err != nil {
		return 0, err
	}
	if policy == nil {
		r.BackupHour.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return policy.hour, nil
}

func (r *mqlDigitaloceanDroplet) backupWindowLengthHours() (int64, error) {
	policy, err := r.backupPolicy()
	if err != nil {
		return 0, err
	}
	if policy == nil {
		r.BackupWindowLengthHours.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return policy.windowLengthHours, nil
}

func (r *mqlDigitaloceanDroplet) backupRetentionPeriodDays() (int64, error) {
	policy, err := r.backupPolicy()
	if err != nil {
		return 0, err
	}
	if policy == nil {
		r.BackupRetentionPeriodDays.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return policy.retentionPeriodDays, nil
}
