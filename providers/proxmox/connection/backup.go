// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "fmt"

// BackupJob describes a cluster-wide scheduled vzdump job from /cluster/backup.
//
// Flags decode through PveBool, since Proxmox declares them boolean but writes
// 1/0 (and a legacy vzdump.cron job reports a disabled schedule as ""). The
// retention and fleecing settings decode through PveProps: the listing
// returns them as objects, not the property strings they are written as.
type BackupJob struct {
	ID string `json:"id"`
	// Enabled is a pointer because the key defaults to enabled when absent.
	Enabled          *PveBool `json:"enabled"`
	Schedule         string   `json:"schedule"`
	Storage          string   `json:"storage"`
	Mode             string   `json:"mode"`
	Comment          string   `json:"comment"`
	VMID             string   `json:"vmid"`
	Pool             string   `json:"pool"`
	All              PveBool  `json:"all"`
	Exclude          string   `json:"exclude"`
	Compress         string   `json:"compress"`
	Mailto           string   `json:"mailto"`
	NotificationMode string   `json:"notification-mode"`
	Node             string   `json:"node"`
	Prune            PveProps `json:"prune-backups"`
	Fleecing         PveProps `json:"fleecing"`
	NotesTemplate    string   `json:"notes-template"`
	Protected        PveBool  `json:"protected"`
	NextRun          int64    `json:"next-run"`
	Type             string   `json:"type"`
	Repeat           PveBool  `json:"repeat-missed"`
	Remove           PveBool  `json:"remove"`
}

// IsEnabled reports whether the job runs. Proxmox treats a job without an
// `enabled` key as enabled.
func (j BackupJob) IsEnabled() bool {
	return j.Enabled == nil || j.Enabled.Bool()
}

func (c *PveConnection) GetBackupJobs() ([]BackupJob, error) {
	var jobs []BackupJob
	if err := c.apiGet("/cluster/backup", &jobs); err != nil {
		return nil, fmt.Errorf("failed to get backup jobs: %w", err)
	}
	return jobs, nil
}

// GetBackupJob returns the full raw config for a specific backup job, used
// to expose less-common fields via the `config` dict on the resource.
func (c *PveConnection) GetBackupJob(id string) (map[string]any, error) {
	var cfg map[string]any
	path := fmt.Sprintf("/cluster/backup/%s", id)
	if err := c.apiGet(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to get backup job %s: %w", id, err)
	}
	return cfg, nil
}
