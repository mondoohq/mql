// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "fmt"

// ReplicationJob describes a guest-storage replication job from
// /cluster/replication. The job `id` has the form `<vmid>-<jobnum>`.
type ReplicationJob struct {
	ID       string `json:"id"`
	VMID     int    `json:"guest"`
	Schedule string `json:"schedule"`
	Source   string `json:"source"` // node name
	Target   string `json:"target"` // node name
	Type     string `json:"type"`   // local
	Comment  string `json:"comment"`
	// Rate is MB/s and may be fractional; 0 = unlimited.
	Rate      PveNumber `json:"rate"`
	Disable   int       `json:"disable"`
	RemoveJob string    `json:"remove_job"`
}

func (c *PveConnection) GetReplicationJobs() ([]ReplicationJob, error) {
	var jobs []ReplicationJob
	if err := c.apiGet("/cluster/replication", &jobs); err != nil {
		return nil, fmt.Errorf("failed to get replication jobs: %w", err)
	}
	return jobs, nil
}
