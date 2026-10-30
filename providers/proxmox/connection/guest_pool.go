// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"sync"
)

// guestPoolIndex memoizes which resource pool each guest belongs to.
//
// Pool membership is not part of a guest's config: `/nodes/<n>/qemu/<id>/config`
// has no `pool` key. The cluster resource listing carries it for every guest,
// so one read answers the question for the whole cluster instead of one read
// per guest.
type guestPoolIndex struct {
	once   sync.Once
	byVMID map[int]string
	err    error
}

type guestPoolRow struct {
	VMID int    `json:"vmid"`
	Type string `json:"type"`
	Pool string `json:"pool"`
}

// GuestPool returns the pool the guest with the given VMID belongs to, or ""
// when it is in none. VMIDs are unique across VMs and containers.
func (c *PveConnection) GuestPool(vmid int) (string, error) {
	c.guestPools.once.Do(func() {
		var rows []guestPoolRow
		if err := c.apiGet("/cluster/resources?type=vm", &rows); err != nil {
			c.guestPools.err = fmt.Errorf("failed to list guest pools: %w", err)
			return
		}
		index := make(map[int]string, len(rows))
		for _, row := range rows {
			if row.Type != "qemu" && row.Type != "lxc" {
				continue
			}
			index[row.VMID] = row.Pool
		}
		c.guestPools.byVMID = index
	})
	if c.guestPools.err != nil {
		return "", c.guestPools.err
	}
	return c.guestPools.byVMID[vmid], nil
}
