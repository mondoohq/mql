// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import "sync"

// cachingManager memoizes a manager's Info() so that a connection queries
// SMBIOS once rather than once per caller.
//
// The callers arrive together and there are more of them than it looks:
// clouddetect.Detect fans out to six detectors concurrently (aws, gcp, azure,
// vmware, ibm, hetzner) and every one of them resolves a manager and calls
// Info(), with the machine resource and the platform ID detectors asking again
// afterwards. Each call is a process: a PowerShell on Windows, two ioreg
// invocations on macOS, a walk of /sys/class/dmi/id on Linux, prtconf on AIX.
// Six of those in parallel is six times the work for one answer, and it lands
// during platform detection, when a busy machine can least afford it.
//
// The lock is held across the underlying query on purpose. Releasing it first
// would let all six callers miss the empty cache together and start their own
// query, which is the behaviour this type exists to prevent.
//
// Only successful results are memoized. A query that failed because the
// machine was busy or mid-boot is retried by the next caller rather than
// turning one bad moment into a permanently empty answer.
type cachingManager struct {
	inner SmBiosManager
	lock  sync.Mutex
	info  *SmBiosInfo
}

func (c *cachingManager) Name() string { return c.inner.Name() }

func (c *cachingManager) Info() (*SmBiosInfo, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.info != nil {
		return c.info, nil
	}

	info, err := c.inner.Info()
	if err != nil {
		return nil, err
	}

	c.info = info
	return c.info, nil
}
