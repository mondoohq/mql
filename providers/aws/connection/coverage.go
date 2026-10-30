// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"sort"
	"sync"

	"github.com/rs/zerolog/log"
)

// GapReason explains why a service/region pair produced no data.
type GapReason string

const (
	// GapDenied means the caller lacked permission to make the read. The
	// resource list is empty, but empty is not the truth: there may well be
	// resources there that the scan could not see.
	GapDenied GapReason = "access denied"
	// GapFailed means the read was attempted and errored for a reason that is
	// neither a permission gap nor an absent service (a throttle, a 5xx, a
	// malformed response).
	GapFailed GapReason = "read failed"
)

// Gap is a single service/region pair the scan could not read.
type Gap struct {
	Service string
	Region  string
	Reason  GapReason
}

// coverageGaps records the reads a scan was not able to make.
//
// AWS gives a denied read and an empty account the same observable shape: a
// list accessor that returns no rows. Left at that, a policy asserting over an
// empty list passes vacuously, and a permission gap reads as a clean bill of
// health. Recording the gaps lets the scan say which answers it does not
// actually have.
type coverageGaps struct {
	mu   sync.Mutex
	gaps map[Gap]struct{}
}

func (c *coverageGaps) record(g Gap) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gaps == nil {
		c.gaps = map[Gap]struct{}{}
	}
	if _, seen := c.gaps[g]; seen {
		return
	}
	c.gaps[g] = struct{}{}
	// Warn once per unique gap. A denied read fans out across every region of
	// every service the caller cannot see, so logging per occurrence would bury
	// the signal in its own repetition.
	log.Warn().
		Str("service", g.Service).
		Str("region", g.Region).
		Str("reason", string(g.Reason)).
		Msg("no data collected; results for this service and region are incomplete")
}

func (c *coverageGaps) list() []Gap {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Gap, 0, len(c.gaps))
	for g := range c.gaps {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Region < out[j].Region
	})
	return out
}

// RecordGap notes that the scan could not read service in region, and why. It
// is safe for concurrent use and deduplicates, so callers may report the same
// gap from every lister that hits it.
func (c *AwsConnection) RecordGap(service, region string, reason GapReason) {
	c.gaps.record(Gap{Service: service, Region: region, Reason: reason})
}

// CoverageGaps returns every service/region pair this connection failed to
// read, sorted by service then region. It is the set of answers the scan does
// not have, as distinct from the answers that are genuinely empty.
func (c *AwsConnection) CoverageGaps() []Gap {
	return c.gaps.list()
}
