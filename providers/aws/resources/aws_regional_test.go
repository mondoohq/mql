// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/aws/connection"
)

// testConn builds a connection pinned to an explicit region list. Regions()
// short-circuits on the region filter, so nothing here touches the network.
func testConn(regions ...string) *connection.AwsConnection {
	return &connection.AwsConnection{
		Filters: connection.DiscoveryFilters{
			General: connection.GeneralDiscoveryFilters{Regions: regions},
		},
	}
}

func TestPerRegionCollectsEveryRegion(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1", "ap-south-1")

	got, err := perRegion(conn, "ecr", func(_ context.Context, region string) ([]any, error) {
		return []any{region}, nil
	})

	require.NoError(t, err)
	strs := toStrings(got)
	sort.Strings(strs)
	require.Equal(t, []string{"ap-south-1", "eu-west-1", "us-east-1"}, strs)
	require.Empty(t, conn.CoverageGaps())
}

// An empty account must produce an empty list, never a nil one: a nil slice
// renders differently to MQL than the empty result it is meant to represent.
func TestPerRegionReturnsEmptySliceNotNil(t *testing.T) {
	conn := testConn("us-east-1")

	got, err := perRegion(conn, "ecr", func(_ context.Context, _ string) ([]any, error) {
		return nil, nil
	})

	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)
}

// A region where the service simply is not deployed contributes nothing and is
// not a failure, and it is not a coverage gap either: empty is the truth there.
func TestPerRegionAbsentServiceIsSilent(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1")

	got, err := perRegion(conn, "bedrock", func(_ context.Context, region string) ([]any, error) {
		if region == "eu-west-1" {
			return nil, errors.New("could not resolve endpoint")
		}
		return []any{region}, nil
	})

	require.NoError(t, err)
	require.Equal(t, []string{"us-east-1"}, toStrings(got))
	require.Empty(t, conn.CoverageGaps(), "an absent service is not a coverage gap")
}

// The case this whole change exists for: a denied read still yields an empty
// list, but it is recorded so the run can say the answer is incomplete.
func TestPerRegionDeniedReadIsRecordedAsGap(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1")

	got, err := perRegion(conn, "macie2", func(_ context.Context, region string) ([]any, error) {
		if region == "eu-west-1" {
			return nil, apiErr("AccessDeniedException", "not authorized to perform macie2:ListFindings")
		}
		return []any{region}, nil
	})

	require.NoError(t, err)
	require.Equal(t, []string{"us-east-1"}, toStrings(got))

	gaps := conn.CoverageGaps()
	require.Len(t, gaps, 1)
	require.Equal(t, connection.Gap{Service: "macie2", Region: "eu-west-1", Reason: connection.GapDenied}, gaps[0])
}

// A gap from a scoped classification key is reported under the bare service.
func TestPerRegionGapUsesBareServiceName(t *testing.T) {
	conn := testConn("us-east-1")

	_, err := perRegion(conn, "macie2/config", func(_ context.Context, _ string) ([]any, error) {
		return nil, apiErr("AccessDeniedException", "not authorized to perform macie2:GetMacieSession")
	})

	require.NoError(t, err)
	gaps := conn.CoverageGaps()
	require.Len(t, gaps, 1)
	require.Equal(t, "macie2", gaps[0].Service, "gaps are reported per service, not per endpoint scope")
}

// One bad region must not discard the regions that answered. This is the
// behaviour change from the old fan-out, which returned the error and dropped
// every collected result.
func TestPerRegionKeepsPartialResults(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1", "ap-south-1")

	got, err := perRegion(conn, "rds", func(_ context.Context, region string) ([]any, error) {
		if region == "eu-west-1" {
			return nil, apiErr("ThrottlingException", "Rate exceeded")
		}
		return []any{region}, nil
	})

	require.NoError(t, err, "a single failed region must not fail the whole listing")
	strs := toStrings(got)
	sort.Strings(strs)
	require.Equal(t, []string{"ap-south-1", "us-east-1"}, strs)

	gaps := conn.CoverageGaps()
	require.Len(t, gaps, 1)
	require.Equal(t, connection.GapFailed, gaps[0].Reason)
}

// If nothing worked anywhere, the caller learned nothing and must be told,
// rather than handed an empty list that reads as "no resources".
func TestPerRegionAllRegionsFailedReturnsError(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1")

	got, err := perRegion(conn, "rds", func(_ context.Context, _ string) ([]any, error) {
		return nil, apiErr("ThrottlingException", "Rate exceeded")
	})

	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "rds")
}

// Every region being denied is still an empty list, not an error: the account
// may genuinely have nothing, and we cannot tell. The gaps are what carry the
// warning.
func TestPerRegionAllRegionsDeniedIsEmptyWithGaps(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1")

	got, err := perRegion(conn, "ecr", func(_ context.Context, _ string) ([]any, error) {
		return nil, apiErr("AccessDenied", "denied")
	})

	require.NoError(t, err)
	require.Empty(t, got)
	require.Len(t, conn.CoverageGaps(), 2)
}

// A panic in one region's mapping code must cost that region, not the scan.
func TestPerRegionRecoversPanic(t *testing.T) {
	conn := testConn("us-east-1", "eu-west-1")

	got, err := perRegion(conn, "ecr", func(_ context.Context, region string) ([]any, error) {
		if region == "eu-west-1" {
			var typed []any
			_ = typed[3] // index out of range
		}
		return []any{region}, nil
	})

	require.NoError(t, err)
	require.Equal(t, []string{"us-east-1"}, toStrings(got))
	require.Len(t, conn.CoverageGaps(), 1)
}

func TestPerRegionRespectsConcurrencyLimit(t *testing.T) {
	regions := make([]string, 40)
	for i := range regions {
		regions[i] = string(rune('a' + i%26))
	}
	conn := testConn(regions...)

	var inFlight, peak int64
	var mu sync.Mutex

	_, err := perRegion(conn, "ecr", func(_ context.Context, region string) ([]any, error) {
		cur := atomic.AddInt64(&inFlight, 1)
		mu.Lock()
		if cur > peak {
			peak = cur
		}
		mu.Unlock()
		defer atomic.AddInt64(&inFlight, -1)
		return []any{region}, nil
	})

	require.NoError(t, err)
	require.LessOrEqual(t, peak, int64(regionalConcurrency))
}

// Gaps are recorded from concurrent goroutines and deduplicated.
func TestCoverageGapsDeduplicate(t *testing.T) {
	conn := testConn("us-east-1")
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			conn.RecordGap("ecr", "us-east-1", connection.GapDenied)
		})
	}
	wg.Wait()
	require.Len(t, conn.CoverageGaps(), 1)
}

func toStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, v.(string))
	}
	return out
}
