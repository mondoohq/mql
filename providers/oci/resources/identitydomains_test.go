// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"github.com/stretchr/testify/assert"
)

func TestOciScimNextIndex(t *testing.T) {
	tests := []struct {
		name       string
		startIndex int
		returned   int
		total      *int
		wantNext   int
		wantMore   bool
	}{
		// SCIM indexes are 1-based, so the second page of a 200-item page
		// size starts at 201, not 200.
		{"first full page of many", 1, ociScimPageSize, new(500), ociScimPageSize + 1, true},
		{"second full page of many", 201, ociScimPageSize, new(500), 401, true},

		// next > total ends the loop.
		{"last partial page", 401, 100, new(500), 0, false},
		{"exactly consumed", 1, 200, new(200), 0, false},

		// The guard that matters: an empty page always terminates. A service
		// reporting a total larger than it will actually return would
		// otherwise spin forever.
		{"empty page with a larger total", 201, 0, new(10000), 0, false},
		{"empty page with no total", 1, 0, nil, 0, false},
		{"empty first page", 1, 0, new(0), 0, false},

		// With no total reported, only a full page implies more to come.
		{"no total, full page", 1, ociScimPageSize, nil, ociScimPageSize + 1, true},
		{"no total, short page", 1, 5, nil, 0, false},

		// A single item in a single-item collection must not loop.
		{"one of one", 1, 1, new(1), 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, more := ociScimNextIndex(tt.startIndex, tt.returned, tt.total, ociScimPageSize)
			assert.Equal(t, tt.wantMore, more, "more")
			if tt.wantMore {
				assert.Equal(t, tt.wantNext, next, "next")
			}
		})
	}
}

// TestOciScimNextIndexHonorsPageSize pins the short-page heuristic to the
// pageSize argument rather than the package constant, which is the whole reason
// it is passed in.
func TestOciScimNextIndexHonorsPageSize(t *testing.T) {
	// 50 returned against a page size of 50 is a full page: more may follow.
	next, more := ociScimNextIndex(1, 50, nil, 50)
	assert.True(t, more)
	assert.Equal(t, 51, next)

	// The same 50 against a page size of 200 is a short page: the collection
	// is exhausted. Reading the constant instead of the argument would get
	// this wrong.
	_, more = ociScimNextIndex(1, 50, nil, 200)
	assert.False(t, more)
}

// TestOciScimNextIndexTerminates walks the loop the way the listers do and
// asserts it both terminates and visits every item exactly once.
func TestOciScimNextIndexTerminates(t *testing.T) {
	for _, total := range []int{0, 1, 199, 200, 201, 999, 1000} {
		t.Run(map[bool]string{true: "many", false: "few"}[total > 200], func(t *testing.T) {
			startIndex := 1
			seen := 0
			for iterations := 0; ; iterations++ {
				if iterations > 100 {
					t.Fatalf("pagination did not terminate for total=%d", total)
				}

				remaining := total - seen
				returned := min(remaining, ociScimPageSize)
				seen += returned

				next, more := ociScimNextIndex(startIndex, returned, &total, ociScimPageSize)
				if !more {
					break
				}
				startIndex = next
			}
			assert.Equal(t, total, seen, "every item visited exactly once for total=%d", total)
		})
	}
}

func TestOciPrimaryEmail(t *testing.T) {
	t.Run("no emails", func(t *testing.T) {
		value, verified := ociPrimaryEmail(nil)
		assert.Empty(t, value)
		assert.False(t, verified)
	})

	t.Run("picks the primary, not the first", func(t *testing.T) {
		value, verified := ociPrimaryEmail([]identitydomains.UserEmails{
			{Value: new("alt@example.com"), Verified: new(true)},
			{Value: new("primary@example.com"), Primary: new(true), Verified: new(true)},
		})
		assert.Equal(t, "primary@example.com", value)
		assert.True(t, verified)
	})

	t.Run("falls back to the first when none is primary", func(t *testing.T) {
		value, verified := ociPrimaryEmail([]identitydomains.UserEmails{
			{Value: new("only@example.com"), Verified: new(false)},
		})
		assert.Equal(t, "only@example.com", value)
		assert.False(t, verified)
	})

	t.Run("an unverified primary reports unverified", func(t *testing.T) {
		// The verified flag has to follow the address that was selected,
		// not the first verified address in the list.
		value, verified := ociPrimaryEmail([]identitydomains.UserEmails{
			{Value: new("alt@example.com"), Verified: new(true)},
			{Value: new("primary@example.com"), Primary: new(true)},
		})
		assert.Equal(t, "primary@example.com", value)
		assert.False(t, verified)
	})
}
