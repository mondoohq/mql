// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestGroupsToDicts(t *testing.T) {
	t.Run("maps fields and skips nil entries", func(t *testing.T) {
		groups := []*gitlab.Group{
			{
				ID:          7,
				Name:        "platform",
				FullPath:    "acme/platform",
				Visibility:  gitlab.PrivateVisibility,
				Description: "platform team",
			},
			nil, // nil entries are dropped, not mapped to a zero dict
			{
				ID:         8,
				Name:       "security",
				FullPath:   "acme/security",
				Visibility: gitlab.PublicVisibility,
			},
		}

		out := groupsToDicts(groups)
		require.Len(t, out, 2)

		first := out[0].(map[string]any)
		assert.Equal(t, int64(7), first["id"])
		assert.Equal(t, "platform", first["name"])
		assert.Equal(t, "acme/platform", first["fullPath"])
		assert.Equal(t, "private", first["visibility"])
		assert.Equal(t, "platform team", first["description"])

		second := out[1].(map[string]any)
		assert.Equal(t, int64(8), second["id"])
		assert.Equal(t, "public", second["visibility"])
		assert.Equal(t, "", second["description"])
	})

	t.Run("empty input yields empty slice", func(t *testing.T) {
		out := groupsToDicts(nil)
		assert.Empty(t, out)
	})
}

func TestNamespaceArgs(t *testing.T) {
	t.Run("nil-able fields stay unset", func(t *testing.T) {
		ns := &gitlab.Namespace{
			ID:       42,
			Name:     "engineering",
			Path:     "engineering",
			Kind:     "group",
			FullPath: "acme/engineering",
			ParentID: 1,
			WebURL:   "https://gitlab.com/groups/acme/engineering",
			Plan:     "ultimate",
			Trial:    false,
			// TrialEndsOn, MaxSeatsUsed, SeatsInUse left nil
		}

		args := namespaceArgs(ns)

		assert.Equal(t, int64(42), args["id"].Value)
		assert.Equal(t, "engineering", args["name"].Value)
		assert.Equal(t, "group", args["kind"].Value)
		assert.Equal(t, "acme/engineering", args["fullPath"].Value)
		assert.Equal(t, int64(1), args["parentId"].Value)
		assert.Equal(t, "ultimate", args["plan"].Value)
		assert.Equal(t, false, args["trial"].Value)
		assert.Nil(t, args["trialEndsOn"].Value)
		assert.Nil(t, args["maxSeatsUsed"].Value)
		assert.Nil(t, args["seatsInUse"].Value)
	})

	t.Run("pointer fields are dereferenced", func(t *testing.T) {
		trialEnd := gitlab.ISOTime(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
		maxSeats := int64(120)
		seatsInUse := int64(98)
		ns := &gitlab.Namespace{
			ID:           5,
			Name:         "trial-group",
			Trial:        true,
			TrialEndsOn:  &trialEnd,
			MaxSeatsUsed: &maxSeats,
			SeatsInUse:   &seatsInUse,
		}

		args := namespaceArgs(ns)

		assert.Equal(t, true, args["trial"].Value)
		require.NotNil(t, args["trialEndsOn"].Value)
		assert.Equal(t, time.Time(trialEnd), *(args["trialEndsOn"].Value.(*time.Time)))
		assert.Equal(t, int64(120), args["maxSeatsUsed"].Value)
		assert.Equal(t, int64(98), args["seatsInUse"].Value)
	})
}
