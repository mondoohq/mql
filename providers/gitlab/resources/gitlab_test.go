// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

func TestValueOrNull(t *testing.T) {
	// Synthetic: an attribute GitLab omitted, and one it reported as false.
	var field plugin.TValue[bool]
	assert.False(t, valueOrNull(&field, nil))
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State, "an omitted attribute must read null, not false")

	var reportedFalse plugin.TValue[bool]
	f := false
	assert.False(t, valueOrNull(&reportedFalse, &f))
	assert.Equal(t, plugin.State(0), reportedFalse.State&plugin.StateIsNull, "a reported false must not be marked null")

	var str plugin.TValue[string]
	v := "maintainer"
	assert.Equal(t, "maintainer", valueOrNull(&str, &v))
}

func TestReportedDistinguishesNullFromAbsent(t *testing.T) {
	// Synthetic: the three shapes GitLab can send for a nullable attribute.
	var out struct {
		Value reported[string] `json:"value"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{}`), &out))
	assert.False(t, out.Value.Set, "an absent attribute is not set")
	assert.Nil(t, out.Value.Value)

	out.Value = reported[string]{}
	require.NoError(t, json.Unmarshal([]byte(`{"value": null}`), &out))
	assert.True(t, out.Value.Set, "an explicit null is set")
	assert.Nil(t, out.Value.Value)

	out.Value = reported[string]{}
	require.NoError(t, json.Unmarshal([]byte(`{"value": "ci/main.yml"}`), &out))
	assert.True(t, out.Value.Set)
	require.NotNil(t, out.Value.Value)
	assert.Equal(t, "ci/main.yml", *out.Value.Value)

	assert.Error(t, json.Unmarshal([]byte(`{"value": 5}`), &out), "a value of the wrong type must not decode silently")
}

func TestStringsOrNull(t *testing.T) {
	// Synthetic: an unreported list, an empty list, and a populated one.
	assert.Nil(t, stringsOrNull(nil).Value, "an unreported list must read null")
	assert.Equal(t, []any{}, stringsOrNull([]string{}).Value, "an empty list must stay an empty list")
	assert.Equal(t, []any{"group", "project"}, stringsOrNull([]string{"group", "project"}).Value)
}

func TestSplitCommaList(t *testing.T) {
	// Synthetic: globally_allowed_ips is a comma-separated string.
	assert.Equal(t, []string{}, splitCommaList(""))
	assert.Equal(t, []string{"10.0.0.0/8"}, splitCommaList("10.0.0.0/8"))
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.1.1", "2001:db8::/32"}, splitCommaList(" 10.0.0.0/8, 192.168.1.1 ,,2001:db8::/32,"))
}

// withStructuredErrors switches the structured-errors feature for one test and
// switches it off again afterwards.
func withStructuredErrors(t *testing.T, on bool) {
	t.Helper()
	features := mql.Features{byte(mql.ResourceContext)}
	if on {
		features = append(features, byte(mql.StructuredErrors))
	}
	plugin.ReadFeatures([]byte(features))
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
}

// statusError returns the error the SDK produces for an HTTP status, read
// through a real client so the classifier sees what it sees in production.
func statusError(t *testing.T, status int) error {
	t.Helper()
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"message":"%d"}`, status)
	}))
	var out json.RawMessage
	_, err := getRawJSON(client, "projects/1/environments", nil, &out)
	require.Error(t, err)
	return err
}

func TestGatedError(t *testing.T) {
	// Synthetic: status codes GitLab documents for unlicensed (404) and
	// under-privileged (403) callers; no target was read.
	t.Run("404 reads as no data", func(t *testing.T) {
		withStructuredErrors(t, true)
		assert.NoError(t, gatedError(statusError(t, http.StatusNotFound)))
	})

	t.Run("403 is a classified refusal with structured errors", func(t *testing.T) {
		withStructuredErrors(t, true)
		err := gatedError(statusError(t, http.StatusForbidden))
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
	})

	t.Run("403 reads as no data without structured errors", func(t *testing.T) {
		withStructuredErrors(t, false)
		assert.NoError(t, gatedError(statusError(t, http.StatusForbidden)))
	})

	t.Run("other failures pass through unclassified", func(t *testing.T) {
		withStructuredErrors(t, true)
		original := statusError(t, http.StatusInternalServerError)
		err := gatedError(original)
		assert.Same(t, original, err)

		transport := errors.New("connection refused")
		assert.Same(t, transport, gatedError(transport))
	})

	t.Run("no error stays no error", func(t *testing.T) {
		assert.NoError(t, gatedError(nil))
	})
}

func TestCollectPages(t *testing.T) {
	// Synthetic: page walks driven by the X-Next-Page header GitLab sends.
	response := func(next int64) *gitlab.Response { return &gitlab.Response{NextPage: next} }

	t.Run("walks every page in order", func(t *testing.T) {
		var asked []int64
		got, err := collectPages(func(page int64) ([]int64, *gitlab.Response, error) {
			asked = append(asked, page)
			next := page + 1
			if page == 3 {
				next = 0
			}
			return []int64{page * 10}, response(next), nil
		})
		require.NoError(t, err)
		assert.Equal(t, []int64{1, 2, 3}, asked)
		assert.Equal(t, []int64{10, 20, 30}, got)
	})

	t.Run("stops on a page number that does not advance", func(t *testing.T) {
		calls := 0
		got, err := collectPages(func(page int64) ([]int64, *gitlab.Response, error) {
			calls++
			return []int64{page}, response(2), nil
		})
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
		assert.Equal(t, []int64{1, 2}, got)
	})

	t.Run("returns the error and nothing else", func(t *testing.T) {
		boom := errors.New("boom")
		got, err := collectPages(func(page int64) ([]int64, *gitlab.Response, error) {
			if page == 2 {
				return nil, nil, boom
			}
			return []int64{page}, response(2), nil
		})
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, got, "a partial walk must not read as the full collection")
	})
}
