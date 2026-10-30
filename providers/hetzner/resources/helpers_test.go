// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestTranslateHcloudError(t *testing.T) {
	t.Run("nil passes through", func(t *testing.T) {
		assert.NoError(t, translateHcloudError(nil))
	})

	// A refused read establishes nothing about what exists. Swallowing it
	// would report an empty list, which asserts the project holds none of the
	// resource, and every audit over that list would pass without reading
	// anything.
	t.Run("unauthorized propagates", func(t *testing.T) {
		err := hcloud.Error{Code: hcloud.ErrorCodeUnauthorized, Message: "bad token"}
		assert.Error(t, translateHcloudError(err))
	})

	t.Run("forbidden propagates", func(t *testing.T) {
		err := hcloud.Error{Code: hcloud.ErrorCodeForbidden, Message: "no access"}
		assert.Error(t, translateHcloudError(err))
	})

	// A collection endpoint answering 404 means the product is not provisioned
	// for the project, which genuinely is none.
	t.Run("not found is an empty collection", func(t *testing.T) {
		err := hcloud.Error{Code: hcloud.ErrorCodeNotFound, Message: "gone"}
		assert.NoError(t, translateHcloudError(err))
	})

	t.Run("rate limit propagates", func(t *testing.T) {
		err := hcloud.Error{Code: hcloud.ErrorCodeRateLimitExceeded, Message: "slow down"}
		assert.Error(t, translateHcloudError(err))
	})

	t.Run("non-hcloud error propagates", func(t *testing.T) {
		err := errors.New("network down")
		assert.Equal(t, err, translateHcloudError(err))
	})

	t.Run("wrapped hcloud error is still classified", func(t *testing.T) {
		// errors.As must unwrap through wrapping, so a wrapped denial is
		// recognised as a denial and propagates like a bare one.
		inner := hcloud.Error{Code: hcloud.ErrorCodeUnauthorized}
		wrapped := errors.Join(errors.New("context"), inner)
		assert.Error(t, translateHcloudError(wrapped))
	})

	t.Run("wrapped not found is still an empty collection", func(t *testing.T) {
		inner := hcloud.Error{Code: hcloud.ErrorCodeNotFound}
		wrapped := errors.Join(errors.New("context"), inner)
		assert.NoError(t, translateHcloudError(wrapped))
	})
}

func TestPaginate(t *testing.T) {
	t.Run("single page no pagination meta breaks", func(t *testing.T) {
		out, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			return []int{1, 2, 3}, &hcloud.Response{}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []int{1, 2, 3}, out)
	})

	t.Run("walks multiple pages until NextPage is zero", func(t *testing.T) {
		pages := []struct {
			items []int
			next  int
		}{
			{[]int{1, 2}, 2},
			{[]int{3, 4}, 3},
			{[]int{5}, 0},
		}
		idx := 0
		var seenPages []int
		out, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			seenPages = append(seenPages, opts.Page)
			p := pages[idx]
			idx++
			return p.items, &hcloud.Response{
				Meta: hcloud.Meta{
					Pagination: &hcloud.Pagination{NextPage: p.next},
				},
			}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []int{1, 2, 3, 4, 5}, out)
		assert.Equal(t, []int{1, 2, 3}, seenPages)
	})

	t.Run("starts at page 1 with PerPage 50", func(t *testing.T) {
		var seen hcloud.ListOpts
		_, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			seen = opts
			return nil, &hcloud.Response{}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, seen.Page)
		assert.Equal(t, 50, seen.PerPage)
	})

	t.Run("propagates non-permission errors", func(t *testing.T) {
		want := errors.New("connection refused")
		_, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			return nil, nil, want
		})
		assert.ErrorIs(t, err, want)
	})

	t.Run("an auth error mid-stream fails rather than truncating", func(t *testing.T) {
		// Returning the rows gathered so far would present a partial list as
		// a complete one, which reads as "the project holds only these".
		calls := 0
		out, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			calls++
			if calls == 1 {
				return []int{1, 2}, &hcloud.Response{
					Meta: hcloud.Meta{Pagination: &hcloud.Pagination{NextPage: 2}},
				}, nil
			}
			return nil, nil, hcloud.Error{Code: hcloud.ErrorCodeForbidden}
		})
		assert.Error(t, err)
		assert.Nil(t, out)
	})

	t.Run("a collection absent from the start is empty", func(t *testing.T) {
		// The product is not provisioned for this project, which is a real
		// answer. Storage Boxes behave this way on a plain cloud project.
		out, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			return nil, nil, hcloud.Error{Code: hcloud.ErrorCodeNotFound}
		})
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("a collection that vanishes mid-walk is not a short list", func(t *testing.T) {
		// Pages were read, so the collection existed. Returning only those
		// would present a truncated list as the complete one.
		calls := 0
		out, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			calls++
			if calls == 1 {
				return []int{1, 2}, &hcloud.Response{
					Meta: hcloud.Meta{Pagination: &hcloud.Pagination{NextPage: 2}},
				}, nil
			}
			return nil, nil, hcloud.Error{Code: hcloud.ErrorCodeNotFound}
		})
		assert.Error(t, err)
		assert.Nil(t, out)
	})

	t.Run("nil response terminates loop", func(t *testing.T) {
		out, err := paginate(func(opts hcloud.ListOpts) ([]int, *hcloud.Response, error) {
			return []int{7}, nil, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []int{7}, out)
	})
}

func TestLabelMap(t *testing.T) {
	t.Run("nil yields empty map (never nil)", func(t *testing.T) {
		got := labelMap(nil)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("converts string values", func(t *testing.T) {
		got := labelMap(map[string]string{"env": "prod", "team": "platform"})
		assert.Equal(t, map[string]any{"env": "prod", "team": "platform"}, got)
	})
}

func TestStringMapAny(t *testing.T) {
	assert.Equal(t, map[string]any{}, stringMapAny(nil))
	assert.Equal(t, map[string]any{"a": "1"}, stringMapAny(map[string]string{"a": "1"}))
}

func TestStringSlice(t *testing.T) {
	assert.Equal(t, []any{}, stringSlice(nil))
	assert.Equal(t, []any{"a", "b"}, stringSlice([]string{"a", "b"}))
}

func TestIpString(t *testing.T) {
	assert.Equal(t, "", ipString(nil))
	assert.Equal(t, "1.2.3.4", ipString(net.ParseIP("1.2.3.4")))
}

func TestIpNetString(t *testing.T) {
	assert.Equal(t, "", ipNetString(nil))
	_, ipnet, err := net.ParseCIDR("10.0.0.0/16")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/16", ipNetString(ipnet))
}

func TestTimePtr(t *testing.T) {
	t.Run("zero time returns nil", func(t *testing.T) {
		assert.Nil(t, timePtr(time.Time{}))
	})
	t.Run("non-zero returns pointer", func(t *testing.T) {
		now := time.Now()
		got := timePtr(now)
		require.NotNil(t, got)
		assert.True(t, now.Equal(*got))
	})
}

func TestTimePtrUnix0(t *testing.T) {
	t.Run("zero time returns nil", func(t *testing.T) {
		assert.Nil(t, timePtrUnix0(time.Time{}))
	})
	t.Run("Unix(0,0) returns nil", func(t *testing.T) {
		// hcloud's DeprecatableResource.UnavailableAfter() returns Unix(0,0)
		// for non-deprecated resources; treat that as "unset".
		assert.Nil(t, timePtrUnix0(time.Unix(0, 0)))
	})
	t.Run("real timestamp returns pointer", func(t *testing.T) {
		ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		got := timePtrUnix0(ts)
		require.NotNil(t, got)
		assert.True(t, ts.Equal(*got))
	})
}

func TestDnsPtrSliceFromMap(t *testing.T) {
	t.Run("empty map yields non-nil empty slice", func(t *testing.T) {
		got := dnsPtrSliceFromMap(nil)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("entries become {ip, dnsPtr} dicts", func(t *testing.T) {
		got := dnsPtrSliceFromMap(map[string]string{
			"2001:db8::1": "host1.example.",
		})
		require.Len(t, got, 1)
		entry, ok := got[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "2001:db8::1", entry["ip"])
		assert.Equal(t, "host1.example.", entry["dnsPtr"])
	})
}

func TestProtectionDict(t *testing.T) {
	assert.Equal(t, map[string]any{"delete": true}, protectionDict(true))
	assert.Equal(t, map[string]any{"delete": false}, protectionDict(false))
}

func TestProtectionDictRebuild(t *testing.T) {
	assert.Equal(t, map[string]any{"delete": true, "rebuild": false},
		protectionDictRebuild(true, false))
}

func TestIdArg(t *testing.T) {
	t.Run("missing key returns false", func(t *testing.T) {
		_, ok := idArg(map[string]*llx.RawData{}, "id")
		assert.False(t, ok)
	})

	t.Run("nil value returns false", func(t *testing.T) {
		_, ok := idArg(map[string]*llx.RawData{"id": nil}, "id")
		assert.False(t, ok)
	})

	t.Run("wrong type returns false", func(t *testing.T) {
		_, ok := idArg(map[string]*llx.RawData{"id": llx.StringData("123")}, "id")
		assert.False(t, ok)
	})

	t.Run("int64 returns value", func(t *testing.T) {
		got, ok := idArg(map[string]*llx.RawData{"id": llx.IntData(42)}, "id")
		assert.True(t, ok)
		assert.EqualValues(t, 42, got)
	})
}

func TestNotFoundErr(t *testing.T) {
	err := notFoundErr("server", 12345)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server")
	assert.Contains(t, err.Error(), "12345")
}
