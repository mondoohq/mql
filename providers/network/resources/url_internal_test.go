// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func parseRawURL(t *testing.T, raw string) map[string]*llx.RawData {
	t.Helper()

	args, res, err := initUrl(nil, map[string]*llx.RawData{"raw": llx.StringData(raw)})
	require.NoError(t, err)
	require.Nil(t, res)
	return args
}

func TestInitUrlParsesTheQuery(t *testing.T) {
	// query was never populated, so every read of it reached the runtime unset
	// and the scan reported a provider bug instead of a value.
	t.Run("splits the query into its parameters", func(t *testing.T) {
		args := parseRawURL(t, "https://example.com/a?x=1&y=two")

		require.Contains(t, args, "query")
		assert.Equal(t, map[string]any{"x": "1", "y": "two"}, args["query"].Value)
	})

	t.Run("is empty rather than absent when there is no query", func(t *testing.T) {
		args := parseRawURL(t, "https://example.com/a")

		require.Contains(t, args, "query")
		assert.Equal(t, map[string]any{}, args["query"].Value)
	})

	t.Run("keeps the first of a repeated parameter", func(t *testing.T) {
		// The field is a map and cannot hold both. First is what
		// url.Values.Get returns and what most servers read.
		args := parseRawURL(t, "https://example.com/a?x=1&x=2")
		assert.Equal(t, map[string]any{"x": "1"}, args["query"].Value)
	})

	t.Run("decodes percent-encoded parameters", func(t *testing.T) {
		args := parseRawURL(t, "https://example.com/a?path=%2Fetc%2Fpasswd")
		assert.Equal(t, map[string]any{"path": "/etc/passwd"}, args["query"].Value)
	})

	t.Run("keeps rawQuery as sent", func(t *testing.T) {
		args := parseRawURL(t, "https://example.com/a?x=1&y=two")
		assert.Equal(t, "x=1&y=two", args["rawQuery"].Value)
	})
}

func TestInitUrlParsesTheFragment(t *testing.T) {
	t.Run("reports an ordinary fragment", func(t *testing.T) {
		// Go fills RawFragment only when the escaping is non-canonical, so this
		// used to come back empty.
		args := parseRawURL(t, "https://example.com/a#section")
		assert.Equal(t, "section", args["rawFragment"].Value)
	})

	t.Run("keeps unusual escaping as sent", func(t *testing.T) {
		args := parseRawURL(t, "https://example.com/a#frag%2Fx")
		assert.Equal(t, "frag%2Fx", args["rawFragment"].Value)
	})

	t.Run("is empty when there is no fragment", func(t *testing.T) {
		args := parseRawURL(t, "https://example.com/a")
		assert.Equal(t, "", args["rawFragment"].Value)
	})
}

func urlFromArgs(args map[string]*llx.RawData) *mqlUrl {
	str := func(key string) plugin.TValue[string] {
		if v, ok := args[key]; ok {
			s, _ := v.Value.(string)
			return plugin.TValue[string]{Data: s, State: plugin.StateIsSet}
		}
		return plugin.TValue[string]{State: plugin.StateIsSet}
	}
	num := func(key string) plugin.TValue[int64] {
		if v, ok := args[key]; ok {
			n, _ := v.Value.(int64)
			return plugin.TValue[int64]{Data: n, State: plugin.StateIsSet}
		}
		return plugin.TValue[int64]{State: plugin.StateIsSet}
	}

	return &mqlUrl{
		Scheme:      str("scheme"),
		User:        str("user"),
		Password:    str("password"),
		Host:        str("host"),
		Port:        num("port"),
		Path:        str("path"),
		RawQuery:    str("rawQuery"),
		RawFragment: str("rawFragment"),
	}
}

func TestUrlStringRoundTrip(t *testing.T) {
	// The fragment was rendered from RawFragment alone, which URL.String only
	// honors when it agrees with Fragment - so it was dropped from the
	// reassembled URL in every case, escaped or not.
	for _, raw := range []string{
		"https://example.com/a#section",
		"https://example.com/a#frag%2Fx",
		"https://example.com/a?x=1&y=two#section",
		"https://user:pass@example.com:8443/a/b?x=1#f",
		"https://example.com/a",
		"http://example.com",
	} {
		t.Run(raw, func(t *testing.T) {
			args := parseRawURL(t, raw)
			got, err := urlFromArgs(args).string()
			require.NoError(t, err)
			assert.Equal(t, raw, got)
		})
	}
}
