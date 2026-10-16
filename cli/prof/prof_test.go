// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package prof

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("no options provided", func(t *testing.T) {
		{
			opts, err := parseProf("")
			require.NoError(t, err)
			require.Equal(t, defaultOpts, opts)
		}

		{
			opts, err := parseProf("     ")
			require.NoError(t, err)
			require.Equal(t, defaultOpts, opts)
		}

		{
			opts, err := parseProf(" , ,,,   ")
			require.NoError(t, err)
			require.Equal(t, defaultOpts, opts)
		}
	})

	t.Run("enable", func(t *testing.T) {
		{
			expected := defaultOpts
			expected.Enabled = true

			opts, err := parseProf("enable")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts
			expected.Enabled = true

			opts, err := parseProf("enable=true")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts

			opts, err := parseProf("enable=truce")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		{
			expected := defaultOpts
			expected.Enabled = true

			opts, err := parseProf("enabled")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts
			expected.Enabled = true

			opts, err := parseProf("enabled=true")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts

			opts, err := parseProf("enabled=truce")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}
	})

	t.Run("listen", func(t *testing.T) {
		{
			expected := defaultOpts

			opts, err := parseProf("listen")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts

			opts, err := parseProf("listen=")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts
			expected.Listen = "localhost:7474"
			opts, err := parseProf("listen=localhost:7474")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}
	})

	t.Run("memprofilerate", func(t *testing.T) {
		{
			expected := defaultOpts

			opts, err := parseProf("memprofilerate")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			expected := defaultOpts

			opts, err := parseProf("memprofilerate=")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}

		{
			_, err := parseProf("memprofilerate=notanumber")
			require.Error(t, err)
		}

		{
			expected := defaultOpts
			expectedMemProfileRate := 43
			expected.MemProfileRate = &expectedMemProfileRate

			opts, err := parseProf("memprofilerate=43")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}
	})

	t.Run("all together", func(t *testing.T) {
		{
			expected := defaultOpts
			expected.Enabled = true
			expectedMemProfileRate := 43
			expected.MemProfileRate = &expectedMemProfileRate
			expected.Listen = "localhost:7474"

			opts, err := parseProf("enabled,memprofilerate = 43, listen= localhost:7474")
			require.NoError(t, err)
			require.Equal(t, expected, opts)
		}
	})
}

func TestInitProfilerForUnset(t *testing.T) {
	// An unset variable must leave the process untouched, in particular it must
	// not open a port.
	InitProfilerFor("MONDOO_PROF_TEST_UNSET")
}

func TestSetupProfiler(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		require.Nil(t, setupProfiler(profilerOpts{Enabled: false, Listen: "localhost:0"}))
	})

	t.Run("serves the heap endpoint", func(t *testing.T) {
		l := setupProfiler(profilerOpts{Enabled: true, Listen: "localhost:0"})
		require.NotNil(t, l)
		t.Cleanup(func() { _ = l.Close() })

		res, err := http.Get("http://" + l.Addr().String() + "/debug/pprof/heap")
		require.NoError(t, err)
		defer res.Body.Close()
		require.Equal(t, 200, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.NotEmpty(t, body)
	})
}
