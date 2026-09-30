// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package wmiquery

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withQuery(t *testing.T, f func(string, any, ...any) error) {
	t.Helper()
	orig := query
	query = f
	t.Cleanup(func() { query = orig })
}

func TestQueryRecoversPanic(t *testing.T) {
	withQuery(t, func(string, any, ...any) error {
		var v any = "not a uint64"
		_ = v.(uint64) // the kind of panic reflect raises on a variant type mismatch
		return nil
	})
	var dst []struct{ Name string }
	err := Query("SELECT Name FROM Win32_OperatingSystem", &dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panicked")
	assert.Contains(t, err.Error(), "Win32_OperatingSystem")
}

func TestQueryPassesErrorsAndResults(t *testing.T) {
	want := errors.New("access denied")
	withQuery(t, func(string, any, ...any) error { return want })
	assert.ErrorIs(t, Query("SELECT x FROM y", &[]struct{}{}), want)

	withQuery(t, func(_ string, dst any, _ ...any) error {
		*(dst.(*[]struct{ Name string })) = []struct{ Name string }{{Name: "host"}}
		return nil
	})
	var dst []struct{ Name string }
	require.NoError(t, Query("SELECT Name FROM y", &dst))
	assert.Equal(t, "host", dst[0].Name)
}

// A real query on the machine that runs the test: the helper must not change
// what wmi.Query returns.
func TestQueryLive(t *testing.T) {
	var dst []struct{ Caption *string }
	require.NoError(t, Query("SELECT Caption FROM Win32_OperatingSystem", &dst))
	require.Len(t, dst, 1)
	require.NotNil(t, dst[0].Caption)
}
