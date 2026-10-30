// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPanicEventIncludesPlatform(t *testing.T) {
	event := panicEvent("cnspec", "12.0.0", "abc123", "boom", []byte("stacktrace"), nil)

	require.NotNil(t, event.Product)
	assert.Equal(t, "cnspec", event.Product.Name)
	assert.Equal(t, "12.0.0", event.Product.Version)
	assert.Equal(t, "abc123", event.Product.Build)

	require.NotNil(t, event.Error)
	assert.Equal(t, "panic: boom", event.Error.Message)
	assert.Equal(t, "stacktrace", event.Error.Stacktrace)

	assert.Equal(t, runtime.GOOS, event.Tags["os"])
	assert.Equal(t, runtime.GOARCH, event.Tags["arch"])
}

func TestPanicEventIncludesQueryTags(t *testing.T) {
	tags := QueryPanicTags("zLKUfd9hgBY=", "groups.map(name).containsAll(suRestrictedGroups)")
	event := panicEvent("cnspec", "12.0.0", "abc123", "boom", []byte("stacktrace"), tags)

	assert.Equal(t, "zLKUfd9hgBY=", event.Tags[TagQueryCodeID])
	assert.Equal(t, "groups.map(name).containsAll(suRestrictedGroups)", event.Tags[TagQuerySource])
	// baseline platform tags are preserved
	assert.Equal(t, runtime.GOOS, event.Tags["os"])
	assert.Equal(t, runtime.GOARCH, event.Tags["arch"])
}

func TestPanicEventPlatformTagsWin(t *testing.T) {
	event := panicEvent("cnspec", "12.0.0", "abc123", "boom", []byte("st"),
		map[string]string{"os": "spoofed", "arch": "spoofed"})

	assert.Equal(t, runtime.GOOS, event.Tags["os"])
	assert.Equal(t, runtime.GOARCH, event.Tags["arch"])
}

// ReportRecoveredPanic must return normally (never re-panic) so callers can
// convert a recovered panic into an error, and it must honor the empty-build
// guard that keeps dev environments from reporting.
//
// The build != "" reporting path is intentionally not exercised here: it
// reads the local mondoo config and would send a real error report to the
// platform on machines with a configured service account. It is covered
// indirectly by TestPanicEvent* above and the exec manager's recovery test.
func TestReportRecoveredPanicSkipsWithoutBuild(t *testing.T) {
	reporterCalled := false
	reporter := func(product, version, build string, r any, stacktrace []byte) {
		reporterCalled = true
	}

	defer func() {
		require.Nil(t, recover(), "ReportRecoveredPanic must not re-panic")
		assert.False(t, reporterCalled, "empty build must skip all reporting")
	}()
	defer func() {
		if r := recover(); r != nil {
			ReportRecoveredPanic("mql", "12.0.0", "", r, debug.Stack(), nil, reporter)
		}
	}()
	panic("boom")
}

func TestQueryPanicTags(t *testing.T) {
	assert.Nil(t, QueryPanicTags("", ""))

	tags := QueryPanicTags("abc=", "")
	assert.Equal(t, map[string]string{TagQueryCodeID: "abc="}, tags)

	long := make([]rune, querySourceMax+100)
	for i := range long {
		long[i] = 'x'
	}
	tags = QueryPanicTags("", string(long))
	assert.Len(t, []rune(tags[TagQuerySource]), querySourceMax)
}
