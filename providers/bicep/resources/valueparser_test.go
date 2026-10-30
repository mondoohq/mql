// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withinBudget runs fn and fails if it has not finished in time. A runaway
// value parser shows up as a hang here rather than as a panic, and an
// unbounded recursion shows up as a Go stack overflow, which is a fatal error
// that recover() cannot catch — so the deadline is the only safe way to assert
// on it from inside the test binary.
func withinBudget(t *testing.T, budget time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("value parser did not finish within %s", budget)
	}
}

// A lone `[` is a fixed point for the value parser: stripping the outer
// brackets off a one-byte string returns it unchanged, so the array parser
// hands the same text back to the value parser forever.
func TestParseBicepValueLoneOpenBracketTerminates(t *testing.T) {
	withinBudget(t, 5*time.Second, func() {
		assert.Equal(t, "[", parseBicepValue("["))
	})
}

func TestParseBicepValueLoneOpenBraceTerminates(t *testing.T) {
	withinBudget(t, 5*time.Second, func() {
		parseBicepValue("{")
	})
}

// The production route to that fixed point: an unbalanced `[` in a resource
// body. `splitTopLevelEntries` only ends an entry at depth 0, so the entry
// after an unclosed bracket runs to end of input and arrives as a bare "[".
func TestUnbalancedBracketInResourceBodyTerminates(t *testing.T) {
	sources := []string{
		"resource r 'T@2020-01-01' = {\n  foo: [\n}\n",
		"resource r 'T@2020-01-01' = {\n  properties: {\n    ips: [\n  }\n}\n",
		"resource r 'T@2020-01-01' = {\n  properties: {\n    rules: [ { name: 'x', ports: [ } ]\n  }\n}\n",
		"module m './m.bicep' = {\n  params: {\n    x: [\n  }\n}\n",
	}
	for _, src := range sources {
		withinBudget(t, 5*time.Second, func() {
			p := parseBicep(src)
			for _, r := range p.resources {
				parseBicepObject(bodyObjectInner(r.body))
			}
			for _, m := range p.modules {
				parseBicepObject(extractFieldBlock(m.body, "params"))
			}
		})
	}
}

// Deeply nested values must degrade rather than drive super-linear work, the
// same way the expression parser already bounds itself with maxExprDepth.
func TestParseBicepValueDeepNestingIsBounded(t *testing.T) {
	v := strings.Repeat("[", 40000) + strings.Repeat("]", 40000)
	withinBudget(t, 5*time.Second, func() {
		parseBicepValue(v)
	})

	obj := strings.Repeat("{ a: ", 20000) + "1" + strings.Repeat(" }", 20000)
	withinBudget(t, 5*time.Second, func() {
		parseBicepValue(obj)
	})
}

// A well-formed nested value must still parse correctly after the bound.
func TestParseBicepValueStillParsesNestedStructures(t *testing.T) {
	v := parseBicepValue("{ a: [ 'x', { b: 2 } ], c: true }")
	m, ok := v.(map[string]any)
	require.True(t, ok, "expected an object, got %T", v)

	arr, ok := m["a"].([]any)
	require.True(t, ok, "expected an array, got %T", m["a"])
	require.Len(t, arr, 2)
	assert.Equal(t, "x", arr[0])

	inner, ok := arr[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2), inner["b"])
	assert.Equal(t, true, m["c"])
}

// A triple-quoted value lost exactly one quote from each side, leaving stray
// ” bookends on every embedded script or certificate body.
func TestParseBicepValueTripleQuoted(t *testing.T) {
	got := parseBicepObject("scriptContent: '''\n  echo hi\n'''")
	require.Contains(t, got, "scriptContent")
	s, ok := got["scriptContent"].(string)
	require.True(t, ok)
	assert.Equal(t, "\n  echo hi\n", s)
	assert.NotContains(t, s, "''")
}
