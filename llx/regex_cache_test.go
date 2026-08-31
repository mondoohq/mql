// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompiledRegexMatchesMustCompile(t *testing.T) {
	patterns := []string{
		`^abc$`,
		`(?i)Hello`,
		`[0-9]+`,
		`^/usr/lib/package-[0-9]+/module_[0-9]+\.so$`,
		`a|b`,
		``,
		`\d{2,4}`,
	}
	inputs := []string{"abc", "hello", "HELLO", "42", "/usr/lib/package-1/module_2.so", "", "1234", "b"}

	for _, pattern := range patterns {
		want := regexp.MustCompile(pattern)
		got := compiledRegex(pattern)
		for _, in := range inputs {
			assert.Equal(t, want.MatchString(in), got.MatchString(in),
				"pattern %q input %q", pattern, in)
		}
	}
}

func TestCompiledRegexReturnsTheSameInstance(t *testing.T) {
	const pattern = `^cache-me$`
	first := compiledRegex(pattern)
	second := compiledRegex(pattern)
	assert.Same(t, first, second)
}

func TestCompiledRegexPanicsOnInvalidPattern(t *testing.T) {
	// The previous code used regexp.MustCompile, so an invalid pattern must still panic.
	assert.Panics(t, func() { compiledRegex(`[`) })
}

func TestCompiledRegexIsBounded(t *testing.T) {
	before := regexCacheLen.Load()
	for i := 0; i < regexCacheMax*3; i++ {
		r := compiledRegex(`^bounded-` + strconv.Itoa(i) + `-[0-9]+$`)
		require.NotNil(t, r)
		assert.True(t, r.MatchString("bounded-"+strconv.Itoa(i)+"-7"))
	}
	assert.LessOrEqual(t, regexCacheLen.Load(), int64(regexCacheMax),
		"cache grew past its bound (was %d before)", before)
}

func TestCompiledRegexConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				pattern := `^concurrent-` + strconv.Itoa(j%8) + `$`
				assert.True(t, compiledRegex(pattern).MatchString(fmt.Sprintf("concurrent-%d", j%8)))
			}
		}(i)
	}
	wg.Wait()
}

func TestOpStringCmpRegexUnchanged(t *testing.T) {
	cases := []struct {
		value, pattern string
		expected       bool
	}{
		{"abc", `^abc$`, true},
		{"abcd", `^abc$`, false},
		{"HELLO", `(?i)hello`, true},
		{"nothing", `[0-9]+`, false},
		{"a1", `[0-9]+`, true},
	}
	for _, c := range cases {
		assert.Equal(t, c.expected, opStringCmpRegex(c.value, c.pattern), "%q =~ %q", c.value, c.pattern)
		assert.Equal(t, c.expected, opRegexCmpString(c.pattern, c.value), "%q =~ %q", c.pattern, c.value)
	}
}

// BenchmarkOpStringCmpRegex models an array comparison, where the same pattern applies to
// every element.
func BenchmarkOpStringCmpRegex(b *testing.B) {
	inputs := make([]string, 0, 5000)
	for i := 0; i < 5000; i++ {
		inputs = append(inputs, fmt.Sprintf("/usr/lib/package-%d/module_%d.so", i%50, i))
	}
	const pattern = `^/usr/lib/package-[0-9]+/module_[0-9]+\.so$`

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range inputs {
			if !opStringCmpRegex(in, pattern) {
				b.Fatal("no match")
			}
		}
	}
}
