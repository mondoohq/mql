// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpe

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPkg2Gen(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		pkg      string
		version  string
		release  string
		arch     string
		expected []string
	}{
		{
			name:    "escapes a plus in the version",
			vendor:  "tar",
			pkg:     "tar",
			version: "1.34+dfsg-1",
			expected: []string{
				"cpe:2.3:a:tar:tar:1.34\\+dfsg-1:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "escapes a scoped npm name",
			vendor:  "@coreui/vue",
			pkg:     "@coreui/vue",
			version: "2.1.2",
			expected: []string{
				"cpe:2.3:a:\\@coreui\\/vue:\\@coreui\\/vue:2.1.2:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "strips a zero epoch and keeps the arch",
			vendor:  "nextgen",
			pkg:     "mirthconnect",
			version: "0:4.4.0.b2948-1",
			arch:    "i386",
			expected: []string{
				"cpe:2.3:a:nextgen:mirthconnect:4.4.0.b2948-1:*:*:*:*:*:i386:*",
			},
		},
		{
			name:    "strips a multi digit epoch",
			vendor:  "acme",
			pkg:     "widget",
			version: "12:1.2.3-4",
			expected: []string{
				"cpe:2.3:a:acme:widget:1.2.3-4:*:*:*:*:*:*:*",
			},
		},
		{
			// The epoch pattern is anchored to leading digits, so it leaves
			// "v1:2.3" alone. WFNize then truncates at the colon because a
			// colon separates WFN components -- long-standing behavior of the
			// nvdtools binding, pinned here so the epoch handling above is not
			// mistaken for the cause.
			name:    "a non-epoch colon is not stripped as an epoch",
			vendor:  "acme",
			pkg:     "widget",
			version: "v1:2.3",
			expected: []string{
				"cpe:2.3:a:acme:widget:v1:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "carries the release through as the update field",
			vendor:  "acme",
			pkg:     "widget",
			version: "1.2.3",
			release: "5",
			expected: []string{
				"cpe:2.3:a:acme:widget:1.2.3:5:*:*:*:*:*:*",
			},
		},
		{
			name:    "uppercase input is lowercased",
			vendor:  "ACME",
			pkg:     "Widget",
			version: "1.2.3",
			arch:    "X86_64",
			expected: []string{
				"cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:x86_64:*",
			},
		},
		{
			// A CPE needs a product and a version, so these are not errors --
			// they simply produce nothing to match against.
			name:     "no name yields no cpe",
			vendor:   "acme",
			pkg:      "",
			version:  "1.2.3",
			expected: []string{},
		},
		{
			name:     "no version yields no cpe",
			vendor:   "acme",
			pkg:      "widget",
			version:  "",
			expected: []string{},
		},
		{
			name:     "an epoch with nothing after it yields no cpe",
			vendor:   "acme",
			pkg:      "widget",
			version:  "3:",
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cpes, err := NewPackage2Cpe(test.vendor, test.pkg, test.version, test.release, test.arch)
			require.NoError(t, err)
			assert.Equal(t, test.expected, cpes)
		})
	}
}

// WFNize rejects a field carrying an escaped wildcard, which is the only path
// out of this function that reports which field it was. The name comes from
// cpeFieldNames positionally, so a table that drifts out of step with the loop
// would blame the wrong field with nothing to catch it.
func TestNewPackage2CpeWFNizeError(t *testing.T) {
	// An escaped wildcard is only rejected when it sits inside the value; a
	// trailing one is a legal WFN wildcard, so every case embeds it.
	tests := []struct {
		name  string
		args  [5]string // vendor, name, version, release, arch
		index int
		field string
	}{
		{"vendor", [5]string{`v\*endor`, "widget", "1.2.3", "", "x86_64"}, 0, "vendor"},
		{"name", [5]string{"acme", `wid\*get`, "1.2.3", "", "x86_64"}, 1, "name"},
		{"version", [5]string{"acme", "widget", `1\*.2.3`, "", "x86_64"}, 2, "version"},
		{"release", [5]string{"acme", "widget", "1.2.3", `5\*x`, "x86_64"}, 3, "release"},
		{"arch", [5]string{"acme", "widget", "1.2.3", "", `x86\*64`}, 4, "arch"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := test.args
			cpes, err := NewPackage2Cpe(a[0], a[1], a[2], a[3], a[4])
			require.Error(t, err)
			assert.Empty(t, cpes)
			// Naming the field and carrying the value that failed. WFNize
			// returns an empty string with its error, so assigning before
			// checking would report `""` here.
			assert.Contains(t, err.Error(),
				fmt.Sprintf("couldn't wfnize %s %q", test.field, strings.ToLower(a[test.index])))
		})
	}
}

// Two malformed fields at once. Ranging a map gave whichever one the runtime
// happened to visit first, so the same input reported a different field from
// run to run; the fixed array makes it the first field in order.
func TestNewPackage2CpeWFNizeErrorIsDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		_, err := NewPackage2Cpe(`v\*endor`, `n\*ame`, `1\*.2`, "", "x86_64")
		require.Error(t, err)
		require.Contains(t, err.Error(), "couldn't wfnize vendor ")
	}
}

// NewPackage2Cpe runs two to three times per package, so the regexp and the
// field-name table are package level rather than rebuilt per call. This pins
// the allocation count so a future edit cannot quietly move them back into the
// function body. The ceiling sits just above the current count: the map this
// function used to range over cost five allocations, and a threshold that does
// not catch its return is not guarding anything.
func TestNewPackage2CpeAllocations(t *testing.T) {
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = NewPackage2Cpe("red hat, inc.", "libfoo-dev", "2:1.2.3-2.el9", "", "x86_64")
	})
	assert.LessOrEqual(t, allocs, float64(25), "NewPackage2Cpe allocations regressed")
}

func BenchmarkNewPackage2Cpe(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = NewPackage2Cpe("red hat, inc.", "libfoo-dev", "2:1.2.3-2.el9", "", "x86_64")
	}
}

// An rpm built with `Vendor: Vendör GmbH` (the g03-uni test package): WFNize
// keeps printable ASCII only, so the umlaut was dropped and the vendor read
// `vendr_gmbh`. CPE dictionaries spell such names transliterated.
func TestNewPackage2CpeTransliteratesNonASCII(t *testing.T) {
	cpes, err := NewPackage2Cpe("Vendör GmbH", "g03-uni", "1.0", "1", "x86_64")
	require.NoError(t, err)
	assert.Equal(t, []string{"cpe:2.3:a:vendor_gmbh:g03-uni:1.0:1:*:*:*:*:x86_64:*"}, cpes)

	cpes, err = NewPackage2Cpe("Straße Søftware Łódź", "naïve-café", "1.0", "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"cpe:2.3:a:strasse_software_lodz:naive-cafe:1.0:*:*:*:*:*:*:*"}, cpes)

	// a vendor with no ASCII spelling at all is unknown, not `_`, and a dropped
	// word does not leave a stray `_` behind
	cpes, err = NewPackage2Cpe("日本語 株式会社", "g03-cjk", "1.0", "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"cpe:2.3:a:*:g03-cjk:1.0:*:*:*:*:*:*:*"}, cpes)

	cpes, err = NewPackage2Cpe("株式会社 Example", "g03-cjk", "1.0", "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"cpe:2.3:a:example:g03-cjk:1.0:*:*:*:*:*:*:*"}, cpes)
}
