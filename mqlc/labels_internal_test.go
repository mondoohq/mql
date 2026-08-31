// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// stripViaTransform is the original implementation. It is the reference the fast
// path must agree with.
func stripViaTransform(str string) string {
	isOk := func(r rune) bool {
		return r < 32 || r >= 127
	}
	t := transform.Chain(norm.NFKD, runes.Remove(runes.Predicate(isOk)))
	str, _, _ = transform.String(t, str)
	return str
}

func TestStripCtlAndExtFromUnicode(t *testing.T) {
	cases := []string{
		"",
		"packages.list",
		"users.list[0].name",
		`file("/etc/passwd").permissions.user_readable`,
		" leading and trailing ",
		"~!@#$%^&*()_+`-={}|[]\\:\";'<>?,./",
		"tab\there",
		"newline\nhere",
		"del\x7fhere",
		"café",
		"ﬁle", // ligature, NFKD splits it into "fi"
		"Ä",   // precomposed, NFKD splits it and the mark is dropped
		"日本語", // fully removed
		"mixed café.list",
	}

	for _, c := range cases {
		assert.Equal(t, stripViaTransform(c), stripCtlAndExtFromUnicode(c), "input %q", c)
	}
}

func TestStripCtlAndExtFromUnicodeRandom(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		var sb strings.Builder
		for j := 0; j < 1+r.Intn(20); j++ {
			sb.WriteRune(rune(r.Intn(0x300)))
		}
		in := sb.String()
		assert.Equal(t, stripViaTransform(in), stripCtlAndExtFromUnicode(in), "input %q", in)
	}
}

var benchSink string

func BenchmarkStripCtlAndExtFromUnicode(b *testing.B) {
	labels := []string{
		"packages.list",
		"asset.platform",
		"users.list[0].name",
		"aws.ec2.instances",
		"file(\"/etc/passwd\").permissions.user_readable",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, l := range labels {
			benchSink = stripCtlAndExtFromUnicode(l)
		}
	}
}
