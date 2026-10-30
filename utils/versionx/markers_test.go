// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versionx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The scale is asserted through markerRank rather than against the rank constants, so
// that reordering the tiers or moving a word between them fails here instead of moving
// the expectation along with it.
func TestMarkerRankScale(t *testing.T) {
	// "" carries no word and so ranks as the release itself: the pivot every other
	// tier is defined against.
	scale := []string{"dev", "milestone", "alpha", "beta", "pre", "rc", "", "post"}

	for i := 1; i < len(scale); i++ {
		lo, hi := scale[i-1], scale[i]
		assert.Less(t, markerRank(lo), markerRank(hi), "%q must rank below %q", lo, hi)
	}
}

func TestMarkerRankWords(t *testing.T) {
	tests := []struct {
		in   string
		want int
		why  string
	}{
		// Each synonym lands on the tier its ecosystem means by it.
		{"devel", rankDev, "the spelled-out dev"},
		{"snapshot", rankDev, "a branch build"},
		{"nightly", rankDev, "a branch build"},
		{"canary", rankDev, "a branch build"},
		{"milestone", rankMilestone, "Tomcat's M-series"},
		{"prerelease", rankPre, "pre must not stop covering prerelease"},
		{"preview", rankPre, "aimed at the release"},

		// A word has to END where it ends, or a distro revision reads as a
		// prerelease and sinks below the release it is a build of.
		{"devuan1", rankRelease, "a Devuan revision, not a dev build"},
		{"precise1", rankRelease, "an Ubuntu codename, not pre"},
		{"postgres1", rankRelease, "a package name, not post"},
		{"prefix", rankRelease, "not pre"},
		{"betamax", rankRelease, "not beta"},

		// Single letters stay letters: openssl ships 1.1.1a..1.1.1w as ordinary
		// patch releases, and apk's -r4 is a build revision, not PEP 440's "r".
		{"a", rankRelease, "openssl patch letter, not alpha"},
		{"b", rankRelease, "openssl patch letter, not beta"},
		{"c", rankRelease, "openssl patch letter, not candidate"},
		{"r", rankRelease, "apk's build revision marker, not a post-release"},
		{"k", rankRelease, "openssl patch letter"},

		// The word only counts where it leads.
		{"1ubuntu1", rankRelease, "opens with a digit"},
		{"1.0rc1", rankRelease, "the word is not at the front"},
		{".el8_7", rankRelease, "opens with punctuation"},
		{"~rc", rankRelease, "a tilde run is ordered before this ever applies"},
		{"", rankRelease, "nothing to read"},

		// Case is decoration; the word is the same word.
		{"DEV", rankDev, "upstreams shout"},
		{"RC1", rankRC, "and so do release tags"},
		{"Beta", rankBeta, "mixed case too"},

		// splitRuns cuts only at digit boundaries, so a run arrives with whatever
		// punctuation trailed it.
		{"rc1", rankRC, "attached number"},
		{"dev.2", rankDev, "dotted identifier"},
		{"beta-3", rankBeta, "dashed identifier"},
		{"post1", rankPost, "a rebuild trails its release"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, markerRank(tt.in), tt.why)
		})
	}
}

func TestIsPostComponent(t *testing.T) {
	tests := []struct {
		in   string
		want bool
		why  string
	}{
		{"post1", true, "PEP 440's canonical spelling"},
		{"post", true, "the number is optional"},
		{"post0", true, "zero is a number"},
		{"post42", true, "multi-digit"},
		{"POST1", true, "case-insensitive, like every other marker"},

		{"postgres1", false, "a package name that starts the same way"},
		{"posted", false, "trailing letters mean it is a different word"},
		{"postfix2", false, "and this one is a mail server"},
		{"1post", false, "the word has to lead"},
		{"pre1", false, "a prerelease is not a post-release"},
		{"0", false, "an ordinary release component"},
		{"", false, "nothing to read"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, isPostComponent(tt.in), tt.why)
		})
	}
}

func TestLeadingWord(t *testing.T) {
	assert.Equal(t, "rc", leadingWord("rc1"), "stops at the first digit")
	assert.Equal(t, "el", leadingWord("el8_7"), "stops at the first digit")
	assert.Equal(t, "dev", leadingWord("dev."), "stops at punctuation")
	assert.Equal(t, "devuan", leadingWord("devuan1"), "takes the whole word, not a prefix of it")
	assert.Equal(t, "dev", leadingWord("DEV"), "lower-cased")
	assert.Equal(t, "", leadingWord("1ubuntu1"), "a leading digit yields no word")
	assert.Equal(t, "", leadingWord("~rc"), "a leading tilde yields no word")
	assert.Equal(t, "", leadingWord(""), "empty yields no word")
	assert.Equal(t, "", leadingWord("ü1"), "non-ASCII is not a stage word")
}
