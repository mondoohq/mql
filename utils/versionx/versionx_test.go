// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versionx

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every version string below is a real one — taken from package inventories, upstream
// release tags, or vendor firmware — not invented to fit the implementation.
func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
		why  string
	}{
		// --- plain semver ---
		{"1.2.3", "1.2.3", 0, "identical"},
		{"1.2", "1.2.0", 0, "missing components are zeros"},
		{"1.2.3", "1.2.4", -1, "patch"},
		{"1.2", "1.10.2", -1, "minor is numeric, not lexical"},
		{"1.10", "1.2.3", 1, "10 > 2"},
		{"2.0", "10.0", -1, "major is numeric, not lexical"},
		{"v1.2.3", "1.2.4", -1, "a leading v is decoration"},
		{"1.2.3", "1.2.3+build.5", 0, "build metadata carries no precedence"},

		// --- semver prereleases ---
		{"1.0.0-alpha", "1.0.0", -1, "a prerelease leads its release"},
		{"1.0.0-rc1", "1.0.0", -1, "rc leads its release"},
		{"1.0.0-alpha.2", "1.0.0-alpha.10", -1, "numeric prerelease identifiers"},
		{"3.0.0-beta.2", "3.0.0-beta.10", -1, "numeric prerelease identifiers"},
		{"1.0.0-alpha", "1.0.0-beta", -1, "alpha before beta"},
		{"1.0.0-beta", "1.0.0-rc", -1, "beta before rc"},

		// --- distro revisions: the opposite rule ---
		{"1.2.3", "1.2.3-1ubuntu1", -1, "a revision is a LATER build of its release"},
		{"2.1.0", "2.1.0-1", -1, "bare numeric revision"},
		{"1.2.3-r4", "1.2.3", 1, "apk revision is newer than the bare release"},
		{"1.2.3-r4", "1.2.3-r10", -1, "apk revisions count, they do not sort as text"},
		{"1.0.0-rc1", "1.0.0-1ubuntu1", -1, "a candidate precedes a build of the release"},
		{"1.2.3-devuan1", "1.2.3", 1, "devuan is a revision, not a dev prerelease"},
		{"1.2.3-preview1", "1.2.3-precise1", -1, "preview leads the release, precise does not"},

		// --- prerelease words, whole words only ---
		{"1.0.0-dev", "1.0.0", -1, "dev leads its release"},
		{"1.0.0-devel", "1.0.0", -1, "and so does the spelled-out form"},
		{"1.0.0-prerelease", "1.0.0", -1, "pre must not stop covering prerelease"},
		{"1.0.0-DEV.2", "1.0.0", -1, "the word is matched case-insensitively"},

		// --- deb / rpm reality ---
		{"1:2.4.52-1ubuntu4.6", "1:2.4.52-1ubuntu4.10", -1, "revision 6 < 10"},
		{"4.18.0-425.3.1.el8_7", "4.18.0-425.13.1.el8_7", -1, "dist tag with an underscore"},
		{"1.1.1f-1ubuntu2.20", "1.1.1k-12.el8", -1, "openssl letter releases"},
		{"1.1.1", "1.1.1k", -1, "a letter release follows the bare one"},
		{"2.4.52", "2.4.52-1ubuntu4.6", -1, "upstream vs packaged"},

		// --- epochs win outright ---
		{"2:1.0.0", "10.0.0", 1, "epoch beats a larger major"},
		{"1:1.2.3", "2:1.0.0", -1, "higher epoch wins"},
		{"1!2.0", "1.9.0", 1, "PEP 440 epoch"},
		{"1.2.3", "1.2.3", 0, "no epoch on either side"},

		// --- more than three components ---
		{"16.1.2.2", "9.1.0.0", 1, "BIG-IP quads"},
		{"4.40.0.0", "10.1.0.0", -1, "Windows driver quads"},
		{"126.0.6478.126", "99.0.4844.51", 1, "Chrome"},
		{"1.2.3.4.5", "1.2.3.4.6", -1, "five components"},

		// --- Debian's tilde ---
		{"1.0~rc1", "1.0", -1, "~ sorts before the release"},
		{"1.0~rc1", "1.0~rc2", -1, "~ runs still compare"},
		{"1.0~beta", "1.0a", -1, "~ sorts before everything"},

		// --- PEP 440 stage words, attached with no separator ---
		// The marker hangs straight off the number in PostGIS's own release naming
		// and in PEP 440's canonical spelling, so there is no '-' to split on.
		{"3.7.0beta2", "3.7.0", -1, "an attached beta is still a candidate for the release"},
		{"1.0rc1", "1.0", -1, "and so is an attached rc"},
		{"1.0alpha1", "1.0beta1", -1, "alpha before beta, attached too"},
		{"1.0beta2", "1.0rc1", -1, "beta before rc"},
		{"3.7.0beta2", "3.7.0beta10", -1, "the number after the word still counts"},
		{"1.0.dev1", "1.0", -1, "a dotted dev component leads its release"},
		{"1.1.1k", "1.1.1", 1, "but a bare letter is openssl's patch, not a stage word"},
		{"1.0.post1", "1.0", 1, "a post-release is a rebuild, so it follows"},
		{"1.0.post1", "1.0.0", 1, "and 1.0.0 is the same version as 1.0"},
		{"1.0.post1", "1.0.1", -1, "but it is below the next real release"},
		{"1.0.post1", "1.0.post2", -1, "post-releases count"},
		{"1.0.postgres1", "1.0", -1, "postgres is not post: it stays an unrecognized word"},
		{"9.0.0.M1", "9.0.0", -1, "Tomcat's dotted milestone spelling"},

		// --- apk writes a build stamp where deb writes an epoch ---
		{"1632431095:1.2.2-r7", "2.0.0", -1, "a build stamp is not an epoch"},
		{"1632431095:1.2.2-r7", "1.2.3-r1", -1, "and must not outrank the whole list"},
		{"1632431095:1.2.2-r7", "1.2.2-r7", 0, "the stamp itself carries no precedence"},
		{"1:1.2.3", "1632431095:1.2.2-r7", 1, "a real epoch still wins outright"},

		// --- unparseable, but still ordered ---
		{"latest", "latest", 0, "equal strings are equal"},
		{"", "1.0", -1, "empty sorts first"},
	}

	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			assert.Equal(t, tt.want, Compare(tt.a, tt.b), tt.why)
			assert.Equal(t, -tt.want, Compare(tt.b, tt.a), "compare must be antisymmetric")
		})
	}
}

func TestKind(t *testing.T) {
	tests := []struct {
		version string
		want    Kind
	}{
		{"1.2.3", KindSemver},
		{"1.2", KindSemver},
		{"v1.2.3", KindSemver},
		{"1.0.0-rc1", KindSemver},
		{"1.0.0-rc.1+build.5", KindSemver},
		{"1:1.2.3", KindDebian},
		{"1:2.4.52-1ubuntu4.6", KindDebian},
		{"5!1.2.3", KindPython},
		{"1.2.3.4", KindGeneric},
		{"1.1.1k", KindGeneric},
		{"4.18.0-425.13.1.el8_7", KindGeneric},
		{"latest", KindUnknown},
		{"", KindUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, Parse(tt.version).Kind())
		})
	}
}

func TestHasEpoch(t *testing.T) {
	assert.False(t, Parse("1.2.3").HasEpoch())
	assert.True(t, Parse("1:1.2.3").HasEpoch())
	assert.True(t, Parse("0:1.2.3").HasEpoch(), "an explicit 0 is a written epoch")
	assert.True(t, Parse("1!2.0").HasEpoch())
	assert.False(t, Parse("1632431095:1.2.2-r7").HasEpoch(), "an apk build stamp is not an epoch")
	assert.False(t, Parse("").HasEpoch())
}

func TestWithoutEpoch(t *testing.T) {
	v := Parse("1:8.2p1-4ubuntu0.13").WithoutEpoch()
	assert.Equal(t, "8.2p1-4ubuntu0.13", v.String())
	assert.False(t, v.HasEpoch())
	assert.Equal(t, KindGeneric, v.Kind())
	assert.Equal(t, -1, v.Compare(Parse("8.5")))

	assert.Equal(t, "2.0", Parse("1!2.0").WithoutEpoch().String())
	assert.Equal(t, "1.2.3", Parse("1.2.3").WithoutEpoch().String())
}

func TestConstraintWithoutEpoch(t *testing.T) {
	c, err := ParseConstraint("^1:8.0")
	require.NoError(t, err)
	assert.True(t, c.HasEpoch())
	assert.False(t, c.Check(Parse("8.2")), "epoch'd bound against an epochless version")
	assert.True(t, c.WithoutEpoch().Check(Parse("8.2")))
	assert.False(t, c.WithoutEpoch().Check(Parse("9.0")), "the upper bound loses its epoch too")
}

func TestEpoch(t *testing.T) {
	assert.Equal(t, 0, Parse("1.2.3").Epoch())
	assert.Equal(t, 7, Parse("7:1.2.3").Epoch())
	assert.Equal(t, 5, Parse("5!1.2.3").Epoch())
	assert.Equal(t, 0, Parse("1.2.3:4").Epoch(), "a colon mid-string is not an epoch")
}

func TestString(t *testing.T) {
	assert.Equal(t, "1:2.4.52-1ubuntu4.6", Parse("1:2.4.52-1ubuntu4.6").String(),
		"the original string must survive parsing")
}

// A sort is where a comparator's mistakes actually surface, so the ordering is asserted
// end to end and not only pairwise.
func TestSortMixedInventory(t *testing.T) {
	versions := []string{
		"1.1.1k-12.el8",
		"126.0.6478.126",
		"1.0.0-alpha",
		"1.2.3-r10",
		"99.0.4844.51",
		"1.0.0",
		"1.2.3-r4",
		"1.1.1f-1ubuntu2.20",
		"1.2.3",
	}
	sort.Slice(versions, func(i, j int) bool { return Less(versions[i], versions[j]) })

	assert.Equal(t, []string{
		"1.0.0-alpha",
		"1.0.0",
		"1.1.1f-1ubuntu2.20",
		"1.1.1k-12.el8",
		"1.2.3",
		"1.2.3-r4",
		"1.2.3-r10",
		"99.0.4844.51",
		"126.0.6478.126",
	}, versions)
}

// Transitivity is the property a hand-rolled comparator loses first, and sort.Slice
// silently produces garbage when it does not hold.
func TestOrderIsTotal(t *testing.T) {
	versions := []string{
		"", "1", "1.0", "1.0.0", "1.0.0-alpha", "1.0.0-rc1", "1.0.0-1", "1.0~rc1",
		"1.0.1", "1.1", "2.0", "10.0", "1:1.0", "2:1.0", "1!1.0", "1.0.0.0", "1.0.0k",
		"latest", "4.18.0-425.13.1.el8_7",
		// The stage words are where transitivity is easiest to lose: "1.0" and
		// "1.0.0" are the SAME version, so any rule that orders a marker against
		// one of them has to give the same answer for the other.
		"1.0.post1", "1.0.post2", "1.0rc1", "1.0beta1", "1.0.dev1", "1.0.0.post1",
		"1632431095:1.2.2-r7",
	}

	for _, a := range versions {
		for _, b := range versions {
			ab, ba := Compare(a, b), Compare(b, a)
			require.Equal(t, ab, -ba, "antisymmetry: %q vs %q", a, b)
			for _, c := range versions {
				bc := Compare(b, c)
				if ab <= 0 && bc <= 0 {
					require.LessOrEqual(t, Compare(a, c), 0,
						"transitivity: %q <= %q <= %q", a, b, c)
				}
			}
		}
	}
}

func TestMax(t *testing.T) {
	assert.Equal(t, "1.2.10", Max("1.2.9", "1.2.10"))
	assert.Equal(t, "1.2.10", Max("1.2.10", "1.2.9"))
	assert.Equal(t, "1.2.3", Max("", "1.2.3"), "a missing version loses")
	assert.Equal(t, "1.2.3", Max("1.2.3", ""), "a missing version loses")
	assert.Equal(t, "", Max("", ""))
	assert.Equal(t, "1:1.0.0", Max("1:1.0.0", "9.9.9"), "epoch wins")
	assert.Equal(t, "1.2.3", Max("1.2.3", "1.2.3"), "ties keep the first")
}

func TestSortStrings(t *testing.T) {
	versions := []string{"1.10.0", "1.9.0", "1.2.3-r10", "1.2.3-r4", "2:1.0.0", "1.0.0-rc1", "1.0.0"}
	SortStrings(versions)
	assert.Equal(t, []string{
		"1.0.0-rc1", "1.0.0", "1.2.3-r4", "1.2.3-r10", "1.9.0", "1.10.0", "2:1.0.0",
	}, versions)

	// The originals survive the round trip — sorting must not normalize what it sorts.
	versions = []string{"v1.2.3", "1.2.3+build.5"}
	SortStrings(versions)
	assert.Contains(t, versions, "v1.2.3")
	assert.Contains(t, versions, "1.2.3+build.5")
}
