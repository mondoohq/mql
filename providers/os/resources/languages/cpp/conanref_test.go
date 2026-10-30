// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseConanRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want ConanCoordinate
		ok   bool
	}{
		{"plain", "boost/1.84.0", ConanCoordinate{Name: "boost", Version: "1.84.0"}, true},
		{"revision", "boost/1.84.0#abc123",
			ConanCoordinate{Name: "boost", Version: "1.84.0", Revision: "abc123"}, true},
		{"user and channel", "boost/1.84.0@acme/stable",
			ConanCoordinate{Name: "boost", Version: "1.84.0", User: "acme", Channel: "stable"}, true},
		{"user, channel and revision", "boost/1.84.0@acme/stable#rev",
			ConanCoordinate{Name: "boost", Version: "1.84.0", User: "acme", Channel: "stable", Revision: "rev"}, true},
		// A v2 lockfile appends the recipe timestamp after the revision.
		{"revision and timestamp", "zlib/1.3.1#def456%1700000000",
			ConanCoordinate{Name: "zlib", Version: "1.3.1", Revision: "def456"}, true},
		// A bare trailing @ is the legal no-user form, not a parse failure.
		{"empty user/channel", "zlib/1.3.1@", ConanCoordinate{Name: "zlib", Version: "1.3.1"}, true},
		{"user without channel", "zlib/1.3.1@acme",
			ConanCoordinate{Name: "zlib", Version: "1.3.1", User: "acme"}, true},
		{"version range", "fmt/[>=9.0]", ConanCoordinate{Name: "fmt", Version: "[>=9.0]"}, true},
		{"surrounding space", "  boost/1.84.0  ", ConanCoordinate{Name: "boost", Version: "1.84.0"}, true},
		{"empty", "", ConanCoordinate{}, false},
		{"no version", "noversion", ConanCoordinate{}, false},
		{"empty version", "name/", ConanCoordinate{}, false},
		{"empty name", "/1.0", ConanCoordinate{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseConanRef(tt.ref)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestResolvedVersion pins that a RANGE is not reported as a version. Conan
// writes ranges in brackets, and "[>=9.0]" as a version matches no advisory
// while reading in a report as though it were one.
func TestResolvedVersion(t *testing.T) {
	exact, _ := ParseConanRef("fmt/10.2.1")
	assert.Equal(t, "10.2.1", exact.ResolvedVersion())

	for _, ref := range []string{"fmt/[>=9.0]", "zlib/[*]", "boost/[>1 <2]"} {
		c, ok := ParseConanRef(ref)
		assert.True(t, ok, ref)
		assert.Empty(t, c.ResolvedVersion(), "%s: a range is not a version", ref)
	}
}

func TestNewConanPackageUrl(t *testing.T) {
	tests := []struct {
		name string
		in   ConanCoordinate
		want string
	}{
		{"plain", ConanCoordinate{Name: "zlib", Version: "1.3.1"}, "pkg:conan/zlib@1.3.1"},
		// The user is the namespace and the channel a qualifier: a package from
		// a private channel is not the ConanCenter package of that name.
		{"user and channel",
			ConanCoordinate{Name: "mylib", Version: "2.0", User: "acme", Channel: "stable"},
			"pkg:conan/acme/mylib@2.0?channel=stable"},
		{"user only", ConanCoordinate{Name: "mylib", Version: "2.0", User: "acme"},
			"pkg:conan/acme/mylib@2.0"},
		// The spec requires a namespace alongside a channel; a channel with no
		// user cannot round-trip, so it is dropped rather than emitted.
		{"channel without user", ConanCoordinate{Name: "mylib", Version: "2.0", Channel: "stable"},
			"pkg:conan/mylib@2.0"},
		// No advisory states a recipe revision, so carrying one could only turn
		// a match into a miss.
		{"revision is omitted",
			ConanCoordinate{Name: "zlib", Version: "1.3.1", Revision: "abc123"},
			"pkg:conan/zlib@1.3.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewConanPackageUrl(tt.in))
		})
	}
}

// TestNewVcpkgPackageUrlWithQualifiers pins that a version>= floor rides as a
// qualifier and never as the version — vcpkg resolves through the baseline,
// routinely above the floor.
func TestNewVcpkgPackageUrlWithQualifiers(t *testing.T) {
	assert.Equal(t, "pkg:vcpkg/fmt", NewVcpkgPackageUrl("fmt", ""))
	assert.Equal(t, "pkg:vcpkg/fmt@10.2.1", NewVcpkgPackageUrl("fmt", "10.2.1"))
	assert.Equal(t, "pkg:vcpkg/openssl?version_min=3.0.8",
		NewVcpkgPackageUrlWithQualifiers("openssl", "", map[string]string{"version_min": "3.0.8"}))
}
