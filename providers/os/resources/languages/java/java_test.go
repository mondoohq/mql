// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPackageUrl(t *testing.T) {
	tests := []struct {
		groupId    string
		artifactId string
		version    string
		expected   string
	}{
		{"org.apache.commons", "commons-lang3", "3.12.0", "pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
		{"com.google.guava", "guava", "31.1-jre", "pkg:maven/com.google.guava/guava@31.1-jre"},
		{"junit", "junit", "4.13.2", "pkg:maven/junit/junit@4.13.2"},
	}

	for _, tt := range tests {
		t.Run(tt.artifactId, func(t *testing.T) {
			result := NewPackageUrl(tt.groupId, tt.artifactId, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVendorFromGroupId(t *testing.T) {
	tests := []struct {
		groupId  string
		expected string
	}{
		{"org.apache.commons", "apache"},
		{"com.google.guava", "google"},
		{"io.netty", "netty"},
		{"junit", "junit"},
		{"org.springframework", "springframework"},
		{"net.sf.ehcache", "sf"},
	}

	for _, tt := range tests {
		t.Run(tt.groupId, func(t *testing.T) {
			result := vendorFromGroupId(tt.groupId)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewCpes(t *testing.T) {
	cpes := NewCpes("org.apache.commons", "commons-lang3", "3.12.0")
	assert.NotEmpty(t, cpes)
	assert.Contains(t, cpes[0], "commons-lang3")
	assert.Contains(t, cpes[0], "3.12.0")
}

// A dynamic version or a range names a set of releases rather than one, so it
// is not recorded as a version at all: a purl carrying "1.+" matches no release
// while reading downstream as a definite claim about what is installed.
//
// Shared by every Java manifest reader, so the rule is pinned once here rather
// than once per extractor, where two copies would drift.
func TestConcreteVersion(t *testing.T) {
	for _, in := range []string{"1.2.3", " 1.2.3 ", "4.12.0", "2.0.0-SNAPSHOT"} {
		assert.Equal(t, strings.TrimSpace(in), ConcreteVersion(in), "concrete: %q", in)
	}
	for _, in := range []string{"1.+", "[1.0, 2.0[", "(1.0, 2.0)", "latest.release", "latest.integration", ""} {
		assert.Empty(t, ConcreteVersion(in), "names a set, not a release: %q", in)
	}
}
