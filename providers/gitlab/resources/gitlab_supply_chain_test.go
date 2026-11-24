// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

func TestPagesDomainCertificate(t *testing.T) {
	// Synthetic: Pages domain certificates as the Pages domains API documents
	// them; no target was read.
	t.Run("no certificate reads as null, not as unexpired", func(t *testing.T) {
		subject, expiresAt, expired := pagesDomainCertificate(gitlab.PagesDomainCertificate{})
		assert.Nil(t, subject.Value)
		assert.Nil(t, expiresAt.Value)
		assert.Nil(t, expired.Value)
	})

	t.Run("a certificate reports its subject and expiry", func(t *testing.T) {
		expiry := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
		subject, expiresAt, expired := pagesDomainCertificate(gitlab.PagesDomainCertificate{
			Subject:    "/CN=www.example.com",
			Expiration: &expiry,
			Expired:    true,
		})
		assert.Equal(t, "/CN=www.example.com", subject.Value)
		assert.Equal(t, &expiry, expiresAt.Value)
		assert.Equal(t, true, expired.Value)
	})
}

func TestDependencyIDDistinguishesDeclarations(t *testing.T) {
	// Synthetic: the dependency list has no id, so the key is built from the
	// fields that tell two entries apart.
	base := &gitlab.Dependency{Name: "lodash", Version: "4.17.21", PackageManager: "npm", DependencyFilePath: "package-lock.json"}
	otherVersion := &gitlab.Dependency{Name: "lodash", Version: "4.17.20", PackageManager: "npm", DependencyFilePath: "package-lock.json"}
	otherFile := &gitlab.Dependency{Name: "lodash", Version: "4.17.21", PackageManager: "npm", DependencyFilePath: "web/package-lock.json"}
	otherManager := &gitlab.Dependency{Name: "lodash", Version: "4.17.21", PackageManager: "yarn", DependencyFilePath: "package-lock.json"}

	assert.NotEqual(t, dependencyID(1, base), dependencyID(2, base), "the same package in two projects")
	assert.NotEqual(t, dependencyID(1, base), dependencyID(1, otherVersion))
	assert.NotEqual(t, dependencyID(1, base), dependencyID(1, otherFile))
	assert.NotEqual(t, dependencyID(1, base), dependencyID(1, otherManager))
	assert.Equal(t, dependencyID(1, base), dependencyID(1, &gitlab.Dependency{Name: "lodash", Version: "4.17.21", PackageManager: "npm", DependencyFilePath: "package-lock.json"}))
}

func TestDependencyLicenseNames(t *testing.T) {
	// Synthetic: license entries including the empty and nil cases.
	names := dependencyLicenseNames([]*gitlab.DependencyLicense{
		{Name: "MIT", URL: "https://spdx.org/licenses/MIT.html"},
		nil,
		{Name: ""},
		{Name: "Apache-2.0"},
	})
	assert.Equal(t, []any{"MIT", "Apache-2.0"}, names)
	assert.NotNil(t, dependencyLicenseNames(nil), "no licenses is an empty list, not null")
}

func TestVulnerabilityGID(t *testing.T) {
	// Synthetic: GraphQL global id format GitLab uses for vulnerabilities.
	assert.Equal(t, "gid://gitlab/Vulnerability/42", vulnerabilityGID(42))
}
