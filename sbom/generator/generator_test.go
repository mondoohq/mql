// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPurlType(t *testing.T) {
	assert.Equal(t, "terraform", purlType("pkg:terraform/hashicorp/aws@5.31.0", "terraform"))
	assert.Equal(t, "opentofu", purlType("pkg:opentofu/hashicorp/aws@5.31.0", "terraform"))
	assert.Equal(t, "terraform-module", purlType("pkg:terraform-module/acme/vpc@1.0.0?target_system=aws", "terraform"))
	assert.Equal(t, "generic", purlType("pkg:generic/github.com/acme/mods@v1", "terraform"))
	// A package with no purl keeps the ecosystem's own label.
	assert.Equal(t, "terraform", purlType("", "terraform"))
	assert.Equal(t, "terraform", purlType("not-a-purl", "terraform"))
}
