// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func TestCollapse(t *testing.T) {
	pkgs := []*languages.Package{
		// Declared in required_providers, with only a constraint.
		{Name: "hashicorp/aws", Purl: "pkg:terraform/hashicorp/aws"},
		// Resolved in the lock file.
		{Name: "hashicorp/aws", Version: "5.31.0", Purl: "pkg:terraform/hashicorp/aws@5.31.0"},
		// Declared but never locked — no lock file was committed.
		{Name: "kreuzwerker/docker", Purl: "pkg:terraform/kreuzwerker/docker"},
		// The same module reached through the configuration and the manifest.
		{Name: "terraform-aws-modules/vpc/aws", Version: "5.1.2", Purl: "pkg:terraform-module/terraform-aws-modules/vpc@5.1.2?target_system=aws"},
		{Name: "terraform-aws-modules/vpc/aws", Version: "5.1.2", Purl: "pkg:terraform-module/terraform-aws-modules/vpc@5.1.2?target_system=aws"},
	}

	got := Collapse(pkgs)

	var names []string
	for _, p := range got {
		names = append(names, p.Name+"@"+p.Version)
	}
	assert.Equal(t, []string{
		"hashicorp/aws@5.31.0",
		"kreuzwerker/docker@",
		"terraform-aws-modules/vpc/aws@5.1.2",
	}, names)
}
