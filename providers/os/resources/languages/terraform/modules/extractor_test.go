// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package modules

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerraformModuleManifest(t *testing.T) {
	f, err := os.Open("./testdata/modules.json")
	require.NoError(t, err)
	defer f.Close()

	bom, err := (&Extractor{}).Parse(f, ".terraform/modules/modules.json")
	require.NoError(t, err)
	assert.Nil(t, bom.Root())

	// An unqualified key is a module this configuration calls itself.
	direct := bom.Direct()
	require.Equal(t, 2, len(direct))
	vpc := direct.Find("terraform-aws-modules/vpc/aws")
	require.NotNil(t, vpc)
	assert.Equal(t, "5.1.2", vpc.Version)
	assert.Equal(t, "pkg:terraform-module/terraform-aws-modules/vpc@5.1.2?target_system=aws", vpc.Purl)
	assert.NotNil(t, direct.Find("github.com/acme/terraform-platform"))
	// The local "shared" call is not a third-party artifact.
	assert.Nil(t, direct.Find("./modules/shared"))

	// A dotted key is a module that a dependency called.
	transitive := bom.Transitive()
	require.Equal(t, 1, len(transitive))
	sg := transitive.Find("terraform-aws-modules/security-group/aws")
	require.NotNil(t, sg)
	assert.Equal(t, "5.1.0", sg.Version)
	// vpc.subnets is a path inside the vpc module, not a separate artifact.
	assert.Nil(t, transitive.Find("./modules/subnets"))
}
