// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

func TestShareFullyQualifiedName(t *testing.T) {
	// OWNER_ACCOUNT is reported as ORG.ACCOUNT.
	assert.Equal(t, `"MYORG"."PROVIDER"."SALES_SHARE"`, shareFullyQualifiedName(sdk.Share{
		OwnerAccount: "MYORG.PROVIDER",
		Name:         "SALES_SHARE",
	}))

	// The same share name from a different owner must not collide.
	assert.NotEqual(t,
		shareFullyQualifiedName(sdk.Share{OwnerAccount: "MYORG.A", Name: "S"}),
		shareFullyQualifiedName(sdk.Share{OwnerAccount: "MYORG.B", Name: "S"}),
	)
}
