// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/osmanagementhub"
	"github.com/stretchr/testify/assert"
)

func TestOciManagedInstanceArgs(t *testing.T) {
	t.Run("counts and flags the listing omits read null", func(t *testing.T) {
		args := ociManagedInstanceArgs(&osmanagementhub.ManagedInstanceSummary{
			Id:     common.String("ocid1.instance.oc1..a"),
			Status: osmanagementhub.ManagedInstanceStatusUnreachable,
		})
		// Zero updates would claim the host is fully patched.
		assert.Nil(t, args["updatesAvailable"].Value)
		assert.Nil(t, args["isRebootRequired"].Value)
		assert.Equal(t, "UNREACHABLE", args["status"].Value)
	})

	t.Run("reported values are kept", func(t *testing.T) {
		args := ociManagedInstanceArgs(&osmanagementhub.ManagedInstanceSummary{
			Id:               common.String("ocid1.instance.oc1..b"),
			Location:         osmanagementhub.ManagedInstanceLocationOciCompute,
			OsFamily:         osmanagementhub.OsFamilyOracleLinux9,
			UpdatesAvailable: common.Int(12),
			IsRebootRequired: common.Bool(true),
		})
		assert.Equal(t, int64(12), args["updatesAvailable"].Value)
		assert.Equal(t, true, args["isRebootRequired"].Value)
		assert.Equal(t, "OCI_COMPUTE", args["location"].Value)
		assert.Equal(t, "ORACLE_LINUX_9", args["osFamily"].Value)
	})
}
