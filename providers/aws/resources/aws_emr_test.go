// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestEmrStepAdditionalInfo(t *testing.T) {
	t.Run("absent info is null", func(t *testing.T) {
		// Synthetic: steps EMR reports without additional info.
		rm, ids := emrStepAdditionalInfo(nil)
		assert.Equal(t, llx.NilData, rm)
		assert.Equal(t, llx.NilData, ids)
	})

	t.Run("resource manager and application ids", func(t *testing.T) {
		// Synthetic: field shape from the v1.71.1 SDK types; no target showed this.
		rm, ids := emrStepAdditionalInfo(&emrtypes.StepAdditionalInfo{
			ResourceManager:               aws.String("ip-10-0-0-1.ec2.internal:8032"),
			ResourceManagerApplicationIds: []string{"application_1700000000000_0001", "application_1700000000000_0002"},
		})
		assert.Equal(t, "ip-10-0-0-1.ec2.internal:8032", rm.Value)
		assert.Equal(t, []any{"application_1700000000000_0001", "application_1700000000000_0002"}, ids.Value)
	})

	t.Run("resource manager without application ids", func(t *testing.T) {
		// Synthetic: info present, id list absent.
		rm, ids := emrStepAdditionalInfo(&emrtypes.StepAdditionalInfo{ResourceManager: aws.String("rm")})
		assert.Equal(t, "rm", rm.Value)
		assert.Equal(t, llx.NilData, ids)
	})
}
