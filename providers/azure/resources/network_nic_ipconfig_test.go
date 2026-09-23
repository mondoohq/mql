// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/stretchr/testify/assert"
)

func TestAppSecurityGroupIDs(t *testing.T) {
	t.Run("nil slice yields nil", func(t *testing.T) {
		assert.Nil(t, appSecurityGroupIDs(nil))
	})

	t.Run("skips nil items and nil IDs", func(t *testing.T) {
		items := []*network.ApplicationSecurityGroup{
			{ID: strPtr("/asgs/web")},
			nil,
			{ID: nil},
			{ID: strPtr("/asgs/db")},
		}
		assert.Equal(t, []string{"/asgs/web", "/asgs/db"}, appSecurityGroupIDs(items))
	})
}
