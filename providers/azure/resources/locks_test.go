// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLockScopeFromID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "subscription-level lock",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/locks/no-delete",
			want: "/subscriptions/00000000-0000-0000-0000-000000000000",
		},
		{
			name: "resource group lock",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Authorization/locks/rg-lock",
			want: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod",
		},
		{
			name: "resource lock keeps the resource's own provider segment",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/sa1/providers/Microsoft.Authorization/locks/sa-lock",
			want: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/sa1",
		},
		{
			name: "casing as returned by ARM is tolerated",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-prod/providers/microsoft.authorization/LOCKS/rg-lock",
			want: "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-prod",
		},
		{
			name: "a lock named like the provider path does not confuse the split",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/locks/locks",
			want: "/subscriptions/00000000-0000-0000-0000-000000000000",
		},
		{
			name: "id without the lock provider path yields nothing",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-prod",
			want: "",
		},
		{
			name: "empty id",
			id:   "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, lockScopeFromID(c.id))
		})
	}
}
