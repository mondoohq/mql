// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckOwnerFilledResourcesArePrivate(t *testing.T) {
	tests := []struct {
		name    string
		lr      string
		wantErr string
	}{
		{
			name: "public, data-only, shadows its accessor",
			lr: `windows {
  deviceGuard() windows.deviceGuard
}
windows.deviceGuard {
  credentialGuardConfig int
}`,
			wantErr: "resource windows.deviceGuard is public",
		},
		{
			name: "same but private",
			lr: `windows {
  deviceGuard() windows.deviceGuard
}
private windows.deviceGuard {
  credentialGuardConfig int
}`,
		},
		{
			name: "one lazy field is enough to fill itself",
			lr: `windows {
  lsa() windows.lsa
}
windows.lsa {
  forceGuest() bool
  noLmHash bool
}`,
		},
		{
			name: "accessor has a different name, so the path is not shadowed",
			lr: `windows.defender.preferences {
  cloudProtection() windows.defender.cloudSettings
}
windows.defender.cloudSettings {
  mapsReporting int
}`,
		},
		{
			name: "reached as a list entry, not a singleton accessor",
			lr: `windows {
  printerDrivers() []windows.printerDriver
}
windows.printerDriver {
  name string
}`,
		},
		{
			name: "owner is synthesized, so there is no accessor to route through",
			lr: `container.repository {
  registry string
}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ast := parse(t, test.lr)
			b := goBuilder{ast: ast, collector: &Collector{}}
			b.checkOwnerFilledResourcesArePrivate(ast.Resources)
			err := b.errors.Deduplicate()

			if test.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantErr)
			assert.Contains(t, err.Error(), "Mark the resource `private`")
		})
	}
}
