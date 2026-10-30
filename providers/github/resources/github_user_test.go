// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestGithubCollaboratorID(t *testing.T) {
	tests := []struct {
		name string
		id   int64
		want string
	}{
		{name: "non-zero id", id: 42, want: "github.collaborator/42"},
		{name: "zero id", id: 0, want: "github.collaborator/0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &mqlGithubCollaborator{Id: plugin.TValue[int64]{Data: tc.id, State: plugin.StateIsSet}}
			got, err := c.id()
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGithubInstallationID(t *testing.T) {
	i := &mqlGithubInstallation{Id: plugin.TValue[int64]{Data: 7, State: plugin.StateIsSet}}
	got, err := i.id()
	assert.NoError(t, err)
	assert.Equal(t, "github.installation/7", got)
}
