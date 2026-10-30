// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
)

func TestSSHKeyNames(t *testing.T) {
	assert.Empty(t, sshKeyNames(nil, nil))
	assert.Equal(t, []string{"a", "b"}, sshKeyNames(&v3.SSHKey{Name: "a"}, []v3.SSHKey{{Name: "a"}, {Name: "b"}}))
	assert.Equal(t, []string{"b"}, sshKeyNames(&v3.SSHKey{}, []v3.SSHKey{{Name: "b"}, {Name: ""}}))
}
