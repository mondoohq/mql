// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestAixDevice(t *testing.T) {
	out, err := os.ReadFile("aix/testdata/lsattr_sys0_aix73.txt")
	require.NoError(t, err)
	rt := newAixRuntime(t, aixPlatform, nil, map[string]*mock.Command{
		`lsattr -El sys0 -F "attribute value"`: {Stdout: string(out)},
	})
	r, err := NewResource(rt, "aix.device", map[string]*llx.RawData{"name": llx.StringData("sys0")})
	require.NoError(t, err)
	attrs := r.(*mqlAixDevice).GetAttributes()
	require.NoError(t, attrs.Error)
	assert.Equal(t, "true", attrs.Data["fullcore"])
}

// The name reaches a command, so anything but a device name is rejected.
func TestAixDeviceRejectsInjection(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, nil, nil)
	_, err := NewResource(rt, "aix.device", map[string]*llx.RawData{"name": llx.StringData("sys0; rm -rf /")})
	assert.Error(t, err)
}
