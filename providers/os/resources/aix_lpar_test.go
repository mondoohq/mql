// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func aixLpar(t *testing.T, out string) *mqlAixLpar {
	t.Helper()
	rt := newAixRuntime(t, aixPlatform, nil, map[string]*mock.Command{
		"lparstat -i": {Stdout: out},
	})
	r, err := CreateResource(rt, "aix.lpar", map[string]*llx.RawData{})
	require.NoError(t, err)
	return r.(*mqlAixLpar)
}

func aixLparFixture(t *testing.T, name string) *mqlAixLpar {
	t.Helper()
	out, err := os.ReadFile("aix/testdata/" + name)
	require.NoError(t, err)
	return aixLpar(t, string(out))
}

// The shared partition shown in IBM's Micro-Partitioning course material.
func TestAixLparShared(t *testing.T) {
	l := aixLparFixture(t, "lparstat_i_shared_ibm.txt")
	assert.Equal(t, "LPAR2", l.GetPartitionName().Data)
	assert.Equal(t, int64(2), l.GetPartitionNumber().Data)
	assert.Equal(t, "Shared-SMT", l.GetType().Data)
	assert.Equal(t, "Capped", l.GetMode().Data)
	assert.Equal(t, 0.5, l.GetEntitledCapacity().Data)
	assert.Equal(t, int64(1), l.GetOnlineVirtualCpus().Data)
	assert.Equal(t, int64(2), l.GetMaxVirtualCpus().Data)
	assert.Equal(t, int64(2), l.GetSmtThreads().Data)

	pool := l.GetSharedPoolId()
	require.NoError(t, pool.Error)
	assert.False(t, pool.IsNull(), "pool 0 is a real pool, not null")
	assert.Equal(t, int64(0), pool.Data)

	assert.Equal(t, int64(1280*1024*1024), l.GetOnlineMemoryBytes().Data)
}

func TestAixLparDedicated(t *testing.T) {
	l := aixLparFixture(t, "lparstat_i_dedicated.txt")
	assert.Equal(t, "Dedicated-SMT-8", l.GetType().Data)
	assert.Equal(t, "Donating", l.GetMode().Data)
	assert.Equal(t, 4.0, l.GetEntitledCapacity().Data)
	assert.Equal(t, int64(8), l.GetSmtThreads().Data)
	assert.Equal(t, int64(32768*1024*1024), l.GetOnlineMemoryBytes().Data)

	pool := l.GetSharedPoolId()
	require.NoError(t, pool.Error)
	assert.True(t, pool.IsNull())
}

func TestAixLparMissingFields(t *testing.T) {
	l := aixLpar(t, "Partition Name : lpar9\nType : Shared\nOnline Memory : lots\n")
	assert.Equal(t, "lpar9", l.GetPartitionName().Data)
	assert.Equal(t, int64(1), l.GetSmtThreads().Data)
	for name, field := range map[string]interface{ IsNull() bool }{
		"partitionNumber":   l.GetPartitionNumber(),
		"mode":              l.GetMode(),
		"entitledCapacity":  l.GetEntitledCapacity(),
		"onlineVirtualCpus": l.GetOnlineVirtualCpus(),
		"maxVirtualCpus":    l.GetMaxVirtualCpus(),
		"sharedPoolId":      l.GetSharedPoolId(),
		"onlineMemoryBytes": l.GetOnlineMemoryBytes(),
	} {
		assert.True(t, field.IsNull(), name)
	}
}

func TestAixLparNotAix(t *testing.T) {
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	rt := newAixRuntime(t, linux, nil, nil)
	r, err := CreateResource(rt, "aix.lpar", map[string]*llx.RawData{})
	require.NoError(t, err)
	name := r.(*mqlAixLpar).GetPartitionName()
	require.Error(t, name.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(name.Error))
}
