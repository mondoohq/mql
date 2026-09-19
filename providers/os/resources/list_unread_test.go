// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// A list accessor cannot express "unknown" by returning a nil slice: the
// runtime writes StateIsSet with no StateIsNull, and TValue.ToDataRes then
// serializes the nil slice as an empty array. Both `return nil, nil` and
// `return []any{}, nil` reach the client as `[]`.
//
// That matters because for list assertions EMPTY is the unsafe state, not null.
// `.none(...)` and `.all(...)` over an empty list are vacuously TRUE, so a host
// where `semodule -l` or `mdadm --detail --scan` could not run used to PASS
// every assertion over data nobody read. A null list fails those same
// assertions.
//
// So each accessor below has to separate two cases that look identical in the
// return value:
//
//   - we could not read      -> StateIsSet|StateIsNull, fails closed
//   - we read, found nothing -> an empty list, a measured fact
//
// These tests pin both directions. Getting either one backwards is a bug.

func TestUnreadListIsNull(t *testing.T) {
	t.Run("mdadm.arrays: scan could not run", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {ExitStatus: 1, Stderr: "mdadm: not found"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "a failed scan must not read as `no arrays`")
	})

	t.Run("mdadm.arrays: scan listed arrays but none could be read", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan":     {Stdout: "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"},
			`mdadm --detail "/dev/md0"`: {ExitStatus: 1, Stderr: "permission denied"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "the scan found an array, so `no arrays` is false")
	})

	t.Run("selinux.modules: semodule could not run", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"semodule -l": {ExitStatus: 127, Stderr: "semodule: command not found"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("selinux.modules: no command execution", func(t *testing.T) {
		v := mustResource(t, noCommandRuntime(t), "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "an image scan never ran semodule")
	})

	t.Run("selinux.booleans: no source answered", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"getsebool -a": {ExitStatus: 127, Stderr: "getsebool: command not found"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetBooleans()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("firewalld.zones: daemon not running", func(t *testing.T) {
		// firewall-cmd can only enumerate zones through a running daemon, so a
		// stopped firewalld leaves the zone set unread rather than empty.
		rt := commandRuntime(t, map[string]*mock.Command{
			"firewall-cmd --state": {ExitStatus: 252, Stderr: "not running"},
		})
		f := mustResource(t, rt, "firewalld").(*mqlFirewalld)
		require.Equal(t, "not running", f.GetStatus().Data)
		v := f.GetZones()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull())
	})

	t.Run("containerd.containers: every namespace refused", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"ctr namespaces list -q":            {Stdout: "default\n"},
			"ctr -n default containers list -q": {ExitStatus: 1, Stderr: "permission denied"},
		})
		v := mustResource(t, rt, "containerd").(*mqlContainerd).GetContainers()
		require.NoError(t, v.Error)
		assert.True(t, v.IsNull(), "we listed no containers because we were refused, not because there are none")
	})
}

func TestMeasuredEmptyListStaysEmpty(t *testing.T) {
	t.Run("mdadm.arrays: scan ran and listed nothing", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {Stdout: ""},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		assert.False(t, v.IsNull(), "exit 0 with no ARRAY lines is a measured `no arrays`")
		assert.Empty(t, v.Data)
	})

	t.Run("selinux.modules: semodule ran and listed nothing", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"semodule -l": {Stdout: "\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		assert.False(t, v.IsNull())
		assert.Empty(t, v.Data)
	})

	t.Run("containerd.containers: no namespaces", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"ctr namespaces list -q": {Stdout: ""},
		})
		v := mustResource(t, rt, "containerd").(*mqlContainerd).GetContainers()
		require.NoError(t, v.Error)
		assert.False(t, v.IsNull())
		assert.Empty(t, v.Data)
	})
}

func TestReadListIsPopulated(t *testing.T) {
	t.Run("mdadm.arrays", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"mdadm --detail --scan": {Stdout: "ARRAY /dev/md0 metadata=1.2 UUID=abc\n"},
			`mdadm --detail "/dev/md0"`: {Stdout: "" +
				"/dev/md0:\n" +
				"     Raid Level : raid1\n" +
				"          State : clean\n" +
				" Active Devices : 2\n"},
		})
		v := mustResource(t, rt, "mdadm").(*mqlMdadm).GetArrays()
		require.NoError(t, v.Error)
		require.False(t, v.IsNull())
		require.Len(t, v.Data, 1)
		arr := v.Data[0].(*mqlMdadmArray)
		assert.Equal(t, "/dev/md0", arr.Name.Data)
		assert.Equal(t, "raid1", arr.Level.Data)
		assert.Equal(t, "clean", arr.State.Data)
	})

	t.Run("selinux.modules", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"semodule -l": {Stdout: "100 zebra enabled\n200 apache disabled\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetModules()
		require.NoError(t, v.Error)
		require.False(t, v.IsNull())
		require.Len(t, v.Data, 2)
		assert.Equal(t, "zebra", v.Data[0].(*mqlSelinuxModule).Name.Data)
		assert.Equal(t, "disabled", v.Data[1].(*mqlSelinuxModule).Status.Data)
	})

	t.Run("selinux.booleans", func(t *testing.T) {
		rt := commandRuntime(t, map[string]*mock.Command{
			"getsebool -a": {Stdout: "httpd_can_network_connect --> on\nhttpd_enable_cgi --> off\n"},
		})
		v := mustResource(t, rt, "selinux").(*mqlSelinux).GetBooleans()
		require.NoError(t, v.Error)
		require.False(t, v.IsNull())
		require.Len(t, v.Data, 2)
		assert.True(t, v.Data[0].(*mqlSelinuxBoolean).Value.Data)
		assert.False(t, v.Data[1].(*mqlSelinuxBoolean).Value.Data)
	})
}
