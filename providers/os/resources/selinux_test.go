// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestParseSelinuxConfig(t *testing.T) {
	t.Run("standard config", func(t *testing.T) {
		content := `# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
SELINUX=enforcing
# SELINUXTYPE= can take one of three values:
#     targeted - Targeted processes are protected,
#     minimum - Modification of targeted policy. Only selected processes are protected.
#     mls - Multi Level Security protection.
SELINUXTYPE=targeted
`
		mode, policyType := ParseSelinuxConfig(content)
		require.Equal(t, "enforcing", mode)
		require.Equal(t, "targeted", policyType)
	})

	t.Run("permissive mls", func(t *testing.T) {
		content := `SELINUX=permissive
SELINUXTYPE=mls
`
		mode, policyType := ParseSelinuxConfig(content)
		require.Equal(t, "permissive", mode)
		require.Equal(t, "mls", policyType)
	})

	t.Run("disabled", func(t *testing.T) {
		content := `SELINUX=disabled
SELINUXTYPE=targeted
`
		mode, policyType := ParseSelinuxConfig(content)
		require.Equal(t, "disabled", mode)
		require.Equal(t, "targeted", policyType)
	})

	t.Run("empty content", func(t *testing.T) {
		mode, policyType := ParseSelinuxConfig("")
		require.Equal(t, "", mode)
		require.Equal(t, "", policyType)
	})

	t.Run("comments only", func(t *testing.T) {
		mode, policyType := ParseSelinuxConfig("# SELINUX=enforcing\n# SELINUXTYPE=targeted\n")
		require.Equal(t, "", mode)
		require.Equal(t, "", policyType)
	})
}

func TestParseGetsebool(t *testing.T) {
	t.Run("standard output", func(t *testing.T) {
		output := `abrt_anon_write --> off
abrt_handle_event --> off
httpd_can_network_connect --> on
httpd_enable_cgi --> on
virt_sandbox_use_all_caps --> off
`
		bools := ParseGetsebool(output)
		require.Len(t, bools, 5)

		require.Equal(t, SELinuxBool{Name: "abrt_anon_write", Value: false}, bools[0])
		require.Equal(t, SELinuxBool{Name: "httpd_can_network_connect", Value: true}, bools[2])
		require.Equal(t, SELinuxBool{Name: "httpd_enable_cgi", Value: true}, bools[3])
	})

	t.Run("empty output", func(t *testing.T) {
		bools := ParseGetsebool("")
		require.Nil(t, bools)
	})
}

func TestParseSemodule(t *testing.T) {
	t.Run("simple format", func(t *testing.T) {
		output := `abrt
accountsd
apache
`
		modules := ParseSemodule(output)
		require.Len(t, modules, 3)

		require.Equal(t, SELinuxModule{Name: "abrt", Status: "enabled"}, modules[0])
		require.Equal(t, SELinuxModule{Name: "accountsd", Status: "enabled"}, modules[1])
		require.Equal(t, SELinuxModule{Name: "apache", Status: "enabled"}, modules[2])
	})

	t.Run("priority format", func(t *testing.T) {
		output := `100 abrt
100 accountsd
200 custom_policy
`
		modules := ParseSemodule(output)
		require.Len(t, modules, 3)

		require.Equal(t, SELinuxModule{Name: "abrt", Priority: 100, Status: "enabled"}, modules[0])
		require.Equal(t, SELinuxModule{Name: "custom_policy", Priority: 200, Status: "enabled"}, modules[2])
	})

	t.Run("full format with status", func(t *testing.T) {
		output := `100 abrt enabled
100 accountsd enabled
200 custom_policy disabled
`
		modules := ParseSemodule(output)
		require.Len(t, modules, 3)

		require.Equal(t, SELinuxModule{Name: "abrt", Priority: 100, Status: "enabled"}, modules[0])
		require.Equal(t, SELinuxModule{Name: "custom_policy", Priority: 200, Status: "disabled"}, modules[2])
	})

	t.Run("empty output", func(t *testing.T) {
		modules := ParseSemodule("")
		require.Nil(t, modules)
	})
}

func TestReadSelinuxBooleansFromFS(t *testing.T) {
	t.Run("reads booleans from sysfs", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		_ = fs.MkdirAll("/sys/fs/selinux/booleans", 0o755)
		_ = afero.WriteFile(fs, "/sys/fs/selinux/booleans/httpd_can_network_connect", []byte("1"), 0o444)
		_ = afero.WriteFile(fs, "/sys/fs/selinux/booleans/httpd_enable_cgi", []byte("0"), 0o444)
		_ = afero.WriteFile(fs, "/sys/fs/selinux/booleans/virt_sandbox_use_all_caps", []byte("0\n"), 0o444)

		bools, read := readSelinuxBooleansFromFS(fs)
		require.True(t, read)
		require.Len(t, bools, 3)

		// afero.ReadDir returns sorted entries
		require.Equal(t, "httpd_can_network_connect", bools[0].Name)
		require.True(t, bools[0].Value)
		require.Equal(t, "httpd_enable_cgi", bools[1].Name)
		require.False(t, bools[1].Value)
		require.Equal(t, "virt_sandbox_use_all_caps", bools[2].Name)
		require.False(t, bools[2].Value)
	})

	// A missing directory and an empty one are different answers: the first
	// means selinuxfs was never readable, the second that it is mounted and
	// reports no booleans. selinux.booleans turns the first into a null list
	// and the second into an empty one, so the bool has to distinguish them.
	t.Run("missing directory reports not read", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		bools, read := readSelinuxBooleansFromFS(fs)
		require.False(t, read)
		require.Nil(t, bools)
	})

	t.Run("empty directory reports read with no booleans", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		_ = fs.MkdirAll("/sys/fs/selinux/booleans", 0o755)
		bools, read := readSelinuxBooleansFromFS(fs)
		require.True(t, read)
		require.Empty(t, bools)
	})
}
