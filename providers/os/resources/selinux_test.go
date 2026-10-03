// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
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

		require.Equal(t, SELinuxModule{Name: "abrt", Priority: intPtr(100), Status: "enabled"}, modules[0])
		require.Equal(t, SELinuxModule{Name: "custom_policy", Priority: intPtr(200), Status: "enabled"}, modules[2])
	})

	t.Run("full format with status", func(t *testing.T) {
		output := `100 abrt enabled
100 accountsd enabled
200 custom_policy disabled
`
		modules := ParseSemodule(output)
		require.Len(t, modules, 3)

		require.Equal(t, SELinuxModule{Name: "abrt", Priority: intPtr(100), Status: "enabled"}, modules[0])
		require.Equal(t, SELinuxModule{Name: "custom_policy", Priority: intPtr(200), Status: "disabled"}, modules[2])
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

		bools := readSelinuxBooleansFromFS(fs)
		require.Len(t, bools, 3)

		// afero.ReadDir returns sorted entries
		require.Equal(t, "httpd_can_network_connect", bools[0].Name)
		require.True(t, bools[0].Value)
		require.Equal(t, "httpd_enable_cgi", bools[1].Name)
		require.False(t, bools[1].Value)
		require.Equal(t, "virt_sandbox_use_all_caps", bools[2].Name)
		require.False(t, bools[2].Value)
	})

	t.Run("missing directory returns nil", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		bools := readSelinuxBooleansFromFS(fs)
		require.Nil(t, bools)
	})

	t.Run("empty directory returns nil", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		_ = fs.MkdirAll("/sys/fs/selinux/booleans", 0o755)
		bools := readSelinuxBooleansFromFS(fs)
		require.Nil(t, bools)
	})
}

func intPtr(i int) *int { return &i }

// Output captured from `semodule --list-modules=full` and `semodule -l` on
// RHEL 9 (policycoreutils 3.6) and RHEL 7 (2.5), with a module installed at
// priority 400 and zosremote disabled.
func TestParseSemoduleListings(t *testing.T) {
	t.Run("full listing on RHEL 9", func(t *testing.T) {
		output := "400 permissive_rhcd_t cil         \n" +
			"400 sweeppol          pp          \n" +
			"200 container         pp          \n" +
			"100 abrt              pp          \n" +
			"100 zosremote         pp  disabled\n"
		modules := ParseSemodule(output)
		require.Len(t, modules, 5)
		assert.Equal(t, SELinuxModule{Name: "sweeppol", Priority: intPtr(400), Status: "enabled"}, modules[1])
		assert.Equal(t, SELinuxModule{Name: "abrt", Priority: intPtr(100), Status: "enabled"}, modules[3])
		assert.Equal(t, SELinuxModule{Name: "zosremote", Priority: intPtr(100), Status: "disabled"}, modules[4])
	})

	t.Run("full listing on RHEL 7", func(t *testing.T) {
		output := "400 sweeppol          pp         \n" +
			"100 abrt              pp         \n" +
			"100 zosremote         pp disabled\n"
		modules := ParseSemodule(output)
		require.Len(t, modules, 3)
		assert.Equal(t, SELinuxModule{Name: "sweeppol", Priority: intPtr(400), Status: "enabled"}, modules[0])
		assert.Equal(t, SELinuxModule{Name: "zosremote", Priority: intPtr(100), Status: "disabled"}, modules[2])
	})

	t.Run("RHEL 7 semodule -l prints versions, not a status", func(t *testing.T) {
		modules := ParseSemodule("abrt\t1.4.1\nsweeppol\t1.0\n")
		require.Len(t, modules, 2)
		assert.Equal(t, SELinuxModule{Name: "abrt", Status: "enabled"}, modules[0])
		assert.Nil(t, modules[1].Priority)
	})

	t.Run("old semodule -l marks disabled modules", func(t *testing.T) {
		modules := ParseSemodule("zosremote\t1.2.0\tDisabled\n")
		require.Len(t, modules, 1)
		assert.Equal(t, "disabled", modules[0].Status)
	})
}

// /sys/fs/selinux/booleans/<name> holds the current and the pending value, as
// read on RHEL 7, RHEL 9 and Fedora 44.
func TestSelinuxBooleanFileValue(t *testing.T) {
	assert.True(t, selinuxBooleanFileValue([]byte("1 1")))
	assert.False(t, selinuxBooleanFileValue([]byte("0 0")))
	// a pending change is not in effect yet
	assert.False(t, selinuxBooleanFileValue([]byte("0 1")))
	assert.True(t, selinuxBooleanFileValue([]byte("1 0")))
	assert.True(t, selinuxBooleanFileValue([]byte("1\n")))
}

// Without /sys/fs/selinux the kernel enforces nothing, which getenforce
// reports as "Disabled". Two hosts reach this: Debian 9 to 13 with the SELinux
// packages installed and SELINUX=permissive configured but booted without
// SELinux (non-root PATH has no getenforce), and SLES 15 SP7, which ships no
// SELinux at all (no getenforce, no /etc/selinux/config, no selinux in
// /sys/kernel/security/lsm).
func TestSelinuxRuntimeMode(t *testing.T) {
	mode, err := selinuxRuntimeMode(false, nil)
	require.NoError(t, err)
	assert.Equal(t, "disabled", mode)

	// RHEL with SELinux enabled: the enforce file is the running mode,
	// whatever /etc/selinux/config says
	mode, err = selinuxRuntimeMode(true, []byte("1"))
	require.NoError(t, err)
	assert.Equal(t, "enforcing", mode)

	mode, err = selinuxRuntimeMode(true, []byte("0\n"))
	require.NoError(t, err)
	assert.Equal(t, "permissive", mode)

	_, err = selinuxRuntimeMode(true, []byte(""))
	assert.Error(t, err)
}

// SLES 15 SP7 as captured live: getenforce is not installed, and neither
// /etc/selinux/config nor /sys/fs/selinux exists. Leap 15.6 with selinux-tools
// installed (but SELinux not enabled at boot) has getenforce, which prints
// "Disabled". Both kernels enforce nothing and must read the same.
func TestSelinuxModeWithoutSelinux(t *testing.T) {
	sles15 := &inventory.Asset{
		Platform: &inventory.Platform{Name: "sles", Version: "15.7", Family: []string{"suse", "linux", "unix"}},
	}
	notFound := &mock.Command{Stderr: "sh: getenforce: command not found\n", ExitStatus: 127}

	conn, err := mock.New(0, sles15, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{getenforceCmd: notFound},
	}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := CreateResource(rt, "selinux", nil)
	require.NoError(t, err)
	s := res.(*mqlSelinux)

	mode := s.GetMode()
	require.NoError(t, mode.Error)
	assert.Equal(t, "disabled", mode.Data)
	installed := s.GetInstalled()
	require.NoError(t, installed.Error)
	assert.False(t, installed.Data)

	conn, err = mock.New(0, sles15, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{getenforceCmd: {Stdout: "Disabled\n"}},
	}))
	require.NoError(t, err)
	rt = &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err = CreateResource(rt, "selinux", nil)
	require.NoError(t, err)
	mode = res.(*mqlSelinux).GetMode()
	require.NoError(t, mode.Error)
	assert.Equal(t, "disabled", mode.Data)
}

// semodule --list-modules=full on Rocky 8 lists cockpit at 200 and 100 and a
// module installed at 400 and 300; each copy is its own selinux.module.
func TestSelinuxModulesKeepEveryPriority(t *testing.T) {
	rocky8 := &inventory.Asset{
		Platform: &inventory.Platform{Name: "rocky", Version: "8.10", Family: []string{"redhat", "linux", "unix"}},
	}
	listing := "400 sweeppol          pp          \n" +
		"300 sweeppol          pp          \n" +
		"200 cockpit           pp          \n" +
		"100 cockpit           pp          \n" +
		"100 zosremote         pp  disabled\n"
	conn, err := mock.New(0, rocky8, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{semoduleListCmd: {Stdout: listing}},
	}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := CreateResource(rt, "selinux", nil)
	require.NoError(t, err)

	modules := res.(*mqlSelinux).GetModules()
	require.NoError(t, modules.Error)
	type module struct {
		priority     int64
		name, status string
	}
	var got []module
	for _, m := range modules.Data {
		mod := m.(*mqlSelinuxModule)
		got = append(got, module{mod.Priority.Data, mod.Name.Data, mod.Status.Data})
	}
	assert.Equal(t, []module{
		{400, "sweeppol", "enabled"}, {300, "sweeppol", "enabled"},
		{200, "cockpit", "enabled"}, {100, "cockpit", "enabled"},
		{100, "zosremote", "disabled"},
	}, got)
}

func TestSelinuxModuleIDNullPriority(t *testing.T) {
	// semodule -l prints no priority; that module must not share an id with
	// one listed at a priority, 0 included
	unset := &mqlSelinuxModule{
		Name:     plugin.TValue[string]{Data: "cockpit", State: plugin.StateIsSet},
		Priority: plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull},
	}
	zero := &mqlSelinuxModule{
		Name:     plugin.TValue[string]{Data: "cockpit", State: plugin.StateIsSet},
		Priority: plugin.TValue[int64]{Data: 0, State: plugin.StateIsSet},
	}
	unsetID, err := unset.id()
	require.NoError(t, err)
	zeroID, err := zero.id()
	require.NoError(t, err)
	assert.NotEqual(t, unsetID, zeroID)
}
