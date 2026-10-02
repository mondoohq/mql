// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestParseYumBool(t *testing.T) {
	for _, v := range []string{"1", "true", "True", "yes", "On", " 1 "} {
		assert.True(t, parseYumBool(v), v)
	}
	for _, v := range []string{"0", "false", "no", "off", "3", ""} {
		assert.False(t, parseYumBool(v), v)
	}
}

func TestYumMainDirectives(t *testing.T) {
	got := yumMainDirectives("# comment\n[main]\ngpgcheck = 1 # inline\n; other\npkg_gpgcheck=0\n\n[other]\ngpgcheck=0\n")
	assert.Equal(t, []yumDirective{{"gpgcheck", "1"}, {"pkg_gpgcheck", "0"}}, got)
}

type yumConfigBools struct {
	gpgcheck, localPkgGpgcheck, repoGpgcheck, cleanRequirementsOnRemove bool
}

func yumConfigFor(t *testing.T, files map[string]string, args map[string]*llx.RawData) yumConfigBools {
	t.Helper()
	rt := newYumRuntime(t, files, nil)
	if args == nil {
		args = map[string]*llx.RawData{}
	}
	o, err := NewResource(rt, "yum.config", args)
	require.NoError(t, err)
	c := o.(*mqlYumConfig)
	get := func(r func() *plugin.TValue[bool]) bool {
		v := r()
		require.NoError(t, v.Error)
		return v.Data
	}
	return yumConfigBools{
		gpgcheck:                  get(c.GetGpgcheck),
		localPkgGpgcheck:          get(c.GetLocalPkgGpgcheck),
		repoGpgcheck:              get(c.GetRepoGpgcheck),
		cleanRequirementsOnRemove: get(c.GetCleanRequirementsOnRemove),
	}
}

// Fedora 44 as installed: dnf.conf has an empty [main], the signature check
// comes from the distribution drop-in. `dnf5 --dump-main-config` reports
// gpgcheck = 1, pkg_gpgcheck = 1, clean_requirements_on_remove = 1.
var fedora44Files = map[string]string{
	"/usr/bin/dnf5":     "",
	"/etc/dnf/dnf.conf": "# see `man dnf.conf` for defaults and possible options\n\n[main]\n",
	"/usr/share/dnf5/libdnf.conf.d/20-fedora-defaults.conf": "[main]\nbest=False\npkg_gpgcheck=True\nskip_if_unavailable=True\n",
	"/usr/share/dnf5/libdnf.conf.d/protect-sudo.conf":       "[main]\nprotected_packages = sudo\n",
}

func withFiles(base map[string]string, extra map[string]string) map[string]string {
	res := map[string]string{}
	for k, v := range base {
		res[k] = v
	}
	for k, v := range extra {
		res[k] = v
	}
	return res
}

func TestYumConfigDnf5DropIns(t *testing.T) {
	t.Run("fedora 44 as installed", func(t *testing.T) {
		assert.Equal(t, yumConfigBools{gpgcheck: true, cleanRequirementsOnRemove: true}, yumConfigFor(t, fedora44Files, nil))
	})

	// The orders below were measured with dnf5 --dump-main-config on Fedora 44.
	t.Run("a user drop-in overrides the distribution one", func(t *testing.T) {
		got := yumConfigFor(t, withFiles(fedora44Files, map[string]string{
			"/etc/dnf/libdnf5.conf.d/99-local.conf": "[main]\npkg_gpgcheck=False\nclean_requirements_on_remove=False\n",
		}), nil)
		assert.Equal(t, yumConfigBools{}, got)
	})

	t.Run("a user drop-in masks the distribution file of the same name", func(t *testing.T) {
		got := yumConfigFor(t, withFiles(fedora44Files, map[string]string{
			"/etc/dnf/libdnf5.conf.d/20-fedora-defaults.conf": "[main]\nbest=False\n",
		}), nil)
		assert.False(t, got.gpgcheck)
	})

	t.Run("dnf.conf is applied after the drop-ins, gpgcheck sets pkg_gpgcheck", func(t *testing.T) {
		got := yumConfigFor(t, withFiles(fedora44Files, map[string]string{
			"/etc/dnf/libdnf5.conf.d/99-local.conf": "[main]\npkg_gpgcheck=False\n",
			"/etc/dnf/dnf.conf":                     "[main]\ngpgcheck=1\n",
		}), nil)
		assert.True(t, got.gpgcheck)
	})

	t.Run("the later of gpgcheck and pkg_gpgcheck wins", func(t *testing.T) {
		got := yumConfigFor(t, withFiles(fedora44Files, map[string]string{
			"/etc/dnf/dnf.conf": "[main]\ngpgcheck=1\npkg_gpgcheck=0\n",
		}), nil)
		assert.False(t, got.gpgcheck)
		got = yumConfigFor(t, withFiles(fedora44Files, map[string]string{
			"/etc/dnf/dnf.conf": "[main]\npkg_gpgcheck=0\ngpgcheck=1\n",
		}), nil)
		assert.True(t, got.gpgcheck)
	})

	t.Run("a file named explicitly is read alone", func(t *testing.T) {
		got := yumConfigFor(t, withFiles(fedora44Files, map[string]string{
			"/tmp/alt.conf": "[main]\nrepo_gpgcheck=1\n",
		}), map[string]*llx.RawData{"path": llx.StringData("/tmp/alt.conf")})
		assert.Equal(t, yumConfigBools{repoGpgcheck: true, cleanRequirementsOnRemove: true}, got)
	})
}

// dnf 4 and dnf 5 remove unneeded dependencies unless told otherwise, yum 3
// does not: `dnf config-manager --dump` with an empty [main] on RHEL 9 prints
// clean_requirements_on_remove = 1, yum.config.YumConf() on RHEL 7 False.
func TestYumConfigDefaults(t *testing.T) {
	empty := "[main]\n"
	dnf4 := yumConfigFor(t, map[string]string{"/usr/bin/dnf": "", "/etc/dnf/dnf.conf": empty}, nil)
	assert.Equal(t, yumConfigBools{cleanRequirementsOnRemove: true}, dnf4)

	yum3 := yumConfigFor(t, map[string]string{"/etc/yum.conf": empty + "gpgcheck=1\n"}, nil)
	assert.Equal(t, yumConfigBools{gpgcheck: true}, yum3)

	// dnf 4 has no pkg_gpgcheck
	dnf4 = yumConfigFor(t, map[string]string{"/usr/bin/dnf": "", "/etc/dnf/dnf.conf": "[main]\npkg_gpgcheck=1\nclean_requirements_on_remove=False\n"}, nil)
	assert.Equal(t, yumConfigBools{}, dnf4)
}

// On a host without yum or dnf (Debian) yum.config reported an empty params
// map and every option false, which reads as a host with signature checks
// disabled. With no configuration file and no package manager whose defaults
// apply, the fields are null.
func TestYumConfigWithoutYum(t *testing.T) {
	newConfig := func(files map[string]string, args map[string]*llx.RawData) *mqlYumConfig {
		rt := newYumRuntime(t, files, nil)
		if args == nil {
			args = map[string]*llx.RawData{}
		}
		o, err := NewResource(rt, "yum.config", args)
		require.NoError(t, err)
		return o.(*mqlYumConfig)
	}
	assertNull := func(c *mqlYumConfig) {
		t.Helper()
		content := c.GetContent()
		require.NoError(t, content.Error)
		assert.True(t, content.IsNull(), "content")
		params := c.GetParams()
		require.NoError(t, params.Error)
		assert.True(t, params.IsNull(), "params")
		for name, get := range map[string]func() *plugin.TValue[bool]{
			"gpgcheck": c.GetGpgcheck, "localPkgGpgcheck": c.GetLocalPkgGpgcheck,
			"repoGpgcheck": c.GetRepoGpgcheck, "cleanRequirementsOnRemove": c.GetCleanRequirementsOnRemove,
		} {
			v := get()
			require.NoError(t, v.Error)
			assert.True(t, v.IsNull(), name)
		}
	}

	t.Run("no yum, no configuration", func(t *testing.T) {
		assertNull(newConfig(map[string]string{"/usr/bin/apt-get": ""}, nil))
	})

	t.Run("a named file that does not exist", func(t *testing.T) {
		assertNull(newConfig(fedora44Files, map[string]*llx.RawData{"path": llx.StringData("/tmp/missing.conf")}))
	})

	// dnf's compiled-in defaults apply without a configuration file
	t.Run("dnf without a configuration file", func(t *testing.T) {
		c := newConfig(map[string]string{"/usr/bin/dnf": ""}, nil)
		params := c.GetParams()
		require.NoError(t, params.Error)
		assert.False(t, params.IsNull())
		clean := c.GetCleanRequirementsOnRemove()
		require.NoError(t, clean.Error)
		assert.False(t, clean.IsNull())
		assert.True(t, clean.Data)
	})
}
