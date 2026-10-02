// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Requirement shapes from METADATA and requires.txt files on the Debian sweep
// hosts. A name followed directly by a specifier used to come back with the
// specifier attached ("requests>=2"), which matched no installed package.
func TestParseRequirement(t *testing.T) {
	for req, want := range map[string][2]string{
		"urllib3 (<1.27,>=1.21.1)":                             {"urllib3", ""},
		`charset-normalizer (~=2.0.0) ; python_version >= "3"`: {"charset-normalizer", `python_version >= "3"`},
		"importlib-metadata; python_version < '3.8'":           {"importlib-metadata", "python_version < '3.8'"},
		"importlib-resources>=1.4.0; python_version < '3.9'":   {"importlib-resources", "python_version < '3.9'"},
		"ruamel.yaml.clib>=0.2.6":                              {"ruamel.yaml.clib", ""},
		"zope.interface[test]":                                 {"zope.interface", ""},
		"secretstorage":                                        {"secretstorage", ""},
		"":                                                     {"", ""},
		"# comment":                                            {"", ""},
	} {
		name, marker := ParseRequirement(req)
		assert.Equal(t, want, [2]string{name, marker}, req)
	}
}

func TestSiteMarkerEnvironment(t *testing.T) {
	env := SiteMarkerEnvironment("/opt/g03venv/lib/python3.11/site-packages/requests-2.27.1.dist-info/METADATA", "linux")
	assert.Equal(t, MarkerEnvironment{"extra": "", "python_version": "3.11", "sys_platform": "linux", "platform_system": "Linux", "os_name": "posix"}, env)

	env = SiteMarkerEnvironment("/usr/lib/python3/dist-packages", "")
	assert.Equal(t, MarkerEnvironment{"extra": "", "python_version": "3"}, env)

	env = SiteMarkerEnvironment(`C:\Python312\Lib\site-packages`, "windows")
	assert.Equal(t, "win32", env["sys_platform"])
	_, ok := env["python_version"]
	assert.False(t, ok, "Python312 is not a pythonX.Y segment")
}

func TestMarkerMayHold(t *testing.T) {
	py311 := SiteMarkerEnvironment("/opt/venv/lib/python3.11/site-packages", "linux")
	py3 := SiteMarkerEnvironment("/usr/lib/python3/dist-packages", "linux")
	nothing := MarkerEnvironment{}

	for _, tc := range []struct {
		marker string
		env    MarkerEnvironment
		want   bool
	}{
		// requests 2.27.1
		{`python_version < "3"`, py311, false},
		{`python_version >= "3"`, py311, true},
		{`extra == 'socks'`, py311, false},
		{`(sys_platform == "win32" and python_version == "2.7") and extra == 'socks'`, py311, false},
		// jsonschema 4.10.3, httplib2 0.20.4
		{`python_version < '3.8'`, py311, false},
		{`python_version < '3.9'`, py311, false},
		{`python_version > "3.0"`, py311, true},
		// keyring 10.1 requires.txt sections
		{`sys_platform=="linux2" or sys_platform=="linux"`, py311, true},
		{`sys_platform=="win32"`, py311, false},
		// ruamel.yaml 0.17.21: the implementation is unknown
		{`platform_python_implementation=="CPython" and python_version<"3.11"`, py311, false},
		{`platform_python_implementation=="CPython" and python_version<"3.12"`, py311, true},
		// only the major version is known in /usr/lib/python3/dist-packages
		{`python_version < "3"`, py3, false},
		{`python_version >= "3"`, py3, true},
		{`python_version < "3.8"`, py3, true},
		{`python_version > "3.0"`, py3, true},
		{`python_version == "2.6"`, py3, false},
		// nothing known: only extras are decided
		{`sys_platform == "win32"`, nothing, true},
		{`python_version < "3"`, nothing, true},
		// operators
		{`python_version ~= "3.9"`, py311, true},
		{`python_version ~= "3.12"`, py311, false},
		{`python_version == "3.*"`, py311, true},
		{`python_version != "3.*"`, py311, false},
		{`"linux" in sys_platform`, py311, true},
		{`sys_platform not in "win32 cygwin"`, py311, true},
		{`os_name == "nt" or python_version >= "3.10"`, py311, true},
		{`extra != "test"`, py311, true},
		// unparsable markers may hold
		{`python_version <`, py311, true},
		{`(python_version < "3"`, py311, true},
	} {
		assert.Equal(t, tc.want, MarkerMayHold(tc.marker, tc.env), "%s in %v", tc.marker, tc.env)
	}
}
