// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// Per-source trust options override apt.config for one repository. On Debian
// 12 and Ubuntu 24.04, apt-get indexes an unsigned file: repository and
// offers its packages for install with `[allow-insecure=yes]`, and refuses it
// without; apt.repos used to read that entry exactly like a normal one.
func TestAptRepoTrustOptions(t *testing.T) {
	yes, no := true, false

	oneLine := parseAptOneLine(strings.Join([]string{
		"deb [allow-insecure=yes] file:/srv/g03unsigned ./",
		"deb [ allow-weak=yes allow-downgrade-to-insecure=yes check-valid-until=no check-date=no ] http://deb.example.invalid/x s main",
		"deb [Allow-Insecure=no arch=amd64] http://deb.example.invalid/y s main",
		"deb http://deb.example.invalid/z s main",
	}, "\n"))
	require.Len(t, oneLine, 4)

	assert.Equal(t, &yes, oneLine[0].AllowInsecure)
	assert.Nil(t, oneLine[0].AllowWeak)
	assert.Nil(t, oneLine[0].CheckValidUntil)
	assert.Equal(t, "file:/srv/g03unsigned", oneLine[0].URL)

	assert.Nil(t, oneLine[1].AllowInsecure)
	assert.Equal(t, &yes, oneLine[1].AllowWeak)
	assert.Equal(t, &yes, oneLine[1].AllowDowngradeToInsecure)
	assert.Equal(t, &no, oneLine[1].CheckValidUntil)
	assert.Equal(t, &no, oneLine[1].CheckDate)

	assert.Equal(t, &no, oneLine[2].AllowInsecure, "an explicit no is not unset")

	for _, opt := range []*bool{oneLine[3].AllowInsecure, oneLine[3].AllowWeak, oneLine[3].AllowDowngradeToInsecure, oneLine[3].CheckValidUntil, oneLine[3].CheckDate} {
		assert.Nil(t, opt, "an entry without options leaves them unset")
	}

	deb822 := parseAptDeb822(`Types: deb
URIs: file:/srv/g03unsigned
Suites: ./
Allow-Insecure: yes
Check-Valid-Until: no

Types: deb deb-src
URIs: http://deb.example.invalid/x
Suites: s
Components: main
allow-weak: yes
Allow-Downgrade-To-Insecure: yes
Check-Date: no
`)
	require.Len(t, deb822, 3)
	assert.Equal(t, &yes, deb822[0].AllowInsecure)
	assert.Equal(t, &no, deb822[0].CheckValidUntil)
	assert.Nil(t, deb822[0].AllowWeak)
	for _, r := range deb822[1:] {
		assert.Nil(t, r.AllowInsecure)
		assert.Equal(t, &yes, r.AllowWeak)
		assert.Equal(t, &yes, r.AllowDowngradeToInsecure)
		assert.Equal(t, &no, r.CheckDate)
	}

	// the options reach the resource, and an unset one is null
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	apt := &mqlApt{MqlRuntime: runtime}
	file := &mqlFile{MqlRuntime: runtime, Path: plugin.TValue[string]{Data: "/etc/apt/sources.list.d/g03insec.list", State: plugin.StateIsSet}}
	oneLine[0].SourceFile = file.Path.Data
	r, err := apt.newRepo(file, 0, oneLine[0])
	require.NoError(t, err)
	assert.True(t, r.AllowInsecure.Data)
	assert.True(t, r.AllowWeak.State&plugin.StateIsNull != 0)
}
