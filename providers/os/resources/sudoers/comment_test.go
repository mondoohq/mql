// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sudoers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripComment(t *testing.T) {
	tests := map[string]string{
		// stock /etc/sudoers on SLES 15 and openSUSE Leap 15, /usr/etc/sudoers on 16
		"Defaults targetpw   # ask for the password of the target user i.e. root":           "Defaults targetpw",
		"ALL   ALL=(ALL) ALL   # WARNING! Only use this together with 'Defaults targetpw'!": "ALL   ALL=(ALL) ALL",
		"## User privilege specification":                                                   "",
		"# %wheel ALL=(ALL:ALL) ALL":                                                        "",
		"#1000 ALL=(ALL) ALL":                                                               "#1000 ALL=(ALL) ALL",
		"%#1001 ALL=(#0) /usr/bin/id # gid and uid":                                         "%#1001 ALL=(#0) /usr/bin/id",
		"#-1 ALL=(ALL) ALL":                                                                 "#-1 ALL=(ALL) ALL",
		"#-comment":                                                                         "",
		`Defaults passprompt="pw # for %u" # prompt`:                                        `Defaults passprompt="pw # for %u"`,
		`bob ALL=/usr/bin/echo \#literal`:                                                   `bob ALL=/usr/bin/echo \#literal`,
		"#includedir /etc/sudoers.d":                                                        "#includedir /etc/sudoers.d",
		"#include /etc/sudoers.local":                                                       "#include /etc/sudoers.local",
		"@includedir /etc/sudoers.d":                                                        "@includedir /etc/sudoers.d",
		"  root ALL=(ALL:ALL) ALL  ":                                                        "root ALL=(ALL:ALL) ALL",
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, StripComment(in))
		})
	}
}

// The tail of the stock SUSE sudoers (SLES 16 /usr/etc/sudoers lines 111-112)
const suseStockTail = `Defaults targetpw   # ask for the password of the target user i.e. root
ALL   ALL=(ALL) ALL   # WARNING! Only use this together with 'Defaults targetpw'!
root ALL=(ALL:ALL) ALL
#1000 ALL=(ALL) NOPASSWD: /usr/bin/id
#includedir /etc/sudoers.d
`

func TestParseInlineComments(t *testing.T) {
	defaults := ParseDefaults("/usr/etc/sudoers", suseStockTail)
	require.Len(t, defaults, 1)
	assert.Equal(t, "targetpw", defaults[0].Parameter)
	assert.Equal(t, "Defaults targetpw", defaults[0].Raw)

	specs := ParseUserSpecs("/usr/etc/sudoers", suseStockTail)
	require.Len(t, specs, 3)
	assert.Equal(t, []string{"ALL"}, specs[0].Users)
	assert.Equal(t, []string{"ALL"}, specs[0].Commands)
	assert.Equal(t, 2, specs[0].LineNumber)
	assert.Equal(t, []string{"#1000"}, specs[2].Users, "a numeric uid is not a comment")
	assert.Equal(t, []string{"/usr/bin/id"}, specs[2].Commands)

	aliases := ParseAliases("/etc/sudoers", "Cmnd_Alias SHUTDOWN = /sbin/halt, /sbin/reboot # power\n")
	require.Len(t, aliases, 1)
	assert.Equal(t, []string{"/sbin/halt", "/sbin/reboot"}, aliases[0].Members)
}
