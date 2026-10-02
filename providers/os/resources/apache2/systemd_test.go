// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// /usr/lib/systemd/system/httpd.service from RHEL 7 (httpd 2.4.6)
const rhel7HttpdService = `[Unit]
Description=The Apache HTTP Server
After=network.target remote-fs.target nss-lookup.target
Documentation=man:httpd(8)
Documentation=man:apachectl(8)

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/httpd
ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND
ExecReload=/usr/sbin/httpd $OPTIONS -k graceful
ExecStop=/bin/kill -WINCH ${MAINPID}
# We want systemd to give httpd some time to finish gracefully, but still want
# it to kill httpd after TimeoutStopSec if something went wrong during the
# graceful stop. Normally, Systemd sends SIGTERM signal right after the
# ExecStop, which would kill httpd. We are sending useless SIGCONT here to give
# httpd time to finish.
KillSignal=SIGCONT
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

// The [Service] section of /usr/lib/systemd/system/httpd.service from RHEL 9
// (httpd 2.4.62), which reads no EnvironmentFile
const rhel9HttpdService = `[Service]
Type=notify
Environment=LANG=C

ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND
ExecReload=/usr/sbin/httpd $OPTIONS -k graceful
# Send SIGWINCH for graceful stop
KillSignal=SIGWINCH
KillMode=mixed
PrivateTmp=true
OOMPolicy=continue
`

// /etc/sysconfig/httpd from RHEL 7, comments trimmed
const rhel7SysconfigHttpd = `#
# To pass additional options (for instance, -D definitions) to the
# httpd binary at startup, set OPTIONS here.
#
#OPTIONS=

LANG=C
`

func TestParseServiceUnit(t *testing.T) {
	unit := ParseServiceUnit(rhel7HttpdService)
	assert.Equal(t, []string{"/etc/sysconfig/httpd"}, unit.EnvironmentFiles)
	assert.Equal(t, "/usr/sbin/httpd $OPTIONS -DFOREGROUND", unit.ExecStart)
	assert.Empty(t, unit.Environment)

	unit = ParseServiceUnit(rhel9HttpdService)
	assert.Empty(t, unit.EnvironmentFiles)
	assert.Equal(t, map[string]string{"LANG": "C"}, unit.Environment)

	// a '-' prefix only makes a missing file non-fatal; an empty assignment
	// resets the list; Environment= takes quoted, space-separated pairs
	unit = ParseServiceUnit("[Service]\nEnvironmentFile=/etc/a\nEnvironmentFile=\n" +
		"EnvironmentFile=-/etc/sysconfig/httpd\n" +
		`Environment="OPTIONS=-DSSL -D STATUS" LANG=C` + "\n" +
		"[Install]\nEnvironment=IGNORED=1\n")
	assert.Equal(t, []string{"/etc/sysconfig/httpd"}, unit.EnvironmentFiles)
	assert.Equal(t, map[string]string{"OPTIONS": "-DSSL -D STATUS", "LANG": "C"}, unit.Environment)
}

func TestParseServiceUnitDropIns(t *testing.T) {
	// `systemctl edit httpd` on RHEL 9, as the unit's own comment suggests
	unit := ParseServiceUnit(rhel9HttpdService, "[Service]\nEnvironment=OPTIONS=-DMY_DEFINE\n")
	assert.Equal(t, map[string]string{"LANG": "C", "OPTIONS": "-DMY_DEFINE"}, unit.Environment)
	assert.Equal(t, []string{"MY_DEFINE", "FOREGROUND"}, UnitDefines(unit.ExecStart, unit.Environment))

	// a drop-in that resets ExecStart= and sets a new one
	unit = ParseServiceUnit(rhel9HttpdService, "[Service]\nExecStart=\nExecStart=/usr/sbin/httpd -DFOREGROUND -DNOSSL\n")
	assert.Equal(t, []string{"FOREGROUND", "NOSSL"}, UnitDefines(unit.ExecStart, unit.Environment))
}

func TestParseEnvironmentFile(t *testing.T) {
	assert.Equal(t, map[string]string{"LANG": "C"}, ParseEnvironmentFile(rhel7SysconfigHttpd))
	vars := ParseEnvironmentFile(rhel7SysconfigHttpd + `OPTIONS="-DSSL -DSTATUS"` + "\nSWEEPTOK=Full\nREF=$LANG\n")
	assert.Equal(t, "-DSSL -DSTATUS", vars["OPTIONS"])
	assert.Equal(t, "Full", vars["SWEEPTOK"])
	// systemd does not expand references in an EnvironmentFile
	assert.Equal(t, "$LANG", vars["REF"])
}

func TestUnitDefines(t *testing.T) {
	unit := ParseServiceUnit(rhel7HttpdService)
	assert.Equal(t, []string{"FOREGROUND"}, UnitDefines(unit.ExecStart, ParseEnvironmentFile(rhel7SysconfigHttpd)))
	assert.Equal(t, []string{"SSL", "STATUS", "FOREGROUND"},
		UnitDefines(unit.ExecStart, map[string]string{"OPTIONS": "-DSSL -D STATUS"}))
}
