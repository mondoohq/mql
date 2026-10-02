// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package haproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Ubuntu 24.04 haproxy.service ([Service] section as shipped; 20.04, 22.04
// and 26.04 differ only in ExecStartPre/ExecReload lines).
const ubuntu2404Unit = `[Unit]
Description=HAProxy Load Balancer
Documentation=man:haproxy(1)
After=network-online.target rsyslog.service
Wants=network-online.target

[Service]
EnvironmentFile=-/etc/default/haproxy
EnvironmentFile=-/etc/sysconfig/haproxy
BindReadOnlyPaths=/dev/log:/var/lib/haproxy/dev/log
Environment="CONFIG=/etc/haproxy/haproxy.cfg" "PIDFILE=/run/haproxy.pid" "EXTRAOPTS=-S /run/haproxy-master.sock"
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS
ExecReload=/usr/sbin/haproxy -Ws -f $CONFIG -c -q $EXTRAOPTS
ExecReload=/bin/kill -USR2 $MAINPID
KillMode=mixed
Restart=always
SuccessExitStatus=143
Type=notify

[Install]
WantedBy=multi-user.target
`

// Ubuntu 16.04 haproxy.service (haproxy 1.6 with the systemd wrapper).
const ubuntu1604Unit = `[Unit]
Description=HAProxy Load Balancer

[Service]
Environment=CONFIG=/etc/haproxy/haproxy.cfg
EnvironmentFile=-/etc/default/haproxy
ExecStartPre=/usr/sbin/haproxy -f ${CONFIG} -c -q
ExecStart=/usr/sbin/haproxy-systemd-wrapper -f ${CONFIG} -p /run/haproxy.pid $EXTRAOPTS
ExecReload=/usr/sbin/haproxy -c -f ${CONFIG}
KillMode=mixed
Restart=always
`

// /etc/default/haproxy as shipped on Ubuntu (every setting commented out).
const ubuntuDefaultHaproxy = `# Defaults file for HAProxy
#
# This is sourced by both, the initscript and the systemd unit file, so do not
# treat it as a shell script fragment.

# Change the config file location if needed
#CONFIG="/etc/haproxy/haproxy.cfg"

# Add extra flags here, see haproxy(1) for a few options
#EXTRAOPTS="-de -m 16"
`

func TestLaunchFromService_UbuntuStock(t *testing.T) {
	for name, unit := range map[string]string{"24.04": ubuntu2404Unit, "16.04": ubuntu1604Unit} {
		t.Run(name, func(t *testing.T) {
			got := LaunchFromService(ParseSystemdService(unit), []string{ubuntuDefaultHaproxy})
			// Only haproxy.cfg: Ubuntu never passes conf.d to haproxy.
			assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg"}, got.Configs)
			assert.Equal(t, "/run/haproxy.pid", got.PidFile)
		})
	}
}

func TestLaunchFromService_DefaultFileOverridesEnvironment(t *testing.T) {
	// systemd lets EnvironmentFile= override Environment=, even when the
	// Environment= line comes later in the unit (as on 24.04).
	defaults := ubuntuDefaultHaproxy + `CONFIG="/srv/lb/main.cfg"
EXTRAOPTS="-f /etc/haproxy/conf.d -S /run/haproxy-master.sock"
`
	got := LaunchFromService(ParseSystemdService(ubuntu2404Unit), []string{defaults})
	assert.Equal(t, []string{"/srv/lb/main.cfg", "/etc/haproxy/conf.d"}, got.Configs)
}

func TestLaunchFromService_ConfigDirInUnit(t *testing.T) {
	// Fedora / RHEL 9 style unit that passes a conf.d directory.
	unit := `[Service]
Environment="CONFIG=/etc/haproxy/haproxy.cfg" "PIDFILE=/run/haproxy.pid" "CFGDIR=/etc/haproxy/conf.d"
EnvironmentFile=/etc/sysconfig/haproxy
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f $CFGDIR -p $PIDFILE $OPTIONS
`
	got := LaunchFromService(ParseSystemdService(unit), nil)
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/conf.d"}, got.Configs)
}

func TestParseSystemdService_DropInResetsExecStart(t *testing.T) {
	dropIn := `[Service]
ExecStart=
ExecStart=/usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/extra.cfg -p /run/haproxy.pid
`
	got := LaunchFromService(ParseSystemdService(ubuntu2404Unit, dropIn), nil)
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/extra.cfg"}, got.Configs)
}

func TestParseSystemdService_IgnoresOtherSections(t *testing.T) {
	unit := "[Unit]\nExecStart=/bin/false -f /nope\n[Service]\nExecStart=-/usr/sbin/haproxy -f /a.cfg\n"
	svc := ParseSystemdService(unit)
	assert.Equal(t, "/usr/sbin/haproxy -f /a.cfg", svc.ExecStart)
}

func TestExpandSystemdCommand(t *testing.T) {
	env := map[string]string{"CONFIG": "/etc/haproxy/haproxy.cfg", "EXTRAOPTS": "-S /run/m.sock", "EMPTY": ""}
	assert.Equal(t,
		[]string{"/usr/sbin/haproxy", "-f", "/etc/haproxy/haproxy.cfg", "-S", "/run/m.sock"},
		ExpandSystemdCommand("/usr/sbin/haproxy -f ${CONFIG} $EXTRAOPTS $EMPTY", env))
	// ${VAR} stays one argument, even when the value has spaces.
	assert.Equal(t,
		[]string{"x", "-S /run/m.sock"},
		ExpandSystemdCommand("x ${EXTRAOPTS}", env))
}

func TestParseLaunchArgs_ProcCmdline(t *testing.T) {
	// /proc/<pid>/cmdline of the haproxy master on Ubuntu 24.04.
	raw := []byte("/usr/sbin/haproxy\x00-Ws\x00-f\x00/etc/haproxy/haproxy.cfg\x00-p\x00/run/haproxy.pid\x00-S\x00/run/haproxy-master.sock\x00")
	got := ParseLaunchArgs(SplitProcCmdline(raw))
	assert.Equal(t, []string{"/etc/haproxy/haproxy.cfg"}, got.Configs)
	assert.Equal(t, "/run/haproxy.pid", got.PidFile)

	got = ParseLaunchArgs([]string{"haproxy", "-f", "/a.cfg", "--", "/b.cfg", "/c.cfg"})
	assert.Equal(t, []string{"/a.cfg", "/b.cfg", "/c.cfg"}, got.Configs)

	assert.Nil(t, SplitProcCmdline(nil))
}

func TestParseEnvironmentFile(t *testing.T) {
	env := ParseEnvironmentFile(ubuntuDefaultHaproxy)
	assert.Empty(t, env)

	env = ParseEnvironmentFile("CONFIG='/x.cfg'\nexport EXTRAOPTS=\"-de\"\nbogus\n")
	assert.Equal(t, map[string]string{"CONFIG": "/x.cfg", "EXTRAOPTS": "-de"}, env)
}
