// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bind9

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		// /proc/<pid>/cmdline of named on Debian 11 to 13 with OPTIONS="-u bind"
		{"debian stock", []string{"-f", "-u", "bind"}, ""},
		// Debian 9 and 10 with OPTIONS="-u bind -c /etc/bind/named-alt.conf"
		{"debian with -c", []string{"-f", "-u", "bind", "-c", "/etc/bind/named-alt.conf"}, "/etc/bind/named-alt.conf"},
		{"debian 10 without -f", []string{"-u", "bind", "-c", "/etc/bind/named-alt.conf"}, "/etc/bind/named-alt.conf"},
		// RHEL named.service: -u named -c ${NAMEDCONF} $OPTIONS
		{"rhel", []string{"-u", "named", "-c", "/etc/named.conf"}, "/etc/named.conf"},
		{"attached value", []string{"-u", "bind", "-c/srv/named.conf"}, "/srv/named.conf"},
		{"grouped flags", []string{"-fc", "/srv/named.conf"}, "/srv/named.conf"},
		{"-c as the value of -u is not a config", []string{"-u", "-c", "-f"}, ""},
		{"flags without an argument before -c", []string{"-4", "-c", "/srv/named.conf"}, "/srv/named.conf"},
		{"last -c wins", []string{"-c", "/a.conf", "-c", "/b.conf"}, "/b.conf"},
		{"dangling -c", []string{"-u", "bind", "-c"}, ""},
		{"stops at --", []string{"-u", "bind", "--", "-c", "/x.conf"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ConfigFromArgs(tt.args))
		})
	}
}

func TestLaunchFromArgsChroot(t *testing.T) {
	for _, tt := range []struct {
		args         string
		conf, chroot string
	}{
		{"-u named -c /etc/named.conf -t /var/named/chroot", "/etc/named.conf", "/var/named/chroot"},
		{"-t/var/named/chroot -c/etc/x.conf", "/etc/x.conf", "/var/named/chroot"},
		{"-u named -c /etc/named.conf", "/etc/named.conf", ""},
		{"-ft /srv/chroot", "", "/srv/chroot"},
	} {
		l := LaunchFromArgs(strings.Fields(tt.args))
		assert.Equal(t, tt.conf, l.Config, tt.args)
		assert.Equal(t, tt.chroot, l.Chroot, tt.args)
	}
}
