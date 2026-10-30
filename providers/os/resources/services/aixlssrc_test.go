// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestLssrcParse(t *testing.T) {
	testOutput := `
Subsystem         Group            PID          Status 
 syslogd          ras              3932558      active
 aso                               4653462      active
 biod             nfs              5046692      active
 rpc.lockd        nfs              5636560      active
 qdaemon          spooler          5767630      active
 ctrmc            rsct             5439966      active
 pmperfrec                         6881768      active
 IBM.HostRM       rsct_rm          5898530      active
 automountd       autofs           7340402      active
 lpd              spooler                       inoperative
 nimsh            nimclient                     inoperative
 nimhttp                                        inoperative
 timed            tcpip                         inoperative
`
	entries := parseLssrc(strings.NewReader(testOutput))
	assert.Equal(t, 13, len(entries), "detected the right amount of services")
	assert.Equal(t, "syslogd", entries[0].Subsystem, "service name detected")
	assert.Equal(t, "active", entries[0].Status, "service status detected")
	assert.Equal(t, "timed", entries[12].Subsystem, "service name detected")
	assert.Equal(t, "inoperative", entries[12].Status, "service status detected")
}

// testdata/aix73 holds the entries of /etc/inittab, the start lines of
// /etc/rc.tcpip and /etc/rc.nfs, and the startsrc lines of rc2.d/Ssshd of
// AIX 7.3 TL4 SP2.
func aix73Fs() afero.Fs {
	return afero.NewReadOnlyFs(afero.NewBasePathFs(afero.NewOsFs(), "testdata/aix73"))
}

func TestAixBootStarts(t *testing.T) {
	fs := aix73Fs()
	inittab := readAixInittab(fs)
	require.NotEmpty(t, inittab)

	boot := aixBootStarts(fs, inittab)
	for _, name := range []string{
		// uncommented start lines of rc.tcpip
		"syslogd", "sendmail", "portmap", "inetd", "xntpd", "snmpd", "hostmibd", "snmpmibd", "aixmibd",
		// rc.nfs
		"biod", "nfsd", "rpc.mountd", "rpc.statd", "rpc.lockd",
		// startsrc in inittab
		"aso", "qdaemon", "writesrv", "pfcdaemon", "clcomd", "ctrmc",
	} {
		assert.True(t, boot.subsystems[name], name)
	}
	// rc2.d/Ssshd runs startsrc -g ssh
	assert.True(t, boot.groups["ssh"])

	for _, name := range []string{
		// commented out in rc.tcpip
		"lpd", "routed", "named", "dhcpcd",
		// not a subsystem: `else	#if srcmstr not running, start manually`
		"manually",
	} {
		assert.False(t, boot.subsystems[name], name)
	}
}

func TestAixInittabDaemons(t *testing.T) {
	daemons := aixInittabDaemons(readAixInittab(aix73Fs()))
	ids := []string{}
	for _, d := range daemons {
		ids = append(ids, d.ID+"="+d.Program)
	}
	// shdaemon is respawn-free and off; startsrc and rc scripts are not daemons
	assert.Equal(t, []string{
		"srcmstr=/usr/sbin/srcmstr",
		"cron=/usr/sbin/cron",
		"cons=/usr/sbin/getty",
		"uprintfd=/usr/sbin/uprintfd",
	}, ids)
}

func TestAixServiceManager(t *testing.T) {
	lssrc, err := os.ReadFile("testdata/aix73/lssrc_a.txt")
	require.NoError(t, err)
	files := map[string]*mock.MockFileData{}
	for _, p := range []string{"/etc/inittab", "/etc/rc.tcpip", "/etc/rc.nfs", "/etc/rc.d/rc2.d/Ssshd"} {
		data, err := os.ReadFile("testdata/aix73" + p)
		require.NoError(t, err)
		files[p] = &mock.MockFileData{Path: p, Content: string(data)}
	}
	files["/etc/rc.d/rc2.d"] = &mock.MockFileData{Path: "/etc/rc.d/rc2.d", StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o755}}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "aix", Family: []string{"unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Files: files,
		Commands: map[string]*mock.Command{
			"lssrc -a": {Stdout: string(lssrc)},
			// AIX 7.3, cut to init, srcmstr, cron and uprintfd
			"ps -A -o args=": {Stdout: "/etc/init\n/usr/sbin/srcmstr\n/usr/sbin/cron\n/usr/sbin/uprintfd\n"},
		},
	}))
	require.NoError(t, err)

	sm := &AixServiceManager{conn: conn}
	byName := func(name string) *Service {
		s, err := sm.Get(name)
		require.NoError(t, err, name)
		return s
	}

	// started from rc.tcpip at boot
	xntpd := byName("xntpd")
	assert.True(t, xntpd.Running)
	assert.True(t, xntpd.Enabled)

	// in group ssh, which rc2.d/Ssshd starts
	sshd := byName("sshd")
	assert.True(t, sshd.Enabled)

	// started by hand with startsrc: running, but not started at boot
	manual := byName("mqltestd")
	assert.True(t, manual.Running)
	assert.False(t, manual.Enabled)

	// commented out in rc.tcpip
	lpd := byName("lpd")
	assert.False(t, lpd.Running)
	assert.False(t, lpd.Enabled)

	// kept running by init, not by SRC
	cron := byName("cron")
	assert.True(t, cron.Running)
	assert.True(t, cron.Enabled)
	assert.Equal(t, "inittab", cron.Type)
	assert.Equal(t, "/usr/sbin/cron", cron.Path)

	// the console getty is not in the cut ps output
	assert.False(t, byName("cons").Running)
}
