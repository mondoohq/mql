// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/apache2"
)

// apacheImagePidFile is where the official httpd image's httpd.conf (the
// source build's default, PidFile logs/httpd.pid under ServerRoot
// /usr/local/apache2) records the master.
const apacheImagePidFile = "/usr/local/apache2/logs/httpd.pid"

// apacheLaunchSpec recognizes httpd's processes: httpd, Debian's apache2,
// SUSE's httpd-prefork (-worker, -event), and the official image's
// httpd-foreground wrapper, which runs `httpd -DFOREGROUND "$@"`.
var apacheLaunchSpec = serverLaunchSpec{
	Names: []string{"httpd", "apache2", "httpd-prefork", "httpd-worker", "httpd-event"},
	IsServer: func(argv []string) bool {
		base := filepath.Base(argv[0])
		return strings.HasPrefix(base, "httpd") || strings.HasPrefix(base, "apache2")
	},
}

// effectiveLaunch returns how httpd is started: the master recorded in a pid
// file; else a running master found in /proc, or the httpd a scanned
// container image starts, which official images run without a probed pid
// file or a unit; else what launchArgs reads from the platform's start
// configuration (SUSE's sysconfig, the unit).
func (s *mqlApache2Conf) effectiveLaunch() (*apache2.Launch, error) {
	s.processLaunchOnce.Do(func() {
		conn := s.MqlRuntime.Connection.(shared.Connection)
		if l := apacheRunningLaunch(&afero.Afero{Fs: conn.FileSystem()}); l != nil {
			s.processLaunch = l
			return
		}
		s.processLaunch = apacheFoundLaunch(findServerLaunches(s.MqlRuntime, apacheLaunchSpec))
	})
	if s.processLaunch != nil {
		return s.processLaunch, nil
	}
	return s.launchArgs()
}

// apacheFoundLaunch parses the command line of the first httpd found, nil
// when none was.
func apacheFoundLaunch(launches []serverLaunch) *apache2.Launch {
	if len(launches) == 0 {
		return nil
	}
	l := apache2.ParseLaunchArgs(launches[0].Argv[1:])
	if filepath.Base(launches[0].Argv[0]) == "httpd-foreground" {
		l.Defines = append([]string{"FOREGROUND"}, l.Defines...)
	}
	return &l
}
