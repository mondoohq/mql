// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// /proc of the official httpd image started with
// `httpd-foreground -f /opt/alt/httpd.conf -D C3FLAG`: pid 1 is the master,
// the others its workers.
var httpdImageProc = map[string]string{
	"/proc/1/cmdline": "httpd\x00-DFOREGROUND\x00-f\x00/opt/alt/httpd.conf\x00-D\x00C3FLAG\x00",
	"/proc/1/stat":    "1 (httpd) S 0 1 1 0 -1",
	"/proc/8/cmdline": "httpd\x00-DFOREGROUND\x00-f\x00/opt/alt/httpd.conf\x00-D\x00C3FLAG\x00",
	"/proc/8/stat":    "8 (httpd) S 1 1 1 0 -1",
}

// The alternate configuration turns ServerSignature on only under the -D
// parameter the server is started with; the decoys at the default paths
// turn it off.
var httpdLaunchFiles = map[string]string{
	"/opt/alt/httpd.conf":                "ServerRoot \"/usr/local/apache2\"\n<IfDefine C3FLAG>\nServerSignature On\n</IfDefine>\n",
	"/usr/local/apache2/conf/httpd.conf": "ServerRoot \"/usr/local/apache2\"\nServerSignature Off\n",
	"/etc/apache2/apache2.conf":          "ServerSignature Off\n",
}

func apacheConfOf(t *testing.T, rt *plugin.Runtime) *mqlApache2Conf {
	t.Helper()
	res, err := NewResource(rt, "apache2.conf", nil)
	require.NoError(t, err)
	return res.(*mqlApache2Conf)
}

func assertHttpdAltLaunch(t *testing.T, conf *mqlApache2Conf) {
	t.Helper()
	file := conf.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, "/opt/alt/httpd.conf", file.Data.Path.Data)
	sig := conf.GetServerSignature()
	require.NoError(t, sig.Error)
	assert.Equal(t, "On", sig.Data)
}

func TestApacheConfFollowsLaunch(t *testing.T) {
	t.Run("the image's pid file", func(t *testing.T) {
		files := mergeFiles(httpdImageProc, httpdLaunchFiles, map[string]string{apacheImagePidFile: "1\n"})
		assertHttpdAltLaunch(t, apacheConfOf(t, newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'httpd|apache2|httpd-prefork|httpd-worker|httpd-event'": {ExitStatus: 1}}, nil)))
	})

	t.Run("no pid file: the master in /proc", func(t *testing.T) {
		files := mergeFiles(httpdImageProc, httpdLaunchFiles)
		assertHttpdAltLaunch(t, apacheConfOf(t, newLaunchRuntime(t, files, map[string]*mock.Command{"pgrep -x 'httpd|apache2|httpd-prefork|httpd-worker|httpd-event'": {Stdout: "1\n8\n"}}, nil)))
	})

	t.Run("the image's Cmd through httpd-foreground", func(t *testing.T) {
		image := &tar.ImageConfig{Cmd: []string{"httpd-foreground", "-f", "/opt/alt/httpd.conf", "-D", "C3FLAG"}, WorkingDir: "/usr/local/apache2"}
		assertHttpdAltLaunch(t, apacheConfOf(t, newLaunchRuntime(t, httpdLaunchFiles, nil, image)))
	})

	t.Run("httpd-foreground passes FOREGROUND", func(t *testing.T) {
		l := apacheFoundLaunch([]serverLaunch{{Argv: []string{"httpd-foreground"}}})
		require.NotNil(t, l)
		assert.Equal(t, []string{"FOREGROUND"}, l.Defines)
		assert.Nil(t, apacheFoundLaunch(nil))
	})
}
