// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// Debian's cron logs "(*system*g04nonl) ERROR (Missing newline before EOF,
// this crontab file will be ignored)" and runs nothing from the file; cronie
// logs "missing newline before EOF" and runs every line but the last.
func TestCronContentWithoutTrailingNewline(t *testing.T) {
	nonl := "* * * * * root /usr/bin/touch /var/tmp/g04cron.first\n* * * * * root /usr/bin/touch /var/tmp/g04cron.nonl"

	content, ok := cronFileContent(nonl, cronFlavorDebian)
	assert.False(t, ok)
	assert.Empty(t, content)

	content, ok = cronFileContent(nonl, cronFlavorCronie)
	assert.True(t, ok)
	assert.Equal(t, "* * * * * root /usr/bin/touch /var/tmp/g04cron.first\n", content)

	// a one-line file without a newline has nothing cronie runs
	content, ok = cronFileContent("* * * * * root /bin/true", cronFlavorCronie)
	assert.True(t, ok)
	assert.Empty(t, content)

	for _, flavor := range []cronFlavor{cronFlavorDebian, cronFlavorCronie, cronFlavorDefault} {
		content, ok = cronFileContent("* * * * * root /bin/true\n", flavor)
		assert.True(t, ok)
		assert.Equal(t, "* * * * * root /bin/true\n", content)
		content, ok = cronFileContent("", flavor)
		assert.True(t, ok)
		assert.Empty(t, content)
	}
	// other crons are left as they were
	content, ok = cronFileContent(nonl, cronFlavorDefault)
	assert.True(t, ok)
	assert.Equal(t, nonl, content)
}

// `stat -L -c '%C\t%n'` on RHEL 9 for cron.d files: cronie refused the
// symlink whose target is etc_t and the file moved in from /tmp
// (user_tmp_t) with "Unauthorized SELinux context". The types RHEL 9's
// policy lets system_cronjob_t enter are taken from
// `sesearch -A -s system_cronjob_t -c file -p entrypoint`.
func TestParseCronSELinuxTypes(t *testing.T) {
	types := parseCronSELinuxTypes("system_u:object_r:system_cron_spool_t:s0\t/etc/crontab\n" +
		"unconfined_u:object_r:etc_t:s0\t/etc/cron.d/g04mlink\n" +
		"unconfined_u:object_r:user_tmp_t:s0\t/etc/cron.d/g04mmoved\n" +
		"unconfined_u:object_r:system_cron_spool_t:s0\t/etc/cron.d/g04m_ok\n" +
		"?\t/etc/cron.d/nolabel\n")
	assert.Equal(t, map[string]string{
		"/etc/crontab":          "system_cron_spool_t",
		"/etc/cron.d/g04mlink":  "etc_t",
		"/etc/cron.d/g04mmoved": "user_tmp_t",
		"/etc/cron.d/g04m_ok":   "system_cron_spool_t",
	}, types)

	assert.True(t, cronieSELinuxRefuses("etc_t"))
	assert.True(t, cronieSELinuxRefuses("user_tmp_t"))
	assert.False(t, cronieSELinuxRefuses("system_cron_spool_t"))
	assert.False(t, cronieSELinuxRefuses("bin_t"))
}

func newCrontabOnMemFs(t *testing.T, family []string, files map[string]string, cmds map[string]*mock.Command) *mqlCrontab {
	t.Helper()
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: family[0], Family: family}}
	mc, err := mock.New(0, asset, mock.WithData(&mock.TomlData{Commands: cmds}))
	require.NoError(t, err)
	fs := afero.NewMemMapFs()
	for p, content := range files {
		require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	}
	runtime := &plugin.Runtime{Connection: &fsWrapConn{Connection: mc, fs: fs}, Resources: &syncx.Map[plugin.Resource]{}}
	raw, err := CreateResource(runtime, "crontab", nil)
	require.NoError(t, err)
	return raw.(*mqlCrontab)
}

func crontabCommands(t *testing.T, c *mqlCrontab) []string {
	t.Helper()
	entries := c.GetEntries()
	require.NoError(t, entries.Error)
	commands := []string{}
	for _, e := range entries.Data {
		commands = append(commands, e.(*mqlCrontabEntry).Command.Data)
	}
	return commands
}

const g04Nonl = "* * * * * root /usr/bin/touch /var/tmp/g04cron.first\n* * * * * root /usr/bin/touch /var/tmp/g04cron.nonl"

func TestCrontabNoTrailingNewline(t *testing.T) {
	files := map[string]string{
		"/etc/crontab":        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
		"/etc/cron.d/g04":     "* * * * * root /usr/bin/touch /var/tmp/g04cron.ok\n",
		"/etc/cron.d/g04nonl": g04Nonl,
	}

	c := newCrontabOnMemFs(t, []string{"debian", "debian", "linux", "unix", "os"}, files, nil)
	assert.ElementsMatch(t, []string{"cd / && run-parts --report /etc/cron.hourly", "/usr/bin/touch /var/tmp/g04cron.ok"}, crontabCommands(t, c))

	c = newCrontabOnMemFs(t, []string{"almalinux", "redhat", "linux", "unix", "os"}, files, nil)
	assert.ElementsMatch(t, []string{"cd / && run-parts --report /etc/cron.hourly", "/usr/bin/touch /var/tmp/g04cron.ok", "/usr/bin/touch /var/tmp/g04cron.first"}, crontabCommands(t, c))
}

func TestCrontabCronieSELinuxLabels(t *testing.T) {
	files := map[string]string{
		"/etc/crontab":            "",
		"/etc/cron.d/g04m_ok":     "* * * * * root /usr/bin/touch /var/tmp/g04cron/ok\n",
		"/etc/cron.d/g04mmoved":   "* * * * * root /usr/bin/touch /var/tmp/g04cron/moved\n",
		"/sys/fs/selinux/enforce": "1",
	}
	cmds := map[string]*mock.Command{
		"stat -L -c '%C\t%n' -- /etc/crontab":                              {Stdout: "system_u:object_r:system_cron_spool_t:s0\t/etc/crontab\n"},
		"stat -L -c '%C\t%n' -- /etc/cron.d/g04m_ok /etc/cron.d/g04mmoved": {Stdout: "unconfined_u:object_r:system_cron_spool_t:s0\t/etc/cron.d/g04m_ok\nunconfined_u:object_r:user_tmp_t:s0\t/etc/cron.d/g04mmoved\n"},
	}
	rhel := []string{"redhat", "redhat", "linux", "unix", "os"}

	c := newCrontabOnMemFs(t, rhel, files, cmds)
	assert.Equal(t, []string{"/usr/bin/touch /var/tmp/g04cron/ok"}, crontabCommands(t, c))

	// permissive: cronie only logs, and runs the file
	files["/sys/fs/selinux/enforce"] = "0"
	c = newCrontabOnMemFs(t, rhel, files, cmds)
	assert.ElementsMatch(t, []string{"/usr/bin/touch /var/tmp/g04cron/ok", "/usr/bin/touch /var/tmp/g04cron/moved"}, crontabCommands(t, c))
}
