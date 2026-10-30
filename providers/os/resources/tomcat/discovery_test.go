// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFs builds an in-memory filesystem from a path -> content map. Symlinks are
// written as their resolved target, which is what Stat reports on a real
// filesystem — the packaged layouts reach both their jars and their
// configuration through symlinks.
func newFs(t *testing.T, files map[string]string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for path, content := range files {
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}
	return fs
}

// officialLayout is the upstream tarball layout the container images ship:
// one directory playing both roles.
func officialLayout() map[string]string {
	return map[string]string{
		"/usr/local/tomcat/lib/catalina.jar":         "jar",
		"/usr/local/tomcat/bin/bootstrap.jar":        "jar",
		"/usr/local/tomcat/bin/catalina.sh":          "#!/bin/sh",
		"/usr/local/tomcat/conf/server.xml":          "<Server/>",
		"/usr/local/tomcat/conf/catalina.properties": "shared.loader=",
	}
}

// redhatLayout is the packaged layout whose bin/ holds nothing but jars.
// Startup goes through /usr/libexec/tomcat/server, so there is no catalina.sh
// and no version.sh anywhere in the installation.
func redhatLayout() map[string]string {
	return map[string]string{
		// lib -> /usr/share/java/tomcat, resolved.
		"/usr/share/tomcat/lib/catalina.jar":       "jar",
		"/usr/share/tomcat/bin/bootstrap.jar":      "jar",
		"/usr/share/tomcat/bin/tomcat-juli.jar":    "jar",
		"/usr/share/tomcat/bin/catalina-tasks.xml": "<project/>",
		// conf -> /etc/tomcat, resolved.
		"/usr/share/tomcat/conf/server.xml":  "<Server/>",
		"/usr/share/tomcat/conf/tomcat.conf": "CATALINA_HOME=\"/usr/share/tomcat\"",
		"/usr/libexec/tomcat/server":         "#!/bin/sh",
	}
}

// debianLayout splits home from base. CATALINA_HOME carries no conf/ at all —
// what it does carry is etc/, a set of pristine template copies of every
// configuration file that the running server never reads.
func debianLayout() map[string]string {
	return map[string]string{
		"/usr/share/tomcat10/lib/catalina.jar":        "jar",
		"/usr/share/tomcat10/bin/catalina.sh":         "#!/bin/sh",
		"/usr/share/tomcat10/etc/server.xml":          "<Server port=\"9999\"><!-- decoy template --></Server>",
		"/usr/share/tomcat10/etc/web.xml":             "<web-app/>",
		"/usr/share/tomcat10/etc/catalina.properties": "decoy=true",
		// base; conf -> /etc/tomcat10, resolved.
		"/var/lib/tomcat10/conf/server.xml":          "<Server port=\"-1\"/>",
		"/var/lib/tomcat10/conf/catalina.properties": "real=true",
	}
}

// TestRedHatLayoutHasNoCatalinaSh is the regression that pins the discovery
// signal. The Red Hat packages ship no catalina.sh, so any probe keyed on the
// startup script misses the installation entirely.
func TestRedHatLayoutHasNoCatalinaSh(t *testing.T) {
	fs := newFs(t, redhatLayout())

	exists, err := afero.Exists(fs, "/usr/share/tomcat/bin/catalina.sh")
	require.NoError(t, err)
	require.False(t, exists, "the fixture must not carry a catalina.sh")

	assert.True(t, IsInstallDir(fs, "/usr/share/tomcat"),
		"catalina.jar identifies the installation without a startup script")
	assert.Equal(t, "/usr/share/tomcat", ProbeHome(fs))
	assert.Equal(t, "/usr/share/tomcat", ProbeBase(fs, "/usr/share/tomcat"),
		"home doubles as base when it owns conf/server.xml")
}

// TestDebianLayoutIgnoresTemplateConfig is the regression for the decoy: the
// installation directory holds template copies of every configuration file
// under etc/, and resolving to those would report settings the running server
// never applies.
func TestDebianLayoutIgnoresTemplateConfig(t *testing.T) {
	fs := newFs(t, debianLayout())

	home := ProbeHome(fs)
	require.Equal(t, "/usr/share/tomcat10", home)

	assert.False(t, IsInstanceDir(fs, home),
		"the installation has no conf/, only the etc/ templates")

	base := ProbeBase(fs, home)
	assert.Equal(t, "/var/lib/tomcat10", base, "the instance owns the live configuration")

	// The templates are only reachable under etc/, which nothing resolves to.
	exists, err := afero.Exists(fs, "/usr/share/tomcat10/etc/server.xml")
	require.NoError(t, err)
	assert.True(t, exists)
	exists, err = afero.Exists(fs, home+"/conf/server.xml")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestProbeLayouts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		home  string
		base  string
	}{
		{"official", officialLayout(), "/usr/local/tomcat", "/usr/local/tomcat"},
		{"redhat", redhatLayout(), "/usr/share/tomcat", "/usr/share/tomcat"},
		{"debian", debianLayout(), "/usr/share/tomcat10", "/var/lib/tomcat10"},
		{"tarball", map[string]string{
			"/opt/apache-tomcat-11.0.24/lib/catalina.jar": "jar",
			"/opt/apache-tomcat-11.0.24/conf/server.xml":  "<Server/>",
		}, "/opt/apache-tomcat-11.0.24", "/opt/apache-tomcat-11.0.24"},
		{"named-instance", map[string]string{
			"/opt/tomcat11/lib/catalina.jar":             "jar",
			"/var/lib/tomcats/instance1/conf/server.xml": "<Server/>",
		}, "/opt/tomcat11", "/var/lib/tomcats/instance1"},
		{"none", map[string]string{"/etc/passwd": "root:x:0:0::/root:/bin/sh"}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFs(t, tc.files)
			home := ProbeHome(fs)
			assert.Equal(t, tc.home, home)
			assert.Equal(t, tc.base, ProbeBase(fs, home))
		})
	}
}

func TestPathsFromSystemd(t *testing.T) {
	t.Run("environment assignments", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/usr/lib/systemd/system/tomcat10.service": `[Service]
Environment="CATALINA_HOME=/usr/share/tomcat10"
Environment="CATALINA_BASE=/var/lib/tomcat10"
Environment="JAVA_OPTS=-Djava.awt.headless=true"
ExecStart=/bin/sh /usr/libexec/tomcat10/tomcat-start.sh
`,
		})
		home, base := PathsFromSystemd(fs)
		assert.Equal(t, "/usr/share/tomcat10", home)
		assert.Equal(t, "/var/lib/tomcat10", base)
	})

	t.Run("environment file", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/usr/lib/systemd/system/tomcat.service": `[Service]
EnvironmentFile=/etc/tomcat/tomcat.conf
Environment="NAME="
EnvironmentFile=-/etc/sysconfig/tomcat
ExecStart=/usr/libexec/tomcat/server start
`,
			"/etc/tomcat/tomcat.conf": `TOMCATS_BASE="/var/lib/tomcats/"
CATALINA_HOME="/usr/share/tomcat"
JAVA_HOME="/usr/lib/jvm/jre"
`,
			"/etc/sysconfig/tomcat": "# every line is a comment\n",
		})
		home, base := PathsFromSystemd(fs)
		assert.Equal(t, "/usr/share/tomcat", home)
		assert.Empty(t, base, "the unit declares no base; the caller falls back to home")
	})

	t.Run("template units are skipped", func(t *testing.T) {
		// A template resolves its base from a %i that is only bound when a
		// named instance is started. Reading it yields a literal "%i" path.
		fs := newFs(t, map[string]string{
			"/usr/lib/systemd/system/tomcat@.service": `[Service]
Environment="CATALINA_BASE=/var/lib/tomcats/%i"
Environment="CATALINA_HOME=/usr/share/tomcat"
ExecStart=/usr/libexec/tomcat/server start
`,
		})
		home, base := PathsFromSystemd(fs)
		assert.Empty(t, home)
		assert.Empty(t, base)
	})

	t.Run("unrelated units", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/etc/systemd/system/sshd.service": "[Service]\nExecStart=/usr/sbin/sshd -D\n",
		})
		home, base := PathsFromSystemd(fs)
		assert.Empty(t, home)
		assert.Empty(t, base)
	})
}

func TestPathsFromEnvConfigs(t *testing.T) {
	fs := newFs(t, map[string]string{
		"/etc/tomcat/tomcat.conf":         "CATALINA_HOME=\"/usr/share/tomcat\"\n",
		"/etc/sysconfig/tomcat@instance1": "CATALINA_BASE=\"/var/lib/tomcats/instance1\"\nCATALINA_OPTS=\"-Xmx512m\"\n",
	})
	home, base := PathsFromEnvConfigs(fs)
	assert.Equal(t, "/usr/share/tomcat", home)
	assert.Equal(t, "/var/lib/tomcats/instance1", base)
}

func TestPathsFromSetenv(t *testing.T) {
	fs := newFs(t, map[string]string{
		"/srv/tomcat/prod1/bin/setenv.sh": `#!/bin/sh
CATALINA_HOME=/opt/tomcat11
CATALINA_BASE=/srv/tomcat/prod1
JAVA_OPTS="-Xms512m"
export CATALINA_HOME CATALINA_BASE JAVA_OPTS
`,
	})
	home, base := PathsFromSetenv(fs, "/srv/tomcat/prod1", "/opt/tomcat11")
	assert.Equal(t, "/opt/tomcat11", home)
	assert.Equal(t, "/srv/tomcat/prod1", base)
}

func TestPathsFromCommand(t *testing.T) {
	cmd := "/opt/java/openjdk/bin/java -Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties " +
		"-Dcatalina.base=/srv/tomcat/prod1 -Dcatalina.home=/opt/tomcat11 " +
		"-Dignore.endorsed.dirs= -classpath /opt/tomcat11/bin/bootstrap.jar " +
		"org.apache.catalina.startup.Bootstrap start"

	assert.True(t, IsCatalinaCommand(cmd))
	home, base := PathsFromCommand(cmd)
	assert.Equal(t, "/opt/tomcat11", home)
	assert.Equal(t, "/srv/tomcat/prod1", base)

	assert.False(t, IsCatalinaCommand("/usr/sbin/sshd -D"))
}

// TestIsCatalinaCommandRejectsBystanders pins the `-D` prefix. A JVM that
// merely mentions a catalina property — a build, a deployment tool, an
// ordinary text editor — is not the server, and treating it as one would hand
// discovery whatever path that process happened to name.
func TestIsCatalinaCommandRejectsBystanders(t *testing.T) {
	for _, cmd := range []string{
		"java -jar deploy-tool.jar --describe catalina.home",
		"/bin/sh -c 'echo catalina.base is unset'",
		"grep -r catalina.home /etc",
		"vim /opt/tomcat/bin/catalina.sh.orig.notes",
	} {
		assert.False(t, IsCatalinaCommand(cmd), cmd)
	}

	for _, cmd := range []string{
		"java -Dcatalina.home=/opt/tomcat11 -jar bootstrap.jar",
		"java -Dcatalina.base=/srv/prod1 start",
		"/bin/sh /usr/local/tomcat/bin/catalina.sh run",
		"java org.apache.catalina.startup.Bootstrap start",
	} {
		assert.True(t, IsCatalinaCommand(cmd), cmd)
	}
}

func TestPathsFromEnviron(t *testing.T) {
	environ := "PATH=/usr/bin\x00CATALINA_HOME=/usr/local/tomcat\x00TOMCAT_VERSION=11.0.24\x00"
	home, base := PathsFromEnviron(environ)
	assert.Equal(t, "/usr/local/tomcat", home)
	assert.Empty(t, base)
}

func TestVersionFromReleaseNotes(t *testing.T) {
	notes := `
                     Apache Tomcat Version 11.0.24
                        Release Notes
`
	assert.Equal(t, "11.0.24", VersionFromReleaseNotes(notes))
	assert.Empty(t, VersionFromReleaseNotes("nothing to see here"))
}

func TestVersionFromInstallDir(t *testing.T) {
	assert.Equal(t, "11.0.24", VersionFromInstallDir("/opt/apache-tomcat-11.0.24"))
	assert.Equal(t, "10.1.57", VersionFromInstallDir("/usr/local/tomcat-10.1.57"))
	assert.Empty(t, VersionFromInstallDir("/usr/share/tomcat10"), "a major-only package name is not a version")
	assert.Empty(t, VersionFromInstallDir("/usr/local/tomcat"))
	assert.Empty(t, VersionFromInstallDir(""))
}

func TestSplitUnitEnvironmentHandlesEscapedQuotes(t *testing.T) {
	// systemd allows a backslash to escape the quote character inside a quoted
	// value. Reading the escaped quote as the closing one truncates the value,
	// which for a path would mean discovering an install directory that does
	// not exist rather than reporting that none was found.
	assert.Equal(t,
		[]string{`JAVA_OPTS=-Dname="prod"`},
		splitUnitEnvironment(`"JAVA_OPTS=-Dname=\"prod\""`))

	assert.Equal(t,
		[]string{`CATALINA_HOME=/opt/tomcat 11`},
		splitUnitEnvironment(`"CATALINA_HOME=/opt/tomcat 11"`),
		"a quoted value keeps its spaces")

	assert.Equal(t,
		[]string{`CATALINA_HOME=/opt/back\slash`},
		splitUnitEnvironment(`"CATALINA_HOME=/opt/back\\slash"`),
		"an escaped backslash is one literal backslash")

	assert.Equal(t,
		[]string{"CATALINA_HOME=/opt/tomcat", "CATALINA_BASE=/srv/prod1"},
		splitUnitEnvironment(`CATALINA_HOME=/opt/tomcat CATALINA_BASE=/srv/prod1`),
		"unquoted assignments still split on whitespace")
}
