// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jboss_test

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/jboss"
)

// newFs builds an in-memory filesystem holding the given files.
func newFs(t *testing.T, files map[string]string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for name, content := range files {
		require.NoError(t, fs.MkdirAll(path.Dir(name), 0o755))
		require.NoError(t, afero.WriteFile(fs, name, []byte(content), 0o644))
	}
	return fs
}

func TestIsJBossCommand(t *testing.T) {
	t.Run("recognizes a server", func(t *testing.T) {
		for _, cmd := range []string{
			"/usr/bin/java -D[Standalone] -server -Djboss.home.dir=/opt/eap org.jboss.as.standalone",
			"/bin/sh /opt/jboss/wildfly/bin/standalone.sh -c standalone-full.xml",
			"/usr/bin/java -D[Process Controller] org.jboss.as.process-controller",
			"/bin/sh /opt/eap/bin/domain.sh",
			"java -jar /opt/eap/jboss-modules.jar -mp /opt/eap/modules org.jboss.modules.Main",
		} {
			assert.True(t, jboss.IsJBossCommand(cmd), cmd)
		}
	})

	t.Run("ignores an unrelated JVM that merely names a path", func(t *testing.T) {
		for _, cmd := range []string{
			"/usr/bin/java -cp /opt/jboss/lib/deploy.jar com.example.Deployer --home /opt/eap",
			"/bin/bash /home/ops/backup-standalone.sh.bak",
			"vim /opt/eap/bin/standalone.sh",
		} {
			assert.False(t, jboss.IsJBossCommand(cmd), cmd)
		}
	})
}

func TestHomeFromCommand(t *testing.T) {
	assert.Equal(t, "/opt/eap",
		jboss.HomeFromCommand("java -Djboss.home.dir=/opt/eap org.jboss.as.standalone"))
	assert.Equal(t, "/opt/jboss eap",
		jboss.HomeFromCommand(`java -Djboss.home.dir="/opt/jboss eap" org.jboss.as.standalone`))
	assert.Empty(t, jboss.HomeFromCommand("java -Dsomething.else=/opt/eap"))
}

func TestLaunchTypeFromCommand(t *testing.T) {
	assert.Equal(t, "standalone",
		jboss.LaunchTypeFromCommand("java -D[Standalone] org.jboss.as.standalone"))
	assert.Equal(t, "domain",
		jboss.LaunchTypeFromCommand("java -D[Host Controller] org.jboss.as.host-controller"))
	assert.Equal(t, "domain",
		jboss.LaunchTypeFromCommand("/bin/sh /opt/eap/bin/domain.sh --host-config=host-slave.xml"))
	assert.Empty(t, jboss.LaunchTypeFromCommand("java -jar app.jar"))
}

func TestConfigFromCommand(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		server, domain, host := jboss.ConfigFromCommand(
			"/bin/sh /opt/eap/bin/standalone.sh -c standalone-full-ha.xml -b 0.0.0.0")
		assert.Equal(t, "standalone-full-ha.xml", server)
		assert.Empty(t, domain)
		assert.Empty(t, host)
	})

	t.Run("long form", func(t *testing.T) {
		server, _, _ := jboss.ConfigFromCommand(
			"java org.jboss.as.standalone --server-config=standalone-ha.xml")
		assert.Equal(t, "standalone-ha.xml", server)
	})

	t.Run("domain", func(t *testing.T) {
		server, domain, host := jboss.ConfigFromCommand(
			"/bin/sh /opt/eap/bin/domain.sh --domain-config=domain-prod.xml --host-config=host-slave.xml")
		assert.Empty(t, server)
		assert.Equal(t, "domain-prod.xml", domain)
		assert.Equal(t, "host-slave.xml", host)
	})
}

func TestHomeFromEnviron(t *testing.T) {
	environ := "PATH=/usr/bin\x00JBOSS_HOME=/opt/rh/eap7/root/usr/share/wildfly\x00LANG=C\x00"
	assert.Equal(t, "/opt/rh/eap7/root/usr/share/wildfly", jboss.HomeFromEnviron(environ))
	assert.Empty(t, jboss.HomeFromEnviron("PATH=/usr/bin\x00"))
}

func TestPathsFromSystemd(t *testing.T) {
	t.Run("reads the unit", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/etc/systemd/system/wildfly.service": `
[Unit]
Description=WildFly Application Server
[Service]
Environment=JBOSS_HOME=/opt/wildfly "JAVA_OPTS=-Xmx1g -Dx=\"y\""
ExecStart=/opt/wildfly/bin/standalone.sh -c standalone-full.xml
`,
		})
		home, launchType := jboss.PathsFromSystemd(fs, "")
		assert.Equal(t, "/opt/wildfly", home)
		assert.Equal(t, "standalone", launchType)
	})

	t.Run("follows EnvironmentFile", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/etc/systemd/system/jboss-eap.service": `
[Service]
EnvironmentFile=-/etc/default/jboss-eap
ExecStart=/bin/sh -c 'exec $JBOSS_HOME/bin/domain.sh'
`,
			"/etc/default/jboss-eap": "JBOSS_HOME=\"/opt/jboss-eap-7.4\"\n",
		})
		home, launchType := jboss.PathsFromSystemd(fs, "")
		assert.Equal(t, "/opt/jboss-eap-7.4", home)
		assert.Equal(t, "domain", launchType)
	})

	t.Run("skips a template unit", func(t *testing.T) {
		// A template resolves its instance from a %i that is only bound when a
		// named instance is started, so reading it would hand back a literal
		// "%i" as a path.
		fs := newFs(t, map[string]string{
			"/etc/systemd/system/wildfly@.service": `
[Service]
Environment=JBOSS_HOME=/opt/wildfly/instances/%i
ExecStart=/opt/wildfly/bin/standalone.sh
`,
		})
		home, launchType := jboss.PathsFromSystemd(fs, "")
		assert.Empty(t, home)
		assert.Empty(t, launchType)
	})

	t.Run("only the unit of the requested home", func(t *testing.T) {
		// The Debian sweep hosts run WildFly from a unit while a domain-only
		// installation sits next to it with no unit of its own.
		fs := newFs(t, map[string]string{
			"/etc/systemd/system/wildfly.service": `
[Service]
User=wildfly
Environment=JBOSS_HOME=/opt/wildfly-41.0.1.Final
ExecStart=/opt/wildfly-41.0.1.Final/bin/standalone.sh -c standalone.xml -b 127.0.0.1 -bmanagement 127.0.0.1
`,
			"/etc/systemd/system/eap-domain.service": `
[Service]
Environment=JBOSS_HOME=/opt/eap-domain
ExecStart=/opt/eap-domain/bin/domain.sh
`,
		})
		home, launchType := jboss.PathsFromSystemd(fs, "/opt/eap-domain/")
		assert.Equal(t, "/opt/eap-domain", home)
		assert.Equal(t, "domain", launchType)

		home, launchType = jboss.PathsFromSystemd(fs, "/opt/sweep-domain")
		assert.Empty(t, home)
		assert.Empty(t, launchType, "another installation's unit says nothing about this one")
	})

	t.Run("ignores an unrelated unit", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/etc/systemd/system/nginx.service": "[Service]\nExecStart=/usr/sbin/nginx\n",
		})
		home, _ := jboss.PathsFromSystemd(fs, "")
		assert.Empty(t, home)
	})
}

func TestHomeFromEnvConfigs(t *testing.T) {
	fs := newFs(t, map[string]string{
		"/etc/default/wildfly": "# JBOSS_HOME=/wrong\nexport JBOSS_HOME=/opt/wildfly\nJBOSS_USER=wildfly\n",
	})
	assert.Equal(t, "/opt/wildfly", jboss.HomeFromEnvConfigs(fs),
		"a commented assignment must not win over the real one")

	assert.Empty(t, jboss.HomeFromEnvConfigs(newFs(t, map[string]string{})))
}

func TestProbeHome(t *testing.T) {
	t.Run("finds the vendor image layout", func(t *testing.T) {
		// The Red Hat OpenShift image installs into /opt/eap, which is not the
		// path any of the other vendor layouts use.
		fs := newFs(t, map[string]string{
			"/opt/eap/jboss-modules.jar":                       "",
			"/opt/eap/standalone/configuration/standalone.xml": "",
		})
		assert.Equal(t, "/opt/eap", jboss.ProbeHome(fs))
	})

	t.Run("finds a versioned unpacked distribution", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/opt/jboss/jboss-eap-6.3/jboss-modules.jar": "",
		})
		assert.Equal(t, "/opt/jboss/jboss-eap-6.3", jboss.ProbeHome(fs))
	})

	t.Run("finds a Software Collections install", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/opt/rh/eap7/root/usr/share/wildfly/bin/standalone.sh": "",
		})
		assert.Equal(t, "/opt/rh/eap7/root/usr/share/wildfly", jboss.ProbeHome(fs))
	})

	t.Run("a matching directory without a marker does not win", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/opt/wildfly/README.md": "",
		})
		assert.Empty(t, jboss.ProbeHome(fs))
	})
}

func TestLaunchTypeFromDisk(t *testing.T) {
	t.Run("answers when only one tree is present", func(t *testing.T) {
		standaloneOnly := newFs(t, map[string]string{
			"/opt/eap/standalone/configuration/standalone.xml": "",
		})
		assert.Equal(t, "standalone", jboss.LaunchTypeFromDisk(standaloneOnly, "/opt/eap"))

		domainOnly := newFs(t, map[string]string{
			"/opt/eap/domain/configuration/domain.xml": "",
		})
		assert.Equal(t, "domain", jboss.LaunchTypeFromDisk(domainOnly, "/opt/eap"))
	})

	t.Run("stays silent when both are present", func(t *testing.T) {
		// A stock installation ships both trees, so their presence alone says
		// nothing about which one is live. Reporting "" lets the caller apply
		// its documented fallback rather than guess here.
		both := newFs(t, map[string]string{
			"/opt/eap/standalone/configuration/standalone.xml": "",
			"/opt/eap/domain/configuration/domain.xml":         "",
		})
		assert.Empty(t, jboss.LaunchTypeFromDisk(both, "/opt/eap"))
	})

	t.Run("stays silent without an installation", func(t *testing.T) {
		assert.Empty(t, jboss.LaunchTypeFromDisk(newFs(t, map[string]string{}), ""))
	})
}

func TestParseVersionFile(t *testing.T) {
	product, version := jboss.ParseVersionFile(
		"Red Hat JBoss Enterprise Application Platform - Version 6.4.23.GA\n")
	assert.Equal(t, "Red Hat JBoss Enterprise Application Platform", product)
	assert.Equal(t, "6.4.23.GA", version)

	product, version = jboss.ParseVersionFile("WildFly Full - Version 26.1.3.Final")
	assert.Equal(t, "WildFly Full", product)
	assert.Equal(t, "26.1.3.Final", version)

	product, version = jboss.ParseVersionFile("nothing useful here")
	assert.Empty(t, product)
	assert.Empty(t, version)
}

func TestParseProductManifest(t *testing.T) {
	product, version := jboss.ParseProductManifest(
		"Manifest-Version: 1.0\r\nJBoss-Product-Release-Name: WildFly Full\r\nJBoss-Product-Release-Version: 26.1.3.Final\r\n")
	assert.Equal(t, "WildFly Full", product)
	assert.Equal(t, "26.1.3.Final", version)
}

func TestParseVersionJarName(t *testing.T) {
	// A community WildFly ships neither version.txt nor a product module, and
	// names its version only in this file.
	product, version := jboss.ParseVersionJarName(
		"/opt/jboss/wildfly/modules/system/layers/base/org/jboss/as/version/main/wildfly-version-8.2.1.Final.jar")
	assert.Equal(t, "WildFly", product)
	assert.Equal(t, "8.2.1.Final", version)

	product, version = jboss.ParseVersionJarName("jboss-as-version-7.1.1.Final.jar")
	assert.Equal(t, "JBoss AS", product)
	assert.Equal(t, "7.1.1.Final", version)

	product, version = jboss.ParseVersionJarName("jboss-modules.jar")
	assert.Empty(t, product)
	assert.Empty(t, version)
}

func TestProductVersionFromJars(t *testing.T) {
	// WildFly ships both jars side by side and kept the jboss-as name for
	// compatibility, so the wildfly one has to win or the product is reported
	// as the server it replaced.
	product, version := jboss.ProductVersionFromJars([]string{
		"/opt/jboss/wildfly/modules/system/layers/base/org/jboss/as/version/main/jboss-as-version-8.2.1.Final.jar",
		"/opt/jboss/wildfly/modules/system/layers/base/org/jboss/as/version/main/wildfly-version-8.2.1.Final.jar",
	})
	assert.Equal(t, "WildFly", product)
	assert.Equal(t, "8.2.1.Final", version)

	product, version = jboss.ProductVersionFromJars([]string{"jboss-as-version-7.1.1.Final.jar"})
	assert.Equal(t, "JBoss AS", product)
	assert.Equal(t, "7.1.1.Final", version)

	product, version = jboss.ProductVersionFromJars(nil)
	assert.Empty(t, product)
	assert.Empty(t, version)
}

func TestVersionFromInstallDir(t *testing.T) {
	assert.Equal(t, "6.3", jboss.VersionFromInstallDir("/opt/jboss/jboss-eap-6.3"))
	assert.Equal(t, "26.1.3.Final", jboss.VersionFromInstallDir("/opt/wildfly-26.1.3.Final"))
	assert.Empty(t, jboss.VersionFromInstallDir("/opt/eap"))
	assert.Empty(t, jboss.VersionFromInstallDir(""))
}

func TestParseStartupConfig(t *testing.T) {
	t.Run("the shipped file turns nothing on", func(t *testing.T) {
		content, err := os.ReadFile(filepath.Join("testdata", "eap-6.4-standalone.conf"))
		require.NoError(t, err)
		cfg := jboss.ParseStartupConfig(string(content))

		assert.False(t, cfg.SecurityManager,
			`the shipped file carries SECMGR="true" as a comment, which does not turn it on`)
		assert.Empty(t, cfg.SecurityPolicy)

		assert.Contains(t, cfg.JavaOpts, "-Xms1303m")
		assert.Contains(t, cfg.JavaOpts, "-Djboss.modules.policy-permissions=true")
		assert.NotContains(t, cfg.JavaOpts, "$JAVA_OPTS",
			"the self-append the file is built from is not an option")
		for _, opt := range cfg.JavaOpts {
			assert.True(t, opt[0] == '-', "unexpected non-option %q", opt)
		}
	})

	t.Run("SECMGR turns the security manager on", func(t *testing.T) {
		cfg := jboss.ParseStartupConfig("SECMGR=\"true\"\n")
		assert.True(t, cfg.SecurityManager)

		cfg = jboss.ParseStartupConfig("export SECMGR=true\n")
		assert.True(t, cfg.SecurityManager)

		cfg = jboss.ParseStartupConfig("SECMGR=\"false\"\n")
		assert.False(t, cfg.SecurityManager)
	})

	t.Run("the JVM option turns it on too", func(t *testing.T) {
		cfg := jboss.ParseStartupConfig(
			`JAVA_OPTS="$JAVA_OPTS -Djava.security.manager -Djava.security.policy==/opt/eap/bin/server.policy"`)
		assert.True(t, cfg.SecurityManager)
		// `policy==` is Java's "replace every other policy" spelling; the path
		// it names is the same one, and that is what is reported.
		assert.Equal(t, "/opt/eap/bin/server.policy", cfg.SecurityPolicy)
	})

	t.Run("a quoted policy path with a space survives", func(t *testing.T) {
		cfg := jboss.ParseStartupConfig(
			`JAVA_OPTS="$JAVA_OPTS -Djava.security.policy=/opt/my policy/server.policy"`)
		// Without quoting the shell would split it too, so the parser reports
		// what a shell would: the first word.
		assert.Equal(t, "/opt/my", cfg.SecurityPolicy)
	})

	t.Run("a missing assignment yields no options", func(t *testing.T) {
		cfg := jboss.ParseStartupConfig("# nothing here\n")
		assert.Empty(t, cfg.JavaOpts)
		assert.NotNil(t, cfg.JavaOpts, "an empty option list is a list, not nil")
	})
}

// countingFs counts the files read, standing in for an SSH --sudo connection
// where every read is a `sudo cat`.
type countingFs struct {
	afero.Fs
	reads int
}

func (c *countingFs) Open(name string) (afero.File, error) {
	if fi, err := c.Stat(name); err == nil && !fi.IsDir() {
		c.reads++
	}
	return c.Fs.Open(name)
}

func TestSystemdUnitsFiltered(t *testing.T) {
	files := map[string]string{
		"/etc/systemd/system/wildfly.service":    "[Service]\nEnvironment=JBOSS_HOME=/opt/wildfly\nExecStart=/opt/wildfly/bin/standalone.sh\n",
		"/usr/lib/systemd/system/domain.service": "[Service]\nEnvironment=JBOSS_HOME=/opt/sweep-domain\nExecStart=/opt/sweep-domain/bin/domain.sh\n",
	}
	// a host carries hundreds of unrelated units
	for i := 0; i < 500; i++ {
		files[path.Join("/usr/lib/systemd/system", "unit"+strconv.Itoa(i)+".service")] = "[Service]\nExecStart=/usr/bin/true\n"
	}
	mem := newFs(t, files)

	all := &countingFs{Fs: mem}
	units := jboss.SystemdUnits(all, nil)
	assert.Equal(t, 502, all.reads)
	require.Len(t, units, 2)

	// one grep over the unit directories names the candidates
	grepped := &countingFs{Fs: mem}
	filter := func() ([]string, bool) {
		return []string{"/etc/systemd/system/wildfly.service", "/usr/lib/systemd/system/domain.service"}, true
	}
	assert.Equal(t, units, jboss.SystemdUnits(grepped, filter))
	assert.Equal(t, 2, grepped.reads)

	home, launch := jboss.SelectUnit(units, "/opt/sweep-domain")
	assert.Equal(t, "/opt/sweep-domain", home)
	assert.Equal(t, "domain", launch)
	home, launch = jboss.SelectUnit(units, "")
	assert.Equal(t, "/opt/wildfly", home)
	assert.Equal(t, "standalone", launch)
	home, _ = jboss.SelectUnit(units, "/opt/other")
	assert.Equal(t, "", home)

	// a filter that could not run falls back to reading every unit
	failed := &countingFs{Fs: mem}
	assert.Equal(t, units, jboss.SystemdUnits(failed, func() ([]string, bool) { return nil, false }))
	assert.Equal(t, 502, failed.reads)
}

func TestParseUnitGrepOutput(t *testing.T) {
	out := "/etc/systemd/system/wildfly.service\n/usr/lib/systemd/system/domain.service\n" + jboss.UnitGrepDone + "\n"
	paths, ok := jboss.ParseUnitGrepOutput(out)
	require.True(t, ok)
	assert.Equal(t, []string{"/etc/systemd/system/wildfly.service", "/usr/lib/systemd/system/domain.service"}, paths)

	paths, ok = jboss.ParseUnitGrepOutput(jboss.UnitGrepDone + "\n")
	require.True(t, ok)
	assert.Empty(t, paths)

	// cut short (no sentinel): not trusted
	_, ok = jboss.ParseUnitGrepOutput("/etc/systemd/system/wildfly.service\n")
	assert.False(t, ok)
}
