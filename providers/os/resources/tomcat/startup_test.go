// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellAssignments(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		seed    map[string]string
		want    map[string]string
	}{
		{
			name:    "double quotes group the value",
			content: `JAVA_OPTS="-Djava.awt.headless=true -Xmx512m"`,
			want:    map[string]string{"JAVA_OPTS": "-Djava.awt.headless=true -Xmx512m"},
		},
		{
			name: "an append expands the value so far",
			content: `CATALINA_OPTS="-Da=1"
CATALINA_OPTS="$CATALINA_OPTS -Db=2"
export CATALINA_OPTS="${CATALINA_OPTS} -Dc=3"`,
			want: map[string]string{"CATALINA_OPTS": "-Da=1 -Db=2 -Dc=3"},
		},
		{
			name:    "an append to an unset variable starts empty",
			content: `CATALINA_OPTS="$CATALINA_OPTS -Dorg.apache.catalina.connector.RECYCLE_FACADES=true"`,
			want:    map[string]string{"CATALINA_OPTS": " -Dorg.apache.catalina.connector.RECYCLE_FACADES=true"},
		},
		{
			name:    "the seeded paths are visible",
			content: `CATALINA_OPTS="-Djava.util.logging.config.file=$CATALINA_BASE/conf/logging.properties"`,
			seed:    map[string]string{"CATALINA_BASE": "/var/lib/tomcat9"},
			want: map[string]string{
				"CATALINA_BASE": "/var/lib/tomcat9",
				"CATALINA_OPTS": "-Djava.util.logging.config.file=/var/lib/tomcat9/conf/logging.properties",
			},
		},
		{
			name:    "single quotes are literal",
			content: `JAVA_OPTS='-Dx=$HOME'`,
			want:    map[string]string{"JAVA_OPTS": "-Dx=$HOME"},
		},
		{
			name:    "an option that carries quotes keeps them for the JVM split",
			content: `JAVA_OPTS="-Dmsg=\"a b\" -Dy=1"`,
			want:    map[string]string{"JAVA_OPTS": `-Dmsg="a b" -Dy=1`},
		},
		{
			name: "a quoted value spans lines and a backslash continues one",
			content: "CATALINA_OPTS=\"-Da=1\n  -Db=2\"\n" +
				"JAVA_OPTS=-Dc=3\\\n",
			want: map[string]string{"CATALINA_OPTS": "-Da=1\n  -Db=2", "JAVA_OPTS": "-Dc=3"},
		},
		{
			name:    "several assignments per line",
			content: `A=1; B="$A 2" && export C=3 D="x y"`,
			want:    map[string]string{"A": "1", "B": "1 2", "C": "3", "D": "x y"},
		},
		{
			name: "comments and commented-out assignments are skipped",
			content: `# JAVA_OPTS="-Dcommented=1"
JAVA_OPTS="-Dlive=1" # trailing comment
#CATALINA_OPTS=-Dno`,
			want: map[string]string{"JAVA_OPTS": "-Dlive=1"},
		},
		{
			name: "conditions are not evaluated",
			content: `if [ -r "$CATALINA_BASE/bin/extra" ]; then
  CATALINA_OPTS="$CATALINA_OPTS -Dextra=1"
fi
[ -n "$JSP_COMPILER" ] && JAVA_OPTS="-Dbuild.compiler=$JSP_COMPILER"`,
			want: map[string]string{"CATALINA_OPTS": " -Dextra=1", "JAVA_OPTS": "-Dbuild.compiler="},
		},
		{
			name:    "an assignment that prefixes a command is the command's environment",
			content: `JAVA_OPTS=-Dx=1 "$CATALINA_HOME/bin/catalina.sh" start`,
			want:    map[string]string{},
		},
		{
			name:    "command substitutions are kept as written",
			content: `JAVA_OPTS="-Xmx$(cat /etc/heap) -Dhost=` + "`hostname`" + `"`,
			want:    map[string]string{"JAVA_OPTS": "-Xmx$(cat /etc/heap) -Dhost=`hostname`"},
		},
		{
			name:    "defaults apply to unset and empty variables",
			content: `EMPTY=""; A="${UNSET:-/tmp}"; B="${EMPTY:-/var/tmp}"; C="${EMPTY-kept}"; D="${UNSET-dflt}"`,
			want:    map[string]string{"EMPTY": "", "A": "/tmp", "B": "/var/tmp", "C": "", "D": "dflt"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			maps.Copy(env, tc.seed)
			ShellAssignments(tc.content, env)
			assert.Equal(t, tc.want, env)
		})
	}
}

func TestEnvironmentFileAssignments(t *testing.T) {
	env := map[string]string{"JAVA_OPTS": "-Dfrom.unit=1"}
	EnvironmentFileAssignments(`# systemd reads this file without a shell
JAVA_OPTS="-Djava.awt.headless=true -Xmx1g"
CATALINA_OPTS=-Da=1 -Db=2
TMP_OPTS="$JAVA_OPTS"
export CATALINA_TMPDIR=/var/cache/tomcat/temp
`, env)

	assert.Equal(t, map[string]string{
		// overrides Environment=
		"JAVA_OPTS": "-Djava.awt.headless=true -Xmx1g",
		// an unquoted value runs to the end of the line
		"CATALINA_OPTS": "-Da=1 -Db=2",
		// systemd does not expand variables
		"TMP_OPTS":        "$JAVA_OPTS",
		"CATALINA_TMPDIR": "/var/cache/tomcat/temp",
	}, env)
}

func TestUnitEnvironment(t *testing.T) {
	env := map[string]string{}
	UnitEnvironment(`[Service]
Environment="CATALINA_HOME=/usr/share/tomcat9"
Environment="CATALINA_TMPDIR=/tmp"
Environment="JAVA_OPTS=-Djava.awt.headless=true"
Environment=CATALINA_OPTS=-Da=1 "LANG=C.UTF-8"
EnvironmentFile=-/etc/default/tomcat9
ExecStart=/bin/sh /usr/libexec/tomcat9/tomcat-start.sh
`, env)

	assert.Equal(t, map[string]string{
		"CATALINA_HOME":   "/usr/share/tomcat9",
		"CATALINA_TMPDIR": "/tmp",
		"JAVA_OPTS":       "-Djava.awt.headless=true",
		"CATALINA_OPTS":   "-Da=1",
		"LANG":            "C.UTF-8",
	}, env)
}

func TestSplitOptions(t *testing.T) {
	assert.Equal(t, []string{}, SplitOptions(""))
	assert.Equal(t, []string{}, SplitOptions("  \n "))
	assert.Equal(t,
		[]string{"-Djava.awt.headless=true", "-Xmx1g", "-Dmsg=a b", "-Dq=it's", "-Dpath=/x y"},
		SplitOptions(" -Djava.awt.headless=true\n\t-Xmx1g -Dmsg=\"a b\" \"-Dq=it's\" -Dpath='/x y'"))
	assert.Equal(t, []string{"-Dempty="}, SplitOptions(`-Dempty=""`))
}

func TestJVMOptionsFromArgs(t *testing.T) {
	// /proc/1/cmdline of the official tomcat:9 image, started with CATALINA_OPTS set
	argv := []string{
		"/opt/java/openjdk/bin/java",
		"-Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties",
		"-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager",
		"-Djdk.tls.ephemeralDHKeySize=2048",
		"-Dorg.apache.catalina.connector.RECYCLE_FACADES=true",
		"-classpath", "/usr/local/tomcat/bin/bootstrap.jar:/usr/local/tomcat/bin/tomcat-juli.jar",
		"-Dcatalina.base=/usr/local/tomcat",
		"-Dcatalina.home=/usr/local/tomcat",
		"-Djava.io.tmpdir=/usr/local/tomcat/temp",
		"org.apache.catalina.startup.Bootstrap",
		"start",
	}
	opts, ok := JVMOptionsFromArgs(argv)
	assert.True(t, ok)
	assert.Equal(t, argv[1:10], opts)

	// the shell that starts the JVM is not one
	_, ok = JVMOptionsFromArgs([]string{"/bin/sh", "/usr/local/tomcat/bin/catalina.sh", "run"})
	assert.False(t, ok)
	_, ok = JVMOptionsFromArgs(nil)
	assert.False(t, ok)
}

func TestSystemProperties(t *testing.T) {
	assert.Equal(t, map[string]string{
		"org.apache.catalina.connector.RECYCLE_FACADES":           "false",
		"java.security.manager":                                   "",
		"java.security.policy":                                    "=/etc/catalina.policy",
		"org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH": "false",
	}, SystemProperties([]string{
		"-Dorg.apache.catalina.connector.RECYCLE_FACADES=true",
		"-Xmx1g",
		"-classpath", "/usr/local/tomcat/bin/bootstrap.jar",
		"-Djava.security.manager",
		"-Djava.security.policy==/etc/catalina.policy",
		"-D",
		"-Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=false",
		// the JVM keeps the last value
		"-Dorg.apache.catalina.connector.RECYCLE_FACADES=false",
	}))
}

// debianPackageUnit is /lib/systemd/system/tomcat9.service of Ubuntu 22.04's
// tomcat9 package, which sources /etc/default/tomcat9 from its start script
// rather than naming it as an EnvironmentFile.
const debianPackageUnit = `[Service]
Environment="CATALINA_HOME=/usr/share/tomcat9"
Environment="CATALINA_BASE=/var/lib/tomcat9"
Environment="CATALINA_TMPDIR=/tmp"
Environment="JAVA_OPTS=-Djava.awt.headless=true"
Type=simple
ExecStart=/bin/sh /usr/libexec/tomcat9/tomcat-start.sh
`

func TestStartupConfig(t *testing.T) {
	t.Run("Debian package: unit, then /etc/default", func(t *testing.T) {
		files := debianLayout()
		files["/lib/systemd/system/tomcat10.service"] = debianPackageUnit
		files["/etc/default/tomcat10"] = "# defaults\nJAVA_OPTS=\"-Djava.awt.headless=true -XX:+UseG1GC\"\n#CATALINA_OPTS=\"-Dcommented=1\"\n"
		p := Paths{Home: "/usr/share/tomcat10", Base: "/var/lib/tomcat10"}
		// the unit fixture declares tomcat9 paths, so it belongs to another
		// installation and must not apply
		cfg := StartupConfig(newFs(t, files), p)
		assert.Equal(t, []string{"-Djava.awt.headless=true", "-XX:+UseG1GC"}, cfg.JVMOptions())
		assert.Equal(t, "/var/lib/tomcat10/temp", cfg.TmpDir(p.Base))
		assert.Equal(t, []string{"/etc/default/tomcat10"}, cfg.Files)
	})

	t.Run("Debian package: the unit sets CATALINA_TMPDIR", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/usr/share/tomcat9/lib/catalina.jar": "jar",
			"/var/lib/tomcat9/conf/server.xml":    "<Server/>",
			"/lib/systemd/system/tomcat9.service": debianPackageUnit,
			"/etc/default/tomcat9":                "JAVA_OPTS=\"-Djava.awt.headless=true -Xmx256m\"\n",
		})
		p := Paths{Home: "/usr/share/tomcat9", Base: "/var/lib/tomcat9"}
		cfg := StartupConfig(fs, p)
		assert.Equal(t, []string{"-Djava.awt.headless=true", "-Xmx256m"}, cfg.JVMOptions())
		assert.Equal(t, "/tmp", cfg.TmpDir(p.Base))
		assert.Equal(t, []string{"/lib/systemd/system/tomcat9.service", "/etc/default/tomcat9"}, cfg.Files)
	})

	t.Run("Red Hat package: EnvironmentFile is read once, without a shell", func(t *testing.T) {
		fs := newFs(t, map[string]string{
			"/usr/share/tomcat/lib/catalina.jar": "jar",
			"/usr/share/tomcat/conf/server.xml":  "<Server/>",
			"/usr/lib/systemd/system/tomcat.service": "[Service]\nEnvironmentFile=/etc/tomcat/tomcat.conf\n" +
				"EnvironmentFile=-/etc/sysconfig/tomcat\nExecStart=/usr/libexec/tomcat/server start\n",
			"/etc/tomcat/tomcat.conf": "CATALINA_HOME=\"/usr/share/tomcat\"\nCATALINA_TMPDIR=\"/var/cache/tomcat/temp\"\n" +
				"JAVA_OPTS=\"-Dred.hat=1\"\n",
			"/etc/sysconfig/tomcat": "CATALINA_OPTS=\"-Dsysconfig=1\"\n",
		})
		p := Paths{Home: "/usr/share/tomcat", Base: "/usr/share/tomcat"}
		cfg := StartupConfig(fs, p)
		assert.Equal(t, []string{"-Dred.hat=1", "-Dsysconfig=1"}, cfg.JVMOptions())
		assert.Equal(t, "/var/cache/tomcat/temp", cfg.TmpDir(p.Base))
		assert.Equal(t, []string{
			"/usr/lib/systemd/system/tomcat.service", "/etc/tomcat/tomcat.conf", "/etc/sysconfig/tomcat",
		}, cfg.Files)
	})

	t.Run("setenv.sh of the instance wins over the installation's", func(t *testing.T) {
		files := officialLayout()
		files["/usr/local/tomcat/bin/setenv.sh"] = "CATALINA_OPTS=\"-Dfrom=home\"\n"
		files["/srv/tomcat/a/conf/server.xml"] = "<Server/>"
		files["/srv/tomcat/a/bin/setenv.sh"] = "#!/bin/sh\nCATALINA_OPTS=\"$CATALINA_OPTS -Dorg.apache.catalina.connector.RECYCLE_FACADES=true\"\n" +
			"CATALINA_TMPDIR=\"$CATALINA_BASE/tmp\"\nexport CATALINA_OPTS CATALINA_TMPDIR\n"
		fs := newFs(t, files)

		p := Paths{Home: "/usr/local/tomcat", Base: "/srv/tomcat/a"}
		cfg := StartupConfig(fs, p)
		assert.Equal(t, []string{"-Dorg.apache.catalina.connector.RECYCLE_FACADES=true"}, cfg.JVMOptions())
		assert.Equal(t, "/srv/tomcat/a/tmp", cfg.TmpDir(p.Base))

		single := Paths{Home: "/usr/local/tomcat", Base: "/usr/local/tomcat"}
		cfg = StartupConfig(fs, single)
		assert.Equal(t, []string{"-Dfrom=home"}, cfg.JVMOptions())
		assert.Equal(t, "/usr/local/tomcat/temp", cfg.TmpDir(single.Base))
	})

	t.Run("an environment file of another instance does not apply", func(t *testing.T) {
		files := officialLayout()
		files["/etc/sysconfig/tomcat@other"] = "CATALINA_BASE=/srv/tomcat/other\nCATALINA_OPTS=-Dother=1\n"
		cfg := StartupConfig(newFs(t, files), Paths{Home: "/usr/local/tomcat", Base: "/usr/local/tomcat"})
		assert.Equal(t, []string{}, cfg.JVMOptions())
	})

	t.Run("nothing configured", func(t *testing.T) {
		cfg := StartupConfig(newFs(t, officialLayout()), Paths{Home: "/usr/local/tomcat", Base: "/usr/local/tomcat"})
		assert.Equal(t, []string{}, cfg.JVMOptions())
		assert.Equal(t, "/usr/local/tomcat/temp", cfg.TmpDir("/usr/local/tomcat"))
		assert.Equal(t, "", Startup{Env: map[string]string{}}.TmpDir(""))
	})
}
