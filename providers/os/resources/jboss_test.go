// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

const jbossTestHome = "/opt/eap"

func jbossMockRuntime(t *testing.T, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()

	for path, file := range files {
		file.Path = path
	}

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:    "linux",
			Family:  []string{"linux", "unix", "os"},
			Version: "test",
		},
	}
	conn, err := mock.New(0, asset, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{},
		Files:    files,
	}))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

func jbossDir() *mock.MockFileData {
	return &mock.MockFileData{StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}}
}

func jbossFile(content string) *mock.MockFileData {
	return &mock.MockFileData{StatData: mock.FileInfo{Mode: 0o644}, Content: content}
}

// jbossMockInstall lays down an installation the discovery can recognize, with
// the given files on top.
func jbossMockInstall(t *testing.T, extra map[string]*mock.MockFileData) *mqlJboss {
	t.Helper()

	files := map[string]*mock.MockFileData{
		jbossTestHome:                        jbossDir(),
		jbossTestHome + "/jboss-modules.jar": jbossFile("jar"),
		jbossTestHome + "/bin":               jbossDir(),
	}
	for path, file := range extra {
		files[path] = file
	}

	raw, err := CreateResource(jbossMockRuntime(t, files), "jboss", map[string]*llx.RawData{})
	require.NoError(t, err)
	return raw.(*mqlJboss)
}

// requireResolvedNullScalar is requireResolvedNull for a scalar field, whose
// zero value is not nil and so cannot be asserted the same way. Only the state
// bits distinguish "resolved to nothing" from "never answered".
func requireResolvedNullScalar(t *testing.T, state plugin.State, err error, field string) {
	t.Helper()
	require.NoError(t, err, field)
	assert.NotZero(t, state&plugin.StateIsSet, "%s must be marked as resolved", field)
	assert.NotZero(t, state&plugin.StateIsNull, "%s must be marked as null", field)
}

// An asset with no JBoss on it must resolve every field to null rather than to
// a zero value. An empty string reads as a configured-but-blank path, and an
// empty list makes `.all(...)` vacuously true — both of which are silent
// passes on an asset the check does not apply to at all.
func TestJbossWithoutAnInstallationResolvesToNull(t *testing.T) {
	raw, err := CreateResource(jbossMockRuntime(t, map[string]*mock.MockFileData{}), "jboss", map[string]*llx.RawData{})
	require.NoError(t, err)
	installation := raw.(*mqlJboss)

	for _, tc := range []struct {
		field string
		value *plugin.TValue[string]
	}{
		{"home", installation.GetHome()},
		{"product", installation.GetProduct()},
		{"version", installation.GetVersion()},
		{"launchType", installation.GetLaunchType()},
		{"baseDir", installation.GetBaseDir()},
		{"configDir", installation.GetConfigDir()},
		{"logDir", installation.GetLogDir()},
		{"dataDir", installation.GetDataDir()},
		{"deploymentDir", installation.GetDeploymentDir()},
		{"vaultDir", installation.GetVaultDir()},
		{"configFile", installation.GetConfigFile()},
		{"securityPolicy", installation.GetSecurityPolicy()},
	} {
		requireResolvedNullScalar(t, tc.value.State, tc.value.Error, "jboss."+tc.field)
	}

	securityManager := installation.GetSecurityManagerEnabled()
	requireResolvedNullScalar(t, securityManager.State, securityManager.Error, "jboss.securityManagerEnabled")

	config := installation.GetConfig()
	requireResolvedNull(t, config.State, config.Error, config.Data, "jboss.config")

	host := installation.GetHost()
	requireResolvedNull(t, host.State, host.Error, host.Data, "jboss.host")

	management := installation.GetManagement()
	requireResolvedNull(t, management.State, management.Error, management.Data, "jboss.management")

	startupScript := installation.GetStartupScript()
	requireResolvedNull(t, startupScript.State, startupScript.Error, startupScript.Data, "jboss.startupScript")

	startupConfig := installation.GetStartupConfig()
	requireResolvedNull(t, startupConfig.State, startupConfig.Error, startupConfig.Data, "jboss.startupConfig")

	configs := installation.GetConfigs()
	requireResolvedNull(t, configs.State, configs.Error, configs.Data, "jboss.configs")

	javaOpts := installation.GetJavaOpts()
	requireResolvedNull(t, javaOpts.State, javaOpts.Error, javaOpts.Data, "jboss.javaOpts")

	managementUsers := installation.GetManagementUsers()
	requireResolvedNull(t, managementUsers.State, managementUsers.Error, managementUsers.Data, "jboss.managementUsers")

	applicationUsers := installation.GetApplicationUsers()
	requireResolvedNull(t, applicationUsers.State, applicationUsers.Error, applicationUsers.Data, "jboss.applicationUsers")
}

// The discovery has to recognize an installation by the module loader the
// server boots through, not by the directory it happens to sit in. The vendor
// images alone disagree on that directory three ways.
func TestJbossDiscoversAnInstallationOutsideTheDefaultPath(t *testing.T) {
	for _, home := range []string{
		"/opt/eap",
		"/opt/jboss/jboss-eap-6.3",
		"/opt/rh/eap7/root/usr/share/wildfly",
		"/usr/share/jbossas",
	} {
		t.Run(home, func(t *testing.T) {
			files := map[string]*mock.MockFileData{
				home:                               jbossDir(),
				home + "/jboss-modules.jar":        jbossFile("jar"),
				home + "/standalone":               jbossDir(),
				home + "/standalone/configuration": jbossDir(),
			}
			// The globs that carry a wildcard are resolved by listing the
			// parent, so every directory on the way down has to exist — which
			// it does on a real target, and has to be spelled out here.
			for dir := path.Dir(home); dir != "/" && dir != "."; dir = path.Dir(dir) {
				files[dir] = jbossDir()
			}
			runtime := jbossMockRuntime(t, files)
			raw, err := CreateResource(runtime, "jboss", map[string]*llx.RawData{})
			require.NoError(t, err)

			installation := raw.(*mqlJboss)
			assert.Equal(t, home, installation.GetHome().Data)
			assert.Equal(t, "standalone", installation.GetLaunchType().Data,
				"only the standalone tree is present, so the mode is not a guess")
			assert.Equal(t, home+"/standalone/log", installation.GetLogDir().Data)
		})
	}
}

// An installation that carries only the domain tree is a managed domain, and
// its management section lives in host.xml rather than in the server profile.
func TestJbossDomainModeReadsHostXml(t *testing.T) {
	installation := jbossMockInstall(t, map[string]*mock.MockFileData{
		jbossTestHome + "/domain":               jbossDir(),
		jbossTestHome + "/domain/configuration": jbossDir(),
		jbossTestHome + "/domain/configuration/domain.xml": jbossFile(
			`<domain xmlns="urn:jboss:domain:1.7"><profiles><profile name="full"/></profiles></domain>`),
		jbossTestHome + "/domain/configuration/host.xml": jbossFile(
			`<host name="master" xmlns="urn:jboss:domain:1.7">
			   <management>
			     <audit-log><logger enabled="true" log-read-only="true"/></audit-log>
			   </management>
			 </host>`),
	})

	assert.Equal(t, "domain", installation.GetLaunchType().Data)
	assert.Equal(t, "domain.xml", installation.GetConfigFile().Data)

	config := installation.GetConfig()
	require.NotNil(t, config.Data)
	assert.Equal(t, "domain", config.Data.GetMode().Data)

	host := installation.GetHost()
	require.NotNil(t, host.Data)
	assert.Equal(t, "master", host.Data.GetHostName().Data)

	// The management section has to come from host.xml. domain.xml has none,
	// and reporting null here would leave every management check vacuous on a
	// domain controller.
	management := installation.GetManagement()
	require.NotNil(t, management.Data, "management must resolve to host.xml's section")
	auditLog := management.Data.GetAuditLog()
	require.NotNil(t, auditLog.Data)
	assert.True(t, auditLog.Data.GetEnabled().Data)

	// A managed domain has no deployment scanner: content is pushed through
	// the domain controller's repository.
	deploymentDir := installation.GetDeploymentDir()
	requireResolvedNullScalar(t, deploymentDir.State, deploymentDir.Error, "jboss.deploymentDir")
}

// A configuration file that exists but yields nothing — empty, or with a root
// element that is not a JBoss one — has to resolve to null. Returning a bare
// nil leaves the field unresolved, which the runtime treats as a provider that
// never answered.
func TestJbossUnparsableConfigResolvesToNull(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"empty file", ""},
		{"whitespace only", "\n  \n\t\n"},
		{"comment without a root element", "<?xml version=\"1.0\"?>\n<!-- nothing -->\n"},
		{"wrong root element", `<Server port="8005" shutdown="SHUTDOWN"/>`},
		{"malformed xml", `<server xmlns="urn:jboss:domain:1.7"><management>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installation := jbossMockInstall(t, map[string]*mock.MockFileData{
				jbossTestHome + "/standalone":                              jbossDir(),
				jbossTestHome + "/standalone/configuration":                jbossDir(),
				jbossTestHome + "/standalone/configuration/standalone.xml": jbossFile(tc.content),
			})

			config := installation.GetConfig()
			requireResolvedNull(t, config.State, config.Error, config.Data, "jboss.config")

			management := installation.GetManagement()
			requireResolvedNull(t, management.State, management.Error, management.Data, "jboss.management")
		})
	}
}

// init(configFile:) reads a profile other than the active one, which is how a
// requirement that must hold across every shipped profile is asserted.
func TestJbossExplicitConfigFile(t *testing.T) {
	runtime := jbossMockRuntime(t, map[string]*mock.MockFileData{
		jbossTestHome:                               jbossDir(),
		jbossTestHome + "/jboss-modules.jar":        jbossFile("jar"),
		jbossTestHome + "/standalone":               jbossDir(),
		jbossTestHome + "/standalone/configuration": jbossDir(),
		jbossTestHome + "/standalone/configuration/standalone.xml": jbossFile(
			`<server xmlns="urn:jboss:domain:1.7"><management><access-control provider="simple"/></management></server>`),
		jbossTestHome + "/standalone/configuration/standalone-full.xml": jbossFile(
			`<server xmlns="urn:jboss:domain:1.7"><management><access-control provider="rbac"/></management></server>`),
	})

	raw, err := CreateResource(runtime, "jboss", map[string]*llx.RawData{
		"configFile": llx.StringData("standalone-full.xml"),
	})
	require.NoError(t, err)
	installation := raw.(*mqlJboss)

	config := installation.GetConfig()
	require.NotNil(t, config.Data)
	assert.Equal(t, "standalone-full.xml", config.Data.GetName().Data)

	management := installation.GetManagement()
	require.NotNil(t, management.Data)
	assert.Equal(t, "rbac", management.Data.GetAccessControlProvider().Data)
}

// A realm properties file that exists but declares no users is a realm with no
// users, which is not the same as having no file to read. The first is an
// empty list, the second is null.
func TestJbossRealmUsersEmptyVersusAbsent(t *testing.T) {
	base := map[string]*mock.MockFileData{
		jbossTestHome + "/standalone":               jbossDir(),
		jbossTestHome + "/standalone/configuration": jbossDir(),
		jbossTestHome + "/standalone/configuration/standalone.xml": jbossFile(
			`<server xmlns="urn:jboss:domain:1.7"/>`),
	}

	t.Run("absent", func(t *testing.T) {
		installation := jbossMockInstall(t, base)
		users := installation.GetManagementUsers()
		requireResolvedNull(t, users.State, users.Error, users.Data, "jboss.managementUsers")
	})

	t.Run("present but empty", func(t *testing.T) {
		files := map[string]*mock.MockFileData{}
		for k, v := range base {
			files[k] = v
		}
		files[jbossTestHome+"/standalone/configuration/mgmt-users.properties"] = jbossFile(
			"#\n# no users have been added\n#\n")

		installation := jbossMockInstall(t, files)
		users := installation.GetManagementUsers()
		require.NoError(t, users.Error)
		assert.Empty(t, users.Data)
		assert.Zero(t, users.State&plugin.StateIsNull,
			"a realm that declares no users is an empty list, not an unknown")
	})
}

// The startup configuration is what turns the Java Security Manager on. When
// there is no such file the answer is not "off" — it is unknown, and reporting
// false would be a silent pass on a control that asks whether it is on.
func TestJbossSecurityManager(t *testing.T) {
	standalone := map[string]*mock.MockFileData{
		jbossTestHome + "/standalone":               jbossDir(),
		jbossTestHome + "/standalone/configuration": jbossDir(),
	}

	t.Run("no startup configuration", func(t *testing.T) {
		installation := jbossMockInstall(t, standalone)
		enabled := installation.GetSecurityManagerEnabled()
		requireResolvedNullScalar(t, enabled.State, enabled.Error, "jboss.securityManagerEnabled")
	})

	t.Run("commented out", func(t *testing.T) {
		files := map[string]*mock.MockFileData{}
		for k, v := range standalone {
			files[k] = v
		}
		files[jbossTestHome+"/bin/standalone.conf"] = jbossFile(
			"# Uncomment this to run with a security manager enabled\n# SECMGR=\"true\"\n" +
				"JAVA_OPTS=\"-Xms1303m -Djava.net.preferIPv4Stack=true\"\n")

		installation := jbossMockInstall(t, files)
		assert.False(t, installation.GetSecurityManagerEnabled().Data)
		assert.Equal(t, []any{"-Xms1303m", "-Djava.net.preferIPv4Stack=true"},
			installation.GetJavaOpts().Data)
	})

	t.Run("turned on", func(t *testing.T) {
		files := map[string]*mock.MockFileData{}
		for k, v := range standalone {
			files[k] = v
		}
		files[jbossTestHome+"/bin/standalone.conf"] = jbossFile(
			"SECMGR=\"true\"\nJAVA_OPTS=\"$JAVA_OPTS -Djava.security.policy==/opt/eap/bin/server.policy\"\n")

		installation := jbossMockInstall(t, files)
		assert.True(t, installation.GetSecurityManagerEnabled().Data)
		assert.Equal(t, "/opt/eap/bin/server.policy", installation.GetSecurityPolicy().Data)
	})
}

// The WildFly server the Debian sweep hosts run, as ps reports it (the JVM
// module flags trimmed).
const jbossSweepWildflyCommand = `java -D[Standalone] @/opt/wildfly-41.0.1.Final/bin/jdk.serialFilter -Xms64m -Xmx512m -Djava.net.preferIPv4Stack=true -Djboss.socket.binding.port-offset=100 -Dorg.jboss.boot.log.file=/opt/wildfly-41.0.1.Final/standalone/log/server.log -Dlogging.configuration=file:/opt/wildfly-41.0.1.Final/standalone/configuration/logging.properties -jar /opt/wildfly-41.0.1.Final/jboss-modules.jar -mp /opt/wildfly-41.0.1.Final/modules org.jboss.as.standalone -Djboss.home.dir=/opt/wildfly-41.0.1.Final -Djboss.server.base.dir=/opt/wildfly-41.0.1.Final/standalone -c standalone-full.xml -b 127.0.0.1 -bmanagement 127.0.0.1`

func TestObserveProcessesOnlyForTheRequestedHome(t *testing.T) {
	procs := []jbossProcess{{command: jbossSweepWildflyCommand, home: "/opt/wildfly-41.0.1.Final"}}

	// Discovery without a home takes the running server.
	observed := observeProcesses(procs, "")
	assert.Equal(t, "/opt/wildfly-41.0.1.Final", observed.home)
	assert.Equal(t, "standalone", observed.launchType)
	assert.Equal(t, "standalone-full.xml", observed.serverConfig)

	// The same server, asked for by its home.
	observed = observeProcesses(procs, "/opt/wildfly-41.0.1.Final/")
	assert.Equal(t, "standalone", observed.launchType)
	assert.Equal(t, "standalone-full.xml", observed.serverConfig)

	// Another installation on the same host borrows nothing from it.
	assert.Equal(t, observedInstall{}, observeProcesses(procs, "/opt/sweep-domain"))

	// A process whose home could not be read cannot be attributed to one.
	assert.Equal(t, observedInstall{}, observeProcesses([]jbossProcess{{command: jbossSweepWildflyCommand}}, "/opt/wildfly-41.0.1.Final"))
}

// jboss(home:) names an installation. A unit that runs a different one must
// not lend it its launch mode, and a home with nothing behind it has none.
func TestJbossExplicitHomeIgnoresOtherInstallations(t *testing.T) {
	const domainHome = "/opt/sweep-domain"
	files := map[string]*mock.MockFileData{
		"/etc/systemd/system":                           jbossDir(),
		"/etc/systemd/system/wildfly.service":           jbossFile("[Service]\nEnvironment=JBOSS_HOME=/opt/wildfly-41.0.1.Final\nExecStart=/opt/wildfly-41.0.1.Final/bin/standalone.sh -c standalone.xml -b 127.0.0.1\n"),
		domainHome:                                      jbossDir(),
		domainHome + "/domain":                          jbossDir(),
		domainHome + "/domain/configuration":            jbossDir(),
		domainHome + "/domain/configuration/domain.xml": jbossFile(`<domain xmlns="urn:jboss:domain:20.0"><profiles><profile name="full"/></profiles></domain>`),
		domainHome + "/domain/configuration/host.xml":   jbossFile(`<host name="primary" xmlns="urn:jboss:domain:20.0"/>`),
	}

	raw, err := CreateResource(jbossMockRuntime(t, files), "jboss", map[string]*llx.RawData{"home": llx.StringData(domainHome)})
	require.NoError(t, err)
	installation := raw.(*mqlJboss)
	assert.Equal(t, "domain", installation.GetLaunchType().Data)
	assert.Equal(t, "domain.xml", installation.GetConfigFile().Data)
	config := installation.GetConfig()
	require.NoError(t, config.Error)
	require.NotNil(t, config.Data)
	assert.Equal(t, "domain", config.Data.GetMode().Data)

	raw, err = CreateResource(jbossMockRuntime(t, files), "jboss", map[string]*llx.RawData{"home": llx.StringData("/nonexistent-jb")})
	require.NoError(t, err)
	missing := raw.(*mqlJboss)
	launchType := missing.GetLaunchType()
	requireResolvedNullScalar(t, launchType.State, launchType.Error, "jboss.launchType")
	configFile := missing.GetConfigFile()
	requireResolvedNullScalar(t, configFile.State, configFile.Error, "jboss.configFile")
}

// The install directory's name is only a version when the directory is there.
func TestJbossVersionNeedsAnInstallDir(t *testing.T) {
	rt := jbossMockRuntime(t, map[string]*mock.MockFileData{})
	raw, err := CreateResource(rt, "jboss", map[string]*llx.RawData{"home": llx.StringData("/opt/wildfly-99.0.0.Final")})
	require.NoError(t, err)
	v := raw.(*mqlJboss).GetVersion()
	require.NoError(t, v.Error)
	assert.True(t, v.IsNull(), "got %q", v.Data)

	rt = jbossMockRuntime(t, map[string]*mock.MockFileData{
		"/opt/wildfly-26.1.3.Final":                   jbossDir(),
		"/opt/wildfly-26.1.3.Final/jboss-modules.jar": jbossFile("jar"),
	})
	raw, err = CreateResource(rt, "jboss", map[string]*llx.RawData{"home": llx.StringData("/opt/wildfly-26.1.3.Final")})
	require.NoError(t, err)
	assert.Equal(t, "26.1.3.Final", raw.(*mqlJboss).GetVersion().Data)
}
