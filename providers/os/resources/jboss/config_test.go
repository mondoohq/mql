// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jboss_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/jboss"
)

func load(t *testing.T, name string) *jboss.Document {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	doc, err := jboss.ParseDocument(data)
	require.NoError(t, err)
	require.NotNil(t, doc)
	return doc
}

// The shipped EAP 6.4 standalone profile is the baseline every finding is
// judged against, so the values it carries are asserted verbatim.
func TestShippedStandaloneProfile(t *testing.T) {
	doc := load(t, "eap-6.4-standalone.xml")

	assert.Equal(t, "server", doc.Mode())
	require.Len(t, doc.AllProfiles(), 1, "a standalone profile holds exactly one, unnamed profile")
	assert.Empty(t, doc.AllProfiles()[0].Name)

	require.NotNil(t, doc.Management)

	t.Run("management interfaces", func(t *testing.T) {
		interfaces := doc.Management.ManagementInterfaces()
		require.Len(t, interfaces, 2)

		byType := map[string]jboss.TypedMgmtInterface{}
		for _, iface := range interfaces {
			byType[iface.Type] = iface
		}

		http := byType["http"]
		assert.Equal(t, "ManagementRealm", jboss.Attr(http.Attrs, "security-realm"))
		assert.Equal(t, "management-http", http.SocketBindingAttrs()["http"])
		assert.Empty(t, http.SocketBindingAttrs()["https"],
			"the shipped profile binds the console to plaintext only")
		assert.True(t, jboss.AttrBool(http.Attrs, "console-enabled", true),
			"console-enabled is absent and defaults to on")

		native := byType["native"]
		assert.Equal(t, "management-native", native.SocketBindingAttrs()["native"])
	})

	t.Run("security realms", func(t *testing.T) {
		require.Len(t, doc.Management.SecurityRealms, 2)
		assert.Equal(t, "ManagementRealm", doc.Management.SecurityRealms[0].Name)
		assert.Equal(t, "ApplicationRealm", doc.Management.SecurityRealms[1].Name)

		auth := doc.Management.SecurityRealms[0].Authentication
		require.NotNil(t, auth)
		assert.NotNil(t, auth.Local, "silent authentication is on in the shipped profile")
		assert.Equal(t, "$local", auth.LocalAttrs()["default-user"])
		require.NotNil(t, auth.Properties)
		assert.Equal(t, "mgmt-users.properties", jboss.Attr(auth.Properties.Attrs, "path"))
		assert.Nil(t, auth.LDAP)
		assert.Nil(t, auth.Truststore)
		assert.Nil(t, doc.Management.SecurityRealms[0].Identity())
	})

	t.Run("audit log is off by default", func(t *testing.T) {
		audit := doc.Management.AuditLog
		require.NotNil(t, audit)

		assert.False(t, audit.Enabled())
		require.NotNil(t, audit.Logger)
		assert.False(t, audit.Logger.Enabled())
		assert.True(t, audit.Logger.LogBoot(), "log-boot is on in the shipped profile")
		assert.False(t, audit.Logger.LogReadOnly())
		assert.Equal(t, []string{"file"}, jboss.Names(audit.Logger.Handlers))
		assert.Nil(t, audit.ServerLogger, "a standalone profile has no server-logger")

		require.Len(t, audit.Formatters, 1)
		assert.Equal(t, "json-formatter", jboss.Attr(audit.Formatters[0].Attrs, "name"))

		handlers := audit.Handlers()
		require.Len(t, handlers, 1)
		assert.Equal(t, "file", handlers[0].Type)
		assert.Equal(t, "audit-log.log", jboss.Attr(handlers[0].Attrs, "path"))
		assert.Equal(t, "jboss.server.data.dir", jboss.Attr(handlers[0].Attrs, "relative-to"))
		assert.Equal(t, int64(10), jboss.AttrInt(handlers[0].Attrs, "max-failure-count", 10))
	})

	t.Run("access control defaults to simple", func(t *testing.T) {
		assert.Equal(t, "simple", doc.Management.AccessControlProvider())
		require.NotNil(t, doc.Management.AccessControl)
		require.Len(t, doc.Management.AccessControl.Roles, 1)
		assert.Equal(t, "SuperUser", doc.Management.AccessControl.Roles[0].Name)
		assert.Equal(t, []string{"$local"}, jboss.Names(doc.Management.AccessControl.Roles[0].IncludeUsers))
	})

	t.Run("interfaces", func(t *testing.T) {
		require.Len(t, doc.Interfaces, 3)
		assert.Equal(t, "management", doc.Interfaces[0].Name)
		assert.Equal(t, "${jboss.bind.address.management:127.0.0.1}", doc.Interfaces[0].Address(),
			"the address is a property expression and is reported as written")
		assert.False(t, doc.Interfaces[0].IsAnyAddress())
	})

	t.Run("socket bindings", func(t *testing.T) {
		groups := doc.AllSocketBindingGroups()
		require.Len(t, groups, 1)
		assert.Equal(t, "public", jboss.Attr(groups[0].Attrs, "default-interface"))
		assert.Len(t, groups[0].SocketBindings, 9)
		require.Len(t, groups[0].OutboundBindings(), 1)
		assert.Equal(t, "localhost", groups[0].OutboundBindings()[0].RemoteAttrs()["host"])
	})

	t.Run("subsystem identity", func(t *testing.T) {
		byName := map[string]*jboss.Subsystem{}
		for i := range doc.AllProfiles()[0].Subsystems {
			s := &doc.AllProfiles()[0].Subsystems[i]
			byName[s.Name()] = s
		}

		require.Contains(t, byName, "logging")
		assert.Equal(t, "1.5", byName["logging"].Version())
		assert.Equal(t, "urn:jboss:domain:logging:1.5", byName["logging"].Namespace())
		require.Contains(t, byName, "deployment-scanner")
		assert.Equal(t, "1.1", byName["deployment-scanner"].Version(),
			"a subsystem name with a hyphen must not lose a segment to the version split")
	})

	t.Run("logging", func(t *testing.T) {
		logging := subsystem(t, doc, "logging")
		parsed, err := jboss.ParseLogging(logging)
		require.NoError(t, err)

		assert.Equal(t, "INFO", parsed.RootLevel())
		assert.Equal(t, []string{"CONSOLE", "FILE"}, parsed.RootHandlers())

		handlers := parsed.Handlers()
		require.Len(t, handlers, 2)
		assert.Equal(t, "console-handler", handlers[0].Type)
		assert.Equal(t, "periodic-rotating-file-handler", handlers[1].Type)
		assert.Equal(t, "server.log", handlers[1].FileAttrs()["path"])
		assert.Equal(t, ".yyyy-MM-dd", handlers[1].Suffix.Get())
		assert.Equal(t, "PATTERN", handlers[1].FormatterName())
		assert.Equal(t, int64(1), handlers[1].MaxBackup(), "max-backup-index defaults to 1")
		assert.Len(t, parsed.Loggers, 6)
	})

	t.Run("web", func(t *testing.T) {
		web, err := jboss.ParseWeb(subsystem(t, doc, "web"))
		require.NoError(t, err)

		assert.Equal(t, "default-host", jboss.Attr(web.Attrs, "default-virtual-server"),
			"the subsystem's own attributes survive the re-parse of its body")
		require.Len(t, web.Connectors, 1)
		assert.Equal(t, "http", jboss.Attr(web.Connectors[0].Attrs, "name"))
		assert.False(t, web.Connectors[0].SSLEnabled(), "the shipped profile serves no TLS")

		require.Len(t, web.VirtualServers, 1)
		assert.True(t, jboss.AttrBool(web.VirtualServers[0].Attrs, "enable-welcome-root", true))
		assert.Equal(t, []string{"localhost", "example.com"}, jboss.Names(web.VirtualServers[0].Aliases))
		assert.False(t, web.VirtualServers[0].AccessLogEnabled())
	})

	t.Run("jmx exposes a remoting connector", func(t *testing.T) {
		jmx, err := jboss.ParseJMX(subsystem(t, doc, "jmx"))
		require.NoError(t, err)
		assert.True(t, jmx.RemotingConnectorEnabled(),
			"<remoting-connector/> is an empty element and its presence is the setting")
		assert.True(t, jmx.UseManagementEndpoint())
		assert.NotNil(t, jmx.ExposeResolvedModel)
		assert.False(t, jmx.NonCoreMbeansSensitive())
	})

	t.Run("deployment scanner is on with the attribute absent", func(t *testing.T) {
		scanners, err := jboss.ParseDeploymentScanners(subsystem(t, doc, "deployment-scanner"))
		require.NoError(t, err)
		require.Len(t, scanners.Scanners, 1)
		assert.True(t, jboss.AttrBool(scanners.Scanners[0].Attrs, "scan-enabled", true),
			"scan-enabled is absent from the shipped profile and defaults to on, "+
				"so an absent attribute leaves automatic deployment enabled")
	})
}

// The hardened profile turns everything to its non-default value, so a parser
// that returns the default instead of the configured value fails here.
func TestHardenedStandaloneProfile(t *testing.T) {
	doc := load(t, "hardened-standalone.xml")
	require.NotNil(t, doc.Management)

	t.Run("audit log", func(t *testing.T) {
		audit := doc.Management.AuditLog
		require.NotNil(t, audit)
		assert.True(t, audit.Enabled())
		assert.True(t, audit.Logger.LogBoot())
		assert.True(t, audit.Logger.LogReadOnly())
		assert.Equal(t, []string{"file", "syslog"}, jboss.Names(audit.Logger.Handlers))

		require.Len(t, audit.Formatters, 1)
		assert.True(t, jboss.AttrBool(audit.Formatters[0].Attrs, "escape-control-characters", false))

		handlers := audit.Handlers()
		require.Len(t, handlers, 2)
		assert.Equal(t, "file", handlers[0].Type)
		assert.False(t, jboss.AttrBool(handlers[0].Attrs, "rotate-at-startup", true))
		assert.Equal(t, int64(5), jboss.AttrInt(handlers[0].Attrs, "max-failure-count", 10))

		assert.Equal(t, "syslog", handlers[1].Type)
		transport, transportAttrs := handlers[1].Transport()
		assert.Equal(t, "tcp", transport)
		assert.Equal(t, "10.0.0.20", transportAttrs["host"])
		assert.Equal(t, "514", transportAttrs["port"])
	})

	t.Run("management interfaces", func(t *testing.T) {
		byType := map[string]jboss.TypedMgmtInterface{}
		for _, iface := range doc.Management.ManagementInterfaces() {
			byType[iface.Type] = iface
		}
		http := byType["http"]
		assert.False(t, jboss.AttrBool(http.Attrs, "console-enabled", true))
		assert.Equal(t, "management-https", http.SocketBindingAttrs()["https"])
	})

	t.Run("realm identity and truststore", func(t *testing.T) {
		realm := doc.Management.SecurityRealms[0]

		identity := realm.Identity()
		require.NotNil(t, identity)
		assert.Equal(t, "management.jks", identity.Path())
		assert.Equal(t, "jboss.server.config.dir", identity.RelativeTo())
		assert.True(t, identity.PasswordIsVaultExpression(),
			"a keystore password held in the vault must be distinguishable from one in the clear")

		auth := realm.Authentication
		require.NotNil(t, auth)
		assert.Nil(t, auth.Local, "silent authentication has been removed")
		require.NotNil(t, auth.Truststore)
		assert.Equal(t, "clients.jks", auth.Truststore.Path())

		require.NotNil(t, auth.LDAP)
		assert.Equal(t, "ldap-connection", jboss.Attr(auth.LDAP.Attrs, "connection"))
		assert.False(t, jboss.AttrBool(auth.LDAP.Attrs, "allow-empty-passwords", false))
		assert.True(t, jboss.AttrBool(auth.LDAP.Attrs, "recursive", false))
		assert.Equal(t, "uid", auth.LDAP.UsernameAttribute(),
			"the username attribute is declared on <username-filter> in this schema version")
	})

	t.Run("access control", func(t *testing.T) {
		assert.Equal(t, "rbac", doc.Management.AccessControlProvider())
	})

	t.Run("vault", func(t *testing.T) {
		require.NotNil(t, doc.Vault)
		options := doc.Vault.OptionMap()
		assert.Equal(t, "/opt/jboss/vault/vault.keystore", options["KEYSTORE_URL"])
		assert.Equal(t, "vault", options["KEYSTORE_ALIAS"])
		assert.Equal(t, "/opt/jboss/vault/", options["ENC_FILE_DIR"])
		assert.Len(t, options, 4)
	})

	t.Run("interfaces", func(t *testing.T) {
		byName := map[string]*jboss.Interface{}
		for i := range doc.Interfaces {
			byName[doc.Interfaces[i].Name] = &doc.Interfaces[i]
		}
		assert.Equal(t, "10.0.0.10", byName["management"].Address())
		assert.True(t, byName["public"].IsAnyAddress())
		assert.Empty(t, byName["public"].Address())
		assert.Equal(t, []string{"nic", "loopback"}, byName["internal"].Criteria())
	})

	t.Run("outbound socket bindings", func(t *testing.T) {
		group := doc.AllSocketBindingGroups()[0]
		outbound := group.OutboundBindings()
		require.Len(t, outbound, 3, "all three spellings of an outbound binding are collected")

		byName := map[string]*jboss.SocketBinding{}
		for i := range outbound {
			byName[jboss.Attr(outbound[i].Attrs, "name")] = &outbound[i]
		}
		assert.Equal(t, "636", byName["ldap-connection"].RemoteAttrs()["port"])
		assert.Equal(t, "management-http", byName["local-http"].LocalRef())
	})

	t.Run("deployments", func(t *testing.T) {
		require.Len(t, doc.Deployments, 2)
		assert.True(t, jboss.AttrBool(doc.Deployments[0].Attrs, "enabled", true))
		assert.False(t, jboss.AttrBool(doc.Deployments[1].Attrs, "enabled", true))
	})

	t.Run("system properties", func(t *testing.T) {
		require.Len(t, doc.SystemProperties, 1)
		assert.Equal(t, "jboss.bind.address", doc.SystemProperties[0].Name)
		assert.Equal(t, "10.0.0.10", doc.SystemProperties[0].Value)
	})

	t.Run("web", func(t *testing.T) {
		web, err := jboss.ParseWeb(subsystem(t, doc, "web"))
		require.NoError(t, err)
		require.Len(t, web.Connectors, 2)

		byName := map[string]jboss.Connector{}
		for _, connector := range web.Connectors {
			byName[jboss.Attr(connector.Attrs, "name")] = connector
		}

		http := byName["http"]
		assert.False(t, http.SSLEnabled())
		assert.False(t, jboss.AttrBool(http.Attrs, "enabled", true))

		https := byName["https"]
		assert.True(t, https.SSLEnabled())
		ssl := https.SSLAttrs()
		assert.Equal(t, "TLSv1.2", ssl["protocol"])
		assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", ssl["cipher-suite"])
		assert.Equal(t, "true", ssl["verify-client"])
		assert.True(t, jboss.AttrBool(https.Attrs, "secure", false))

		require.Len(t, web.VirtualServers, 1)
		vs := web.VirtualServers[0]
		assert.False(t, jboss.AttrBool(vs.Attrs, "enable-welcome-root", true))
		assert.True(t, vs.AccessLogEnabled())
		assert.Equal(t, "combined", vs.AccessLogPattern())
		assert.Equal(t, "/var/log/jboss-access", vs.AccessLogDirectory())
	})

	t.Run("logging handlers", func(t *testing.T) {
		parsed, err := jboss.ParseLogging(subsystem(t, doc, "logging"))
		require.NoError(t, err)

		handlers := parsed.Handlers()
		byName := map[string]*jboss.TypedLogHandler{}
		for i := range handlers {
			byName[jboss.Attr(handlers[i].Attrs, "name")] = &handlers[i]
		}
		require.Len(t, byName, 3)

		assert.Equal(t, "periodic-rotating-file-handler", byName["FILE"].Type)
		assert.True(t, byName["FILE"].Appends())

		size := byName["SIZE"]
		assert.Equal(t, "10m", size.RotateSize.Get())
		assert.Equal(t, int64(7), size.MaxBackup())
		assert.False(t, size.Appends())

		syslog := byName["SYSLOG"]
		assert.Equal(t, "syslog-handler", syslog.Type)
		assert.Equal(t, "10.0.0.20", syslog.ServerAddress.Get())
		assert.Equal(t, "514", syslog.Port.Get())
		assert.Equal(t, "WARN", syslog.LevelName())

		require.Len(t, parsed.Loggers, 1)
		assert.Equal(t, "org.example.app", parsed.Loggers[0].Category)
		assert.Equal(t, "DEBUG", parsed.Loggers[0].LevelName())
		assert.False(t, jboss.AttrBool(parsed.Loggers[0].Attrs, "use-parent-handlers", true))
	})

	t.Run("deployment scanner off", func(t *testing.T) {
		scanners, err := jboss.ParseDeploymentScanners(subsystem(t, doc, "deployment-scanner"))
		require.NoError(t, err)
		require.Len(t, scanners.Scanners, 1)
		assert.False(t, jboss.AttrBool(scanners.Scanners[0].Attrs, "scan-enabled", true))
		assert.Equal(t, int64(0), jboss.AttrInt(scanners.Scanners[0].Attrs, "scan-interval", 5000))
	})

	t.Run("jmx sensitivity", func(t *testing.T) {
		jmx, err := jboss.ParseJMX(subsystem(t, doc, "jmx"))
		require.NoError(t, err)
		assert.False(t, jmx.RemotingConnectorEnabled())
		assert.True(t, jmx.NonCoreMbeansSensitive())
		assert.Nil(t, jmx.ExposeExpressionModel)
	})
}

// host.xml carries the management section of a managed domain, and spells the
// management endpoint differently from a standalone profile.
func TestHostConfiguration(t *testing.T) {
	doc := load(t, "eap-6.4-host.xml")

	assert.Equal(t, "host", doc.Mode())
	assert.Equal(t, "master", jboss.Attr(doc.Attrs, "name"))
	assert.Equal(t, "local", doc.DomainController.Kind())
	assert.Empty(t, doc.AllProfiles(), "a host controller declares no profiles")

	require.NotNil(t, doc.Management)

	t.Run("endpoint is an interface and a port, not a socket binding", func(t *testing.T) {
		byType := map[string]jboss.TypedMgmtInterface{}
		for _, iface := range doc.Management.ManagementInterfaces() {
			byType[iface.Type] = iface
		}
		require.Len(t, byType, 2)

		http := byType["http"]
		assert.Empty(t, http.SocketBindingAttrs()["http"])
		assert.Equal(t, "management", http.SocketAttrs()["interface"])
		assert.Equal(t, "${jboss.management.http.port:9990}", http.SocketAttrs()["port"])
	})

	t.Run("a domain audits through two loggers", func(t *testing.T) {
		audit := doc.Management.AuditLog
		require.NotNil(t, audit)
		require.NotNil(t, audit.Logger)
		require.NotNil(t, audit.ServerLogger,
			"the managed servers of a domain are audited by <server-logger>, not by <logger>")

		assert.False(t, audit.Logger.Enabled())
		assert.False(t, audit.ServerLogger.Enabled())
		assert.Equal(t, []string{"host-file"}, jboss.Names(audit.Logger.Handlers))
		assert.Equal(t, []string{"server-file"}, jboss.Names(audit.ServerLogger.Handlers))
		assert.Len(t, audit.Handlers(), 2)
	})

	t.Run("servers", func(t *testing.T) {
		require.Len(t, doc.HostServers, 3)
		assert.Equal(t, "server-one", jboss.Attr(doc.HostServers[0].Attrs, "name"))
		assert.Equal(t, "main-server-group", jboss.Attr(doc.HostServers[0].Attrs, "group"))
		assert.True(t, jboss.AttrBool(doc.HostServers[0].Attrs, "auto-start", true),
			"auto-start is absent on server-one and defaults to on")
		assert.False(t, jboss.AttrBool(doc.HostServers[2].Attrs, "auto-start", true))
		require.NotNil(t, doc.HostServers[1].SocketBindings)
		assert.Equal(t, "150", jboss.Attr(doc.HostServers[1].SocketBindings.Attrs, "port-offset"))
	})
}

func TestDomainConfiguration(t *testing.T) {
	doc := load(t, "domain.xml")

	assert.Equal(t, "domain", doc.Mode())

	profiles := doc.AllProfiles()
	require.Len(t, profiles, 2, "domain.xml wraps its profiles in <profiles> and names each one")
	assert.Equal(t, "default", profiles[0].Name)
	assert.Equal(t, "ha", profiles[1].Name)

	groups := doc.AllSocketBindingGroups()
	require.Len(t, groups, 2, "domain.xml wraps its socket binding groups one level deeper")
	assert.Equal(t, "standard-sockets", jboss.Attr(groups[0].Attrs, "name"))

	require.Len(t, doc.ServerGroups, 2)
	assert.Equal(t, "main-server-group", jboss.Attr(doc.ServerGroups[0].Attrs, "name"))
	assert.Equal(t, "default", jboss.Attr(doc.ServerGroups[0].Attrs, "profile"))
	assert.Equal(t, "standard-sockets", doc.ServerGroups[0].SocketBindingAttrs()["ref"])
	assert.Equal(t, "100", doc.ServerGroups[1].SocketBindingAttrs()["port-offset"])

	require.NotNil(t, doc.Management)
	assert.Equal(t, "rbac", doc.Management.AccessControlProvider())
	assert.Empty(t, doc.Management.ManagementInterfaces(),
		"domain.xml carries access control only; the endpoints live in host.xml")
	assert.Empty(t, doc.Management.SecurityRealms)
	assert.Nil(t, doc.Management.AuditLog)

	require.NotNil(t, doc.Management.AccessControl)
	require.Len(t, doc.Management.AccessControl.Roles, 2)
	auditor := doc.Management.AccessControl.Roles[1]
	assert.Equal(t, "Auditor", auditor.Name)
	assert.Equal(t, []string{"auditor"}, jboss.Names(auditor.IncludeUsers))
	assert.Equal(t, []string{"auditors"}, jboss.Names(auditor.IncludeGroups))
	assert.Equal(t, []string{"contractor"}, jboss.Names(auditor.ExcludeUsers))
}

// A repeated element and a single one must both arrive as a list, or a check
// written against a one-realm server stops matching when a second is added.
func TestRepeatedElementsAreAlwaysLists(t *testing.T) {
	single := `<server xmlns="urn:jboss:domain:1.7">
	  <management>
	    <security-realms>
	      <security-realm name="OnlyRealm"/>
	    </security-realms>
	  </management>
	  <interfaces><interface name="public"/></interfaces>
	</server>`

	doc, err := jboss.ParseDocument([]byte(single))
	require.NoError(t, err)
	assert.Len(t, doc.Management.SecurityRealms, 1)
	assert.Len(t, doc.Interfaces, 1)

	// An absent element is an empty list, never nil-with-a-value.
	empty, err := jboss.ParseDocument([]byte(`<server xmlns="urn:jboss:domain:1.7"/>`))
	require.NoError(t, err)
	assert.Nil(t, empty.Management)
	assert.Empty(t, empty.Interfaces)
	assert.Empty(t, empty.AllProfiles())
	assert.Empty(t, empty.AllSocketBindingGroups())
	// The accessors answer on an absent element rather than panicking, so the
	// resource layer never has to guard a chain of nil checks around them.
	assert.Equal(t, "", empty.DomainController.Kind())
	assert.Equal(t, "simple", empty.Management.AccessControlProvider())
	assert.Empty(t, empty.Management.ManagementInterfaces())
	assert.False(t, (*jboss.AuditLog)(nil).Enabled())
	assert.Empty(t, (*jboss.AuditLog)(nil).Handlers())
	assert.False(t, (*jboss.AuditLogger)(nil).LogBoot())
	assert.Empty(t, (*jboss.Keystore)(nil).Path())
	assert.False(t, (*jboss.Keystore)(nil).PasswordIsVaultExpression())
}

// An attribute JBoss resolves at boot is not a boolean. Reporting the
// documented default is the honest answer, and the raw text stays reachable.
func TestBooleanAttributeExpressions(t *testing.T) {
	doc, err := jboss.ParseDocument([]byte(`<server xmlns="urn:jboss:domain:1.7">
	  <management>
	    <audit-log>
	      <logger enabled="${env.AUDIT:false}" log-read-only="true"/>
	    </audit-log>
	  </management>
	</server>`))
	require.NoError(t, err)

	logger := doc.Management.AuditLog.Logger
	require.NotNil(t, logger)
	assert.False(t, logger.Enabled(), "an unresolvable expression falls back to the default")
	assert.True(t, logger.LogReadOnly())
	assert.Equal(t, "${env.AUDIT:false}", jboss.Attr(logger.Attrs, "enabled"),
		"the raw text stays available so a check can tell an expression from a literal")
}

func TestIsVaultExpression(t *testing.T) {
	assert.True(t, jboss.IsVaultExpression("${VAULT::block::attribute::1}"))
	assert.True(t, jboss.IsVaultExpression("  ${VAULT::block::attribute::1}  "))
	assert.False(t, jboss.IsVaultExpression("${env.PASSWORD}"))
	assert.False(t, jboss.IsVaultExpression(""))
	assert.False(t, jboss.IsVaultExpression("VAULT::block::attribute::1"))
}

func subsystem(t *testing.T, doc *jboss.Document, name string) *jboss.Subsystem {
	t.Helper()
	for _, profile := range doc.AllProfiles() {
		for i := range profile.Subsystems {
			if profile.Subsystems[i].Name() == name {
				return &profile.Subsystems[i]
			}
		}
	}
	t.Fatalf("subsystem %q not found", name)
	return nil
}

// Inline realm users carry their name in a username attribute. The realm below
// is the one the Debian sweep hosts carry in standalone-sweep.xml.
func TestRealmInlineUsers(t *testing.T) {
	doc, err := jboss.ParseDocument([]byte(`<server xmlns="urn:jboss:domain:20.0">
  <management>
    <security-realms>
      <security-realm name="SweepRealm">
        <authentication>
          <users><user username="inlineadmin"><password>pw</password></user><user username="inlineops"><password>pw2</password></user></users>
          <ldap connection="ldap_conn" base-dn="ou=people,dc=example,dc=test"><advanced-filter filter="(&amp;(uid={0})(objectClass=person))"/></ldap>
        </authentication>
      </security-realm>
    </security-realms>
  </management>
</server>`))
	require.NoError(t, err)
	require.Len(t, doc.Management.SecurityRealms, 1)

	auth := doc.Management.SecurityRealms[0].Authentication
	require.NotNil(t, auth)
	assert.Equal(t, []string{"inlineadmin", "inlineops"}, jboss.InlineUsernames(auth.Users))

	// A name attribute is read when username is absent.
	assert.Equal(t, []string{"legacy"}, jboss.InlineUsernames([]jboss.InlineUser{{Name: "legacy"}}))
}
