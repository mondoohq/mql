// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPaths = Paths{Home: "/opt/tomcat", Base: "/srv/instance1"}

func parseTestServer(t *testing.T, name string) *Server {
	t.Helper()
	data, err := os.ReadFile("./testdata/" + name)
	require.NoError(t, err)
	srv, err := ParseServerXML(data, testPaths)
	require.NoError(t, err)
	require.NotNil(t, srv)
	return srv
}

// TestServerCardinality is the reason this package exists. Every collection has
// to read as a list at all three cardinalities — none, one, many — so a check
// written against a stock single-Connector installation keeps working when a
// second Connector is added.
func TestServerCardinality(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		srv := parseTestServer(t, "server-zero.xml")

		assert.Equal(t, int64(-1), srv.Port)
		assert.Equal(t, "disabled", srv.Shutdown)
		assert.NotNil(t, srv.Services, "services must be an empty list, not nil")
		assert.Empty(t, srv.Services)
		assert.NotNil(t, srv.Listeners, "listeners must be an empty list, not nil")
		assert.Empty(t, srv.Listeners)
	})

	t.Run("one", func(t *testing.T) {
		srv := parseTestServer(t, "server-one.xml")

		require.Len(t, srv.Services, 1, "a single Service is still a one-element list")
		require.Len(t, srv.Listeners, 1)

		service := srv.Services[0]
		assert.Equal(t, "Catalina", service.Name)
		require.Len(t, service.Connectors, 1, "a single Connector is still a one-element list")
		require.Len(t, service.Engines, 1)

		engine := service.Engines[0]
		require.Len(t, engine.Hosts, 1, "a single Host is still a one-element list")
		require.Len(t, engine.Realms, 1)
		assert.Empty(t, engine.Valves, "an Engine with no Valve reads as an empty list")

		host := engine.Hosts[0]
		require.Len(t, host.Valves, 1)
		assert.Empty(t, host.Contexts, "a Host with no Context reads as an empty list")
	})

	t.Run("many", func(t *testing.T) {
		srv := parseTestServer(t, "server-many.xml")

		require.Len(t, srv.Services, 2)
		assert.Equal(t, "Catalina", srv.Services[0].Name)
		assert.Equal(t, "Admin", srv.Services[1].Name)

		// Three live Connectors. The document also holds a commented-out one,
		// which an XML parser drops and a line-based one would not.
		require.Len(t, srv.Services[0].Connectors, 3)
		require.Len(t, srv.Services[1].Connectors, 1)

		require.Len(t, srv.Services[0].Engines, 1)
		require.Len(t, srv.Services[0].Engines[0].Hosts, 2)
		require.Len(t, srv.Services[1].Engines[0].Hosts, 1)
		require.Len(t, srv.Services[0].Engines[0].Valves, 1)
	})
}

// TestNestedRealms covers the shape every stock server.xml ships: a LockOutRealm
// wrapping the realm that authenticates. `realms` holds the direct children of
// the element it hangs off, and each realm carries its own nested realms, so
// the inner one is reachable without walking the raw XML by hand.
func TestNestedRealms(t *testing.T) {
	srv := parseTestServer(t, "server-many.xml")
	engine := srv.Services[0].Engines[0]

	require.Len(t, engine.Realms, 1, "realms are the direct children of the Engine")
	outer := engine.Realms[0]
	assert.Equal(t, "org.apache.catalina.realm.LockOutRealm", outer.ClassName)
	assert.Equal(t, int64(5), outer.FailureCount)
	assert.Equal(t, int64(600), outer.LockOutTime)
	assert.Empty(t, outer.CredentialHandlers)

	require.Len(t, outer.Realms, 1, "the wrapped realm is reachable through realms")
	inner := outer.Realms[0]
	assert.Equal(t, "org.apache.catalina.realm.UserDatabaseRealm", inner.ClassName)
	assert.Equal(t, "UserDatabase", inner.Params["resourceName"])
	assert.Empty(t, inner.Realms, "the innermost realm has an empty list, not nil")

	require.Len(t, inner.CredentialHandlers, 1)
	assert.Equal(t, "SHA-512", inner.CredentialHandlers[0]["algorithm"])

	// A realm with no nesting at all is still a list.
	adminRealms := srv.Services[1].Engines[0].Realms
	require.Len(t, adminRealms, 1)
	assert.NotNil(t, adminRealms[0].Realms)
	assert.Empty(t, adminRealms[0].Realms)
}

func TestConnectorAttributes(t *testing.T) {
	srv := parseTestServer(t, "server-many.xml")
	connectors := srv.Services[0].Connectors

	plain := connectors[0]
	assert.Equal(t, int64(8080), plain.Port)
	assert.Equal(t, "HTTP/1.1", plain.Protocol)
	assert.Equal(t, int64(20000), plain.ConnectionTimeout)
	assert.False(t, plain.SSLEnabled)

	tls := connectors[1]
	assert.True(t, tls.SSLEnabled, "@SSLEnabled is read despite its capitalization")
	assert.Equal(t, "https", tls.Scheme)
	assert.True(t, tls.Secure)
	assert.Equal(t, "TLSv1.2,TLSv1.3", tls.SSLEnabledProtocols)

	require.Len(t, tls.SSLHostConfigs, 2, "SSLHostConfig is a list at every cardinality")
	assert.Equal(t, "TLSv1.2+TLSv1.3", tls.SSLHostConfigs[0]["protocols"])
	assert.Equal(t, "required", tls.SSLHostConfigs[0]["certificateVerification"])
	certs, ok := tls.SSLHostConfigs[0]["certificates"].([]any)
	require.True(t, ok)
	require.Len(t, certs, 1)
	assert.Equal(t, "conf/keystore.jks", certs[0].(map[string]any)["certificateKeystoreFile"])
	assert.Empty(t, tls.SSLHostConfigs[1]["certificates"])

	// Attributes the document does not declare fall back to Tomcat's own
	// defaults, so the field describes the connector's effective behavior.
	assert.Equal(t, int64(defaultConnectionTimeout), tls.ConnectionTimeout)
	assert.Equal(t, int64(defaultMaxHTTPHeaderSize), tls.MaxHTTPHeaderSize)
	assert.False(t, tls.AllowTrace)
	assert.False(t, tls.EnableLookups)
	assert.False(t, tls.XPoweredBy)

	// params stays verbatim, which is how an absent attribute can still be
	// told apart from one that was declared with the default value.
	_, declared := tls.Params["allowTrace"]
	assert.False(t, declared)
	assert.Equal(t, "true", tls.Params["SSLEnabled"])
}

func TestHostDefaults(t *testing.T) {
	srv := parseTestServer(t, "server-many.xml")
	hosts := srv.Services[0].Engines[0].Hosts

	// Tomcat deploys by default, so an undeclared attribute is on, not off.
	bare := srv.Services[1].Engines[0].Hosts[0]
	assert.True(t, bare.AutoDeploy)
	assert.True(t, bare.DeployOnStartup)
	assert.True(t, bare.DeployXML)
	assert.True(t, bare.UnpackWARs)
	assert.Equal(t, "/srv/admin-apps", bare.AppBase)

	assert.False(t, hosts[1].AutoDeploy, "an explicit false is honored")
}

func TestValveDefaults(t *testing.T) {
	srv := parseTestServer(t, "server-many.xml")
	valve := srv.Services[0].Engines[0].Hosts[0].Valves[0]

	assert.Equal(t, "org.apache.catalina.valves.AccessLogValve", valve.ClassName)
	assert.Equal(t, `%h %l %u %t "%r" %s %b`, valve.Pattern)
	assert.Equal(t, "/srv/instance1/logs", valve.Directory, "${catalina.base} is expanded")
	assert.Equal(t, "localhost_access_log", valve.Prefix)
	assert.Equal(t, ".txt", valve.Suffix)

	// showServerInfo / showReport only mean something on an ErrorReportValve,
	// so the true default must not leak onto every other valve.
	assert.False(t, valve.ShowServerInfo)
	assert.False(t, valve.ShowReport)

	engineValve := srv.Services[0].Engines[0].Valves[0]
	assert.Equal(t, `10\.\d+\.\d+\.\d+`, engineValve.Allow)
	assert.Empty(t, engineValve.Deny)
}

func TestErrorReportValveDefaults(t *testing.T) {
	srv, err := ParseServerXML([]byte(`<Server><Service name="s"><Engine name="e">
	  <Host name="h" appBase="webapps">
	    <Valve className="org.apache.catalina.valves.ErrorReportValve" />
	    <Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false" />
	  </Host>
	</Engine></Service></Server>`), testPaths)
	require.NoError(t, err)

	valves := srv.Services[0].Engines[0].Hosts[0].Valves
	require.Len(t, valves, 2)
	assert.True(t, valves[0].ShowServerInfo, "an undeclared ErrorReportValve discloses by default")
	assert.True(t, valves[0].ShowReport)
	assert.False(t, valves[1].ShowServerInfo)
	assert.False(t, valves[1].ShowReport)
}

func TestInlineContexts(t *testing.T) {
	srv := parseTestServer(t, "server-many.xml")
	contexts := srv.Services[0].Engines[0].Hosts[0].Contexts

	require.Len(t, contexts, 1)
	assert.Equal(t, "/app", contexts[0].Path)
	assert.False(t, contexts[0].Privileged)
	assert.True(t, contexts[0].CrossContext)
	assert.True(t, contexts[0].AllowLinking, "allowLinking is read off the nested <Resources>")
	assert.Empty(t, srv.Services[0].Engines[0].Hosts[1].Contexts)
}

func TestParseContextXML(t *testing.T) {
	data, err := os.ReadFile("./testdata/context.xml")
	require.NoError(t, err)

	ctx, err := ParseContextXML(data, testPaths)
	require.NoError(t, err)
	require.NotNil(t, ctx)

	assert.True(t, ctx.Privileged)
	assert.False(t, ctx.CrossContext)
	assert.True(t, ctx.LogEffectiveWebXml)
	assert.True(t, ctx.AllowLinking)
	require.Len(t, ctx.Valves, 1)
	assert.Equal(t, "/srv/instance1/logs", ctx.Valves[0].Directory)
}

func TestParseContextXMLRejectsOtherRoots(t *testing.T) {
	ctx, err := ParseContextXML([]byte(`<Server port="8005"/>`), testPaths)
	require.NoError(t, err)
	assert.Nil(t, ctx)
}

func TestParseServerXMLEmpty(t *testing.T) {
	srv, err := ParseServerXML(nil, testPaths)
	require.NoError(t, err)
	assert.Nil(t, srv)
}

func TestParseUsersXML(t *testing.T) {
	data, err := os.ReadFile("./testdata/tomcat-users.xml")
	require.NoError(t, err)

	users, err := ParseUsersXML(data)
	require.NoError(t, err)
	require.Len(t, users, 2)

	assert.Equal(t, "svc-deploy", users[0].Username)
	assert.Equal(t, "DIGEST-PLACEHOLDER-NOT-A-CREDENTIAL", users[0].Password)
	assert.Equal(t, []string{"manager-script", "manager-gui"}, users[0].Roles)

	assert.Equal(t, "observer", users[1].Username)
	assert.NotNil(t, users[1].Roles, "a user with no role has an empty list, not nil")
	assert.Empty(t, users[1].Roles)
}

func TestParseUsersXMLEmpty(t *testing.T) {
	users, err := ParseUsersXML(nil)
	require.NoError(t, err)
	assert.NotNil(t, users)
	assert.Empty(t, users)
}

func TestPathsExpand(t *testing.T) {
	assert.Equal(t, "/srv/instance1/logs", testPaths.Expand("${catalina.base}/logs"))
	assert.Equal(t, "/opt/tomcat/lib", testPaths.Expand("${catalina.home}/lib"))
	assert.Equal(t, "/var/log/tomcat", testPaths.Expand("/var/log/tomcat"))
	assert.Equal(t, "", testPaths.Expand(""))
}
