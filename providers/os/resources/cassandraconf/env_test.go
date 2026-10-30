// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cassandraconf_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/cassandraconf"
)

// shippedJMXBlock is the JMX section of the cassandra-env.sh Cassandra ships,
// reproduced verbatim. Both branches are present in the file, which is the
// whole reason the parser has to resolve LOCAL_JMX before reading properties.
const shippedJMXBlock = `
if [ "x$LOCAL_JMX" = "x" ]; then
    LOCAL_JMX=yes
fi

JMX_PORT="7199"

if [ "$LOCAL_JMX" = "yes" ]; then
  JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.local.port=$JMX_PORT"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.authenticate=false"
else
  JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.remote.port=$JMX_PORT"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.rmi.port=$JMX_PORT"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.authenticate=true"
  #JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.ssl=true"
  #JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.ssl.need.client.auth=true"
fi

JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.password.file=/etc/cassandra/jmxremote.password"
#JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.access.file=/etc/cassandra/jmxremote.access"
#JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.authorizer=org.apache.cassandra.auth.jmx.AuthorizationProxy"
`

// The default file: JMX is localhost-only, and the authenticate=false from the
// then-branch is what applies. Reading the last -D in the file would report
// true here and describe an unauthenticated local socket as authenticated.
func TestParseEnvDefaultsToLocalJMX(t *testing.T) {
	env := cassandraconf.ParseEnv(shippedJMXBlock)

	assert.True(t, env.LocalJMX())
	assert.Equal(t, int64(7199), env.JMXPort())
	assert.False(t, env.Bool(cassandraconf.PropJMXAuthenticate, true))

	// The else-branch never runs, so none of its properties are reported.
	assert.NotContains(t, env.Properties, cassandraconf.PropJMXRemotePort)
	assert.Contains(t, env.Properties, cassandraconf.PropJMXLocalPort)

	// Properties outside the conditional apply either way.
	assert.Equal(t, "/etc/cassandra/jmxremote.password", env.String(cassandraconf.PropJMXPasswordFile))
	// ...and commented-out ones do not.
	assert.Empty(t, env.String(cassandraconf.PropJMXAccessFile))
	assert.Empty(t, env.String(cassandraconf.PropJMXAuthorizer))
}

// An operator enabling remote JMX by adding the assignment above the guard.
// The guard does not fire because the variable is already set, so the
// else-branch is the live one.
func TestParseEnvRemoteJMXSetOutsideGuard(t *testing.T) {
	env := cassandraconf.ParseEnv("LOCAL_JMX=no\n" + shippedJMXBlock)

	assert.False(t, env.LocalJMX())
	assert.Equal(t, int64(7199), env.JMXPort())
	assert.True(t, env.Bool(cassandraconf.PropJMXAuthenticate, false))

	assert.Contains(t, env.Properties, cassandraconf.PropJMXRemotePort)
	assert.NotContains(t, env.Properties, cassandraconf.PropJMXLocalPort)

	// SSL stays off: both lines that would enable it are commented out.
	assert.False(t, env.Bool(cassandraconf.PropJMXSSL, false))
	assert.False(t, env.Bool(cassandraconf.PropJMXSSLClientAuth, false))
}

// The other way operators do it: editing the default inside the guard. The
// guard is the only assignment, so its value is the effective one.
func TestParseEnvRemoteJMXSetInsideGuard(t *testing.T) {
	env := cassandraconf.ParseEnv(strings.Replace(shippedJMXBlock, "LOCAL_JMX=yes", "LOCAL_JMX=no", 1))

	assert.False(t, env.LocalJMX())
	assert.True(t, env.Bool(cassandraconf.PropJMXAuthenticate, false))
}

// An assignment outside the guard beats the guard's default, because the
// guard only fires when the variable is unset.
func TestParseEnvOutsideAssignmentBeatsGuardDefault(t *testing.T) {
	env := cassandraconf.ParseEnv("LOCAL_JMX=no\n" + strings.Replace(shippedJMXBlock, "LOCAL_JMX=yes", "LOCAL_JMX=yes", 1))
	assert.False(t, env.LocalJMX(), "the outside assignment decides, not the guard default")
}

// A fully hardened remote setup, which is what an audit is looking for.
func TestParseEnvHardenedRemoteJMX(t *testing.T) {
	env := cassandraconf.ParseEnv(`
LOCAL_JMX=no
JMX_PORT="7299"
if [ "x$LOCAL_JMX" = "x" ]; then
    LOCAL_JMX=yes
fi
if [ "$LOCAL_JMX" = "yes" ]; then
  JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.local.port=$JMX_PORT"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.authenticate=false"
else
  JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.remote.port=$JMX_PORT"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.authenticate=true"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.ssl=true"
  JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.ssl.need.client.auth=true"
fi
JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.authorizer=org.apache.cassandra.auth.jmx.AuthorizationProxy"
JVM_OPTS="$JVM_OPTS -Dcassandra.jmx.remote.login.config=CassandraLogin"
`)

	assert.False(t, env.LocalJMX())
	assert.Equal(t, int64(7299), env.JMXPort(), "$JMX_PORT must expand")
	assert.True(t, env.Bool(cassandraconf.PropJMXAuthenticate, false))
	assert.True(t, env.Bool(cassandraconf.PropJMXSSL, false))
	assert.True(t, env.Bool(cassandraconf.PropJMXSSLClientAuth, false))
	assert.Equal(t, "org.apache.cassandra.auth.jmx.AuthorizationProxy", env.String(cassandraconf.PropJMXAuthorizer))
	assert.Equal(t, "CassandraLogin", env.String(cassandraconf.PropJMXLoginConfig))
}

// With no assignment anywhere, Cassandra's own default applies.
func TestParseEnvNoAssignmentDefaultsToYes(t *testing.T) {
	env := cassandraconf.ParseEnv("JMX_PORT=\"7199\"\n")
	assert.True(t, env.LocalJMX())
	assert.Equal(t, int64(7199), env.JMXPort())
}

func TestParseEnvEmpty(t *testing.T) {
	env := cassandraconf.ParseEnv("")
	assert.True(t, env.LocalJMX(), "Cassandra ships JMX localhost-only")
	assert.Equal(t, int64(7199), env.JMXPort())
	assert.Empty(t, env.Properties)
}

// The heap conditionals surrounding the JMX block are not ones this reader
// evaluates, so both of their branches are read. That is fine as long as
// nothing inside them sets a JMX property, but it must not knock the
// conditional stack out of alignment and drop the JMX block with it.
func TestParseEnvUnknownConditionalsDoNotBreakNesting(t *testing.T) {
	env := cassandraconf.ParseEnv(`
if [ "x$MAX_HEAP_SIZE" = "x" ] && [ "x$HEAP_NEWSIZE" = "x" ]; then
    MAX_HEAP_SIZE="4G"
elif [ "x$MAX_HEAP_SIZE" = "x" ]; then
    echo "please set both"
fi
if [ $USING_G1 -eq 0 ]; then
    if [ "$JVM_ARCH" = "64-Bit" ]; then
        JVM_OPTS="$JVM_OPTS -XX:+UseG1GC"
    fi
fi
` + shippedJMXBlock)

	assert.True(t, env.LocalJMX())
	assert.False(t, env.Bool(cassandraconf.PropJMXAuthenticate, true))
	assert.Equal(t, "4G", env.Variables["MAX_HEAP_SIZE"])
}

// A trailing comment is not part of the value. Getting this wrong on
// LOCAL_JMX reports remote JMX on a host that is localhost-only, and on
// JMX_PORT it silently falls back to 7199 rather than the configured port.
func TestParseEnvInlineComments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		script   string
		localJMX bool
		port     int64
	}{
		{"unquoted", "LOCAL_JMX=yes # local mode\nJMX_PORT=7299 # custom\n", true, 7299},
		{"quoted", "LOCAL_JMX=\"yes\" # local mode\nJMX_PORT=\"7299\" # custom\n", true, 7299},
		{"single quoted", "LOCAL_JMX='no' # remote\nJMX_PORT='7299'\n", false, 7299},
		{"tab before comment", "LOCAL_JMX=no\t# remote\n", false, 7199},
		{"separator and comment", "LOCAL_JMX=no; export FOO=1 # note\n", false, 7199},
		{"no comment", "LOCAL_JMX=yes\nJMX_PORT=7299\n", true, 7299},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := cassandraconf.ParseEnv(tc.script)
			assert.Equal(t, tc.localJMX, env.LocalJMX())
			assert.Equal(t, tc.port, env.JMXPort())
		})
	}
}

// A `#` only opens a comment at the start of a word, and one inside quotes is
// not a comment at all, so neither may be cut out of a value.
func TestParseEnvHashInsideValueIsNotAComment(t *testing.T) {
	env := cassandraconf.ParseEnv(`
CASSANDRA_TAG=build#1234
CASSANDRA_NOTE="a # inside quotes"
CASSANDRA_SEMI="keep;this"
`)

	assert.Equal(t, "build#1234", env.Variables["CASSANDRA_TAG"])
	assert.Equal(t, "a # inside quotes", env.Variables["CASSANDRA_NOTE"])
	assert.Equal(t, "keep;this", env.Variables["CASSANDRA_SEMI"])
}

// A note after the closing quote is prose, not configuration, so a -D flag
// mentioned in it must not be collected.
func TestParseEnvIgnoresPropertiesInTrailingComments(t *testing.T) {
	env := cassandraconf.ParseEnv(`
JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.authenticate=true" # not -Dcom.sun.management.jmxremote.ssl=true
`)

	assert.True(t, env.Bool(cassandraconf.PropJMXAuthenticate, false))
	assert.False(t, env.Bool(cassandraconf.PropJMXSSL, false), "the commented flag must not be collected")
	assert.NotContains(t, env.Properties, cassandraconf.PropJMXSSL)
}

func TestParseEnvVariableExpansion(t *testing.T) {
	env := cassandraconf.ParseEnv(`
CASSANDRA_CONF=/etc/cassandra
JVM_OPTS="$JVM_OPTS -Djava.security.auth.login.config=${CASSANDRA_CONF}/cassandra-jaas.config"
JVM_OPTS="$JVM_OPTS -Dcom.sun.management.jmxremote.password.file=$CASSANDRA_CONF/jmxremote.password"
`)

	assert.Equal(t, "/etc/cassandra/cassandra-jaas.config", env.String("java.security.auth.login.config"))
	assert.Equal(t, "/etc/cassandra/jmxremote.password", env.String(cassandraconf.PropJMXPasswordFile))
	assert.NotContains(t, env.Variables, "JVM_OPTS", "JVM_OPTS is an accumulator, not a setting")
}
