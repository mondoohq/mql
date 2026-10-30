// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseProperties(t *testing.T) {
	content := `# catalina.properties
! an alternative comment marker

common.loader="${catalina.base}/lib","${catalina.base}/lib/*.jar"
shared.loader=
package.access=sun.,org.apache.catalina.,\
               org.apache.coyote.,\
               org.apache.jasper.
tomcat.util.scan.StandardJarScanFilter.jarsToSkip : annotations-api.jar
colon.free.value some value
`
	props := ParseProperties(content, Paths{Home: "/opt/tomcat", Base: "/srv/instance1"})

	assert.Equal(t, `"/srv/instance1/lib","/srv/instance1/lib/*.jar"`, props["common.loader"],
		"${catalina.base} resolves to an absolute path")
	assert.Equal(t, "", props["shared.loader"])
	assert.Equal(t, "sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.",
		props["package.access"], "a trailing backslash continues the value")
	assert.Equal(t, "annotations-api.jar", props["tomcat.util.scan.StandardJarScanFilter.jarsToSkip"])
	assert.Equal(t, "some value", props["colon.free.value"])

	_, hasComment := props["# catalina.properties"]
	assert.False(t, hasComment)
}

// TestParseLoggingProperties covers the case the placeholder expansion exists
// for: a handler's directory is written three different ways across
// installations, and only the resolved path can be compared.
func TestParseLoggingProperties(t *testing.T) {
	content := `handlers = 1catalina.org.apache.juli.AsyncFileHandler, java.util.logging.ConsoleHandler

1catalina.org.apache.juli.AsyncFileHandler.level = FINE
1catalina.org.apache.juli.AsyncFileHandler.directory = ${catalina.base}/logs
1catalina.org.apache.juli.AsyncFileHandler.prefix = catalina.
2localhost.org.apache.juli.AsyncFileHandler.directory = ${catalina.home}/logs
`
	props := ParseProperties(content, Paths{Home: "/opt/tomcat", Base: "/srv/instance1"})

	assert.Equal(t, "1catalina.org.apache.juli.AsyncFileHandler, java.util.logging.ConsoleHandler",
		props["handlers"])
	assert.Equal(t, "/srv/instance1/logs", props["1catalina.org.apache.juli.AsyncFileHandler.directory"])
	assert.Equal(t, "/opt/tomcat/logs", props["2localhost.org.apache.juli.AsyncFileHandler.directory"])
	assert.Equal(t, "FINE", props["1catalina.org.apache.juli.AsyncFileHandler.level"])
}

func TestParsePropertiesEscapes(t *testing.T) {
	content := `path\:with\:colons=value
tab.value=a\tb
unicode.value=caf\u00e9
literal.backslash=C:\\Tomcat\\conf
`
	props := ParseProperties(content, Paths{})

	assert.Equal(t, "value", props["path:with:colons"])
	assert.Equal(t, "a\tb", props["tab.value"])
	assert.Equal(t, "café", props["unicode.value"])
	assert.Equal(t, `C:\Tomcat\conf`, props["literal.backslash"])
}

func TestParsePropertiesEmpty(t *testing.T) {
	props := ParseProperties("", Paths{})
	assert.NotNil(t, props)
	assert.Empty(t, props)
}
