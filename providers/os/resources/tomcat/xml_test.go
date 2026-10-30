// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseXMLKeepsDocumentOrder(t *testing.T) {
	root, err := ParseXML([]byte(`<?xml version="1.0"?>
<Server>
  <Service name="a"/>
  <Service name="b"/>
  <Service name="c"/>
</Server>`))
	require.NoError(t, err)
	require.NotNil(t, root)

	assert.Equal(t, "Server", root.Name)
	services := root.Elements("Service")
	require.Len(t, services, 3)
	assert.Equal(t, "a", services[0].AttrString("name"))
	assert.Equal(t, "b", services[1].AttrString("name"))
	assert.Equal(t, "c", services[2].AttrString("name"))
}

// TestParseXMLDropsComments is the reason the implementation decodes XML rather
// than scanning lines: every stock server.xml ships several commented-out
// Connector examples, and a text-based count reports four or five where the
// server sees one.
func TestParseXMLDropsComments(t *testing.T) {
	root, err := ParseXML([]byte(`<Service name="Catalina">
  <Connector port="8080" protocol="HTTP/1.1"/>
  <!-- Define an SSL/TLS HTTP/1.1 Connector on port 8443
  <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true"/>
  -->
  <!--
  <Connector protocol="AJP/1.3" address="::1" port="8009"/>
  -->
</Service>`))
	require.NoError(t, err)

	connectors := root.Elements("Connector")
	require.Len(t, connectors, 1, "only the live Connector counts")
	assert.Equal(t, "8080", connectors[0].AttrString("port"))
}

func TestParseXMLStripsNamespaces(t *testing.T) {
	root, err := ParseXML([]byte(`<tomcat-users xmlns="http://tomcat.apache.org/xml"
	  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	  xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd" version="1.0">
	  <user username="admin" password="PLACEHOLDER-NOT-A-CREDENTIAL" roles="manager-gui"/>
	</tomcat-users>`))
	require.NoError(t, err)

	assert.Equal(t, "tomcat-users", root.Name)
	assert.Equal(t, "1.0", root.AttrString("version"))
	_, hasXmlns := root.Attr("xmlns")
	assert.False(t, hasXmlns, "namespace declarations are not configuration")
	require.Len(t, root.Elements("user"), 1)
}

func TestParseXMLHandlesDoctypeAndText(t *testing.T) {
	root, err := ParseXML([]byte(`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN"
  "http://java.sun.com/dtd/web-app_2_3.dtd">
<web-app>
  <session-config>
    <session-timeout>30</session-timeout>
  </session-config>
</web-app>`))
	require.NoError(t, err)

	assert.Equal(t, "web-app", root.Name)
	assert.Equal(t, "30", root.Element("session-config").ChildText("session-timeout"))
	assert.Empty(t, root.Element("session-config").ChildText("cookie-config"))
}

func TestParseXMLEmpty(t *testing.T) {
	for _, input := range []string{"", "   \n\t ", "\n"} {
		root, err := ParseXML([]byte(input))
		require.NoError(t, err)
		assert.Nil(t, root)
	}
}

// TestAttrFold covers the spellings Tomcat itself is inconsistent about.
func TestAttrFold(t *testing.T) {
	root, err := ParseXML([]byte(`<Connector SSLEnabled="true" SSLEnabledProtocols="TLSv1.2,TLSv1.3"/>`))
	require.NoError(t, err)

	assert.True(t, root.AttrBool(false, "SSLEnabled"))
	assert.True(t, root.AttrBool(false, "sslEnabled"))
	assert.Equal(t, "TLSv1.2,TLSv1.3", root.AttrString("sslEnabledProtocols", "SSLEnabledProtocols"))

	assert.False(t, root.AttrBool(false, "allowTrace"), "an absent attribute takes the default")
	assert.True(t, root.AttrBool(true, "autoDeploy"))
	assert.Equal(t, int64(42), root.AttrInt(42, "port"))
}

func TestAttrBoolLenientCase(t *testing.T) {
	root, err := ParseXML([]byte(`<Host autoDeploy="FALSE" deployXML="True" unpackWARs="yes"/>`))
	require.NoError(t, err)

	assert.False(t, root.AttrBool(true, "autoDeploy"))
	assert.True(t, root.AttrBool(false, "deployXML"))
	// "yes" is not a boolean Tomcat accepts; the default stands rather than a
	// guess in either direction.
	assert.True(t, root.AttrBool(true, "unpackWARs"))
}

func TestNilNodeHelpers(t *testing.T) {
	var node *Node
	assert.Empty(t, node.Elements("Service"))
	assert.Nil(t, node.Element("Service"))
	assert.Empty(t, node.ChildText("name"))
	assert.Empty(t, node.AttrString("name"))
	assert.False(t, node.AttrBool(false, "secure"))
	assert.Equal(t, int64(7), node.AttrInt(7, "port"))
	assert.NotNil(t, node.Params())
	assert.NotNil(t, node.AttrsDict())
}
