// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWebXML(t *testing.T) {
	data, err := os.ReadFile("./testdata/web.xml")
	require.NoError(t, err)

	web, err := ParseWebXML(data)
	require.NoError(t, err)
	require.NotNil(t, web)

	assert.True(t, web.MetadataComplete)
	assert.Equal(t, int64(15), web.SessionTimeout)
	assert.True(t, web.CookieHTTPOnly)
	assert.True(t, web.CookieSecure)

	assert.Equal(t, "CLIENT-CERT", web.LoginConfig["authMethod"])
	assert.Equal(t, "Protected", web.LoginConfig["realmName"])

	require.Len(t, web.ErrorPages, 2)
	assert.Equal(t, "404", web.ErrorPages[0]["errorCode"])
	assert.Equal(t, "/error.jsp", web.ErrorPages[0]["location"])
	assert.Equal(t, "java.lang.Throwable", web.ErrorPages[1]["exceptionType"])

	require.Len(t, web.SecurityConstraints, 1)
	sc := web.SecurityConstraints[0]
	assert.Equal(t, "Everything over TLS", sc["displayName"])
	assert.Equal(t, map[string]any{"transportGuarantee": "CONFIDENTIAL"}, sc["userDataConstraint"])

	collections, ok := sc["webResourceCollections"].([]any)
	require.True(t, ok)
	require.Len(t, collections, 1)
	collection := collections[0].(map[string]any)
	assert.Equal(t, []any{"/*"}, collection["urlPatterns"])
	assert.Equal(t, []any{"PUT", "DELETE"}, collection["httpMethods"])
	assert.Empty(t, collection["httpMethodOmissions"])

	// An <auth-constraint> with no roles denies everyone. That is a different
	// statement from having no auth-constraint at all, so the empty role list
	// must survive rather than read as absent.
	authConstraint, ok := sc["authConstraint"].(map[string]any)
	require.True(t, ok, "a declared auth-constraint is not null")
	assert.Empty(t, authConstraint["roleNames"])
}

// TestWebXMLRepeatedInitParam guards the collapse hazard inside the descriptor:
// a servlet may declare the same parameter twice with opposing values, and a
// map keyed by name would keep only one of them.
func TestWebXMLRepeatedInitParam(t *testing.T) {
	data, err := os.ReadFile("./testdata/web.xml")
	require.NoError(t, err)

	web, err := ParseWebXML(data)
	require.NoError(t, err)

	require.Len(t, web.Servlets, 1)
	servlet := web.Servlets[0]
	assert.Equal(t, "default", servlet["name"])
	assert.Equal(t, "org.apache.catalina.servlets.DefaultServlet", servlet["class"])
	assert.Equal(t, "1", servlet["loadOnStartup"])
	assert.Equal(t, []any{"/"}, servlet["urlPatterns"], "the servlet-mapping is joined in")

	params, ok := servlet["initParams"].([]any)
	require.True(t, ok)
	require.Len(t, params, 2, "both declarations of readonly survive")
	assert.Equal(t, map[string]any{"name": "readonly", "value": "true"}, params[0])
	assert.Equal(t, map[string]any{"name": "readonly", "value": "false"}, params[1])
}

func TestWebXMLFilters(t *testing.T) {
	data, err := os.ReadFile("./testdata/web.xml")
	require.NoError(t, err)

	web, err := ParseWebXML(data)
	require.NoError(t, err)

	require.Len(t, web.Filters, 1)
	assert.Equal(t, "httpHeaderSecurity", web.Filters[0]["name"])
	assert.Equal(t, "org.apache.catalina.filters.HttpHeaderSecurityFilter", web.Filters[0]["class"])
	assert.Equal(t, []any{"/*"}, web.Filters[0]["urlPatterns"])
	assert.Empty(t, web.Filters[0]["initParams"])
}

func TestWebXMLMinimal(t *testing.T) {
	web, err := ParseWebXML([]byte(`<web-app version="6.0"></web-app>`))
	require.NoError(t, err)
	require.NotNil(t, web)

	assert.False(t, web.MetadataComplete)
	assert.Equal(t, int64(0), web.SessionTimeout)
	assert.False(t, web.CookieHTTPOnly)
	assert.False(t, web.CookieSecure)

	// Every collection is present and empty rather than null.
	assert.NotNil(t, web.ErrorPages)
	assert.Empty(t, web.ErrorPages)
	assert.NotNil(t, web.SecurityConstraints)
	assert.Empty(t, web.SecurityConstraints)
	assert.NotNil(t, web.Servlets)
	assert.Empty(t, web.Servlets)
	assert.NotNil(t, web.Filters)
	assert.Empty(t, web.Filters)
	assert.NotNil(t, web.LoginConfig)
	assert.Empty(t, web.LoginConfig)
}

func TestParseWebXMLRejectsOtherRoots(t *testing.T) {
	web, err := ParseWebXML([]byte(`<Context path="/app"/>`))
	require.NoError(t, err)
	assert.Nil(t, web)

	web, err = ParseWebXML(nil)
	require.NoError(t, err)
	assert.Nil(t, web)
}
