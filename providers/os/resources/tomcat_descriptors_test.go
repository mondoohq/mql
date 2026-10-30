// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/tomcat"
)

// Ubuntu's tomcat10-admin deploys manager and host-manager through context
// descriptors in $CATALINA_BASE/conf/Catalina/localhost, with a docBase under
// /usr/share/tomcat10-admin. They are not in the Host's appBase.
func TestTomcatDeployedApps(t *testing.T) {
	const managerXML = `<?xml version="1.0" encoding="UTF-8"?>
<Context path="/manager" 
	docBase="/usr/share/tomcat10-admin/manager"
	antiResourceLocking="false" privileged="true" />
`
	mem := afero.NewMemMapFs()
	write := func(p, c string) { require.NoError(t, afero.WriteFile(mem, p, []byte(c), 0o644)) }
	mkdir := func(p string) { require.NoError(t, mem.MkdirAll(p, 0o755)) }
	base := "/var/lib/tomcat10"
	mkdir(base + "/webapps/ROOT")
	mkdir(base + "/webapps/sweepapp")
	mkdir(base + "/webapps/legacy")
	write(base+"/webapps/old.war", "war")
	write(base+"/conf/Catalina/localhost/manager.xml", managerXML)
	write(base+"/conf/Catalina/localhost/host-manager.xml",
		`<Context docBase="/usr/share/tomcat10-admin/host-manager" antiResourceLocking="false" privileged="true" />`)
	// a descriptor for an application in appBase overrides the directory
	write(base+"/conf/Catalina/localhost/legacy.xml", `<Context reloadable="true"/>`)
	write(base+"/conf/Catalina/localhost/shop#v2.xml", `<Context docBase="shop-2.0"/>`)
	write(base+"/conf/Catalina/localhost/notes.txt", "not a descriptor")

	srv := &tomcat.Server{Services: []tomcat.Service{{
		Name: "Catalina",
		Engines: []tomcat.Engine{{
			Name: "Catalina",
			Hosts: []tomcat.Host{{
				Name:    "localhost",
				AppBase: "webapps",
				Contexts: []tomcat.Context{
					{Path: "/static", DocBase: "/srv/static"},
					{Path: "", DocBase: "ROOT"},
				},
			}},
		}},
	}}}

	apps := tomcatDeployedApps(&afero.Afero{Fs: mem}, srv, tomcat.Paths{Home: "/usr/share/tomcat10", Base: base})
	got := map[string]tomcatDeployedApp{}
	var names []string
	for _, a := range apps {
		got[a.name] = a
		names = append(names, a.name)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"ROOT", "host-manager", "legacy", "manager", "shop#v2", "static", "sweepapp"}, names)

	assert.Equal(t, "/usr/share/tomcat10-admin/manager", got["manager"].path)
	assert.Equal(t, base+"/conf/Catalina/localhost/manager.xml", got["manager"].descriptor)
	assert.Equal(t, "/usr/share/tomcat10-admin/host-manager", got["host-manager"].path)
	assert.Equal(t, base+"/webapps/legacy", got["legacy"].path)
	assert.Equal(t, base+"/conf/Catalina/localhost/legacy.xml", got["legacy"].descriptor)
	assert.Equal(t, base+"/webapps/shop-2.0", got["shop#v2"].path)
	assert.Equal(t, "/srv/static", got["static"].path)
	assert.Equal(t, base+"/webapps/ROOT", got["ROOT"].path)
	assert.Equal(t, base+"/webapps/sweepapp", got["sweepapp"].path)
	assert.Equal(t, "", got["sweepapp"].descriptor)
	for _, a := range apps {
		assert.Equal(t, "localhost", a.host)
	}
}

func TestParseContextDocBase(t *testing.T) {
	ctx, err := tomcat.ParseContextXML([]byte(`<Context path="/manager" docBase="${catalina.home}/webapps/manager"/>`), tomcat.Paths{Home: "/opt/tomcat", Base: "/opt/tomcat"})
	require.NoError(t, err)
	assert.Equal(t, "/opt/tomcat/webapps/manager", ctx.DocBase)
}
