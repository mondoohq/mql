// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
)

// rockyPlatform is Rocky Linux; debianPlatform is declared with the os.date
// tests.
var rockyPlatform = &inventory.Platform{Name: "rockylinux", Version: "9", Family: []string{"redhat", "linux", "unix"}}

// commandCountingConn records the commands a resource runs, so a test can
// assert that a host without a web server is not asked about one.
type commandCountingConn struct {
	*mock.Connection
	commands []string
}

func (c *commandCountingConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

// websitesRuntime is a runtime over a measured fixture in testdata, or over
// an empty filesystem when fixture is "".
func websitesRuntime(t *testing.T, fixture string, platform *inventory.Platform) (*plugin.Runtime, *commandCountingConn) {
	t.Helper()
	var opts []mock.Option
	if fixture != "" {
		path, err := filepath.Abs(filepath.Join("testdata", fixture))
		require.NoError(t, err)
		opts = append(opts, mock.WithPath(path))
	}
	m, err := mock.New(0, &inventory.Asset{Platform: platform}, opts...)
	require.NoError(t, err)
	conn := &commandCountingConn{Connection: m}
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}, conn
}

// siteRow is a website's fields, for comparing a whole list at once.
type siteRow struct {
	name         string
	address      string
	port         int64
	tls          bool
	sources      []any
	file         string
	documentRoot string
	proxyTarget  string
	isDefault    bool
}

func listWebsites(t *testing.T, runtime *plugin.Runtime) []siteRow {
	t.Helper()
	o, err := CreateResource(runtime, "websites", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := o.(*mqlWebsites).GetList()
	require.NoError(t, list.Error)

	rows := []siteRow{}
	for _, r := range list.Data {
		site := r.(*mqlWebsite)
		file := site.GetFile()
		require.NoError(t, file.Error)
		path := ""
		if file.Data != nil {
			path = file.Data.Path.Data
		}
		rows = append(rows, siteRow{
			name:         site.Name.Data,
			address:      site.Address.Data,
			port:         site.Port.Data,
			tls:          site.Tls.Data,
			sources:      site.Sources.Data,
			file:         path,
			documentRoot: site.DocumentRoot.Data,
			proxyTarget:  site.ProxyTarget.Data,
			isDefault:    site.IsDefault.Data,
		})
	}
	return rows
}

// Measured: debian:13 nginx 1.26.3, 2026-10-30 (websites_debian13_nginx.toml).
// The package's server block listens on both address families with
// default_server and is named `_`. It is one site answering for any name,
// not two, and `_` is not a name. Fails if `_` is reported as a host name, if
// the IPv6 listener makes a second entry, or if the file is the nginx.conf
// that includes the block rather than sites-enabled/default.
func TestWebsitesDebianNginx(t *testing.T) {
	runtime, _ := websitesRuntime(t, "websites_debian13_nginx.toml", debianPlatform)
	assert.Equal(t, []siteRow{{
		name:         "",
		address:      "*",
		port:         80,
		sources:      []any{"nginx"},
		file:         "/etc/nginx/sites-enabled/default",
		documentRoot: "/var/www/html",
		isDefault:    true,
	}}, listWebsites(t, runtime))
}

// Measured: nginx:1.29 image, nginx 1.29.8, 2026-10-30
// (websites_nginx_official.toml). The server block sets no root of its own;
// its content comes from the root of `location /`, and no block is marked
// default_server, so the first one is the default. Fails if documentRoot reads
// only the server block's root, or if isDefault requires default_server.
func TestWebsitesOfficialNginxImage(t *testing.T) {
	runtime, _ := websitesRuntime(t, "websites_nginx_official.toml", debianPlatform)
	assert.Equal(t, []siteRow{{
		name:         "localhost",
		address:      "*",
		port:         80,
		sources:      []any{"nginx"},
		file:         "/etc/nginx/conf.d/default.conf",
		documentRoot: "/usr/share/nginx/html",
		isDefault:    true,
	}}, listWebsites(t, runtime))
}

// Measured: debian:13 Apache 2.4.69 with ssl and default-ssl enabled,
// 2026-10-30 (websites_debian13_apache2.toml). Both virtual hosts set no
// ServerName and neither does apache2.conf, so both answer for any name.
// ports.conf listens on 443 inside <IfModule ssl_module>, and default-ssl
// claims it. Fails if a Listen claimed by a virtual host also yields a main
// server entry, or if a virtual host is attributed to apache2.conf.
func TestWebsitesDebianApache(t *testing.T) {
	runtime, _ := websitesRuntime(t, "websites_debian13_apache2.toml", debianPlatform)
	assert.Equal(t, []siteRow{
		{
			name:         "",
			address:      "*",
			port:         80,
			sources:      []any{"apache2"},
			file:         "/etc/apache2/sites-enabled/000-default.conf",
			documentRoot: "/var/www/html",
			isDefault:    true,
		},
		{
			name:         "",
			address:      "*",
			port:         443,
			tls:          true,
			sources:      []any{"apache2"},
			file:         "/etc/apache2/sites-enabled/default-ssl.conf",
			documentRoot: "/var/www/html",
			isDefault:    true,
		},
	}, listWebsites(t, runtime))
}

// Measured: rockylinux:9 httpd 2.4.62 with mod_ssl, 2026-10-30
// (websites_rocky9_httpd.toml). httpd.conf declares no virtual host, so the
// main server answers on port 80, and the _default_:443 virtual host takes its
// DocumentRoot from the main configuration. Fails if the main server is not
// modeled, which loses the only plain HTTP site of a stock Red Hat install, or
// if a virtual host without DocumentRoot reports none.
func TestWebsitesRockyHttpd(t *testing.T) {
	runtime, _ := websitesRuntime(t, "websites_rocky9_httpd.toml", rockyPlatform)
	assert.Equal(t, []siteRow{
		{
			name:         "",
			address:      "*",
			port:         443,
			tls:          true,
			sources:      []any{"apache2"},
			file:         "/etc/httpd/conf.d/ssl.conf",
			documentRoot: "/var/www/html",
			isDefault:    true,
		},
		{
			name:         "",
			address:      "*",
			port:         80,
			sources:      []any{"apache2"},
			file:         "/etc/httpd/conf/httpd.conf",
			documentRoot: "/var/www/html",
			isDefault:    true,
		},
	}, listWebsites(t, runtime))
}

// Synthetic: a Linux host with no web server; no target showed this. The
// list is empty, and finding that out runs no command: nginx.conf and
// apache2.conf would each ask a binary on the PATH where its configuration
// is. Fails if a source is read without checking that its web server is
// installed.
func TestWebsitesWithoutWebServerRunsNoCommand(t *testing.T) {
	runtime, conn := websitesRuntime(t, "", debianPlatform)
	assert.Empty(t, listWebsites(t, runtime))
	assert.Empty(t, conn.commands)
}

// Synthetic: names in the forms nginx's server_name accepts; no target
// showed these.
func TestNginxSiteNames(t *testing.T) {
	assert.Equal(t, []string{"example.com", "www.example.com"}, nginxSiteNames("Example.COM www.example.com."))
	assert.Equal(t, []string{"example.org", "*.example.org", "www.example.org"}, nginxSiteNames(".example.org www.example.org example.org"))
	assert.Equal(t, []string{`~^(?<user>\w+)\.Example\.net$`}, nginxSiteNames(`~^(?<user>\w+)\.Example\.net$`))
	assert.Empty(t, nginxSiteNames("_"))
	assert.Empty(t, nginxSiteNames(""))
}

// Synthetic: listener shapes nginx accepts; no target showed these.
func TestNginxWebsiteEntries(t *testing.T) {
	certs := func() ([]any, error) { return nil, nil }
	entries := nginxWebsiteEntries([]nginxSiteServer{
		{
			// First on *:80 and *:443, but another block claims both with
			// default_server.
			serverName: "example.com www.example.com",
			listens: []nginxListen{
				{Raw: "80", Port: 80},
				{Raw: "443 ssl", Port: 443, SSL: true},
				{Raw: "443 quic reuseport", Port: 443},
				{Raw: "unix:/run/nginx.sock", Address: "unix:/run/nginx.sock"},
			},
			documentRoot: "/srv/example",
			proxyTarget:  "http://backend",
			file:         "/etc/nginx/conf.d/example.conf",
			certs:        certs,
		},
		{
			serverName: "_",
			listens: []nginxListen{
				{Raw: "[::]:80 default_server", Address: "[::]", Port: 80, DefaultServer: true},
				{Raw: "443 ssl default_server", Port: 443, SSL: true, DefaultServer: true},
			},
		},
		{
			// No listen directive, and an address without a port.
			serverName: "noport.example.com",
		},
		{
			serverName: "local.example.com",
			listens:    []nginxListen{{Raw: "127.0.0.1", Address: "127.0.0.1"}},
			legacySSL:  true,
		},
	})

	type got struct {
		name      string
		address   string
		port      int64
		tls       bool
		isDefault bool
		certs     bool
	}
	var rows []got
	for _, e := range entries {
		assert.Equal(t, "nginx", e.source)
		rows = append(rows, got{e.name, e.address, e.port, e.tls, e.isDefault, e.certs != nil})
	}
	assert.Equal(t, []got{
		{"example.com", "*", 80, false, false, false},
		{"www.example.com", "*", 80, false, false, false},
		{"example.com", "*", 443, true, false, true},
		{"www.example.com", "*", 443, true, false, true},
		{"", "*", 80, false, true, false},
		{"", "*", 443, true, true, false},
		{"noport.example.com", "*", 80, false, false, false},
		{"local.example.com", "127.0.0.1", 80, true, true, false},
	}, rows)
	assert.Equal(t, "/srv/example", entries[0].documentRoot)
	assert.Equal(t, "http://backend", entries[0].proxyTarget)
	assert.Equal(t, "/etc/nginx/conf.d/example.conf", entries[0].file)
}

// Synthetic: <VirtualHost> and Listen arguments in the forms httpd accepts;
// no target showed these.
func TestParseApacheEndpoint(t *testing.T) {
	cases := map[string]apacheEndpoint{
		"80":                {"*", 80},
		"*:443":             {"*", 443},
		"_default_:443":     {"*", 443},
		"0.0.0.0:8080":      {"*", 8080},
		"[::]:443":          {"*", 443},
		"192.0.2.10:80":     {"192.0.2.10", 80},
		"[2001:DB8::1]:443": {"2001:db8::1", 443},
		"[2001:db8::1]":     {"2001:db8::1", 0},
		"*":                 {"*", 0},
		"*:*":               {"*", 0},
		"Example.com:80":    {"example.com", 80},
	}
	for in, want := range cases {
		got, ok := parseApacheEndpoint(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "*:http", "[::1", "192.0.2.1:70000"} {
		_, ok := parseApacheEndpoint(in)
		assert.False(t, ok, in)
	}
}

// Synthetic: ServerName in the forms httpd accepts; no target showed these.
func TestApacheServerName(t *testing.T) {
	assert.Equal(t, "www.example.com", apacheServerName("www.example.com"))
	assert.Equal(t, "www.example.com", apacheServerName("WWW.Example.com:443"))
	assert.Equal(t, "www.example.com", apacheServerName("https://www.example.com:8443"))
	assert.Equal(t, "2001:db8::1", apacheServerName("[2001:db8::1]:443"))
	assert.Equal(t, "", apacheServerName(""))
}

// Synthetic: ProxyPass forms; no target showed these.
func TestApacheRootProxyTarget(t *testing.T) {
	assert.Equal(t, "http://127.0.0.1:8080/", apacheRootProxyTarget("/ http://127.0.0.1:8080/"))
	assert.Equal(t, "balancer://cluster/", apacheRootProxyTarget(`/" "balancer://cluster/`))
	assert.Equal(t, "", apacheRootProxyTarget("/api http://api/"))
	assert.Equal(t, "", apacheRootProxyTarget("/ !"))
	assert.Equal(t, "", apacheRootProxyTarget(""))
}

// Synthetic: virtual host layouts no target showed. A virtual host answers on
// each of its addresses, one without a port on every Listen port, and the
// first one on a listener is its default. The main server answers where no
// virtual host claims the listener, including on the other addresses of a
// Listen that a virtual host claims on one address only.
func TestApacheWebsiteEntries(t *testing.T) {
	certs := func() ([]any, error) { return nil, nil }
	entries := apacheWebsiteEntries([]apacheSiteVHost{
		{
			address:    "192.0.2.10:8080 [2001:db8::1]:8080",
			serverName: "https://www.example.com:8080",
			aliases:    []string{"Example.com", "www.example.com"},
			tls:        true,
			proxyPass:  "/ http://127.0.0.1:3000/",
			file:       "/etc/httpd/conf.d/example.conf",
			certs:      certs,
		},
		{
			address:      "192.0.2.10:8080",
			serverName:   "second.example.com",
			documentRoot: "/srv/second",
		},
		{
			// No ServerName: inherits the main server's.
			address: "*",
		},
	}, apacheSiteMain{
		serverName:   "main.example.com:80",
		documentRoot: "/var/www/html",
		listens:      []string{"80", "8080", "443 https"},
		file:         "/etc/httpd/conf/httpd.conf",
	})

	type got struct {
		name      string
		address   string
		port      int64
		tls       bool
		isDefault bool
		file      string
	}
	var rows []got
	for _, e := range entries {
		assert.Equal(t, "apache2", e.source)
		rows = append(rows, got{e.name, e.address, e.port, e.tls, e.isDefault, e.file})
	}
	const exampleConf, httpdConf = "/etc/httpd/conf.d/example.conf", "/etc/httpd/conf/httpd.conf"
	assert.Equal(t, []got{
		{"www.example.com", "192.0.2.10", 8080, true, true, exampleConf},
		{"example.com", "192.0.2.10", 8080, true, true, exampleConf},
		{"www.example.com", "2001:db8::1", 8080, true, true, exampleConf},
		{"example.com", "2001:db8::1", 8080, true, true, exampleConf},
		{"second.example.com", "192.0.2.10", 8080, false, false, ""},
		{"main.example.com", "*", 80, false, true, ""},
		{"main.example.com", "*", 8080, false, true, ""},
		{"main.example.com", "*", 443, false, true, ""},
	}, rows)

	assert.Equal(t, "http://127.0.0.1:3000/", entries[0].proxyTarget)
	assert.NotNil(t, entries[0].certs)
	assert.Equal(t, "/var/www/html", entries[0].documentRoot, "inherited from the main server")
	assert.Equal(t, "/srv/second", entries[4].documentRoot)

	// Every Listen is claimed by the `<VirtualHost *>`, so the main server
	// answers nowhere.
	for _, e := range entries {
		assert.NotEqual(t, httpdConf, e.file)
	}
}

// Synthetic: a Listen on every address with a virtual host on one address
// only; no target showed this. Requests to the other addresses reach the
// main server.
func TestApacheWebsiteEntriesMainServerBesideAddressVHost(t *testing.T) {
	entries := apacheWebsiteEntries([]apacheSiteVHost{
		{address: "192.0.2.10:80", serverName: "vhost.example.com"},
	}, apacheSiteMain{listens: []string{"80"}, file: "/etc/httpd/conf/httpd.conf"})
	require.Len(t, entries, 2)
	assert.Equal(t, "192.0.2.10", entries[0].address)
	assert.Equal(t, "", entries[1].name)
	assert.Equal(t, "*", entries[1].address)
	assert.Equal(t, int64(80), entries[1].port)
	assert.True(t, entries[1].isDefault)
	assert.Equal(t, "/etc/httpd/conf/httpd.conf", entries[1].file)
}

// Measured: Windows Server 2022 build 20348, IIS 10.0, 2026-10-30. The
// bindings as Microsoft.Web.Administration reports them on a host with the
// Default Web Site, a site with two SNI bindings and a net.tcp binding, a
// non-SNI catch-all with a second binding on the private address, and a
// stopped site. The live scan returned these entries, and http.sys served
// the bound certificate on 443 and 8443. Fails if the net.tcp binding is
// kept, if a binding without a host name is not the default of its
// listener, or if 0.0.0.0 is reported instead of `*`.
func TestIisWebsiteEntries(t *testing.T) {
	certs := func() ([]any, error) { return nil, nil }
	const appHost = `C:\Windows\system32\inetsrv\config\applicationHost.config`
	entries := iisWebsiteEntries([]iisSiteBinding{
		{protocol: "http", ipAddress: "0.0.0.0", port: 80, physicalPath: `%SystemDrive%\inetpub\wwwroot`},
		{protocol: "http", hostName: "shop.example.test", ipAddress: "0.0.0.0", port: 8080, physicalPath: `C:\inetpub\shop`},
		{protocol: "https", hostName: "shop.example.test", ipAddress: "0.0.0.0", port: 443, physicalPath: `C:\inetpub\shop`, certs: certs},
		{protocol: "https", hostName: "www.shop.example.test", ipAddress: "0.0.0.0", port: 443, physicalPath: `C:\inetpub\shop`, certs: certs},
		{protocol: "net.tcp", physicalPath: `C:\inetpub\shop`},
		{protocol: "https", ipAddress: "0.0.0.0", port: 8443, physicalPath: `C:\inetpub\catchall`, certs: certs},
		{protocol: "http", ipAddress: "10.0.101.207", port: 8082, physicalPath: `C:\inetpub\catchall`},
		{protocol: "http", hostName: "parked.example.test", ipAddress: "0.0.0.0", port: 8081, physicalPath: `C:\inetpub\parked`},
	}, appHost)

	type got struct {
		name         string
		address      string
		port         int64
		tls          bool
		isDefault    bool
		certs        bool
		documentRoot string
	}
	var rows []got
	for _, e := range entries {
		assert.Equal(t, "iis", e.source)
		assert.Equal(t, appHost, e.file)
		rows = append(rows, got{e.name, e.address, e.port, e.tls, e.isDefault, e.certs != nil, e.documentRoot})
	}
	assert.Equal(t, []got{
		{"", "*", 80, false, true, false, `%SystemDrive%\inetpub\wwwroot`},
		{"shop.example.test", "*", 8080, false, false, false, `C:\inetpub\shop`},
		{"shop.example.test", "*", 443, true, false, true, `C:\inetpub\shop`},
		{"www.shop.example.test", "*", 443, true, false, true, `C:\inetpub\shop`},
		{"", "*", 8443, true, true, true, `C:\inetpub\catchall`},
		{"", "10.0.101.207", 8082, false, true, false, `C:\inetpub\catchall`},
		{"parked.example.test", "*", 8081, false, false, false, `C:\inetpub\parked`},
	}, rows)
}

// Synthetic: a host name in capitals and an HTTP binding without an
// endpoint; no target showed these.
func TestIisWebsiteEntriesNormalizesNames(t *testing.T) {
	entries := iisWebsiteEntries([]iisSiteBinding{
		{protocol: "HTTP", hostName: "WWW.Example.com", ipAddress: "0.0.0.0", port: 80},
		{protocol: "http", port: 0},
	}, "")
	require.Len(t, entries, 1)
	assert.Equal(t, "www.example.com", entries[0].name)
	assert.False(t, entries[0].isDefault)
}

// Synthetic: no target showed these. One name on two listeners is two sites
// with distinct ids. A second declaration of a site by the same web server is
// dropped, as nginx and Apache ignore it. The same site from a second source
// (certbot here, which websites does not read yet) adds that source, fills in
// what the first left empty, and adds its certificates.
func TestMergeWebsiteEntries(t *testing.T) {
	first := func() ([]any, error) { return nil, nil }
	second := func() ([]any, error) { return nil, nil }
	rows := mergeWebsiteEntries([]websiteEntry{
		{name: "www.example.com", address: "*", port: 80, source: "nginx", documentRoot: "/srv/a"},
		{name: "www.example.com", address: "*", port: 443, tls: true, source: "nginx", certs: first},
		{name: "www.example.com", address: "*", port: 80, source: "nginx", documentRoot: "/srv/b"},
		{name: "www.example.com", address: "*", port: 443, tls: true, source: "certbot", file: "/etc/letsencrypt/renewal/www.example.com.conf", certs: second},
	})

	require.Len(t, rows, 2)
	assert.NotEqual(t, websiteKey(rows[0].address, rows[0].port, rows[0].name), websiteKey(rows[1].address, rows[1].port, rows[1].name))
	assert.Equal(t, []string{"nginx"}, rows[0].sources)
	assert.Equal(t, "/srv/a", rows[0].documentRoot, "the first declaration wins")
	assert.Equal(t, []string{"nginx", "certbot"}, rows[1].sources)
	assert.Equal(t, "/etc/letsencrypt/renewal/www.example.com.conf", rows[1].file)
	assert.Len(t, rows[1].certSources, 2)
}

// Synthetic: address forms nginx, Apache, IIS and the socket list write; no
// target showed these.
func TestWebsiteAddress(t *testing.T) {
	cases := map[string]string{
		"":              "*",
		"*":             "*",
		"_default_":     "*",
		"0.0.0.0":       "*",
		"[::]":          "*",
		"::":            "*",
		"127.0.0.1":     "127.0.0.1",
		"[::1]":         "::1",
		"::ffff:a00:5":  "10.0.0.5",
		"[2001:DB8::1]": "2001:db8::1",
		"Localhost":     "localhost",
	}
	for in, want := range cases {
		assert.Equal(t, want, websiteAddress(in), in)
	}
}

// Synthetic: socket lists no target showed. A site takes the TCP socket on
// its port bound to its own address, else one bound to every address. A site
// on every address takes a socket bound to one address when there is no
// other.
func TestWebsiteListenerIndex(t *testing.T) {
	sockets := []websiteSocket{
		{protocol: "udp4", address: "0.0.0.0", port: 443},
		{protocol: "tcp6", address: "[::]", port: 443},
		{protocol: "tcp4", address: "192.0.2.10", port: 443},
		{protocol: "tcp4", address: "127.0.0.1", port: 8080},
	}
	assert.Equal(t, 1, websiteListenerIndex(sockets, "*", 443))
	assert.Equal(t, 2, websiteListenerIndex(sockets, "192.0.2.10", 443))
	assert.Equal(t, 1, websiteListenerIndex(sockets, "192.0.2.99", 443))
	assert.Equal(t, 3, websiteListenerIndex(sockets, "*", 8080))
	assert.Equal(t, -1, websiteListenerIndex(sockets, "192.0.2.10", 8080))
	assert.Equal(t, -1, websiteListenerIndex(sockets, "*", 80))
}

// fakeCertificate stands in for a network.certificate, which is keyed by its
// SHA-256 fingerprint.
type fakeCertificate string

func (c fakeCertificate) MqlID() string   { return "certificate:" + string(c) }
func (c fakeCertificate) MqlName() string { return "certificate" }

// Synthetic: no target showed this. Two web servers naming the same
// certificate report it once, and a certificate that cannot be read is an
// error rather than a shorter list.
func TestWebsiteCertificates(t *testing.T) {
	site := &mqlWebsite{}
	site.certSources = []func() ([]any, error){
		func() ([]any, error) { return []any{fakeCertificate("aa")}, nil },
		func() ([]any, error) { return nil, nil },
		func() ([]any, error) { return []any{fakeCertificate("aa"), fakeCertificate("bb")}, nil },
	}
	certs, err := site.certificates()
	require.NoError(t, err)
	assert.Equal(t, []any{fakeCertificate("aa"), fakeCertificate("bb")}, certs)

	denied := errors.New("permission denied")
	site.certSources = append(site.certSources, func() ([]any, error) { return nil, denied })
	_, err = site.certificates()
	assert.ErrorIs(t, err, denied)

	assert.Equal(t, []any{fakeCertificate("leaf")}, leafCertificates([]any{fakeCertificate("leaf"), fakeCertificate("intermediate")}))
	assert.Nil(t, leafCertificates(nil))
}
