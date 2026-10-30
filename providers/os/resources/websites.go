// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/apache2"
	"go.mondoo.com/mql/types"
)

// websiteEntry is one site as one web server's configuration declares it,
// before the entries of every web server are merged into websites.
type websiteEntry struct {
	name         string
	address      string
	port         int64
	tls          bool
	source       string
	file         string
	documentRoot string
	proxyTarget  string
	isDefault    bool
	// certs returns the leaf certificates the configuration names for the
	// site. Nil when the listener does not speak TLS.
	certs func() ([]any, error)
}

// websiteRow is one site after merging: one per address, port and name.
type websiteRow struct {
	websiteEntry
	sources     []string
	certSources []func() ([]any, error)
}

type mqlWebsiteInternal struct {
	// filePath is the configuration file that declares the site.
	filePath string
	// certSources return the leaf certificates each web server's
	// configuration names for the site.
	certSources []func() ([]any, error)
}

// websiteSource is one web server websites reads the sites of.
type websiteSource struct {
	name string
	// installed reports whether the web server is on the host, from the
	// filesystem alone, so a host that serves nothing pays a few stats rather
	// than the commands each configuration lookup falls back to.
	installed func(afs *afero.Afero, conn shared.Connection) bool
	read      func(runtime *plugin.Runtime) ([]websiteEntry, error)
}

// websiteSources are the web servers that can run on the asset's platform.
func websiteSources(conn shared.Connection) []websiteSource {
	if isWindowsAsset(conn) {
		return []websiteSource{
			{name: "iis", installed: iisInstalled, read: iisWebsites},
		}
	}
	return []websiteSource{
		{name: "nginx", installed: nginxInstalled, read: nginxWebsites},
		{name: "apache2", installed: apache2Installed, read: apache2Websites},
	}
}

func (w *mqlWebsites) list() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)
	afs := &afero.Afero{Fs: conn.FileSystem()}

	var entries []websiteEntry
	for _, src := range websiteSources(conn) {
		if !src.installed(afs, conn) {
			continue
		}
		e, err := src.read(w.MqlRuntime)
		if err != nil {
			// One web server that cannot be read must not hide the sites of the
			// others, the way a denied region does not hide the other regions.
			log.Warn().Err(err).Str("webserver", src.name).Msg("websites> cannot read the sites of this web server, leaving them out")
			continue
		}
		entries = append(entries, e...)
	}

	rows := mergeWebsiteEntries(entries)
	res := make([]any, 0, len(rows))
	for _, row := range rows {
		r, err := CreateResource(w.MqlRuntime, "website", map[string]*llx.RawData{
			"__id":         llx.StringData("website/" + websiteKey(row.address, row.port, row.name)),
			"name":         llx.StringData(row.name),
			"address":      llx.StringData(row.address),
			"port":         llx.IntData(row.port),
			"tls":          llx.BoolData(row.tls),
			"sources":      llx.ArrayData(convert.SliceAnyToInterface(row.sources), types.String),
			"documentRoot": llx.StringData(row.documentRoot),
			"proxyTarget":  llx.StringData(row.proxyTarget),
			"isDefault":    llx.BoolData(row.isDefault),
		})
		if err != nil {
			return nil, err
		}
		site := r.(*mqlWebsite)
		site.filePath = row.file
		site.certSources = row.certSources
		res = append(res, site)
	}
	return res, nil
}

// websiteKey is the identity of a site: a name on one listener.
func websiteKey(address string, port int64, name string) string {
	return address + "|" + strconv.FormatInt(port, 10) + "|" + name
}

// mergeWebsiteEntries folds entries into one row per address, port and name,
// in the order they are first declared. A later entry from the web server
// that declared the row is the same site declared twice, which nginx, Apache
// and IIS all settle in favor of the first declaration, so it is dropped. An
// entry from another web server adds that server to the row's sources, fills
// in what the row does not say yet, and adds its certificates.
func mergeWebsiteEntries(entries []websiteEntry) []*websiteRow {
	rows := []*websiteRow{}
	byKey := map[string]*websiteRow{}
	for _, e := range entries {
		key := websiteKey(e.address, e.port, e.name)
		row, ok := byKey[key]
		if !ok {
			row = &websiteRow{websiteEntry: e, sources: []string{e.source}}
			if e.certs != nil {
				row.certSources = []func() ([]any, error){e.certs}
			}
			byKey[key] = row
			rows = append(rows, row)
			continue
		}
		if slices.Contains(row.sources, e.source) {
			continue
		}
		row.sources = append(row.sources, e.source)
		row.tls = row.tls || e.tls
		row.isDefault = row.isDefault || e.isDefault
		if row.file == "" {
			row.file = e.file
		}
		if row.documentRoot == "" {
			row.documentRoot = e.documentRoot
		}
		if row.proxyTarget == "" {
			row.proxyTarget = e.proxyTarget
		}
		if e.certs != nil {
			row.certSources = append(row.certSources, e.certs)
		}
	}
	return rows
}

// websiteAddress spells a listener's address the way websites reports it:
// `*` for every address in whichever form the configuration writes it, an IP
// address in canonical form without brackets, or a host name in lowercase.
func websiteAddress(address string) string {
	a := strings.TrimSpace(address)
	a = strings.TrimSuffix(strings.TrimPrefix(a, "["), "]")
	switch a {
	case "", "*", "_default_":
		return "*"
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		if ip.IsUnspecified() {
			return "*"
		}
		return ip.Unmap().String()
	}
	return strings.ToLower(a)
}

// websiteName is a configured host name the way websites reports it:
// lowercase, without the trailing dot of a fully qualified name.
func websiteName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// leafCertificates keeps the first certificate of a chain read from a
// certificate file. nginx, Apache httpd and IIS all require the certificate
// the server presents to come first, ahead of its intermediates.
func leafCertificates(chain []any) []any {
	if len(chain) == 0 {
		return nil
	}
	return chain[:1]
}

func (w *mqlWebsite) file() (*mqlFile, error) {
	if w.filePath == "" {
		w.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := CreateResource(w.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(w.filePath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// certificates collects the leaf certificate of every web server that
// declares the site, once each: two web servers naming the same file, or two
// files holding the same certificate, report it once.
func (w *mqlWebsite) certificates() ([]any, error) {
	res := []any{}
	seen := map[string]bool{}
	for _, source := range w.certSources {
		certs, err := source()
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			cert, ok := c.(plugin.Resource)
			if !ok || cert == nil {
				continue
			}
			if seen[cert.MqlID()] {
				continue
			}
			seen[cert.MqlID()] = true
			res = append(res, cert)
		}
	}
	return res, nil
}

func (w *mqlWebsite) process() (*mqlProcess, error) {
	o, err := CreateResource(w.MqlRuntime, "ports", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	listening := o.(*mqlPorts).GetListening()
	if listening.Error != nil {
		return nil, listening.Error
	}

	sockets := make([]websiteSocket, len(listening.Data))
	for i, p := range listening.Data {
		port := p.(*mqlPort)
		sockets[i] = websiteSocket{protocol: port.Protocol.Data, address: port.Address.Data, port: port.Port.Data}
	}
	idx := websiteListenerIndex(sockets, w.Address.Data, w.Port.Data)
	if idx < 0 {
		w.Process.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	proc := listening.Data[idx].(*mqlPort).GetProcess()
	if proc.Error != nil {
		return nil, proc.Error
	}
	if proc.Data == nil {
		w.Process.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return proc.Data, nil
}

// websiteSocket is a listening socket as websiteListenerIndex compares it.
type websiteSocket struct {
	protocol string
	address  string
	port     int64
}

// websiteListenerIndex returns the index of the socket that is a site's
// listener, or -1 when none is: a TCP socket on the site's port, bound to
// the site's address or, failing that, to every address. A site on every
// address takes a socket bound to every address over one bound to a single
// address.
func websiteListenerIndex(sockets []websiteSocket, address string, port int64) int {
	exact, wildcard, other := -1, -1, -1
	for i, s := range sockets {
		if !strings.HasPrefix(s.protocol, "tcp") || s.port != port {
			continue
		}
		switch a := websiteAddress(s.address); {
		case a == address && exact < 0:
			exact = i
		case a == "*" && wildcard < 0:
			wildcard = i
		case other < 0:
			other = i
		}
	}
	switch {
	case exact >= 0:
		return exact
	case wildcard >= 0:
		return wildcard
	case address == "*":
		return other
	}
	return -1
}

// anyPathExists reports whether any of paths exists. A path the scan may not
// stat counts as existing, so a permission problem is left to the web
// server's own resource to report rather than reading as an absent server.
func anyPathExists(afs *afero.Afero, paths []string) bool {
	for _, p := range paths {
		if ok, err := afs.Exists(p); ok || err != nil {
			return true
		}
	}
	return false
}

// nginx

// nginxInstallPaths are where nginx's binary lives when a distribution
// package or Homebrew installs it.
var nginxInstallPaths = append(slices.Clone(nginxVersionBinaries), "/opt/homebrew/bin/nginx")

// nginxInstalled reports whether nginx is on the host: its configuration at
// the platform's default location, its binary at a well-known path, or a pid
// file naming a running master.
func nginxInstalled(afs *afero.Afero, conn shared.Connection) bool {
	paths := append([]string{nginxConfPath(conn)}, nginxInstallPaths...)
	return anyPathExists(afs, append(paths, nginxPidFiles...))
}

// nginxSiteServer is what websites reads from one nginx server block.
type nginxSiteServer struct {
	serverName string
	listens    []nginxListen
	// legacySSL is set by `ssl on`, which turned on TLS for every listener of
	// the block before nginx 1.25.1 removed it.
	legacySSL    bool
	documentRoot string
	proxyTarget  string
	file         string
	certs        func() ([]any, error)
}

// nginxSiteEndpoint is one listener of a server block.
type nginxSiteEndpoint struct {
	address       string
	port          int64
	tls           bool
	defaultServer bool
}

func nginxWebsites(runtime *plugin.Runtime) ([]websiteEntry, error) {
	o, err := NewResource(runtime, "nginx.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	conf := o.(*mqlNginxConf)

	// An installed nginx whose configuration is missing serves nothing, and
	// reading the servers of a file that does not exist is an error.
	file := conf.GetFile()
	if file.Error != nil {
		return nil, file.Error
	}
	if file.Data == nil {
		return nil, nil
	}
	exists := file.Data.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return nil, nil
	}

	servers := conf.GetServers()
	if servers.Error != nil {
		return nil, servers.Error
	}
	sites := make([]nginxSiteServer, 0, len(servers.Data))
	for _, s := range servers.Data {
		sites = append(sites, nginxSiteFromServer(s.(*mqlNginxConfServer)))
	}
	return nginxWebsiteEntries(sites), nil
}

// nginxSiteFromServer reads what websites needs from a server block.
func nginxSiteFromServer(srv *mqlNginxConfServer) nginxSiteServer {
	site := nginxSiteServer{
		serverName:   srv.ServerName.Data,
		documentRoot: srv.Root.Data,
		file:         srv.file,
	}
	for _, raw := range srv.Listens.Data {
		l, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		listen := nginxListen{}
		listen.Raw, _ = l["raw"].(string)
		listen.Address, _ = l["address"].(string)
		listen.Port, _ = l["port"].(int64)
		listen.SSL, _ = l["ssl"].(bool)
		listen.DefaultServer, _ = l["defaultServer"].(bool)
		site.listens = append(site.listens, listen)
	}
	if v, ok := srv.Params.Data["ssl"].(string); ok && strings.EqualFold(v, "on") {
		site.legacySSL = true
	}
	for _, raw := range srv.Locations.Data {
		loc, ok := raw.(*mqlNginxConfLocation)
		if !ok || !nginxIsRootLocation(loc.Modifier.Data, loc.Path.Data) {
			continue
		}
		if loc.Root.Data != "" {
			site.documentRoot = loc.Root.Data
		}
		site.proxyTarget = loc.ProxyPass.Data
		break
	}
	if srv.SslCertificate.Data != "" {
		site.certs = func() ([]any, error) {
			chain := srv.GetCertificate()
			if chain.Error != nil {
				return nil, chain.Error
			}
			return leafCertificates(chain.Data), nil
		}
	}
	return site
}

// nginxIsRootLocation reports whether a location block handles requests for
// `/`: `location /`, `location ^~ /` or `location = /`.
func nginxIsRootLocation(modifier, path string) bool {
	return path == "/" && (modifier == "" || modifier == "^~" || modifier == "=")
}

// nginxSiteNames splits a server block's server_name into the names websites
// reports, each once. `_` is not a host name and is left out, as is the empty
// name `""`, which the parser has already unquoted to nothing.
// `.example.com` is nginx's shorthand for example.com and *.example.com. A
// regular expression, which starts with `~`, is kept as written, since its
// case is part of the expression.
func nginxSiteNames(serverName string) []string {
	var names []string
	add := func(n string) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, n := range strings.Fields(serverName) {
		switch {
		case n == "_":
			continue
		case strings.HasPrefix(n, "~"):
			add(n)
		case strings.HasPrefix(n, ".") && len(n) > 1:
			base := websiteName(n[1:])
			add(base)
			add("*." + base)
		default:
			add(websiteName(n))
		}
	}
	return names
}

// nginxSiteEndpoints returns the listeners of a server block, one per
// address and port however many listen directives name it. A block without a
// listen directive listens on *:80, as nginx does when it runs as root, and a
// listen directive with an address and no port listens on port 80. Unix
// sockets are left out: nothing outside the host reaches them.
func nginxSiteEndpoints(srv nginxSiteServer) []nginxSiteEndpoint {
	listens := srv.listens
	if len(listens) == 0 {
		listens = []nginxListen{{Port: 80}}
	}
	var eps []nginxSiteEndpoint
	for _, l := range listens {
		if strings.HasPrefix(l.Address, "unix:") {
			continue
		}
		port := l.Port
		if port == 0 {
			port = 80
		}
		ep := nginxSiteEndpoint{
			address: websiteAddress(l.Address),
			port:    port,
			// HTTP/3 always runs over TLS.
			tls:           l.SSL || srv.legacySSL || slices.Contains(strings.Fields(l.Raw), "quic"),
			defaultServer: l.DefaultServer,
		}
		i := slices.IndexFunc(eps, func(e nginxSiteEndpoint) bool {
			return e.address == ep.address && e.port == ep.port
		})
		if i < 0 {
			eps = append(eps, ep)
			continue
		}
		eps[i].tls = eps[i].tls || ep.tls
		eps[i].defaultServer = eps[i].defaultServer || ep.defaultServer
	}
	return eps
}

// nginxWebsiteEntries turns nginx server blocks, in configuration order, into
// one entry per name on each of a block's listeners. The default site of a
// listener is the block marked default_server on it, or else the first block
// on it.
func nginxWebsiteEntries(servers []nginxSiteServer) []websiteEntry {
	type endpoint struct {
		address string
		port    int64
	}
	endpoints := make([][]nginxSiteEndpoint, len(servers))
	first := map[endpoint]int{}
	marked := map[endpoint]bool{}
	for i, srv := range servers {
		endpoints[i] = nginxSiteEndpoints(srv)
		for _, ep := range endpoints[i] {
			key := endpoint{ep.address, ep.port}
			if _, ok := first[key]; !ok {
				first[key] = i
			}
			if ep.defaultServer {
				marked[key] = true
			}
		}
	}

	var entries []websiteEntry
	for i, srv := range servers {
		names := nginxSiteNames(srv.serverName)
		if len(names) == 0 {
			names = []string{""}
		}
		for _, ep := range endpoints[i] {
			key := endpoint{ep.address, ep.port}
			isDefault := ep.defaultServer || (!marked[key] && first[key] == i)
			for _, name := range names {
				e := websiteEntry{
					name:         name,
					address:      ep.address,
					port:         ep.port,
					tls:          ep.tls,
					source:       "nginx",
					file:         srv.file,
					documentRoot: srv.documentRoot,
					proxyTarget:  srv.proxyTarget,
					isDefault:    isDefault,
				}
				if ep.tls {
					e.certs = srv.certs
				}
				entries = append(entries, e)
			}
		}
	}
	return entries
}

// Apache httpd

// apache2Installed reports whether Apache httpd is on the host: its
// configuration at the platform's default location, its binary at one of the
// paths apache2 reads it from, or a pid file naming a running server.
func apache2Installed(afs *afero.Afero, conn shared.Connection) bool {
	paths := append([]string{apacheConfPath(conn)}, apacheBinaries...)
	return anyPathExists(afs, append(paths, apachePidFiles...))
}

// apacheSiteVHost is what websites reads from one virtual host.
type apacheSiteVHost struct {
	// address is the argument of <VirtualHost>, one or more addr[:port].
	address      string
	serverName   string
	aliases      []string
	documentRoot string
	tls          bool
	proxyPass    string
	file         string
	certs        func() ([]any, error)
}

// apacheSiteMain is the main server: what httpd serves on a listener no
// virtual host claims, configured by the directives outside every virtual
// host.
type apacheSiteMain struct {
	serverName   string
	documentRoot string
	// listens are the arguments of the Listen directives.
	listens   []string
	tls       bool
	proxyPass string
	file      string
	certs     func() ([]any, error)
}

// apacheEndpoint is a listener as Apache httpd names it, with port 0 for any
// port.
type apacheEndpoint struct {
	address string
	port    int64
}

func apache2Websites(runtime *plugin.Runtime) ([]websiteEntry, error) {
	o, err := NewResource(runtime, "apache2.conf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	conf := o.(*mqlApache2Conf)

	file := conf.GetFile()
	if file.Error != nil {
		return nil, file.Error
	}
	if file.Data == nil {
		return nil, nil
	}
	params := conf.GetParams()
	if params.Error != nil {
		return nil, params.Error
	}
	vhosts := conf.GetVirtualHosts()
	if vhosts.Error != nil {
		return nil, vhosts.Error
	}
	listens := conf.GetListenAddresses()
	if listens.Error != nil {
		return nil, listens.Error
	}

	main := apacheSiteMain{file: file.Data.Path.Data}
	main.serverName, _ = apache2.ParamValue(params.Data, "ServerName")
	main.documentRoot, _ = apache2.ParamValue(params.Data, "DocumentRoot")
	main.proxyPass, _ = apache2.ParamValue(params.Data, "ProxyPass")
	if engine, _ := apache2.ParamValue(params.Data, "SSLEngine"); strings.EqualFold(engine, "on") {
		main.tls = true
		if path, _ := apache2.ParamValue(params.Data, "SSLCertificateFile"); path != "" {
			main.certs = func() ([]any, error) {
				chain, err := readCertificatesFromPath(runtime, path)
				return leafCertificates(chain), err
			}
		}
	}
	for _, l := range listens.Data {
		if s, ok := l.(string); ok {
			main.listens = append(main.listens, s)
		}
	}

	sites := make([]apacheSiteVHost, 0, len(vhosts.Data))
	for _, v := range vhosts.Data {
		vh := v.(*mqlApache2ConfVirtualHost)
		site := apacheSiteVHost{
			address:      vh.Address.Data,
			serverName:   vh.ServerName.Data,
			documentRoot: vh.DocumentRoot.Data,
			tls:          vh.Ssl.Data,
			file:         vh.file,
		}
		for _, a := range vh.ServerAliases.Data {
			if s, ok := a.(string); ok {
				site.aliases = append(site.aliases, s)
			}
		}
		site.proxyPass, _ = apache2.ParamValue(vh.Params.Data, "ProxyPass")
		if vh.SslCertificateFile.Data != "" {
			site.certs = func() ([]any, error) {
				chain := vh.GetCertificate()
				if chain.Error != nil {
					return nil, chain.Error
				}
				return leafCertificates(chain.Data), nil
			}
		}
		sites = append(sites, site)
	}
	return apacheWebsiteEntries(sites, main), nil
}

// parseApacheEndpoint reads one addr[:port] of a <VirtualHost> or Listen
// argument: `*:80`, `_default_:443`, `192.0.2.1:8080`, `[2001:db8::1]:443`, a
// bare port as Listen writes it, or an address without a port, which for a
// virtual host means any port.
func parseApacheEndpoint(s string) (apacheEndpoint, bool) {
	s = strings.Trim(strings.TrimSpace(s), `"`)
	if s == "" {
		return apacheEndpoint{}, false
	}
	if p, err := strconv.ParseInt(s, 10, 64); err == nil {
		return apacheEndpoint{address: "*", port: p}, p > 0 && p <= 65535
	}

	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return apacheEndpoint{}, false
		}
		host = s[1:end]
		if rest := s[end+1:]; rest != "" {
			p, ok := strings.CutPrefix(rest, ":")
			if !ok {
				return apacheEndpoint{}, false
			}
			port = p
		}
	} else if h, p, ok := strings.Cut(s, ":"); ok {
		host, port = h, p
	}

	ep := apacheEndpoint{address: websiteAddress(host)}
	if port == "" || port == "*" {
		return ep, true
	}
	p, err := strconv.ParseInt(port, 10, 64)
	if err != nil || p <= 0 || p > 65535 {
		return apacheEndpoint{}, false
	}
	ep.port = p
	return ep, true
}

// apacheListenEndpoints reads the Listen directives, `[address:]port
// [protocol]`, into the listeners httpd opens.
func apacheListenEndpoints(listens []string) []apacheEndpoint {
	var eps []apacheEndpoint
	for _, l := range listens {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		ep, ok := parseApacheEndpoint(fields[0])
		if !ok || ep.port == 0 || slices.Contains(eps, ep) {
			continue
		}
		eps = append(eps, ep)
	}
	return eps
}

// apacheVHostEndpoints returns the listeners a virtual host answers on: each
// address of its <VirtualHost> argument, on the port it names or, for an
// address without a port, on every port httpd listens on.
func apacheVHostEndpoints(address string, listens []apacheEndpoint) []apacheEndpoint {
	var eps []apacheEndpoint
	add := func(ep apacheEndpoint) {
		if !slices.Contains(eps, ep) {
			eps = append(eps, ep)
		}
	}
	for _, field := range strings.Fields(address) {
		ep, ok := parseApacheEndpoint(field)
		if !ok {
			continue
		}
		if ep.port != 0 {
			add(ep)
			continue
		}
		for _, l := range listens {
			add(apacheEndpoint{address: ep.address, port: l.port})
		}
	}
	return eps
}

// apacheServerName returns the host name of a ServerName directive,
// `[scheme://]name[:port]`.
func apacheServerName(s string) string {
	s = strings.TrimSpace(s)
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			return websiteName(s[1:end])
		}
	}
	if host, _, ok := strings.Cut(s, ":"); ok {
		s = host
	}
	return websiteName(s)
}

// apacheSiteNames returns the names a virtual host answers for: its
// ServerName, or else the one it inherits from the main server, then its
// ServerAlias names.
func apacheSiteNames(serverName, mainServerName string, aliases []string) []string {
	var names []string
	name := apacheServerName(serverName)
	if name == "" {
		name = apacheServerName(mainServerName)
	}
	if name != "" {
		names = append(names, name)
	}
	for _, a := range aliases {
		if n := websiteName(a); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return []string{""}
	}
	return names
}

// apacheRootProxyTarget returns the target of a `ProxyPass / <url>`
// directive, or "" when the directive forwards another path or, with `!`,
// excludes one.
func apacheRootProxyTarget(proxyPass string) string {
	fields := strings.Fields(proxyPass)
	for i := range fields {
		fields[i] = strings.Trim(fields[i], `"`)
	}
	if len(fields) < 2 || fields[0] != "/" || fields[1] == "!" {
		return ""
	}
	return fields[1]
}

// apacheWebsiteEntries turns Apache httpd's virtual hosts, in configuration
// order, into one entry per name on each listener they answer on, and the
// main server into an entry on each listener no virtual host claims. The
// default site of a listener is the first virtual host on it, which is what
// httpd serves for a name no virtual host on the listener claims.
func apacheWebsiteEntries(vhosts []apacheSiteVHost, main apacheSiteMain) []websiteEntry {
	listens := apacheListenEndpoints(main.listens)

	var entries []websiteEntry
	var claimed []apacheEndpoint
	for _, vh := range vhosts {
		names := apacheSiteNames(vh.serverName, main.serverName, vh.aliases)
		documentRoot := vh.documentRoot
		if documentRoot == "" {
			documentRoot = main.documentRoot
		}
		for _, ep := range apacheVHostEndpoints(vh.address, listens) {
			isDefault := !slices.Contains(claimed, ep)
			if isDefault {
				claimed = append(claimed, ep)
			}
			for _, name := range names {
				e := websiteEntry{
					name:         name,
					address:      ep.address,
					port:         ep.port,
					tls:          vh.tls,
					source:       "apache2",
					file:         vh.file,
					documentRoot: documentRoot,
					proxyTarget:  apacheRootProxyTarget(vh.proxyPass),
					isDefault:    isDefault,
				}
				if vh.tls {
					e.certs = vh.certs
				}
				entries = append(entries, e)
			}
		}
	}

	// A listener a virtual host claims on its address, or on every address,
	// is served by virtual hosts. Requests on any other listener go to the
	// main server.
	mainName := apacheServerName(main.serverName)
	for _, l := range listens {
		if slices.ContainsFunc(claimed, func(c apacheEndpoint) bool {
			return c.port == l.port && (c.address == "*" || c.address == l.address)
		}) {
			continue
		}
		e := websiteEntry{
			name:         mainName,
			address:      l.address,
			port:         l.port,
			tls:          main.tls,
			source:       "apache2",
			file:         main.file,
			documentRoot: main.documentRoot,
			proxyTarget:  apacheRootProxyTarget(main.proxyPass),
			isDefault:    true,
		}
		if main.tls {
			e.certs = main.certs
		}
		entries = append(entries, e)
	}
	return entries
}

// IIS

// iisApplicationHostPath is applicationHost.config under the default Windows
// directory, which every IIS installation has.
const iisApplicationHostPath = `C:\Windows\System32\inetsrv\config\applicationHost.config`

// iisInstalled reports whether IIS is on the host from its configuration
// file, so a Windows host without IIS does not run the IIS collection.
func iisInstalled(afs *afero.Afero, _ shared.Connection) bool {
	return anyPathExists(afs, []string{iisApplicationHostPath})
}

// iisSiteBinding is what websites reads from one binding of an IIS site.
type iisSiteBinding struct {
	protocol     string
	hostName     string
	ipAddress    string
	port         int64
	physicalPath string
	certs        func() ([]any, error)
}

func iisWebsites(runtime *plugin.Runtime) ([]websiteEntry, error) {
	o, err := CreateResource(runtime, "iis", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	iis := o.(*mqlIis)

	installed := iis.GetInstalled()
	if installed.Error != nil {
		return nil, installed.Error
	}
	if !installed.Data {
		return nil, nil
	}
	sites := iis.GetSites()
	if sites.Error != nil {
		return nil, sites.Error
	}
	file := ""
	if appHost := iis.GetApplicationHost(); appHost.Error == nil && appHost.Data != nil {
		file = appHost.Data.Path.Data
	}

	var bindings []iisSiteBinding
	for _, s := range sites.Data {
		site := s.(*mqlIisSite)
		for _, b := range site.Bindings.Data {
			binding := b.(*mqlIisBinding)
			bindings = append(bindings, iisSiteBinding{
				protocol:     binding.Protocol.Data,
				hostName:     binding.HostName.Data,
				ipAddress:    binding.IpAddress.Data,
				port:         binding.Port.Data,
				physicalPath: site.PhysicalPath.Data,
				certs: func() ([]any, error) {
					cert := binding.GetCertificate()
					if cert.Error != nil {
						return nil, cert.Error
					}
					if cert.Data == nil {
						return nil, nil
					}
					return []any{cert.Data}, nil
				},
			})
		}
	}
	return iisWebsiteEntries(bindings, file), nil
}

// iisWebsiteEntries turns the HTTP and HTTPS bindings of IIS sites into one
// entry each. A binding without a host name answers for every name on its
// address and port, which makes it the default site there.
func iisWebsiteEntries(bindings []iisSiteBinding, file string) []websiteEntry {
	var entries []websiteEntry
	for _, b := range bindings {
		protocol := strings.ToLower(b.protocol)
		if (protocol != "http" && protocol != "https") || b.port == 0 {
			continue
		}
		e := websiteEntry{
			name:         websiteName(b.hostName),
			address:      websiteAddress(b.ipAddress),
			port:         b.port,
			tls:          protocol == "https",
			source:       "iis",
			file:         file,
			documentRoot: b.physicalPath,
			isDefault:    strings.TrimSpace(b.hostName) == "",
		}
		if e.tls {
			e.certs = b.certs
		}
		entries = append(entries, e)
	}
	return entries
}
