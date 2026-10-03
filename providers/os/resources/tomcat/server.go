// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import "strings"

// Paths carries the installation and instance directories so that
// ${catalina.home} and ${catalina.base} placeholders in configuration values
// can be resolved to absolute paths.
type Paths struct {
	Home string
	Base string
}

// Expand replaces the ${catalina.home} and ${catalina.base} placeholders
// Tomcat itself resolves at startup. A configuration value that names a
// directory is otherwise opaque: the same directory can be written three ways,
// and a check comparing paths would have to enumerate all of them.
func (p Paths) Expand(value string) string {
	if value == "" || !strings.Contains(value, "${") {
		return value
	}
	replacer := strings.NewReplacer(
		"${catalina.base}", p.Base,
		"${catalina.home}", p.Home,
	)
	return replacer.Replace(value)
}

// Tomcat's own defaults for attributes that a configuration file may leave
// out. A typed resource has to report the connector's effective behavior, not
// merely what the XML spells out, or a check reading an omitted attribute
// judges a default that is not in effect.
const (
	defaultConnectionTimeout = 60000
	defaultMaxHTTPHeaderSize = 8192
)

// Server is the <Server> element of server.xml.
type Server struct {
	Port      int64
	Shutdown  string
	Listeners []Listener
	Services  []Service
}

// Listener is a <Listener> element.
type Listener struct {
	ClassName string
	Params    map[string]string
}

// Service is a <Service> element.
type Service struct {
	Name       string
	Connectors []Connector
	Engines    []Engine
}

// Connector is a <Connector> element.
type Connector struct {
	Port                int64
	Address             string
	Protocol            string
	SSLEnabled          bool
	Scheme              string
	Secure              bool
	AllowTrace          bool
	XPoweredBy          bool
	EnableLookups       bool
	ConnectionTimeout   int64
	MaxHTTPHeaderSize   int64
	Server              string
	Ciphers             string
	SSLProtocol         string
	SSLEnabledProtocols string
	ClientAuth          string
	SSLHostConfigs      []map[string]any
	Params              map[string]string
}

// Engine is an <Engine> element.
type Engine struct {
	Name        string
	DefaultHost string
	Hosts       []Host
	Realms      []Realm
	Valves      []Valve
}

// Host is a <Host> element.
type Host struct {
	Name            string
	AppBase         string
	AutoDeploy      bool
	DeployOnStartup bool
	DeployXML       bool
	UnpackWARs      bool
	Valves          []Valve
	Contexts        []Context
}

// Valve is a <Valve> element, wherever it is declared.
type Valve struct {
	ClassName      string
	Pattern        string
	Directory      string
	Prefix         string
	Suffix         string
	ShowServerInfo bool
	ShowReport     bool
	Allow          string
	Deny           string
	Params         map[string]string
}

// Realm is a <Realm> element. Realms nest: a LockOutRealm wraps the realm that
// performs the actual authentication.
type Realm struct {
	ClassName          string
	Digest             string
	ConnectionURL      string
	FailureCount       int64
	LockOutTime        int64
	Realms             []Realm
	CredentialHandlers []map[string]any
	Params             map[string]string
}

// Context is a <Context> element, from server.xml, conf/context.xml or an
// application's META-INF/context.xml.
type Context struct {
	Path string
	// DocBase is the application's directory or WAR (@docBase), with
	// ${catalina.*} expanded; relative to the Host's appBase when not absolute.
	DocBase            string
	Privileged         bool
	CrossContext       bool
	LogEffectiveWebXml bool
	AllowLinking       bool
	Valves             []Valve
	Params             map[string]string
}

// ParseServerXML parses the contents of conf/server.xml. It returns nil when
// the document is empty or its root element is not <Server>.
func ParseServerXML(data []byte, paths Paths) (*Server, error) {
	root, err := ParseXML(data)
	if err != nil {
		return nil, err
	}
	if root == nil || root.Name != "Server" {
		return nil, nil
	}

	srv := &Server{
		Port:      root.AttrInt(0, "port"),
		Shutdown:  root.AttrString("shutdown"),
		Listeners: parseListeners(root),
		Services:  []Service{},
	}

	for _, node := range root.Elements("Service") {
		srv.Services = append(srv.Services, Service{
			Name:       node.AttrString("name"),
			Connectors: parseConnectors(node),
			Engines:    parseEngines(node, paths),
		})
	}

	return srv, nil
}

func parseListeners(node *Node) []Listener {
	res := []Listener{}
	for _, l := range node.Elements("Listener") {
		res = append(res, Listener{
			ClassName: l.AttrString("className"),
			Params:    l.Params(),
		})
	}
	return res
}

func parseConnectors(node *Node) []Connector {
	res := []Connector{}
	for _, c := range node.Elements("Connector") {
		conn := Connector{
			Port:                c.AttrInt(0, "port"),
			Address:             c.AttrString("address"),
			Protocol:            c.AttrString("protocol"),
			SSLEnabled:          c.AttrBool(false, "SSLEnabled"),
			Scheme:              c.AttrString("scheme"),
			Secure:              c.AttrBool(false, "secure"),
			AllowTrace:          c.AttrBool(false, "allowTrace"),
			XPoweredBy:          c.AttrBool(false, "xpoweredBy"),
			EnableLookups:       c.AttrBool(false, "enableLookups"),
			ConnectionTimeout:   c.AttrInt(defaultConnectionTimeout, "connectionTimeout"),
			MaxHTTPHeaderSize:   c.AttrInt(defaultMaxHTTPHeaderSize, "maxHttpHeaderSize"),
			Server:              c.AttrString("server"),
			Ciphers:             c.AttrString("ciphers"),
			SSLProtocol:         c.AttrString("sslProtocol"),
			SSLEnabledProtocols: c.AttrString("sslEnabledProtocols", "SSLEnabledProtocols"),
			ClientAuth:          c.AttrString("clientAuth"),
			SSLHostConfigs:      parseSSLHostConfigs(c),
			Params:              c.Params(),
		}
		res = append(res, conn)
	}
	return res
}

func parseSSLHostConfigs(node *Node) []map[string]any {
	res := []map[string]any{}
	for _, sslHost := range node.Elements("SSLHostConfig") {
		entry := sslHost.AttrsDict()
		// <Certificate> children carry the key store the connector presents,
		// which is what a permission check on the store needs to find it.
		certs := []any{}
		for _, cert := range sslHost.Elements("Certificate") {
			certs = append(certs, cert.AttrsDict())
		}
		entry["certificates"] = certs
		res = append(res, entry)
	}
	return res
}

func parseEngines(node *Node, paths Paths) []Engine {
	res := []Engine{}
	for _, e := range node.Elements("Engine") {
		res = append(res, Engine{
			Name:        e.AttrString("name"),
			DefaultHost: e.AttrString("defaultHost"),
			Hosts:       parseHosts(e, paths),
			Realms:      parseRealms(e),
			Valves:      parseValves(e, paths),
		})
	}
	return res
}

func parseHosts(node *Node, paths Paths) []Host {
	res := []Host{}
	for _, h := range node.Elements("Host") {
		res = append(res, Host{
			Name:    h.AttrString("name"),
			AppBase: h.AttrString("appBase"),
			// Tomcat deploys by default; an absent attribute means the
			// behavior is on, not off.
			AutoDeploy:      h.AttrBool(true, "autoDeploy"),
			DeployOnStartup: h.AttrBool(true, "deployOnStartup"),
			DeployXML:       h.AttrBool(true, "deployXML"),
			UnpackWARs:      h.AttrBool(true, "unpackWARs"),
			Valves:          parseValves(h, paths),
			Contexts:        parseContexts(h, paths),
		})
	}
	return res
}

func parseValves(node *Node, paths Paths) []Valve {
	res := []Valve{}
	for _, v := range node.Elements("Valve") {
		className := v.AttrString("className")
		// ErrorReportValve reveals the server version and stack traces unless
		// told otherwise; every other valve has no such attribute at all, so
		// the default only applies where it means something.
		isErrorReport := strings.HasSuffix(className, "ErrorReportValve")
		res = append(res, Valve{
			ClassName:      className,
			Pattern:        v.AttrString("pattern"),
			Directory:      paths.Expand(v.AttrString("directory")),
			Prefix:         v.AttrString("prefix"),
			Suffix:         v.AttrString("suffix"),
			ShowServerInfo: v.AttrBool(isErrorReport, "showServerInfo"),
			ShowReport:     v.AttrBool(isErrorReport, "showReport"),
			Allow:          v.AttrString("allow"),
			Deny:           v.AttrString("deny"),
			Params:         v.Params(),
		})
	}
	return res
}

func parseRealms(node *Node) []Realm {
	res := []Realm{}
	for _, r := range node.Elements("Realm") {
		handlers := []map[string]any{}
		for _, ch := range r.Elements("CredentialHandler") {
			handlers = append(handlers, ch.AttrsDict())
		}
		res = append(res, Realm{
			ClassName:          r.AttrString("className"),
			Digest:             r.AttrString("digest"),
			ConnectionURL:      r.AttrString("connectionURL"),
			FailureCount:       r.AttrInt(0, "failureCount"),
			LockOutTime:        r.AttrInt(0, "lockOutTime"),
			Realms:             parseRealms(r),
			CredentialHandlers: handlers,
			Params:             r.Params(),
		})
	}
	return res
}

func parseContexts(node *Node, paths Paths) []Context {
	res := []Context{}
	for _, c := range node.Elements("Context") {
		res = append(res, newContext(c, paths))
	}
	return res
}

// ParseContextXML parses a standalone context document — conf/context.xml or
// an application's META-INF/context.xml — whose root element is <Context>.
func ParseContextXML(data []byte, paths Paths) (*Context, error) {
	root, err := ParseXML(data)
	if err != nil {
		return nil, err
	}
	if root == nil || root.Name != "Context" {
		return nil, nil
	}
	ctx := newContext(root, paths)
	return &ctx, nil
}

func newContext(node *Node, paths Paths) Context {
	return Context{
		Path:               node.AttrString("path"),
		DocBase:            paths.Expand(node.AttrString("docBase")),
		Privileged:         node.AttrBool(false, "privileged"),
		CrossContext:       node.AttrBool(false, "crossContext"),
		LogEffectiveWebXml: node.AttrBool(false, "logEffectiveWebXml"),
		// allowLinking lives on the nested <Resources> element, not on the
		// context itself.
		AllowLinking: node.Element("Resources").AttrBool(false, "allowLinking"),
		Valves:       parseValves(node, paths),
		Params:       node.Params(),
	}
}

// User is an entry of conf/tomcat-users.xml.
type User struct {
	Username string
	Password string
	Roles    []string
}

// ParseUsersXML parses conf/tomcat-users.xml.
func ParseUsersXML(data []byte) ([]User, error) {
	root, err := ParseXML(data)
	if err != nil {
		return nil, err
	}
	res := []User{}
	if root == nil {
		return res, nil
	}

	for _, u := range root.Elements("user") {
		roles := []string{}
		for _, role := range strings.Split(u.AttrString("roles"), ",") {
			role = strings.TrimSpace(role)
			if role != "" {
				roles = append(roles, role)
			}
		}
		res = append(res, User{
			Username: u.AttrString("username"),
			Password: u.AttrString("password"),
			Roles:    roles,
		})
	}

	return res, nil
}
