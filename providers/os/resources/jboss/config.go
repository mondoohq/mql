// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package jboss parses the on-disk configuration of a JBoss EAP / WildFly
// installation: the server configuration documents, the realm properties
// files, and the startup configuration that carries the JVM options.
//
// Nothing in this package runs a command or talks to the management endpoint.
// Every value the hardening guidance for these servers asks about is persisted
// in the configuration, so reading it from disk works the same on a live host,
// a container image and a filesystem snapshot.
package jboss

import (
	"encoding/xml"
	"strconv"
	"strings"
)

// Document is a parsed JBoss server configuration.
//
// One type covers all three root elements — <server> for a standalone profile,
// <domain> for domain.xml and <host> for host.xml — because they share most of
// their structure and differ only in which parts they carry. Fields that the
// document does not have stay nil or empty, and Mode reports which of the
// three it is.
type Document struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`

	Management *Management `xml:"management"`

	// A standalone profile declares one unnamed <profile>; domain.xml wraps
	// several named ones in <profiles>.
	Profile  []Profile `xml:"profile"`
	Profiles []Profile `xml:"profiles>profile"`

	Interfaces []Interface `xml:"interfaces>interface"`

	// Likewise for socket binding groups: one per standalone profile,
	// several inside <socket-binding-groups> in domain.xml.
	SocketBindingGroup  []SocketBindingGroup `xml:"socket-binding-group"`
	SocketBindingGroups []SocketBindingGroup `xml:"socket-binding-groups>socket-binding-group"`

	ServerGroups []ServerGroup `xml:"server-groups>server-group"`
	HostServers  []HostServer  `xml:"servers>server"`

	DomainController *DomainController `xml:"domain-controller"`

	Vault            *Vault     `xml:"vault"`
	Deployments      []Deploy   `xml:"deployments>deployment"`
	Extensions       []Module   `xml:"extensions>extension"`
	SystemProperties []Property `xml:"system-properties>property"`
}

// Mode reports the root element of the document: "server", "domain" or "host".
func (d *Document) Mode() string {
	if d == nil {
		return ""
	}
	return d.XMLName.Local
}

// AllProfiles returns the profiles of the document in one list, whichever of
// the two spellings the document uses.
func (d *Document) AllProfiles() []Profile {
	if d == nil {
		return nil
	}
	res := make([]Profile, 0, len(d.Profile)+len(d.Profiles))
	res = append(res, d.Profile...)
	res = append(res, d.Profiles...)
	return res
}

// AllSocketBindingGroups returns the socket binding groups of the document in
// one list, whichever of the two spellings the document uses.
func (d *Document) AllSocketBindingGroups() []SocketBindingGroup {
	if d == nil {
		return nil
	}
	res := make([]SocketBindingGroup, 0, len(d.SocketBindingGroup)+len(d.SocketBindingGroups))
	res = append(res, d.SocketBindingGroup...)
	res = append(res, d.SocketBindingGroups...)
	return res
}

type Module struct {
	Module string `xml:"module,attr"`
}

type Property struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type Deploy struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

type DomainController struct {
	Local  *struct{} `xml:"local"`
	Remote *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"remote"`
}

// Kind reports how the host controller reaches its domain controller:
// "local", "remote", or "" when the element declares neither.
func (d *DomainController) Kind() string {
	switch {
	case d == nil:
		return ""
	case d.Local != nil:
		return "local"
	case d.Remote != nil:
		return "remote"
	default:
		return ""
	}
}

// Management is the <management> section.
type Management struct {
	SecurityRealms []SecurityRealm `xml:"security-realms>security-realm"`
	AuditLog       *AuditLog       `xml:"audit-log"`
	Interfaces     *struct {
		HTTP   *MgmtInterface `xml:"http-interface"`
		Native *MgmtInterface `xml:"native-interface"`
	} `xml:"management-interfaces"`
	AccessControl       *AccessControl `xml:"access-control"`
	OutboundConnections []LDAPOutbound `xml:"outbound-connections>ldap"`
}

// ManagementInterfaces returns the http and native interfaces as a list,
// tagged with their type. The list is empty when <management-interfaces> is
// absent, which is the case for domain.xml.
func (m *Management) ManagementInterfaces() []TypedMgmtInterface {
	res := []TypedMgmtInterface{}
	if m == nil || m.Interfaces == nil {
		return res
	}
	if m.Interfaces.HTTP != nil {
		res = append(res, TypedMgmtInterface{Type: "http", MgmtInterface: *m.Interfaces.HTTP})
	}
	if m.Interfaces.Native != nil {
		res = append(res, TypedMgmtInterface{Type: "native", MgmtInterface: *m.Interfaces.Native})
	}
	return res
}

// AccessControlProvider reports the configured provider. The element is
// optional and its absence means "simple", which is JBoss's own default and
// leaves role based access control off.
func (m *Management) AccessControlProvider() string {
	if m == nil || m.AccessControl == nil {
		return "simple"
	}
	if p := attr(m.AccessControl.Attrs, "provider"); p != "" {
		return p
	}
	return "simple"
}

type AccessControl struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Roles []Role     `xml:"role-mapping>role"`
}

type Role struct {
	Name          string     `xml:"name,attr"`
	IncludeUsers  []NamedRef `xml:"include>user"`
	IncludeGroups []NamedRef `xml:"include>group"`
	ExcludeUsers  []NamedRef `xml:"exclude>user"`
	ExcludeGroups []NamedRef `xml:"exclude>group"`
}

type NamedRef struct {
	Name  string `xml:"name,attr"`
	Realm string `xml:"realm,attr"`
}

// Names returns the @name of each reference, in document order.
func Names(refs []NamedRef) []string {
	res := make([]string, 0, len(refs))
	for i := range refs {
		res = append(res, refs[i].Name)
	}
	return res
}

type LDAPOutbound struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

// MgmtInterface is an <http-interface> or <native-interface>.
//
// The two operating modes spell the endpoint differently: a standalone profile
// names socket bindings, a host controller names an interface and ports. Both
// are captured, and the one the document does not use stays nil.
type MgmtInterface struct {
	Attrs         []xml.Attr `xml:",any,attr"`
	SocketBinding *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"socket-binding"`
	Socket *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"socket"`
}

type TypedMgmtInterface struct {
	Type string
	MgmtInterface
}

func (m *MgmtInterface) SocketBindingAttrs() map[string]string {
	if m == nil || m.SocketBinding == nil {
		return map[string]string{}
	}
	return AttrMap(m.SocketBinding.Attrs)
}

func (m *MgmtInterface) SocketAttrs() map[string]string {
	if m == nil || m.Socket == nil {
		return map[string]string{}
	}
	return AttrMap(m.Socket.Attrs)
}

// SecurityRealm is a <security-realm> element.
type SecurityRealm struct {
	Name             string `xml:"name,attr"`
	ServerIdentities *struct {
		SSL *struct {
			Attrs    []xml.Attr `xml:",any,attr"`
			Keystore *Keystore  `xml:"keystore"`
		} `xml:"ssl"`
		Secret *struct {
			Attrs []xml.Attr `xml:",any,attr"`
		} `xml:"secret"`
	} `xml:"server-identities"`
	Authentication *RealmAuthentication `xml:"authentication"`
	Authorization  *struct {
		Attrs      []xml.Attr  `xml:",any,attr"`
		Properties *Properties `xml:"properties"`
	} `xml:"authorization"`
}

// Identity returns the realm's TLS keystore. JBoss allows the keystore to be
// declared either as attributes on <ssl> itself or on a nested <keystore>
// element, so both are folded into one answer here.
func (r *SecurityRealm) Identity() *Keystore {
	if r == nil || r.ServerIdentities == nil || r.ServerIdentities.SSL == nil {
		return nil
	}
	if ks := r.ServerIdentities.SSL.Keystore; ks != nil {
		return ks
	}
	return &Keystore{Attrs: r.ServerIdentities.SSL.Attrs}
}

func (r *SecurityRealm) HasSecretIdentity() bool {
	return r != nil && r.ServerIdentities != nil && r.ServerIdentities.Secret != nil
}

type RealmAuthentication struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Local *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"local"`
	Properties *Properties `xml:"properties"`
	LDAP       *LDAPAuth   `xml:"ldap"`
	Truststore *Keystore   `xml:"truststore"`
	JAAS       *struct {
		Name string `xml:"name,attr"`
	} `xml:"jaas"`
	Users []InlineUser `xml:"users>user"`
}

// InlineUser is a <user> declared inside a realm's <authentication><users>.
// The schema names it with a username attribute; name is read as well for
// configurations written against it by hand.
type InlineUser struct {
	Username string `xml:"username,attr"`
	Name     string `xml:"name,attr"`
}

// InlineUsernames returns the name of each inline user, in document order.
func InlineUsernames(users []InlineUser) []string {
	res := make([]string, 0, len(users))
	for i := range users {
		name := users[i].Username
		if name == "" {
			name = users[i].Name
		}
		res = append(res, name)
	}
	return res
}

func (a *RealmAuthentication) LocalAttrs() map[string]string {
	if a == nil || a.Local == nil {
		return map[string]string{}
	}
	return AttrMap(a.Local.Attrs)
}

type Properties struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

type LDAPAuth struct {
	Attrs          []xml.Attr `xml:",any,attr"`
	UsernameFilter *struct {
		Attribute string `xml:"attribute,attr"`
	} `xml:"username-filter"`
	AdvancedFilter *struct {
		Filter string `xml:"filter,attr"`
	} `xml:"advanced-filter"`
}

// UsernameAttribute is declared either as an attribute on <ldap> or on a
// nested <username-filter>, depending on the schema version.
func (l *LDAPAuth) UsernameAttribute() string {
	if l == nil {
		return ""
	}
	if l.UsernameFilter != nil && l.UsernameFilter.Attribute != "" {
		return l.UsernameFilter.Attribute
	}
	return attr(l.Attrs, "username-attribute")
}

func (l *LDAPAuth) Filter() string {
	if l == nil || l.AdvancedFilter == nil {
		return ""
	}
	return l.AdvancedFilter.Filter
}

// Keystore is a <keystore> or <truststore> reference.
type Keystore struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

// Path returns the keystore location. Schema versions differ on whether the
// attribute is called `path` or `keystore-path`.
func (k *Keystore) Path() string {
	if k == nil {
		return ""
	}
	if p := attr(k.Attrs, "path"); p != "" {
		return p
	}
	return attr(k.Attrs, "keystore-path")
}

func (k *Keystore) RelativeTo() string {
	if k == nil {
		return ""
	}
	if p := attr(k.Attrs, "relative-to"); p != "" {
		return p
	}
	return attr(k.Attrs, "keystore-relative-to")
}

// PasswordIsVaultExpression reports whether the keystore password is supplied
// through the password vault rather than written into the configuration in the
// clear. The password itself is never returned.
func (k *Keystore) PasswordIsVaultExpression() bool {
	if k == nil {
		return false
	}
	for _, name := range []string{"keystore-password", "password", "key-password"} {
		if v := attr(k.Attrs, name); v != "" {
			return IsVaultExpression(v)
		}
	}
	return false
}

// IsVaultExpression reports whether a configuration value is a reference into
// the password vault, which is how JBoss keeps a secret out of the file.
func IsVaultExpression(value string) bool {
	v := strings.TrimSpace(value)
	return strings.HasPrefix(v, "${VAULT::") && strings.HasSuffix(v, "}")
}

// AuditLog is the <audit-log> section of <management>.
type AuditLog struct {
	Formatters     []AuditFormatter `xml:"formatters>json-formatter"`
	FileHandlers   []AuditHandler   `xml:"handlers>file-handler"`
	SyslogHandlers []AuditHandler   `xml:"handlers>syslog-handler"`
	Logger         *AuditLogger     `xml:"logger"`
	ServerLogger   *AuditLogger     `xml:"server-logger"`
}

// Handlers returns the file and syslog handlers as one list, each tagged with
// its type.
func (a *AuditLog) Handlers() []TypedAuditHandler {
	res := []TypedAuditHandler{}
	if a == nil {
		return res
	}
	for i := range a.FileHandlers {
		res = append(res, TypedAuditHandler{Type: "file", AuditHandler: a.FileHandlers[i]})
	}
	for i := range a.SyslogHandlers {
		res = append(res, TypedAuditHandler{Type: "syslog", AuditHandler: a.SyslogHandlers[i]})
	}
	return res
}

// Enabled reports the master audit switch. The <logger> element is what
// carries it, and its absence means auditing is off.
func (a *AuditLog) Enabled() bool {
	if a == nil || a.Logger == nil {
		return false
	}
	return a.Logger.Enabled()
}

type AuditLogger struct {
	Attrs    []xml.Attr `xml:",any,attr"`
	Handlers []NamedRef `xml:"handlers>handler"`
}

// Enabled reports logger/@enabled. JBoss ships the attribute set to false, and
// treats an absent attribute the same way.
func (l *AuditLogger) Enabled() bool {
	if l == nil {
		return false
	}
	return AttrBool(l.Attrs, "enabled", false)
}

// LogBoot reports logger/@log-boot, which defaults to true.
func (l *AuditLogger) LogBoot() bool {
	if l == nil {
		return false
	}
	return AttrBool(l.Attrs, "log-boot", true)
}

// LogReadOnly reports logger/@log-read-only, which defaults to false — so a
// server that has auditing on still does not record reads unless this is set.
func (l *AuditLogger) LogReadOnly() bool {
	if l == nil {
		return false
	}
	return AttrBool(l.Attrs, "log-read-only", false)
}

type AuditFormatter struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

type AuditHandler struct {
	Attrs []xml.Attr `xml:",any,attr"`
	UDP   *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"udp"`
	TCP *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"tcp"`
	TLS *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"tls"`
}

type TypedAuditHandler struct {
	Type string
	AuditHandler
}

// Transport reports which of the three syslog transports the handler declares,
// and the attributes of that element.
func (h *AuditHandler) Transport() (string, map[string]string) {
	switch {
	case h == nil:
		return "", map[string]string{}
	case h.UDP != nil:
		return "udp", AttrMap(h.UDP.Attrs)
	case h.TCP != nil:
		return "tcp", AttrMap(h.TCP.Attrs)
	case h.TLS != nil:
		return "tls", AttrMap(h.TLS.Attrs)
	default:
		return "", map[string]string{}
	}
}

// Interface is an <interface> element.
type Interface struct {
	Name        string `xml:"name,attr"`
	InetAddress *struct {
		Value string `xml:"value,attr"`
	} `xml:"inet-address"`
	AnyAddress *struct{} `xml:"any-address"`
	Rest       []struct {
		XMLName xml.Name
	} `xml:",any"`
}

func (i *Interface) Address() string {
	if i == nil || i.InetAddress == nil {
		return ""
	}
	return i.InetAddress.Value
}

func (i *Interface) IsAnyAddress() bool {
	return i != nil && i.AnyAddress != nil
}

// Criteria returns the names of the selection elements the interface declares
// beyond <inet-address> and <any-address>, e.g. "nic", "loopback" or
// "public-address". Those two have fields of their own, so encoding/xml does
// not route them into Rest.
func (i *Interface) Criteria() []string {
	res := []string{}
	if i == nil {
		return res
	}
	for _, child := range i.Rest {
		res = append(res, child.XMLName.Local)
	}
	return res
}

// SocketBindingGroup is a <socket-binding-group> element.
type SocketBindingGroup struct {
	Attrs          []xml.Attr      `xml:",any,attr"`
	SocketBindings []SocketBinding `xml:"socket-binding"`
	Outbound       []SocketBinding `xml:"outbound-socket-binding"`
	RemoteOutbound []SocketBinding `xml:"remote-destination-outbound-socket-binding"`
	LocalOutbound  []SocketBinding `xml:"local-destination-outbound-socket-binding"`
}

// OutboundBindings returns every outbound binding of the group, whichever of
// the three element names declares it.
func (g *SocketBindingGroup) OutboundBindings() []SocketBinding {
	res := []SocketBinding{}
	if g == nil {
		return res
	}
	res = append(res, g.Outbound...)
	res = append(res, g.RemoteOutbound...)
	res = append(res, g.LocalOutbound...)
	return res
}

type SocketBinding struct {
	Attrs             []xml.Attr `xml:",any,attr"`
	RemoteDestination *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"remote-destination"`
	LocalDestination *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"local-destination"`
}

func (b *SocketBinding) RemoteAttrs() map[string]string {
	if b == nil || b.RemoteDestination == nil {
		return map[string]string{}
	}
	return AttrMap(b.RemoteDestination.Attrs)
}

func (b *SocketBinding) LocalRef() string {
	if b == nil || b.LocalDestination == nil {
		return ""
	}
	return attr(b.LocalDestination.Attrs, "socket-binding-ref")
}

type ServerGroup struct {
	Attrs             []xml.Attr `xml:",any,attr"`
	SocketBindingElem *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"socket-binding-group"`
}

func (g *ServerGroup) SocketBindingAttrs() map[string]string {
	if g == nil || g.SocketBindingElem == nil {
		return map[string]string{}
	}
	return AttrMap(g.SocketBindingElem.Attrs)
}

type HostServer struct {
	Attrs          []xml.Attr `xml:",any,attr"`
	SocketBindings *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"socket-bindings"`
}

// Vault is the <vault> element, which holds the configuration of the password
// vault rather than any secret from it.
type Vault struct {
	Attrs   []xml.Attr    `xml:",any,attr"`
	Options []VaultOption `xml:"vault-option"`
}

type VaultOption struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func (v *Vault) OptionMap() map[string]string {
	res := map[string]string{}
	if v == nil {
		return res
	}
	for i := range v.Options {
		res[v.Options[i].Name] = v.Options[i].Value
	}
	return res
}

// Profile is a <profile> element and the subsystems it declares.
type Profile struct {
	Name       string      `xml:"name,attr"`
	Subsystems []Subsystem `xml:"subsystem"`
}

// Subsystem keeps both the identity of a subsystem and its unparsed body, so
// that the subsystems this package types can be decoded a second time without
// re-reading the document, and the ones it does not remain listed.
type Subsystem struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	InnerXML []byte     `xml:",innerxml"`
}

// Namespace returns the subsystem's XML namespace. It is carried on the
// element as an xmlns attribute, which encoding/xml resolves onto XMLName.
func (s *Subsystem) Namespace() string {
	if s == nil {
		return ""
	}
	return s.XMLName.Space
}

// Name returns the short subsystem name, e.g. "deployment-scanner" for
// urn:jboss:domain:deployment-scanner:1.1.
func (s *Subsystem) Name() string {
	name, _ := splitNamespace(s.Namespace())
	return name
}

// Version returns the schema version of the subsystem namespace, e.g. "1.1".
func (s *Subsystem) Version() string {
	_, version := splitNamespace(s.Namespace())
	return version
}

// splitNamespace pulls the subsystem name and schema version out of a
// urn:jboss:domain:<name>:<version> namespace. Both parts are optional: some
// subsystems carry no version, and a namespace that does not follow the
// convention is returned whole as the name.
func splitNamespace(ns string) (string, string) {
	const prefix = "urn:jboss:domain:"
	if !strings.HasPrefix(ns, prefix) {
		return ns, ""
	}
	rest := strings.TrimPrefix(ns, prefix)
	idx := strings.LastIndex(rest, ":")
	if idx < 0 {
		return rest, ""
	}
	version := rest[idx+1:]
	// Only a trailing numeric component is a version. A name that itself
	// contains a colon and no version must not lose its last segment.
	if version == "" || strings.IndexFunc(version, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	}) >= 0 {
		return rest, ""
	}
	return rest[:idx], version
}

// Body re-wraps the subsystem's inner XML so it can be unmarshalled into a
// typed structure. The children lose their namespace prefix in the process,
// which encoding/xml does not mind: a struct tag without a namespace matches
// on the local name.
func (s *Subsystem) Body() []byte {
	if s == nil {
		return nil
	}
	res := make([]byte, 0, len(s.InnerXML)+24)
	res = append(res, "<subsystem>"...)
	res = append(res, s.InnerXML...)
	res = append(res, "</subsystem>"...)
	return res
}

// Logging is the urn:jboss:domain:logging subsystem.
type Logging struct {
	RootLogger *struct {
		Level *struct {
			Name string `xml:"name,attr"`
		} `xml:"level"`
		Handlers []NamedRef `xml:"handlers>handler"`
	} `xml:"root-logger"`
	Console      []LogHandler `xml:"console-handler"`
	File         []LogHandler `xml:"file-handler"`
	Periodic     []LogHandler `xml:"periodic-rotating-file-handler"`
	Size         []LogHandler `xml:"size-rotating-file-handler"`
	PeriodicSize []LogHandler `xml:"periodic-size-rotating-file-handler"`
	Syslog       []LogHandler `xml:"syslog-handler"`
	Async        []LogHandler `xml:"async-handler"`
	Custom       []LogHandler `xml:"custom-handler"`
	Loggers      []Logger     `xml:"logger"`
}

// Handlers returns every handler of the subsystem, each tagged with the
// element name that declared it.
func (l *Logging) Handlers() []TypedLogHandler {
	res := []TypedLogHandler{}
	if l == nil {
		return res
	}
	add := func(kind string, handlers []LogHandler) {
		for i := range handlers {
			res = append(res, TypedLogHandler{Type: kind, LogHandler: handlers[i]})
		}
	}
	add("console-handler", l.Console)
	add("file-handler", l.File)
	add("periodic-rotating-file-handler", l.Periodic)
	add("size-rotating-file-handler", l.Size)
	add("periodic-size-rotating-file-handler", l.PeriodicSize)
	add("syslog-handler", l.Syslog)
	add("async-handler", l.Async)
	add("custom-handler", l.Custom)
	return res
}

func (l *Logging) RootLevel() string {
	if l == nil || l.RootLogger == nil || l.RootLogger.Level == nil {
		return ""
	}
	return l.RootLogger.Level.Name
}

func (l *Logging) RootHandlers() []string {
	if l == nil || l.RootLogger == nil {
		return []string{}
	}
	return Names(l.RootLogger.Handlers)
}

type LogHandler struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Level *struct {
		Name string `xml:"name,attr"`
	} `xml:"level"`
	File *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"file"`
	Suffix         *ValueElement `xml:"suffix"`
	Append         *ValueElement `xml:"append"`
	RotateSize     *ValueElement `xml:"rotate-size"`
	MaxBackupIndex *ValueElement `xml:"max-backup-index"`
	ServerAddress  *ValueElement `xml:"server-address"`
	Port           *ValueElement `xml:"port"`
	AppName        *ValueElement `xml:"app-name"`
	Formatter      *struct {
		Named *struct {
			Name string `xml:"name,attr"`
		} `xml:"named-formatter"`
		Pattern *struct {
			Pattern string `xml:"pattern,attr"`
		} `xml:"pattern-formatter"`
	} `xml:"formatter"`
}

type TypedLogHandler struct {
	Type string
	LogHandler
}

type ValueElement struct {
	Value string `xml:"value,attr"`
}

func (v *ValueElement) Get() string {
	if v == nil {
		return ""
	}
	return v.Value
}

func (h *LogHandler) LevelName() string {
	if h == nil || h.Level == nil {
		return ""
	}
	return h.Level.Name
}

func (h *LogHandler) FileAttrs() map[string]string {
	if h == nil || h.File == nil {
		return map[string]string{}
	}
	return AttrMap(h.File.Attrs)
}

// FormatterName returns the named formatter the handler renders through, or
// the inline pattern when the handler declares one instead.
func (h *LogHandler) FormatterName() string {
	if h == nil || h.Formatter == nil {
		return ""
	}
	if h.Formatter.Named != nil {
		return h.Formatter.Named.Name
	}
	if h.Formatter.Pattern != nil {
		return h.Formatter.Pattern.Pattern
	}
	return ""
}

// MaxBackup returns max-backup-index/@value, defaulting to JBoss's own 1.
func (h *LogHandler) MaxBackup() int64 {
	if h == nil || h.MaxBackupIndex == nil {
		return 1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(h.MaxBackupIndex.Value), 10, 64)
	if err != nil {
		return 1
	}
	return n
}

// Appends returns append/@value, defaulting to JBoss's own true.
func (h *LogHandler) Appends() bool {
	if h == nil || h.Append == nil {
		return true
	}
	return parseBool(h.Append.Value, true)
}

type Logger struct {
	Category string     `xml:"category,attr"`
	Attrs    []xml.Attr `xml:",any,attr"`
	Level    *struct {
		Name string `xml:"name,attr"`
	} `xml:"level"`
	Handlers []NamedRef `xml:"handlers>handler"`
}

func (l *Logger) LevelName() string {
	if l == nil || l.Level == nil {
		return ""
	}
	return l.Level.Name
}

// Web is the urn:jboss:domain:web subsystem, the servlet container of JBoss
// AS 7 and EAP 6.
type Web struct {
	Attrs          []xml.Attr      `xml:",any,attr"`
	Connectors     []Connector     `xml:"connector"`
	VirtualServers []VirtualServer `xml:"virtual-server"`
}

type Connector struct {
	Attrs []xml.Attr `xml:",any,attr"`
	SSL   *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"ssl"`
}

func (c *Connector) SSLEnabled() bool {
	return c != nil && c.SSL != nil
}

func (c *Connector) SSLAttrs() map[string]string {
	if c == nil || c.SSL == nil {
		return map[string]string{}
	}
	return AttrMap(c.SSL.Attrs)
}

type VirtualServer struct {
	Attrs     []xml.Attr `xml:",any,attr"`
	Aliases   []NamedRef `xml:"alias"`
	AccessLog *struct {
		Attrs     []xml.Attr `xml:",any,attr"`
		Directory *struct {
			Attrs []xml.Attr `xml:",any,attr"`
		} `xml:"directory"`
	} `xml:"access-log"`
}

func (v *VirtualServer) AccessLogEnabled() bool {
	return v != nil && v.AccessLog != nil
}

func (v *VirtualServer) AccessLogPattern() string {
	if v == nil || v.AccessLog == nil {
		return ""
	}
	return attr(v.AccessLog.Attrs, "pattern")
}

func (v *VirtualServer) AccessLogDirectory() string {
	if v == nil || v.AccessLog == nil || v.AccessLog.Directory == nil {
		return ""
	}
	return attr(v.AccessLog.Directory.Attrs, "path")
}

// JMX is the urn:jboss:domain:jmx subsystem.
type JMX struct {
	RemotingConnector *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"remoting-connector"`
	ExposeResolvedModel   *struct{} `xml:"expose-resolved-model"`
	ExposeExpressionModel *struct{} `xml:"expose-expression-model"`
	Sensitivity           *struct {
		Attrs []xml.Attr `xml:",any,attr"`
	} `xml:"sensitivity"`
}

// RemotingConnectorEnabled reports whether the MBean server is reachable by
// remote clients. The element carries no attribute of its own in the shipped
// configuration — its mere presence is what exposes JMX.
func (j *JMX) RemotingConnectorEnabled() bool {
	return j != nil && j.RemotingConnector != nil
}

func (j *JMX) UseManagementEndpoint() bool {
	if j == nil || j.RemotingConnector == nil {
		return true
	}
	return AttrBool(j.RemotingConnector.Attrs, "use-management-endpoint", true)
}

func (j *JMX) NonCoreMbeansSensitive() bool {
	if j == nil || j.Sensitivity == nil {
		return false
	}
	return AttrBool(j.Sensitivity.Attrs, "non-core-mbeans", false)
}

// DeploymentScanners is the urn:jboss:domain:deployment-scanner subsystem.
type DeploymentScanners struct {
	Scanners []DeploymentScanner `xml:"deployment-scanner"`
}

type DeploymentScanner struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

// ParseDocument parses a JBoss server configuration document.
func ParseDocument(data []byte) (*Document, error) {
	doc := &Document{}
	if err := xml.Unmarshal(data, doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// ParseLogging decodes the logging subsystem out of a subsystem element.
func ParseLogging(s *Subsystem) (*Logging, error) {
	res := &Logging{}
	if err := xml.Unmarshal(s.Body(), res); err != nil {
		return nil, err
	}
	return res, nil
}

// ParseWeb decodes the web subsystem out of a subsystem element.
func ParseWeb(s *Subsystem) (*Web, error) {
	res := &Web{}
	if err := xml.Unmarshal(s.Body(), res); err != nil {
		return nil, err
	}
	// Assigned after unmarshalling, not before: the re-wrapped body carries the
	// wrapper's own (empty) attribute list, which would overwrite these.
	res.Attrs = s.Attrs
	return res, nil
}

// ParseJMX decodes the jmx subsystem out of a subsystem element.
func ParseJMX(s *Subsystem) (*JMX, error) {
	res := &JMX{}
	if err := xml.Unmarshal(s.Body(), res); err != nil {
		return nil, err
	}
	return res, nil
}

// ParseDeploymentScanners decodes the deployment-scanner subsystem out of a
// subsystem element.
func ParseDeploymentScanners(s *Subsystem) (*DeploymentScanners, error) {
	res := &DeploymentScanners{}
	if err := xml.Unmarshal(s.Body(), res); err != nil {
		return nil, err
	}
	return res, nil
}

// AttrMap turns an attribute list into a map, verbatim and unexpanded.
func AttrMap(attrs []xml.Attr) map[string]string {
	res := make(map[string]string, len(attrs))
	for _, a := range attrs {
		res[a.Name.Local] = a.Value
	}
	return res
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Attr returns a single attribute value, or the empty string when the
// attribute is not declared.
func Attr(attrs []xml.Attr, name string) string {
	return attr(attrs, name)
}

// AttrBool reads a boolean attribute, falling back to JBoss's documented
// default for that attribute when it is absent.
//
// A value the server resolves at boot — `${env.AUDIT_ENABLED:false}` and the
// like — is not a boolean here and also falls back to the default. The raw
// text stays available through the params map, so a check that cares can tell
// the two apart.
func AttrBool(attrs []xml.Attr, name string, fallback bool) bool {
	v := attr(attrs, name)
	if v == "" {
		return fallback
	}
	return parseBool(v, fallback)
}

// AttrInt reads a numeric attribute, falling back to JBoss's documented
// default for that attribute when it is absent or not a number.
func AttrInt(attrs []xml.Attr, name string, fallback int64) int64 {
	v := strings.TrimSpace(attr(attrs, name))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func parseBool(value string, fallback bool) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return b
}
