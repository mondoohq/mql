// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	_ "embed"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

// IIS_CONFIGURATION collects the whole IIS configuration in a single run. It
// reads through the IIS management assembly, which resolves a value down the
// machine.config, root web.config, applicationHost.config, location, site and
// application chain the same way the server does when it serves a request.
// Parsing applicationHost.config instead would report what that one file
// declares, which is a different answer whenever a site or an application
// overrides it.
//
//go:embed iis.ps1
var IIS_CONFIGURATION string

// Configuration section paths the script resolves. Kept here so a caller can
// name a section without repeating the string, and so the parser and the script
// cannot drift apart silently.
const (
	IisSectionAnonymousAuthentication = "system.webServer/security/authentication/anonymousAuthentication"
	IisSectionBasicAuthentication     = "system.webServer/security/authentication/basicAuthentication"
	IisSectionDigestAuthentication    = "system.webServer/security/authentication/digestAuthentication"
	IisSectionWindowsAuthentication   = "system.webServer/security/authentication/windowsAuthentication"
	IisSectionClientCertMapping       = "system.webServer/security/authentication/clientCertificateMappingAuthentication"
	IisSectionIisClientCertMapping    = "system.webServer/security/authentication/iisClientCertificateMappingAuthentication"
	IisSectionAccess                  = "system.webServer/security/access"
	IisSectionRequestFiltering        = "system.webServer/security/requestFiltering"
	IisSectionIsapiCgiRestriction     = "system.webServer/security/isapiCgiRestriction"
	IisSectionDirectoryBrowse         = "system.webServer/directoryBrowse"
	IisSectionHandlers                = "system.webServer/handlers"
	IisSectionHttpErrors              = "system.webServer/httpErrors"
	IisSectionHttpProtocol            = "system.webServer/httpProtocol"
	IisSectionAsp                     = "system.webServer/asp"
	IisSectionDotNetAuthentication    = "system.web/authentication"
	IisSectionCompilation             = "system.web/compilation"
	IisSectionCustomErrors            = "system.web/customErrors"
	IisSectionDeployment              = "system.web/deployment"
	IisSectionHttpCookies             = "system.web/httpCookies"
	IisSectionMachineKey              = "system.web/machineKey"
	IisSectionSessionState            = "system.web/sessionState"
	IisSectionTrace                   = "system.web/trace"
	IisSectionTrust                   = "system.web/trust"

	// Server scope only: applicationPoolDefaults, which every pool inherits.
	IisSectionApplicationPools = "system.applicationHost/applicationPools"
)

// IisData is the whole result of one collection run.
type IisData struct {
	Installed           bool           `json:"installed"`
	Version             string         `json:"version"`
	ApplicationHostPath string         `json:"applicationHostPath"`
	Config              map[string]any `json:"config"`
	Sites               []IisSite      `json:"sites"`
	AppPools            []IisAppPool   `json:"appPools"`
}

// IisSite is one website and everything reachable from it.
type IisSite struct {
	ID                   int64            `json:"id"`
	Name                 string           `json:"name"`
	State                string           `json:"state"`
	PhysicalPath         string           `json:"physicalPath"`
	ApplicationPool      string           `json:"applicationPool"`
	ServerAutoStart      bool             `json:"serverAutoStart"`
	LogEnabled           bool             `json:"logEnabled"`
	LogDirectory         string           `json:"logDirectory"`
	LogFormat            string           `json:"logFormat"`
	LogPeriod            string           `json:"logPeriod"`
	LogTruncateSize      int64            `json:"logTruncateSize"`
	LogFields            string           `json:"logFields"`
	LogTarget            string           `json:"logTarget"`
	LogLocalTimeRollover bool             `json:"logLocalTimeRollover"`
	Hsts                 map[string]any   `json:"hsts"`
	Bindings             []IisBinding     `json:"bindings"`
	Applications         []IisApplication `json:"applications"`
	Config               map[string]any   `json:"config"`
}

// IisApplication is one application mounted under a site.
type IisApplication struct {
	Path               string          `json:"path"`
	PhysicalPath       string          `json:"physicalPath"`
	ApplicationPool    string          `json:"applicationPool"`
	EnabledProtocols   string          `json:"enabledProtocols"`
	VirtualDirectories []IisVirtualDir `json:"virtualDirectories"`
	Config             map[string]any  `json:"config"`
}

// IisVirtualDir is one virtual directory of an application.
type IisVirtualDir struct {
	Path         string `json:"path"`
	PhysicalPath string `json:"physicalPath"`
	UserName     string `json:"userName"`
	LogonMethod  string `json:"logonMethod"`
}

// IisBinding is one address, port and protocol a site answers on.
type IisBinding struct {
	Protocol             string `json:"protocol"`
	BindingInformation   string `json:"bindingInformation"`
	HostName             string `json:"hostName"`
	Port                 int64  `json:"port"`
	IPAddress            string `json:"ipAddress"`
	CertificateHash      string `json:"certificateHash"`
	CertificateStoreName string `json:"certificateStoreName"`
	SslFlags             int64  `json:"sslFlags"`
}

// IisAppPool is one application pool.
type IisAppPool struct {
	Name                           string  `json:"name"`
	State                          string  `json:"state"`
	AutoStart                      bool    `json:"autoStart"`
	StartMode                      string  `json:"startMode"`
	ManagedRuntimeVersion          string  `json:"managedRuntimeVersion"`
	ManagedPipelineMode            string  `json:"managedPipelineMode"`
	Enable32BitAppOnWin64          bool    `json:"enable32BitAppOnWin64"`
	QueueLength                    int64   `json:"queueLength"`
	IdentityType                   string  `json:"identityType"`
	UserName                       string  `json:"userName"`
	IdleTimeout                    int64   `json:"idleTimeout"`
	MaxProcesses                   int64   `json:"maxProcesses"`
	PingingEnabled                 bool    `json:"pingingEnabled"`
	LoadUserProfile                bool    `json:"loadUserProfile"`
	PeriodicRestartTime            int64   `json:"periodicRestartTime"`
	PeriodicRestartRequests        int64   `json:"periodicRestartRequests"`
	PeriodicRestartPrivateMemory   int64   `json:"periodicRestartPrivateMemory"`
	PeriodicRestartMemory          int64   `json:"periodicRestartMemory"`
	PeriodicRestartSchedule        []int64 `json:"periodicRestartSchedule"`
	LogEventOnRecycle              string  `json:"logEventOnRecycle"`
	DisallowRotationOnConfigChange bool    `json:"disallowRotationOnConfigChange"`
	DisallowOverlappingRotation    bool    `json:"disallowOverlappingRotation"`
	RapidFailProtection            bool    `json:"rapidFailProtection"`
	RapidFailProtectionInterval    int64   `json:"rapidFailProtectionInterval"`
	RapidFailProtectionMaxCrashes  int64   `json:"rapidFailProtectionMaxCrashes"`
}

// ParseIisData decodes the collection script's output. Empty output means the
// command produced nothing, which is reported as "not installed" rather than as
// an error, so a host that does not run IIS answers instead of failing.
func ParseIisData(r io.Reader) (*IisData, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &IisData{}, nil
	}

	var res IisData
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	if res.Sites == nil {
		res.Sites = []IisSite{}
	}
	if res.AppPools == nil {
		res.AppPools = []IisAppPool{}
	}
	return &res, nil
}

// IisConfiguration is the typed view of one resolved configuration scope. Every
// field is a pointer, so a section that is not declared at the scope reports
// null rather than a zero value that reads as a real setting.
type IisConfiguration struct {
	DirectoryBrowsingEnabled *bool

	AnonymousAuthenticationEnabled *bool
	AnonymousAuthenticationUser    *string
	BasicAuthenticationEnabled     *bool
	DigestAuthenticationEnabled    *bool
	WindowsAuthenticationEnabled   *bool
	ClientCertMappingEnabled       *bool
	IisClientCertMappingEnabled    *bool

	AuthenticationMode             *string
	FormsRequireSsl                *bool
	FormsCookieless                *string
	FormsProtection                *string
	FormsTimeout                   *int64
	FormsCredentialsPasswordFormat *string
	FormsCredentialsDeclared       *bool

	SslFlags []string

	MaxAllowedContentLength     *int64
	MaxUrl                      *int64
	MaxQueryString              *int64
	AllowHighBitCharacters      *bool
	AllowDoubleEscaping         *bool
	AllowUnlistedFileExtensions *bool
	RemoveServerHeader          *bool

	HandlerAccessPolicy    *string
	NotListedIsapisAllowed *bool
	NotListedCgisAllowed   *bool

	CompilationDebug       *bool
	CustomErrorsMode       *string
	HttpErrorsMode         *string
	TraceEnabled           *bool
	DeploymentRetail       *bool
	TrustLevel             *string
	MachineKeyValidation   *string
	SessionStateMode       *string
	SessionStateCookieless *string
	SessionStateTimeout    *int64
	HttpCookiesHttpOnly    *bool
	HttpCookiesRequireSsl  *bool
	AspKeepSessionIdSecure *bool

	CustomHeaders map[string]string
}

// ParseIisConfiguration pulls the typed fields out of a resolved section map.
// A section the scope does not declare leaves its fields nil.
func ParseIisConfiguration(sections map[string]any) *IisConfiguration {
	c := &IisConfiguration{CustomHeaders: map[string]string{}}
	if sections == nil {
		return c
	}

	c.DirectoryBrowsingEnabled = iisBool(sections, IisSectionDirectoryBrowse, "enabled")

	c.AnonymousAuthenticationEnabled = iisBool(sections, IisSectionAnonymousAuthentication, "enabled")
	c.AnonymousAuthenticationUser = iisString(sections, IisSectionAnonymousAuthentication, "userName")
	c.BasicAuthenticationEnabled = iisBool(sections, IisSectionBasicAuthentication, "enabled")
	c.DigestAuthenticationEnabled = iisBool(sections, IisSectionDigestAuthentication, "enabled")
	c.WindowsAuthenticationEnabled = iisBool(sections, IisSectionWindowsAuthentication, "enabled")
	c.ClientCertMappingEnabled = iisBool(sections, IisSectionClientCertMapping, "enabled")
	c.IisClientCertMappingEnabled = iisBool(sections, IisSectionIisClientCertMapping, "enabled")

	c.AuthenticationMode = iisString(sections, IisSectionDotNetAuthentication, "mode")
	c.FormsRequireSsl = iisBool(sections, IisSectionDotNetAuthentication, "forms", "requireSSL")
	c.FormsCookieless = iisString(sections, IisSectionDotNetAuthentication, "forms", "cookieless")
	c.FormsProtection = iisString(sections, IisSectionDotNetAuthentication, "forms", "protection")
	c.FormsTimeout = iisInt(sections, IisSectionDotNetAuthentication, "forms", "timeout")
	c.FormsCredentialsPasswordFormat = iisString(sections, IisSectionDotNetAuthentication, "forms", "credentials", "passwordFormat")
	if credentials, ok := iisElement(sections, IisSectionDotNetAuthentication, "forms", "credentials"); ok {
		declared := len(iisCollection(credentials)) > 0
		c.FormsCredentialsDeclared = &declared
	}

	c.SslFlags = ParseIisSslFlags(iisValue(sections, IisSectionAccess, "sslFlags"))

	c.MaxAllowedContentLength = iisInt(sections, IisSectionRequestFiltering, "requestLimits", "maxAllowedContentLength")
	c.MaxUrl = iisInt(sections, IisSectionRequestFiltering, "requestLimits", "maxUrl")
	c.MaxQueryString = iisInt(sections, IisSectionRequestFiltering, "requestLimits", "maxQueryString")
	c.AllowHighBitCharacters = iisBool(sections, IisSectionRequestFiltering, "allowHighBitCharacters")
	c.AllowDoubleEscaping = iisBool(sections, IisSectionRequestFiltering, "allowDoubleEscaping")
	c.AllowUnlistedFileExtensions = iisBool(sections, IisSectionRequestFiltering, "fileExtensions", "allowUnlisted")
	c.RemoveServerHeader = iisBool(sections, IisSectionRequestFiltering, "removeServerHeader")

	c.HandlerAccessPolicy = iisString(sections, IisSectionHandlers, "accessPolicy")
	c.NotListedIsapisAllowed = iisBool(sections, IisSectionIsapiCgiRestriction, "notListedIsapisAllowed")
	c.NotListedCgisAllowed = iisBool(sections, IisSectionIsapiCgiRestriction, "notListedCgisAllowed")

	c.CompilationDebug = iisBool(sections, IisSectionCompilation, "debug")
	c.CustomErrorsMode = iisString(sections, IisSectionCustomErrors, "mode")
	c.HttpErrorsMode = iisString(sections, IisSectionHttpErrors, "errorMode")
	c.TraceEnabled = iisBool(sections, IisSectionTrace, "enabled")
	c.DeploymentRetail = iisBool(sections, IisSectionDeployment, "retail")
	c.TrustLevel = iisString(sections, IisSectionTrust, "level")
	c.MachineKeyValidation = iisString(sections, IisSectionMachineKey, "validation")
	c.SessionStateMode = iisString(sections, IisSectionSessionState, "mode")
	c.SessionStateCookieless = iisString(sections, IisSectionSessionState, "cookieless")
	c.SessionStateTimeout = iisInt(sections, IisSectionSessionState, "timeout")
	c.HttpCookiesHttpOnly = iisBool(sections, IisSectionHttpCookies, "httpOnlyCookies")
	c.HttpCookiesRequireSsl = iisBool(sections, IisSectionHttpCookies, "requireSSL")
	c.AspKeepSessionIdSecure = iisBool(sections, IisSectionAsp, "session", "keepSessionIdSecure")

	if headers, ok := iisElement(sections, IisSectionHttpProtocol, "customHeaders"); ok {
		for _, entry := range iisCollection(headers) {
			name, ok := entry["name"].(string)
			if !ok || name == "" {
				continue
			}
			value, _ := entry["value"].(string)
			c.CustomHeaders[name] = value
		}
	}

	return c
}

// iisSslFlagBits maps the bits of the access section's sslFlags attribute. IIS
// reports the attribute as a number on some installations and as the flag names
// on others, so both forms are accepted.
var iisSslFlagBits = []struct {
	bit  int64
	name string
}{
	{8, "Ssl"},
	{32, "SslNegotiateCert"},
	{64, "SslRequireCert"},
	{128, "SslMapCert"},
	{256, "Ssl128"},
}

// ParseIisSslFlags turns the sslFlags attribute into the flag names it sets. An
// absent attribute and an attribute set to none both yield an empty list, which
// is the state that means requests are accepted over plain HTTP.
func ParseIisSslFlags(v any) []string {
	if v == nil {
		return []string{}
	}

	if s, ok := v.(string); ok {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" || strings.EqualFold(trimmed, "None") {
			return []string{}
		}
		// A numeric string is still a bit field.
		if n, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return iisSslFlagNames(n)
		}
		res := []string{}
		for part := range strings.SplitSeq(trimmed, ",") {
			part = strings.TrimSpace(part)
			if part == "" || strings.EqualFold(part, "None") {
				continue
			}
			res = append(res, part)
		}
		sort.Strings(res)
		return res
	}

	if n, ok := iisToInt(v); ok {
		return iisSslFlagNames(n)
	}
	return []string{}
}

func iisSslFlagNames(n int64) []string {
	res := []string{}
	var named int64
	for _, flag := range iisSslFlagBits {
		if n&flag.bit != 0 {
			res = append(res, flag.name)
			named |= flag.bit
		}
	}
	// A bit this table does not name is kept rather than dropped: dropping it
	// would report a stricter transport requirement than the one actually
	// configured. Kept one entry per bit, not as the combined remainder, so
	// that every element of the list is a single flag whichever branch produced
	// it. The named branch above already yields one name per element, and a
	// caller testing for a specific unnamed bit can compare against it
	// directly instead of decomposing a sum. (ConvertTo-AttributeValue in
	// iis.ps1 appends the combined remainder instead, but it is building one
	// joined string rather than a list.)
	if residue := n & ^named; residue > 0 {
		for i := range 63 {
			bit := int64(1) << i
			if residue&bit != 0 {
				res = append(res, strconv.FormatInt(bit, 10))
			}
		}
	}
	sort.Strings(res)
	return res
}

// iisElement walks a section and its child elements. The final path segment
// names the child element to return.
func iisElement(sections map[string]any, section string, path ...string) (map[string]any, bool) {
	current, ok := sections[section].(map[string]any)
	if !ok {
		return nil, false
	}
	for _, segment := range path {
		next, ok := current[segment].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

// iisCollection returns the members of an element whose collection carries the
// setting, and an empty slice for an element that has none.
func iisCollection(element map[string]any) []map[string]any {
	raw, ok := element["collection"].([]any)
	if !ok {
		return nil
	}
	res := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if entry, ok := item.(map[string]any); ok {
			res = append(res, entry)
		}
	}
	return res
}

// iisValue reads one attribute. The last element of path is the attribute name
// and anything before it names child elements to descend through.
func iisValue(sections map[string]any, section string, path ...string) any {
	if len(path) == 0 {
		return nil
	}
	element, ok := iisElement(sections, section, path[:len(path)-1]...)
	if !ok {
		return nil
	}
	return element[path[len(path)-1]]
}

func iisBool(sections map[string]any, section string, path ...string) *bool {
	v := iisValue(sections, section, path...)
	switch value := v.(type) {
	case bool:
		return &value
	case string:
		if parsed, err := strconv.ParseBool(value); err == nil {
			return &parsed
		}
	}
	return nil
}

func iisString(sections map[string]any, section string, path ...string) *string {
	v := iisValue(sections, section, path...)
	switch value := v.(type) {
	case string:
		return &value
	case bool:
		s := strconv.FormatBool(value)
		return &s
	case float64:
		s := strconv.FormatInt(int64(value), 10)
		return &s
	}
	return nil
}

func iisInt(sections map[string]any, section string, path ...string) *int64 {
	if n, ok := iisToInt(iisValue(sections, section, path...)); ok {
		return &n
	}
	return nil
}

func iisToInt(v any) (int64, bool) {
	switch value := v.(type) {
	case float64:
		return int64(value), true
	case int64:
		return value, true
	case int:
		return int64(value), true
	case json.Number:
		if n, err := value.Int64(); err == nil {
			return n, true
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}
