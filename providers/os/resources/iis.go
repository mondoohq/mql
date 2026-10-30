// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
)

// iisServerConfigPath is the IIS configuration path of the server scope, the
// point every site inherits from.
const iisServerConfigPath = "MACHINE/WEBROOT/APPHOST"

type mqlIisInternal struct {
	lock sync.Mutex
	// collected records that the collection has run. data and collectErr hold
	// its outcome and are only meaningful once it is set.
	collected  bool
	data       *windows.IisData
	collectErr error
	// pools holds the application pool resources by name so a site or an
	// application resolves its pool out of the list that was already built,
	// rather than creating a second copy of one that is already modeled.
	pools     map[string]*mqlIisAppPool
	poolOrder []any
}

// mqlIisSiteInternal carries what a site needs to resolve its application pool:
// the parent resource that owns the pool list, and the pool's name.
type mqlIisSiteInternal struct {
	parent   *mqlIis
	poolName string
}

type mqlIisApplicationInternal struct {
	parent   *mqlIis
	poolName string
}

func (i *mqlIis) id() (string, error) {
	return "iis", nil
}

// collect runs the collection script once and caches its outcome. Every field of
// every resource below iis comes out of this one run, so a scan spawns a single
// PowerShell process however many settings it reads.
//
// A failure is cached alongside the data and handed to every later caller. It
// has to be: the fields do not share a cache entry, so an error reported only to
// whichever field happened to run first would leave the rest reading an empty
// result, which is indistinguishable from a host that does not run IIS. That
// turns an unreachable or locked-down server into a clean report on which every
// IIS check passes.
func (i *mqlIis) collect() (*windows.IisData, error) {
	i.lock.Lock()
	defer i.lock.Unlock()
	if i.collected {
		return i.data, i.collectErr
	}

	i.data, i.collectErr = i.runCollection()
	i.collected = true
	return i.data, i.collectErr
}

// runCollection does the work behind collect. It is separate so that collect
// records the outcome of every return path, including the error ones.
func (i *mqlIis) runCollection() (*windows.IisData, error) {
	empty := &windows.IisData{Sites: []windows.IisSite{}, AppPools: []windows.IisAppPool{}}

	conn, ok := i.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return empty, nil
	}

	// IIS only exists on Windows. Reporting "not installed" rather than failing
	// keeps a mixed-platform scan from erroring on every non-Windows asset.
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil || !asset.Platform.IsFamily("windows") {
		return empty, nil
	}

	// A Windows asset reached over a connection that cannot run commands (a
	// mounted volume, a disk image, a container filesystem) passes the check
	// above and then cannot be read at all. Refuse before staging rather than
	// after, for two reasons. Staging writes the script through the mounted
	// filesystem, so a literal `C:\Windows\Temp\iis-<hash>.ps1` would be
	// created in the mount root, and Remove needs the same capability to clean
	// it up, so it would be left behind. And an error is the honest answer:
	// reporting installed=false would state that the host does not run IIS,
	// which is a fact this connection cannot establish, and every check
	// asserting IIS is absent would pass on it.
	if !powershell.CanStage(conn) {
		return nil, errors.New("iis cannot be read over this connection: it requires running a PowerShell script, which this connection type does not support")
	}

	// The collection script is far too long to travel on a command line:
	// 18,545 characters, 49,554 once Encode has widened it to UTF-16 and base64
	// encoded it, against a ceiling of about 32k over SSH and 8,191 over WinRM.
	// Passed as an encoded command it is rejected by the target before
	// PowerShell runs, and the non-zero exit with empty stdout reads as "IIS is
	// not installed" rather than as an error — so it fails on every real host,
	// quietly. Staging it as a file and running it with `-File` removes the
	// ceiling; see powershell.Stage for why the path is a client-side literal
	// and why it is named by content hash.
	staged, err := powershell.Stage(conn, "iis", windows.IIS_CONFIGURATION)
	if err != nil {
		return nil, err
	}
	// On the error path too: a scan that dies between the write and the run
	// would otherwise leave the file behind.
	defer staged.Remove()

	// Run through the command resource rather than the connection directly, so
	// the call goes through the provider's execution path and is visible to
	// recording and replay like any other command.
	o, err := CreateResource(i.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(staged.Command),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)

	exitcode := cmd.GetExitcode()
	if exitcode.Error != nil {
		return nil, exitcode.Error
	}
	if exitcode.Data != 0 {
		stderr := cmd.GetStderr()
		message := ""
		if stderr.Error == nil {
			message = strings.TrimSpace(stderr.Data)
		}
		return nil, errors.New("failed to read IIS configuration: " + message)
	}

	stdout := cmd.GetStdout()
	if stdout.Error != nil {
		return nil, stdout.Error
	}

	return windows.ParseIisData(strings.NewReader(stdout.Data))
}

func (i *mqlIis) installed() (bool, error) {
	data, err := i.collect()
	if err != nil {
		return false, err
	}
	return data.Installed, nil
}

func (i *mqlIis) version() (string, error) {
	data, err := i.collect()
	if err != nil {
		return "", err
	}
	return data.Version, nil
}

func (i *mqlIis) applicationHost() (*mqlFile, error) {
	data, err := i.collect()
	if err != nil {
		return nil, err
	}
	if !data.Installed || data.ApplicationHostPath == "" {
		i.ApplicationHost.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	f, err := CreateResource(i.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(data.ApplicationHostPath),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (i *mqlIis) config() (*mqlIisConfiguration, error) {
	data, err := i.collect()
	if err != nil {
		return nil, err
	}
	if !data.Installed {
		i.Config.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return i.newConfiguration(iisServerConfigPath, data.Config)
}

func (i *mqlIis) appPools() ([]any, error) {
	if err := i.buildPools(); err != nil {
		return nil, err
	}
	i.lock.Lock()
	defer i.lock.Unlock()
	return i.poolOrder, nil
}

// buildPools creates the application pool resources once, so the list accessor
// and every site and application that points at a pool share one instance.
func (i *mqlIis) buildPools() error {
	data, err := i.collect()
	if err != nil {
		return err
	}

	i.lock.Lock()
	defer i.lock.Unlock()
	if i.pools != nil {
		return nil
	}

	i.pools = map[string]*mqlIisAppPool{}
	i.poolOrder = []any{}
	for idx := range data.AppPools {
		pool := data.AppPools[idx]
		resource, err := CreateResource(i.MqlRuntime, "iis.appPool", map[string]*llx.RawData{
			"__id":                           llx.StringData("iis.appPool/" + pool.Name),
			"name":                           llx.StringData(pool.Name),
			"state":                          llx.StringData(pool.State),
			"autoStart":                      llx.BoolData(pool.AutoStart),
			"startMode":                      llx.StringData(pool.StartMode),
			"managedRuntimeVersion":          llx.StringData(pool.ManagedRuntimeVersion),
			"managedPipelineMode":            llx.StringData(pool.ManagedPipelineMode),
			"enable32BitAppOnWin64":          llx.BoolData(pool.Enable32BitAppOnWin64),
			"queueLength":                    llx.IntData(pool.QueueLength),
			"identityType":                   llx.StringData(pool.IdentityType),
			"userName":                       llx.StringData(pool.UserName),
			"idleTimeout":                    llx.IntData(pool.IdleTimeout),
			"maxProcesses":                   llx.IntData(pool.MaxProcesses),
			"pingingEnabled":                 llx.BoolData(pool.PingingEnabled),
			"loadUserProfile":                llx.BoolData(pool.LoadUserProfile),
			"periodicRestartTime":            llx.IntData(pool.PeriodicRestartTime),
			"periodicRestartRequests":        llx.IntData(pool.PeriodicRestartRequests),
			"periodicRestartPrivateMemory":   llx.IntData(pool.PeriodicRestartPrivateMemory),
			"periodicRestartMemory":          llx.IntData(pool.PeriodicRestartMemory),
			"periodicRestartSchedule":        llx.ArrayData(convert.SliceAnyToInterface(pool.PeriodicRestartSchedule), types.Int),
			"logEventOnRecycle":              llx.StringData(pool.LogEventOnRecycle),
			"disallowRotationOnConfigChange": llx.BoolData(pool.DisallowRotationOnConfigChange),
			"disallowOverlappingRotation":    llx.BoolData(pool.DisallowOverlappingRotation),
			"rapidFailProtection":            llx.BoolData(pool.RapidFailProtection),
			"rapidFailProtectionInterval":    llx.IntData(pool.RapidFailProtectionInterval),
			"rapidFailProtectionMaxCrashes":  llx.IntData(pool.RapidFailProtectionMaxCrashes),
		})
		if err != nil {
			return err
		}
		mqlPool := resource.(*mqlIisAppPool)
		i.pools[pool.Name] = mqlPool
		i.poolOrder = append(i.poolOrder, mqlPool)
	}
	return nil
}

// lookupPool resolves a pool name against the list already built. A name that
// no pool answers to is reported as null rather than as an empty pool, so a
// site pointing at a pool that no longer exists is visible instead of looking
// like a pool with default settings.
func (i *mqlIis) lookupPool(name string) (*mqlIisAppPool, error) {
	if name == "" {
		return nil, nil
	}
	if err := i.buildPools(); err != nil {
		return nil, err
	}
	i.lock.Lock()
	defer i.lock.Unlock()
	return i.pools[name], nil
}

func (i *mqlIis) sites() ([]any, error) {
	data, err := i.collect()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(data.Sites))
	for idx := range data.Sites {
		site := data.Sites[idx]

		siteConfigPath := iisServerConfigPath + "/" + site.Name
		siteConfig, err := i.newConfiguration(siteConfigPath, site.Config)
		if err != nil {
			return nil, err
		}

		bindings := make([]any, 0, len(site.Bindings))
		for _, binding := range site.Bindings {
			resource, err := CreateResource(i.MqlRuntime, "iis.binding", map[string]*llx.RawData{
				"__id":                 llx.StringData("iis.binding/" + site.Name + "/" + binding.Protocol + "/" + binding.BindingInformation),
				"protocol":             llx.StringData(binding.Protocol),
				"bindingInformation":   llx.StringData(binding.BindingInformation),
				"hostName":             llx.StringData(binding.HostName),
				"port":                 llx.IntData(binding.Port),
				"ipAddress":            llx.StringData(binding.IPAddress),
				"certificateHash":      llx.StringData(binding.CertificateHash),
				"certificateStoreName": llx.StringData(binding.CertificateStoreName),
				"sslFlags":             llx.IntData(binding.SslFlags),
			})
			if err != nil {
				return nil, err
			}
			bindings = append(bindings, resource)
		}

		applications := make([]any, 0, len(site.Applications))
		for _, application := range site.Applications {
			// The root application resolves at the same configuration path as
			// the site, so it shares the site's configuration resource instead
			// of resolving and storing a second identical copy.
			applicationConfig := siteConfig
			if application.Path != "/" {
				applicationConfig, err = i.newConfiguration(siteConfigPath+application.Path, application.Config)
				if err != nil {
					return nil, err
				}
			}

			virtualDirectories := make([]any, 0, len(application.VirtualDirectories))
			for _, directory := range application.VirtualDirectories {
				resource, err := CreateResource(i.MqlRuntime, "iis.virtualDirectory", map[string]*llx.RawData{
					"__id":         llx.StringData("iis.virtualDirectory/" + site.Name + application.Path + "#" + directory.Path),
					"path":         llx.StringData(directory.Path),
					"physicalPath": llx.StringData(directory.PhysicalPath),
					"userName":     llx.StringData(directory.UserName),
					"logonMethod":  llx.StringData(directory.LogonMethod),
				})
				if err != nil {
					return nil, err
				}
				virtualDirectories = append(virtualDirectories, resource)
			}

			resource, err := CreateResource(i.MqlRuntime, "iis.application", map[string]*llx.RawData{
				"__id":               llx.StringData("iis.application/" + site.Name + application.Path),
				"path":               llx.StringData(application.Path),
				"physicalPath":       llx.StringData(application.PhysicalPath),
				"enabledProtocols":   llx.StringData(application.EnabledProtocols),
				"virtualDirectories": llx.ArrayData(virtualDirectories, types.Resource("iis.virtualDirectory")),
				"config":             llx.ResourceData(applicationConfig, "iis.configuration"),
			})
			if err != nil {
				return nil, err
			}
			mqlApplication := resource.(*mqlIisApplication)
			mqlApplication.parent = i
			mqlApplication.poolName = application.ApplicationPool
			applications = append(applications, mqlApplication)
		}

		resource, err := CreateResource(i.MqlRuntime, "iis.site", map[string]*llx.RawData{
			"__id":                 llx.StringData("iis.site/" + site.Name),
			"name":                 llx.StringData(site.Name),
			"id":                   llx.IntData(site.ID),
			"state":                llx.StringData(site.State),
			"physicalPath":         llx.StringData(site.PhysicalPath),
			"serverAutoStart":      llx.BoolData(site.ServerAutoStart),
			"bindings":             llx.ArrayData(bindings, types.Resource("iis.binding")),
			"applications":         llx.ArrayData(applications, types.Resource("iis.application")),
			"logEnabled":           llx.BoolData(site.LogEnabled),
			"logDirectory":         llx.StringData(site.LogDirectory),
			"logFormat":            llx.StringData(site.LogFormat),
			"logPeriod":            llx.StringData(site.LogPeriod),
			"logTruncateSize":      llx.IntData(site.LogTruncateSize),
			"logFields":            llx.StringData(site.LogFields),
			"logTarget":            llx.StringData(site.LogTarget),
			"logLocalTimeRollover": llx.BoolData(site.LogLocalTimeRollover),
			"hsts":                 llx.DictData(site.Hsts),
			"config":               llx.ResourceData(siteConfig, "iis.configuration"),
		})
		if err != nil {
			return nil, err
		}
		mqlSite := resource.(*mqlIisSite)
		mqlSite.parent = i
		mqlSite.poolName = site.ApplicationPool
		res = append(res, mqlSite)
	}
	return res, nil
}

// newConfiguration turns one resolved section map into a typed configuration
// resource. Fields whose section is not declared at the scope stay null.
func (i *mqlIis) newConfiguration(path string, sections map[string]any) (*mqlIisConfiguration, error) {
	parsed := windows.ParseIisConfiguration(sections)

	args := map[string]*llx.RawData{
		"__id":          llx.StringData("iis.configuration/" + path),
		"path":          llx.StringData(path),
		"sslFlags":      llx.ArrayData(convert.SliceAnyToInterface(parsed.SslFlags), types.String),
		"customHeaders": llx.MapData(convert.MapToInterfaceMap(parsed.CustomHeaders), types.String),
		"sections":      llx.DictData(iisSectionsToDict(sections)),

		"directoryBrowsingEnabled":                         llx.BoolDataPtr(parsed.DirectoryBrowsingEnabled),
		"anonymousAuthenticationEnabled":                   llx.BoolDataPtr(parsed.AnonymousAuthenticationEnabled),
		"anonymousAuthenticationUser":                      llx.StringDataPtr(parsed.AnonymousAuthenticationUser),
		"basicAuthenticationEnabled":                       llx.BoolDataPtr(parsed.BasicAuthenticationEnabled),
		"digestAuthenticationEnabled":                      llx.BoolDataPtr(parsed.DigestAuthenticationEnabled),
		"windowsAuthenticationEnabled":                     llx.BoolDataPtr(parsed.WindowsAuthenticationEnabled),
		"clientCertificateMappingAuthenticationEnabled":    llx.BoolDataPtr(parsed.ClientCertMappingEnabled),
		"iisClientCertificateMappingAuthenticationEnabled": llx.BoolDataPtr(parsed.IisClientCertMappingEnabled),

		"authenticationMode":             llx.StringDataPtr(parsed.AuthenticationMode),
		"formsRequireSsl":                llx.BoolDataPtr(parsed.FormsRequireSsl),
		"formsCookieless":                llx.StringDataPtr(parsed.FormsCookieless),
		"formsProtection":                llx.StringDataPtr(parsed.FormsProtection),
		"formsTimeout":                   llx.IntDataPtr(parsed.FormsTimeout),
		"formsCredentialsPasswordFormat": llx.StringDataPtr(parsed.FormsCredentialsPasswordFormat),
		"formsCredentialsDeclared":       llx.BoolDataPtr(parsed.FormsCredentialsDeclared),

		"maxAllowedContentLength":     llx.IntDataPtr(parsed.MaxAllowedContentLength),
		"maxUrl":                      llx.IntDataPtr(parsed.MaxUrl),
		"maxQueryString":              llx.IntDataPtr(parsed.MaxQueryString),
		"allowHighBitCharacters":      llx.BoolDataPtr(parsed.AllowHighBitCharacters),
		"allowDoubleEscaping":         llx.BoolDataPtr(parsed.AllowDoubleEscaping),
		"allowUnlistedFileExtensions": llx.BoolDataPtr(parsed.AllowUnlistedFileExtensions),
		"removeServerHeader":          llx.BoolDataPtr(parsed.RemoveServerHeader),

		"handlerAccessPolicy":    llx.StringDataPtr(parsed.HandlerAccessPolicy),
		"notListedIsapisAllowed": llx.BoolDataPtr(parsed.NotListedIsapisAllowed),
		"notListedCgisAllowed":   llx.BoolDataPtr(parsed.NotListedCgisAllowed),

		"compilationDebug":       llx.BoolDataPtr(parsed.CompilationDebug),
		"customErrorsMode":       llx.StringDataPtr(parsed.CustomErrorsMode),
		"httpErrorsMode":         llx.StringDataPtr(parsed.HttpErrorsMode),
		"traceEnabled":           llx.BoolDataPtr(parsed.TraceEnabled),
		"deploymentRetail":       llx.BoolDataPtr(parsed.DeploymentRetail),
		"trustLevel":             llx.StringDataPtr(parsed.TrustLevel),
		"machineKeyValidation":   llx.StringDataPtr(parsed.MachineKeyValidation),
		"sessionStateMode":       llx.StringDataPtr(parsed.SessionStateMode),
		"sessionStateCookieless": llx.StringDataPtr(parsed.SessionStateCookieless),
		"sessionStateTimeout":    llx.IntDataPtr(parsed.SessionStateTimeout),
		"httpCookiesHttpOnly":    llx.BoolDataPtr(parsed.HttpCookiesHttpOnly),
		"httpCookiesRequireSsl":  llx.BoolDataPtr(parsed.HttpCookiesRequireSsl),
		"aspKeepSessionIdSecure": llx.BoolDataPtr(parsed.AspKeepSessionIdSecure),
	}

	resource, err := CreateResource(i.MqlRuntime, "iis.configuration", args)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlIisConfiguration), nil
}

// iisSectionsToDict hands the resolved sections through as a dict. An absent map
// becomes an empty one so the field is never null on an installed host.
func iisSectionsToDict(sections map[string]any) any {
	if sections == nil {
		return map[string]any{}
	}
	return sections
}

func (s *mqlIisSite) appPool() (*mqlIisAppPool, error) {
	if s.parent == nil {
		s.AppPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pool, err := s.parent.lookupPool(s.poolName)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		s.AppPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pool, nil
}

func (a *mqlIisApplication) appPool() (*mqlIisAppPool, error) {
	if a.parent == nil {
		a.AppPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	pool, err := a.parent.lookupPool(a.poolName)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		a.AppPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return pool, nil
}
