// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/stmcginnis/gofish/oem/smc"
	"github.com/stmcginnis/gofish/schemas"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/redfish/connection"
	"go.mondoo.com/mql/types"
)

func redfishConn(runtime *plugin.Runtime) *connection.RedfishConnection {
	return runtime.Connection.(*connection.RedfishConnection)
}

// uintPtrToAny converts an optional *uint into a dict-friendly value.
func uintPtrToAny(p *uint) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func (r *mqlRedfish) id() (string, error) {
	return "redfish", nil
}

func (r *mqlRedfish) systems() ([]any, error) {
	systems, err := redfishConn(r.MqlRuntime).Systems()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(systems))
	for _, s := range systems {
		overrideEnabled := string(s.Boot.BootSourceOverrideEnabled)
		overrideTarget := string(s.Boot.BootSourceOverrideTarget)

		o, err := CreateResource(r.MqlRuntime, "redfish.system", map[string]*llx.RawData{
			"__id":                      llx.StringData(s.ODataID),
			"uuid":                      llx.StringData(s.UUID),
			"name":                      llx.StringData(s.Name),
			"manufacturer":              llx.StringData(s.Manufacturer),
			"model":                     llx.StringData(s.Model),
			"serialNumber":              llx.StringData(s.SerialNumber),
			"sku":                       llx.StringData(s.SKU),
			"biosVersion":               llx.StringData(s.BiosVersion),
			"hostName":                  llx.StringData(s.HostName),
			"powerState":                llx.StringData(string(s.PowerState)),
			"systemType":                llx.StringData(string(s.SystemType)),
			"bootSourceOverrideEnabled": llx.StringData(overrideEnabled),
			"bootSourceOverrideTarget":  llx.StringData(overrideTarget),
			"bootSourceOverrideMode":    llx.StringData(string(s.Boot.BootSourceOverrideMode)),
			"persistentBootOverride":    llx.BoolData(isPersistentBootOverride(overrideEnabled, overrideTarget)),
			"trustedModules":            llx.ArrayData(trustedModuleDicts(s.TrustedModules), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlSystem := o.(*mqlRedfishSystem)
		mqlSystem.sys = s
		res = append(res, mqlSystem)
	}
	return res, nil
}

func (r *mqlRedfish) managers() ([]any, error) {
	managers, err := redfishConn(r.MqlRuntime).Managers()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(managers))
	for _, m := range managers {
		// The console services are decoded from the manager document the
		// provider already holds, because gofish types their ServiceEnabled as
		// a plain bool: that reports a console the controller never described
		// as one that is switched off.
		consoles := parseManagerConsoles(m.RawData)

		o, err := CreateResource(r.MqlRuntime, "redfish.manager", map[string]*llx.RawData{
			"__id":            llx.StringData(m.ODataID),
			"uuid":            llx.StringData(m.UUID),
			"manufacturer":    llx.StringData(m.Manufacturer),
			"model":           llx.StringData(m.Model),
			"firmwareVersion": llx.StringData(m.FirmwareVersion),
			"managerType":     llx.StringData(string(m.ManagerType)),
			"powerState":      llx.StringData(string(m.PowerState)),
			"dateTime":        llx.StringData(m.DateTime),

			"commandShellEnabled":                   llx.BoolDataPtr(consoleEnabled(consoles.CommandShell)),
			"commandShellMaxConcurrentSessions":     llx.IntDataPtr(consoleMaxSessions(consoles.CommandShell)),
			"commandShellConnectTypes":              consoleConnectTypes(consoles.CommandShell),
			"graphicalConsoleEnabled":               llx.BoolDataPtr(consoleEnabled(consoles.GraphicalConsole)),
			"graphicalConsoleMaxConcurrentSessions": llx.IntDataPtr(consoleMaxSessions(consoles.GraphicalConsole)),
			"graphicalConsoleConnectTypes":          consoleConnectTypes(consoles.GraphicalConsole),
			"serialConsoleEnabled":                  llx.BoolDataPtr(consoleEnabled(consoles.SerialConsole)),
			"serialConsoleMaxConcurrentSessions":    llx.IntDataPtr(consoleMaxSessions(consoles.SerialConsole)),
			"serialConsoleConnectTypes":             consoleConnectTypes(consoles.SerialConsole),
		})
		if err != nil {
			return nil, err
		}
		mqlManager := o.(*mqlRedfishManager)
		mqlManager.mgr = m
		res = append(res, mqlManager)
	}
	return res, nil
}

func (r *mqlRedfish) chassis() ([]any, error) {
	svc := redfishConn(r.MqlRuntime).Client().Service
	chassis, err := svc.Chassis()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(chassis))
	for _, c := range chassis {
		o, err := CreateResource(r.MqlRuntime, "redfish.chassisEnclosure", map[string]*llx.RawData{
			"__id":         llx.StringData(c.ODataID),
			"name":         llx.StringData(c.Name),
			"chassisType":  llx.StringData(string(c.ChassisType)),
			"manufacturer": llx.StringData(c.Manufacturer),
			"model":        llx.StringData(c.Model),
			"serialNumber": llx.StringData(c.SerialNumber),
			"sku":          llx.StringData(c.SKU),
			"powerState":   llx.StringData(string(c.PowerState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlRedfish) accounts() ([]any, error) {
	accountService, err := redfishConn(r.MqlRuntime).AccountService()
	if err != nil {
		return nil, err
	}
	if accountService == nil {
		return []any{}, nil
	}
	accounts, err := accountService.Accounts()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(accounts))
	for _, a := range accounts {
		accountTypes := make([]any, 0, len(a.AccountTypes))
		for _, t := range a.AccountTypes {
			accountTypes = append(accountTypes, string(t))
		}

		// The optional properties are decoded from the account document the
		// provider already holds, because gofish types them as plain values:
		// that reports an account on a controller which never mentioned a
		// pending password change as one with no change pending.
		flags := parseAccountFlags(a.RawData)

		o, err := CreateResource(r.MqlRuntime, "redfish.account", map[string]*llx.RawData{
			"__id":                   llx.StringData(a.ODataID),
			"userName":               llx.StringData(a.UserName),
			"roleId":                 llx.StringData(a.RoleID),
			"enabled":                llx.BoolData(a.Enabled),
			"locked":                 llx.BoolData(a.Locked),
			"accountTypes":           llx.ArrayData(accountTypes, types.String),
			"defaultVendorAccount":   llx.BoolData(isDefaultVendorAccountName(a.UserName)),
			"passwordChangeRequired": llx.BoolDataPtr(flags.PasswordChangeRequired),
			"strictAccountTypes":     llx.BoolDataPtr(flags.StrictAccountTypes),
			"passwordExpiration":     llx.TimeDataPtr(parseRedfishTime(flags.PasswordExpiration)),
			"accountExpiration":      llx.TimeDataPtr(parseRedfishTime(flags.AccountExpiration)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlRedfish) firmware() ([]any, error) {
	svc := redfishConn(r.MqlRuntime).Client().Service
	updateService, err := svc.UpdateService()
	if err != nil {
		return nil, err
	}
	inventory, err := updateService.FirmwareInventory()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(inventory))
	for _, sw := range inventory {
		o, err := CreateResource(r.MqlRuntime, "redfish.softwareInventory", map[string]*llx.RawData{
			"__id":                   llx.StringData(sw.ODataID),
			"name":                   llx.StringData(sw.Name),
			"version":                llx.StringData(sw.Version),
			"manufacturer":           llx.StringData(sw.Manufacturer),
			"softwareId":             llx.StringData(sw.SoftwareID),
			"updateable":             llx.BoolData(sw.Updateable),
			"releaseDate":            llx.StringData(sw.ReleaseDate),
			"lowestSupportedVersion": llx.StringData(sw.LowestSupportedVersion),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

// trustedModuleDicts maps the trusted modules of a system. A value the
// controller leaves out is written as null rather than as an empty string, so
// an audit does not read a withheld interface type as a reported one.
func trustedModuleDicts(modules []schemas.TrustedModules) []any {
	res := make([]any, 0, len(modules))
	for _, m := range modules {
		res = append(res, map[string]any{
			"interfaceType":          emptyStringToNil(string(m.InterfaceType)),
			"interfaceTypeSelection": emptyStringToNil(string(m.InterfaceTypeSelection)),
			"firmwareVersion":        emptyStringToNil(m.FirmwareVersion),
			"firmwareVersion2":       emptyStringToNil(m.FirmwareVersion2),
			"health":                 emptyStringToNil(string(m.Status.Health)),
			"state":                  emptyStringToNil(string(m.Status.State)),
		})
	}
	return res
}

// emptyStringToNil maps an empty string to a null dict value, so a property the
// controller withheld stays distinguishable from one it reported as empty.
func emptyStringToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// mqlRedfishSystemInternal caches the source system so sub-collections can be
// resolved without re-fetching the parent, and the Secure Boot resource, which
// three fields read.
type mqlRedfishSystemInternal struct {
	sys *schemas.ComputerSystem

	secureBootOnce   sync.Once
	secureBoot       *schemas.SecureBoot
	secureBootLoaded bool
}

// loadSecureBoot fetches the Secure Boot resource of the system once. loaded
// stays false when the system exposes none or the controller cannot report it,
// so every field reading it resolves to null rather than to Secure Boot being
// switched off.
func (r *mqlRedfishSystem) loadSecureBoot() (*schemas.SecureBoot, bool) {
	r.secureBootOnce.Do(func() {
		if r.sys == nil {
			return
		}
		sb, err := r.sys.SecureBoot()
		if err != nil || sb == nil {
			log.Debug().Err(err).Msg("redfish: system serves no secure boot resource")
			return
		}
		r.secureBoot = sb
		r.secureBootLoaded = true
	})
	return r.secureBoot, r.secureBootLoaded
}

// secureBootEnabled reports whether UEFI Secure Boot is enabled. It is null
// when the system exposes no Secure Boot resource or the controller cannot
// report its state, so an unsupported or unreachable system is not conflated
// with one where Secure Boot is switched off.
func (r *mqlRedfishSystem) secureBootEnabled() (bool, error) {
	sb, ok := r.loadSecureBoot()
	if !ok {
		r.SecureBootEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return sb.SecureBootEnable, nil
}

// secureBootMode reports the Secure Boot key management mode. SetupMode is the
// state in which the firmware enrolls any key presented to it, so a system can
// report Secure Boot as enabled and still accept an attacker supplied platform
// key.
func (r *mqlRedfishSystem) secureBootMode() (string, error) {
	sb, ok := r.loadSecureBoot()
	if !ok || sb.SecureBootMode == "" {
		r.SecureBootMode.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(sb.SecureBootMode), nil
}

// secureBootCurrentBoot reports what the firmware enforced on the boot that is
// running, which differs from the configured state when the setting changed
// since the last reset.
func (r *mqlRedfishSystem) secureBootCurrentBoot() (string, error) {
	sb, ok := r.loadSecureBoot()
	if !ok || sb.SecureBootCurrentBoot == "" {
		r.SecureBootCurrentBoot.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(sb.SecureBootCurrentBoot), nil
}

func (r *mqlRedfishSystem) processors() ([]any, error) {
	if r.sys == nil {
		return nil, errors.New("redfish.system is missing its source system reference")
	}
	processors, err := r.sys.Processors()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(processors))
	for _, p := range processors {
		o, err := CreateResource(r.MqlRuntime, "redfish.processor", map[string]*llx.RawData{
			"__id":           llx.StringData(p.ODataID),
			"manufacturer":   llx.StringData(p.Manufacturer),
			"model":          llx.StringData(p.Model),
			"processorType":  llx.StringData(string(p.ProcessorType)),
			"instructionSet": llx.StringData(string(p.InstructionSet)),
			"socket":         llx.StringData(p.Socket),
			"totalCores":     llx.IntDataPtr(p.TotalCores),
			"totalThreads":   llx.IntDataPtr(p.TotalThreads),
			"maxSpeedMHz":    llx.IntDataPtr(p.MaxSpeedMHz),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlRedfishSystem) memory() ([]any, error) {
	if r.sys == nil {
		return nil, errors.New("redfish.system is missing its source system reference")
	}
	memory, err := r.sys.Memory()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(memory))
	for _, m := range memory {
		o, err := CreateResource(r.MqlRuntime, "redfish.memory", map[string]*llx.RawData{
			"__id":              llx.StringData(m.ODataID),
			"capacityMiB":       llx.IntDataPtr(m.CapacityMiB),
			"memoryDeviceType":  llx.StringData(string(m.MemoryDeviceType)),
			"operatingSpeedMhz": llx.IntDataPtr(m.OperatingSpeedMhz),
			"manufacturer":      llx.StringData(m.Manufacturer),
			"partNumber":        llx.StringData(m.PartNumber),
			"serialNumber":      llx.StringData(m.SerialNumber),
			"rankCount":         llx.IntDataPtr(m.RankCount),
			"dataWidthBits":     llx.IntDataPtr(m.DataWidthBits),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlRedfishSystem) ethernetInterfaces() ([]any, error) {
	if r.sys == nil {
		return nil, errors.New("redfish.system is missing its source system reference")
	}
	interfaces, err := r.sys.EthernetInterfaces()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(interfaces))
	for _, eth := range interfaces {
		o, err := CreateResource(r.MqlRuntime, "redfish.ethernetInterface", map[string]*llx.RawData{
			"__id":                llx.StringData(eth.ODataID),
			"macAddress":          llx.StringData(eth.MACAddress),
			"permanentMACAddress": llx.StringData(eth.PermanentMACAddress),
			"speedMbps":           llx.IntDataPtr(eth.SpeedMbps),
			"fullDuplex":          llx.BoolData(eth.FullDuplex),
			"linkStatus":          llx.StringData(string(eth.LinkStatus)),
			"interfaceEnabled":    llx.BoolData(eth.InterfaceEnabled),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

// mqlRedfishManagerInternal caches the source manager for computed fields.
type mqlRedfishManagerInternal struct {
	mgr *schemas.Manager
}

func (r *mqlRedfishManager) networkProtocol() (any, error) {
	if r.mgr == nil {
		r.NetworkProtocol.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	np, err := r.mgr.NetworkProtocol()
	if err != nil {
		return nil, err
	}
	if np == nil {
		r.NetworkProtocol.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	result := map[string]any{
		"hostName": np.HostName,
		"fqdn":     np.FQDN,
		"http":     map[string]any{"enabled": np.HTTP.ProtocolEnabled, "port": uintPtrToAny(np.HTTP.Port)},
		"https":    map[string]any{"enabled": np.HTTPS.ProtocolEnabled, "port": uintPtrToAny(np.HTTPS.Port)},
		"ssh":      map[string]any{"enabled": np.SSH.ProtocolEnabled, "port": uintPtrToAny(np.SSH.Port)},
		"ipmi":     map[string]any{"enabled": np.IPMI.ProtocolEnabled, "port": uintPtrToAny(np.IPMI.Port)},
		"snmp":     map[string]any{"enabled": np.SNMP.ProtocolEnabled, "port": uintPtrToAny(np.SNMP.Port)},
		"kvmip":    map[string]any{"enabled": np.KVMIP.ProtocolEnabled, "port": uintPtrToAny(np.KVMIP.Port)},
		"virtualMedia": map[string]any{
			"enabled": np.VirtualMedia.ProtocolEnabled,
			"port":    uintPtrToAny(np.VirtualMedia.Port),
		},
	}
	return result, nil
}

// hpeManagerOem is the subset of the HPE manager OEM block we surface. Older
// iLO firmware nests data under "Hp" rather than "Hpe".
type hpeManagerOem struct {
	Hpe *hpeLicenseWrap `json:"Hpe"`
	Hp  *hpeLicenseWrap `json:"Hp"`
}

type hpeLicenseWrap struct {
	License struct {
		LicenseType   string `json:"LicenseType"`
		LicenseString string `json:"LicenseString"`
	} `json:"License"`
}

// parseHpeManagerLicense extracts the iLO license from a manager's OEM block.
// Older iLO firmware nests the data under "Hp" rather than "Hpe"; found is
// false when the block is empty, unparseable, or carries no HPE license.
func parseHpeManagerLicense(raw json.RawMessage) (licenseType, licenseLabel string, found bool) {
	if len(raw) == 0 {
		return "", "", false
	}
	var oem hpeManagerOem
	if err := json.Unmarshal(raw, &oem); err != nil {
		log.Debug().Err(err).Msg("redfish: could not parse HPE manager OEM block")
		return "", "", false
	}
	wrap := oem.Hpe
	if wrap == nil {
		wrap = oem.Hp
	}
	if wrap == nil {
		return "", "", false
	}
	return wrap.License.LicenseType, wrap.License.LicenseString, true
}

// mqlRedfishHpeInternal caches the parsed HPE OEM license data.
type mqlRedfishHpeInternal struct {
	once               sync.Once
	cachedLicenseType  string
	cachedLicenseLabel string
}

func (r *mqlRedfishHpe) id() (string, error) {
	return "redfish.hpe", nil
}

func (r *mqlRedfishHpe) load() {
	r.once.Do(func() {
		managers, err := redfishConn(r.MqlRuntime).Managers()
		if err != nil {
			log.Warn().Err(err).Msg("redfish: could not list managers for HPE OEM detection")
			return
		}
		for _, m := range managers {
			licenseType, licenseLabel, found := parseHpeManagerLicense(m.OEM)
			if !found {
				continue
			}
			r.cachedLicenseType = licenseType
			r.cachedLicenseLabel = licenseLabel
			return
		}
	})
}

func (r *mqlRedfishHpe) licenseType() (string, error) {
	r.load()
	return r.cachedLicenseType, nil
}

func (r *mqlRedfishHpe) licenseLabel() (string, error) {
	r.load()
	return r.cachedLicenseLabel, nil
}

// dellSystemOem is the subset of the Dell system OEM block we surface.
type dellSystemOem struct {
	Dell struct {
		DellSystem struct {
			SystemGeneration string `json:"SystemGeneration"`
			SystemID         int64  `json:"SystemID"`
			BIOSReleaseDate  string `json:"BIOSReleaseDate"`
		} `json:"DellSystem"`
	} `json:"Dell"`
}

// parseDellSystemOem extracts the Dell system data from a system's OEM block.
// found is false when the block is empty, unparseable, or carries no Dell
// system generation or numeric ID (the fields that identify Dell hardware).
func parseDellSystemOem(raw json.RawMessage) (generation string, systemID int64, biosReleaseDate string, found bool) {
	if len(raw) == 0 {
		return "", 0, "", false
	}
	var oem dellSystemOem
	if err := json.Unmarshal(raw, &oem); err != nil {
		log.Debug().Err(err).Msg("redfish: could not parse Dell system OEM block")
		return "", 0, "", false
	}
	d := oem.Dell.DellSystem
	if d.SystemGeneration == "" && d.SystemID == 0 {
		return "", 0, "", false
	}
	return d.SystemGeneration, d.SystemID, d.BIOSReleaseDate, true
}

// mqlRedfishDellInternal caches the parsed Dell OEM system data.
type mqlRedfishDellInternal struct {
	once                  sync.Once
	cachedGeneration      string
	cachedSystemID        int64
	cachedBiosReleaseDate string
}

func (r *mqlRedfishDell) id() (string, error) {
	return "redfish.dell", nil
}

func (r *mqlRedfishDell) load() {
	r.once.Do(func() {
		systems, err := redfishConn(r.MqlRuntime).Systems()
		if err != nil {
			log.Warn().Err(err).Msg("redfish: could not list systems for Dell OEM detection")
			return
		}
		for _, s := range systems {
			generation, systemID, biosReleaseDate, found := parseDellSystemOem(s.OEM)
			if !found {
				continue
			}
			r.cachedGeneration = generation
			r.cachedSystemID = systemID
			r.cachedBiosReleaseDate = biosReleaseDate
			return
		}
	})
}

func (r *mqlRedfishDell) generation() (string, error) {
	r.load()
	return r.cachedGeneration, nil
}

func (r *mqlRedfishDell) systemID() (int64, error) {
	r.load()
	return r.cachedSystemID, nil
}

func (r *mqlRedfishDell) biosReleaseDate() (string, error) {
	r.load()
	return r.cachedBiosReleaseDate, nil
}

// smcDocument memoizes one Supermicro OEM document across the managers that
// might serve it. loaded stays false when no manager serves the document, so a
// field reading it can resolve to null rather than to a setting that is
// switched off.
type smcDocument[T any] struct {
	once   sync.Once
	loaded bool
	value  *T
}

// get returns the document, fetching it from the first manager that serves it.
// A manager that is not Supermicro hardware, or that omits the link, fails the
// fetch and is skipped rather than ending the search: license data and the
// hardening settings can sit on different managers of the same server.
func (d *smcDocument[T]) get(managers []*smc.Manager, fetch func(*smc.Manager) (*T, error)) (*T, bool) {
	d.once.Do(func() {
		for _, m := range managers {
			v, err := fetch(m)
			if err != nil || v == nil {
				continue
			}
			d.value = v
			d.loaded = true
			return
		}
	})
	return d.value, d.loaded
}

// mqlRedfishSupermicroInternal caches the Supermicro OEM data, which lives in
// linked sub-resources (license manager, system lockdown, RAKP, KCS, IP access
// control, RADIUS, NTP, syslog) rather than inline in the manager's OEM block.
// Each document is fetched only by the fields that read it, so querying one
// setting does not pull the rest.
type mqlRedfishSupermicroInternal struct {
	managersOnce sync.Once
	managers     []*smc.Manager

	licenseDoc  smcDocument[smc.QueryLicense]
	lockdownDoc smcDocument[smc.SysLockdown]
	rakpDoc     smcDocument[smc.SMCRAKP]
	kcsDoc      smcDocument[smc.KCSInterface]
	ipAccessDoc smcDocument[smc.IPAccessControl]
	radiusDoc   smcDocument[smc.RADIUS]
	ntpDoc      smcDocument[smc.NTP]
	syslogDoc   smcDocument[smc.Syslog]
}

func (r *mqlRedfishSupermicro) id() (string, error) {
	return "redfish.supermicro", nil
}

// smcManagers returns the management controllers as Supermicro OEM managers.
// FromManager succeeds on any controller, leaving the OEM links empty when the
// hardware is not Supermicro, so the per-document fetches are what actually
// decide whether a setting exists.
func (r *mqlRedfishSupermicro) smcManagers() []*smc.Manager {
	r.managersOnce.Do(func() {
		managers, err := redfishConn(r.MqlRuntime).Managers()
		if err != nil {
			log.Warn().Err(err).Msg("redfish: could not list managers for Supermicro OEM detection")
			return
		}
		res := make([]*smc.Manager, 0, len(managers))
		for _, m := range managers {
			smcManager, err := smc.FromManager(m)
			if err != nil {
				continue
			}
			res = append(res, smcManager)
		}
		r.managers = res
	})
	return r.managers
}

// licenses returns the activated node-management license keys. It keeps the
// behavior it shipped with: an empty list when the controller reports none.
func (r *mqlRedfishSupermicro) licenses() ([]any, error) {
	license, ok := r.licenseDoc.get(r.smcManagers(), func(m *smc.Manager) (*smc.QueryLicense, error) {
		lm, err := m.LicenseManager()
		if err != nil || lm == nil {
			return nil, err
		}
		return lm.QueryLicense()
	})
	if !ok {
		return []any{}, nil
	}
	res := make([]any, 0, len(license.Licenses))
	for _, l := range license.Licenses {
		res = append(res, l)
	}
	return res, nil
}

// systemLockdownEnabled reports whether BMC system lockdown mode is engaged.
// It keeps the behavior it shipped with: false when the controller reports no
// lockdown setting.
func (r *mqlRedfishSupermicro) systemLockdownEnabled() (bool, error) {
	lockdown, ok := r.lockdownDoc.get(r.smcManagers(), (*smc.Manager).SysLockdown)
	if !ok {
		return false, nil
	}
	return lockdown.Enabled, nil
}

func (r *mqlRedfishSupermicro) rakpEnabled() (bool, error) {
	rakp, ok := r.rakpDoc.get(r.smcManagers(), (*smc.Manager).SMCRAKP)
	if !ok {
		r.RakpEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return rakp.Mode == smc.SMCRAKPTypeEnabled, nil
}

func (r *mqlRedfishSupermicro) kcsPrivilege() (string, error) {
	kcs, ok := r.kcsDoc.get(r.smcManagers(), (*smc.Manager).KCSInterface)
	if !ok || kcs.Privilege == "" {
		r.KcsPrivilege.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return kcs.Privilege, nil
}

// smcOemLinks are the Supermicro OEM links of a manager document. gofish parses
// every one of these into an unexported field and exposes a getter for each,
// except for IPAccessControl, so that link is recovered here and handed back to
// the SDK's own getter.
type smcOemLinks struct {
	Oem struct {
		Supermicro struct {
			IPAccessControl odataRef `json:"IPAccessControl"`
		} `json:"Supermicro"`
	} `json:"Oem"`
}

// smcIPAccessControl fetches the IP access control document of a controller. It
// returns nil without an error when the controller links none, which is the
// case on every manager that is not Supermicro hardware.
func smcIPAccessControl(m *smc.Manager) (*smc.IPAccessControl, error) {
	var links smcOemLinks
	if len(m.RawData) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(m.RawData, &links); err != nil {
		log.Debug().Err(err).Msg("redfish: could not decode the Supermicro OEM links of a manager")
		return nil, nil
	}
	uri := links.Oem.Supermicro.IPAccessControl.ODataID
	if uri == "" {
		return nil, nil
	}
	return smc.GetIPAccessControl(m.GetClient(), uri)
}

func (r *mqlRedfishSupermicro) ipAccessControlEnabled() (bool, error) {
	ipac, ok := r.ipAccessDoc.get(r.smcManagers(), smcIPAccessControl)
	if !ok {
		r.IpAccessControlEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return ipac.Enabled, nil
}

func (r *mqlRedfishSupermicro) ipAccessControlRules() ([]any, error) {
	ipac, ok := r.ipAccessDoc.get(r.smcManagers(), smcIPAccessControl)
	if !ok {
		r.IpAccessControlRules.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	rules, err := ipac.FilterRules()
	if err != nil {
		// The controller advertises the rule collection but does not serve it.
		log.Debug().Err(err).Msg("redfish: controller serves no IP access control rules")
		r.IpAccessControlRules.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res := make([]any, 0, len(rules))
	for _, rule := range rules {
		res = append(res, map[string]any{
			"address":      rule.Address,
			"prefixLength": int64(rule.PrefixLength),
			"policy":       string(rule.Policy),
		})
	}
	return res, nil
}

func (r *mqlRedfishSupermicro) radiusEnabled() (bool, error) {
	radius, ok := r.radiusDoc.get(r.smcManagers(), (*smc.Manager).RADIUS)
	if !ok {
		r.RadiusEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return radius.Enabled, nil
}

func (r *mqlRedfishSupermicro) radiusServer() (string, error) {
	radius, ok := r.radiusDoc.get(r.smcManagers(), (*smc.Manager).RADIUS)
	if !ok || radius.Server == "" {
		r.RadiusServer.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return radius.Server, nil
}

func (r *mqlRedfishSupermicro) radiusPort() (int64, error) {
	radius, ok := r.radiusDoc.get(r.smcManagers(), (*smc.Manager).RADIUS)
	if !ok {
		r.RadiusPort.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return int64(radius.Port), nil
}

func (r *mqlRedfishSupermicro) ntpEnabled() (bool, error) {
	ntp, ok := r.ntpDoc.get(r.smcManagers(), (*smc.Manager).NTP)
	if !ok {
		r.NtpEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return ntp.Enabled, nil
}

func (r *mqlRedfishSupermicro) ntpPrimaryServer() (string, error) {
	ntp, ok := r.ntpDoc.get(r.smcManagers(), (*smc.Manager).NTP)
	if !ok || ntp.PrimaryServer == "" {
		r.NtpPrimaryServer.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return ntp.PrimaryServer, nil
}

func (r *mqlRedfishSupermicro) ntpSecondaryServer() (string, error) {
	ntp, ok := r.ntpDoc.get(r.smcManagers(), (*smc.Manager).NTP)
	if !ok || ntp.SecondaryServer == "" {
		r.NtpSecondaryServer.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return ntp.SecondaryServer, nil
}

func (r *mqlRedfishSupermicro) syslogEnabled() (bool, error) {
	syslog, ok := r.syslogDoc.get(r.smcManagers(), (*smc.Manager).Syslog)
	if !ok {
		r.SyslogEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return syslog.Enabled, nil
}

// syslogServers returns the destinations the controller forwards its event log
// to. gofish fills Servers for both document shapes, so firmware that reports a
// single destination appears here as a list of one.
func (r *mqlRedfishSupermicro) syslogServers() ([]any, error) {
	syslog, ok := r.syslogDoc.get(r.smcManagers(), (*smc.Manager).Syslog)
	if !ok {
		r.SyslogServers.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return syslogServerDicts(syslog), nil
}

// syslogServerDicts maps the syslog destinations of a Supermicro controller.
// gofish fills Servers for both shapes of the document, so firmware that
// reports a single destination as a string appears here as a list of one. It
// also fills Servers with one address-less entry when the controller forwards
// nowhere, and that entry is dropped rather than reported as a destination,
// because a controller that forwards nothing is the finding. A port the
// controller leaves out is written as null rather than as zero.
func syslogServerDicts(syslog *smc.Syslog) []any {
	res := make([]any, 0, len(syslog.Servers))
	for _, s := range syslog.Servers {
		if s.ServerIP == "" {
			continue
		}
		var port any
		if s.Port != nil {
			port = int64(*s.Port)
		}
		res = append(res, map[string]any{"host": s.ServerIP, "port": port})
	}
	return res
}
