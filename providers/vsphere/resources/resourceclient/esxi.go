// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resourceclient

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/cli/esx"
	"github.com/vmware/govmomi/object"
)

func NewEsxiClient(c *govmomi.Client, inventoryPath string, host *object.HostSystem) *Esxi {
	return &Esxi{
		c:             c,
		InventoryPath: inventoryPath,
		host:          host,
	}
}

type Esxi struct {
	InventoryPath string
	c             *govmomi.Client
	host          *object.HostSystem

	// esx.NewExecutor costs two SOAP round trips of its own --
	// RetrieveManagedMethodExecuter and RetrieveDynamicTypeManager -- and every
	// esxcli helper below used to build a fresh one per command. On a
	// four-asset scan that was 275 executors, so 550 setup calls: 36% of all
	// SOAP traffic. It also threw away the executor's CommandInfo cache each
	// time.
	execOnce sync.Once
	exec     *esx.Executor
	execErr  error
	// Executor.Run populates that CommandInfo map, so one executor cannot be
	// used concurrently -- and llx runs query blocks in goroutines.
	execMu sync.Mutex
}

// executor returns this host's esxcli executor, building it at most once.
func (esxi *Esxi) executor() (*esx.Executor, error) {
	esxi.execOnce.Do(func() {
		esxi.exec, esxi.execErr = esx.NewExecutor(context.Background(), esxi.c.Client, esxi.host)
	})
	return esxi.exec, esxi.execErr
}

// runEsxCli runs one esxcli command on this host's shared executor.
func (esxi *Esxi) runEsxCli(args ...string) (*esx.Response, error) {
	e, err := esxi.executor()
	if err != nil {
		return nil, err
	}

	esxi.execMu.Lock()
	defer esxi.execMu.Unlock()

	return e.Run(context.Background(), args)
}

var sliceKeys = []string{"Uplinks", "Portgroups"}

// isSliceKey implements special handling for keys where we always want to return a slice
// The issue is that esx.Values always return []string values although that does not make
// any sense for most values. We want to avoid to expose this as a bad user experience
func isSliceKey(key string) bool {
	for i := range sliceKeys {
		if sliceKeys[i] == key {
			return true
		}
	}
	return false
}

func esxiValuesToDict(val esx.Values) map[string]any {
	dict := map[string]any{}
	for k := range val {
		if len(val[k]) == 1 && !isSliceKey(k) {
			dict[k] = val[k][0]
		} else {
			// convert to []interface
			dict[k] = convert.SliceAnyToInterface(val[k])
		}
	}
	return dict
}

func esxiValuesSliceToDict(values []esx.Values) []map[string]any {
	dicts := make([]map[string]any, len(values))
	for i, val := range values {
		dicts[i] = esxiValuesToDict(val)
	}
	return dicts
}

// (Get - EsxCli).network.vswitch.standard.list()
func (esxi *Esxi) VswitchStandard() ([]map[string]any, error) {
	res, err := esxi.runEsxCli("network", "vswitch", "standard", "list")
	if err != nil {
		return nil, err
	}

	return esxiValuesSliceToDict(res.Values), nil
}

var doubleSpaceRegex = regexp.MustCompile(`\s+`)

func (esxi *Esxi) Command(command string) ([]map[string]any, error) {
	sanitizedCommand := doubleSpaceRegex.ReplaceAllString(command, " ")
	args := strings.Split(sanitizedCommand, " ")

	resp, err := esxi.runEsxCli(args...)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	return esxiValuesSliceToDict(resp.Values), nil
}

// (Get-ESXCli).network.vswitch.standard.policy.shaping.get('vSwitch0')
func (esxi *Esxi) VswitchStandardShapingPolicy(standardSwitchName string) (map[string]any, error) {
	resp, err := esxi.runEsxCli("network", "vswitch", "standard", "policy", "shaping", "get", "--vswitch-name", standardSwitchName)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	if len(resp.Values) > 1 {
		return nil, errors.New("vsphere network.vswitch.standard.policy.shaping returns more than one value, this is unexpected")
	}

	return esxiValuesToDict(resp.Values[0]), nil
}

// (Get-ESXCli).network.vswitch.standard.policy.failover.get('vSwitch0')
func (esxi *Esxi) VswitchStandardFailoverPolicy(standardSwitchName string) (map[string]any, error) {
	resp, err := esxi.runEsxCli("network", "vswitch", "standard", "policy", "failover", "get", "--vswitch-name", standardSwitchName)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	if len(resp.Values) > 1 {
		return nil, errors.New("vsphere network.vswitch.standard.policy.failover returns more than one value, this is unexpected")
	}

	return esxiValuesToDict(resp.Values[0]), nil
}

// (Get-ESXCli).network.vswitch.standard.policy.security.get('vSwitch0')
func (esxi *Esxi) VswitchStandardSecurityPolicy(standardSwitchName string) (map[string]any, error) {
	resp, err := esxi.runEsxCli("network", "vswitch", "standard", "policy", "security", "get", "--vswitch-name", standardSwitchName)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	if len(resp.Values) > 1 {
		return nil, errors.New("vsphere network.vswitch.standard.policy.security returns more than one value, this is unexpected")
	}

	return esxiValuesToDict(resp.Values[0]), nil
}

// (Get-EsxCli).network.vswitch.dvs.vmware.list()
func (esxi *Esxi) VswitchDvs() ([]map[string]any, error) {
	res, err := esxi.runEsxCli("network", "vswitch", "dvs", "vmware", "list")
	if err != nil {
		return nil, err
	}

	return esxiValuesSliceToDict(res.Values), nil
}

// Adapters will list the Physical NICs currently installed and loaded on the system.
// (Get-EsxCli).network.nic.list.Invoke()
func (esxi *Esxi) Adapters() ([]map[string]any, error) {
	res, err := esxi.runEsxCli("network", "nic", "list")
	if err != nil {
		return nil, err
	}

	return esxiValuesSliceToDict(res.Values), nil
}

// List adapter details for nic
// Usage esxcli network nic pauseParams list
func (esxi *Esxi) ListNicDetails(interfacename string) (map[string]any, error) {
	resp, err := esxi.runEsxCli("network", "nic", "get", "--nic-name", interfacename)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	if len(resp.Values) > 1 {
		return nil, errors.New("network.ip.interface.tag returns more than one value, this is unexpected")
	}

	return esxiValuesToDict(resp.Values[0]), nil
}

// List pause parameters of all NICs
// Usage esxcli network nic pauseParams list
func (esxi *Esxi) ListNicPauseParams() ([]map[string]any, error) {
	res, err := esxi.runEsxCli("network", "nic", "pauseParams", "list")
	if err != nil {
		return nil, err
	}

	return esxiValuesSliceToDict(res.Values), nil
}

type VmKernelNic struct {
	Properties map[string]any
	Ipv4       []any
	Ipv6       []any
	Tags       []string
}

// (Get-EsxCli).network.ip.interface.list()
//
// Per-host ESXCli ipv4/ipv6 enumeration is batched once per protocol — the
// list-without-interface-name form returns every vmkernel NIC's IP info in a
// single call. That cuts vmknic ESXCli call count from `1 + 3N` (list + 3
// per-NIC) to `3 + N` (list + ipv4-batch + ipv6-batch + per-NIC tags) for
// hosts with N vmkernel NICs. Tags don't have an esxcli-list form, so they
// stay per-NIC.
func (esxi *Esxi) Vmknics() ([]VmKernelNic, error) {
	res, err := esxi.runEsxCli("network", "ip", "interface", "list")
	if err != nil {
		return nil, err
	}

	ipv4ByName, err := esxi.vmknicIpAll("ipv4")
	if err != nil {
		return nil, err
	}
	ipv6ByName, err := esxi.vmknicIpAll("ipv6")
	if err != nil {
		return nil, err
	}

	vmknics := make([]VmKernelNic, 0, len(res.Values))
	for _, val := range res.Values {
		// `network ip interface list` always reports Name and NetstackInstance
		// as a single-string column on supported ESXi releases, but defend
		// against an unexpected schema rather than panicking on missing keys.
		nameCol := val["Name"]
		netstackCol := val["NetstackInstance"]
		if len(nameCol) == 0 || len(netstackCol) == 0 {
			continue
		}
		name := nameCol[0]
		if name == "" {
			continue
		}

		nic := VmKernelNic{
			Properties: esxiValuesToDict(val),
			Ipv4:       ipv4ByName[name],
			Ipv6:       ipv6ByName[name],
		}

		// Tags are still per-interface — esxcli has no list form for them.
		tags, err := esxi.VmknicTags(name)
		if err != nil {
			return nil, err
		}
		nic.Tags = tags

		vmknics = append(vmknics, nic)
	}
	return vmknics, nil
}

// vmknicIpAll returns ipv4 / ipv6 records for every vmkernel NIC in a single
// ESXCli call, indexed by interface name. Replaces N per-interface
// VmknicIp() calls in the Vmknics() loop.
func (esxi *Esxi) vmknicIpAll(ipprotocol string) (map[string][]any, error) {
	resp, err := esxi.runEsxCli("network", "ip", "interface", ipprotocol, "get")
	if err != nil {
		return nil, err
	}

	out := map[string][]any{}
	for i := range resp.Values {
		val := resp.Values[i]
		nameCol := val["Name"]
		if len(nameCol) == 0 {
			continue
		}
		name := nameCol[0]
		out[name] = append(out[name], esxiValuesToDict(val))
	}
	return out, nil
}

// (Get-EsxCli).network.ip.interface.ipv4.get('vmk0', 'defaultTcpipStack')
func (esxi *Esxi) VmknicIp(interfacename string, netstack string, ipprotocol string) ([]any, error) {
	resp, err := esxi.runEsxCli("network", "ip", "interface", ipprotocol, "get", "--interface-name", interfacename, "--netstack", netstack)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	res := []any{}
	for i := range resp.Values {
		entry := esxiValuesToDict(resp.Values[i])
		res = append(res, entry)
	}
	return res, nil
}

// (Get-EsxCli).network.ip.interface.tag.get('vmk0')
// see https://blogs.vmware.com/vsphere/2012/12/tagging-vmkernel-traffic-types-using-esxcli-5-1.html
// see https://kb.vmware.com/s/article/65184
func (esxi *Esxi) VmknicTags(interfacename string) ([]string, error) {
	resp, err := esxi.runEsxCli("network", "ip", "interface", "tag", "get", "--interface-name", interfacename)
	if err != nil {
		return nil, err
	}

	if len(resp.Values) == 0 {
		return nil, nil
	}

	if len(resp.Values) > 1 {
		return nil, errors.New("network.ip.interface.tag returns more than one value, this is unexpected")
	}

	val := resp.Values[0]
	tags := val["Tags"]
	return tags, nil
}

type EsxiVib struct {
	ID              string
	Name            string
	AcceptanceLevel string
	CreationDate    string
	InstallDate     string
	Status          string
	Vendor          string
	Version         string
}

// ($ESXCli).software.vib.list()
// AcceptanceLevel : VMwareCertified
// CreationDate    : 2018-04-03
// ID              : VMware_bootbank_vmware-esx-esxcli-nvme-plugin_1.2.0.32-0.0.8169922
// InstallDate     : 2020-07-16
// Name            : vmware-esx-esxcli-nvme-plugin
// Status          :
// Vendor          : VMware
// Version         : 1.2.0.32-0.0.8169922
func (esxi *Esxi) Vibs() ([]EsxiVib, error) {
	res, err := esxi.runEsxCli("software", "vib", "list")
	if err != nil {
		return nil, err
	}

	vibs := []EsxiVib{}
	for _, val := range res.Values {
		vib := EsxiVib{}
		for k := range val {
			if len(val[k]) == 1 {
				value := val[k][0]
				switch k {
				case "AcceptanceLevel":
					vib.AcceptanceLevel = value
				case "CreationDate":
					vib.CreationDate = value
				case "ID":
					vib.ID = value
				case "InstallDate":
					vib.InstallDate = value
				case "Name":
					vib.Name = value
				case "Status":
					vib.Status = value
				case "Vendor":
					vib.Vendor = value
				case "Version":
					vib.Version = value
				}
			} else {
				log.Error().Str("key", k).Msg("Vibs> unsupported key")
			}
		}
		vibs = append(vibs, vib)
	}
	return vibs, nil
}

// ($ESXCli).software.acceptance.get()
//
// `software acceptance get` returns a single string value (e.g.
// "PartnerSupported"). govmomi's esx executor surfaces that on res.String;
// on some ESXi releases it lands in res.Values as a single-key map. Try
// both before reporting "unknown".
func (esxi *Esxi) SoftwareAcceptance() (string, error) {
	res, err := esxi.runEsxCli("software", "acceptance", "get")
	if err != nil {
		return "", err
	}

	if res.String != "" {
		return res.String, nil
	}
	// `software acceptance get` returns a single key/value, so iteration
	// order across the maps is irrelevant — return the first populated value.
	for _, v := range res.Values {
		for _, vals := range v {
			if len(vals) > 0 && vals[0] != "" {
				return vals[0], nil
			}
		}
	}

	return "", errors.New("unknown software acceptance level")
}

type EsxiKernelModule struct {
	Module               string
	ModuleFile           string
	ProvidedNamespaces   string
	RequiredNamespaces   string
	BuildType            string
	ContainingVIB        string
	FileVersion          string
	License              string
	Version              string
	SignatureDigest      string
	SignatureFingerPrint string
	SignatureIssuer      string
	SignedStatus         string
	VIBAcceptanceLevel   string
	Enabled              bool
	Loaded               bool
}

// KernelModules
//
// ($ESXCli).system.module.list()
// IsEnabled IsLoaded Name
// --------- -------- ----
// true      true     vmkernel
// true      true     chardevs
// true      true     user
// true      true     procfs
func (esxi *Esxi) KernelModules() ([]*EsxiKernelModule, error) {
	res, err := esxi.runEsxCli("system", "module", "list")
	if err != nil {
		return nil, err
	}

	kernelmodules := []*EsxiKernelModule{}
	for _, val := range res.Values {
		var modulename string
		loaded := false
		enabled := false

		for k := range val {
			if len(val[k]) == 1 {
				value := val[k][0]

				switch k {
				case "IsEnabled":
					if value == "true" {
						enabled = true
					}
				case "IsLoaded":
					if value == "true" {
						loaded = true
					}
				case "Name":
					modulename = value
				}
			} else {
				log.Error().Str("key", k).Msg("Vibs> unsupported key")
			}
		}

		// gather module additional details
		// NOTE: not sure why but not all list entries have module details
		// e.g "vmkernel", "user" do not return any results
		module, err := esxi.KernelModuleDetails(modulename)
		if err == nil {
			module.Enabled = enabled
			module.Loaded = loaded
			kernelmodules = append(kernelmodules, module)
		} else {
			module = &EsxiKernelModule{
				Module:  modulename,
				Enabled: enabled,
				Loaded:  loaded,
			}
			kernelmodules = append(kernelmodules, module)
		}
	}
	return kernelmodules, nil
}

// $ESXCli.system.module.get("swapobj")
//
// BuildType            :
// ContainingVIB        : esx-base
// FileVersion          :
// License              : VMware
// Module               : swapobj
// ModuleFile           : /usr/lib/vmware/vmkmod/swapobj
// ProvidedNamespaces   : com.vmware.swapobj@0
// RequiredNamespaces   : {com.vmware.vmkapi@v2_5_0_0, com.vmware.vmkapi.incompat@v2_5_0_0, com.vmware.vmklinkmpi@0, vmkernel@nover}
// SignatureDigest      : 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
// SignatureFingerPrint : 0000 0000 0000 0000 0000 0000 0000 0000
// SignatureIssuer      :
// SignedStatus         : Unsigned
// VIBAcceptanceLevel   : certified
// Version              :
func (esxi *Esxi) KernelModuleDetails(modulename string) (*EsxiKernelModule, error) {
	// NOTE: do not use the powershell syntax, stick with the plain esxcli syntax
	// esxcli <conn_options> system module get --module=module_name
	res, err := esxi.runEsxCli("system", "module", "get", "--module", modulename)
	if err != nil {
		return nil, err
	}

	if len(res.Values) == 0 {
		return nil, errors.New("could not find esxi kernel module " + modulename)
	}

	if len(res.Values) > 1 {
		return nil, errors.New("ambiguous esxi kernel module name" + modulename)
	}

	module := EsxiKernelModule{}
	val := res.Values[0]
	for k := range val {
		if len(val[k]) >= 1 {
			value := val[k][0]

			switch k {
			case "BuildType":
				module.BuildType = value
			case "ContainingVIB":
				module.ContainingVIB = value
			case "FileVersion":
				module.FileVersion = value
			case "License":
				module.License = value
			case "Module":
				module.Module = value
			case "ModuleFile":
				module.ModuleFile = value
			case "ProvidedNamespaces":
				module.ProvidedNamespaces = value
			case "SignatureDigest":
				module.SignatureDigest = value
			case "SignatureFingerPrint":
				module.SignatureFingerPrint = value
			case "SignatureIssuer":
				module.SignatureIssuer = value
			case "SignedStatus":
				module.SignedStatus = value
			case "VIBAcceptanceLevel":
				module.VIBAcceptanceLevel = value
			case "Version":
				module.Version = value
			case "RequiredNamespaces":
				module.RequiredNamespaces = strings.Join(val[k], ",")
			}
		} else {
			log.Error().Str("key", k).Msg("kernelmodule> unsupported key")
		}
	}
	return &module, nil
}

type EsxiAdvancedSetting struct {
	Key         string
	Path        string
	Description string
	Default     string
	Value       string
}

func (s EsxiAdvancedSetting) Overridden() bool {
	return s.Default != s.Value
}

// esxiColumn returns the single value for an esxcli result column, or "" when
// the column is absent or carries anything other than exactly one value. An
// empty XML element decodes to a present, len-1 slice holding "", so an absent
// value and a genuinely empty value both collapse to "" here.
func esxiColumn(val map[string][]string, key string) string {
	if v, ok := val[key]; ok && len(v) == 1 {
		return v[0]
	}
	return ""
}

// buildAdvancedSetting maps one `system settings advanced list` DataObject into
// an EsxiAdvancedSetting. esxcli emits BOTH the integer and the string variant
// of the value/default columns for every setting; the variant that doesn't
// apply is present but empty (`DefaultStringValue :` for an integer setting).
// The Type column ("integer" or "string") tells us which pair is authoritative,
// so we select on it rather than writing both variants to the same field and
// letting Go's randomized map-iteration order decide the winner (which produced
// nondeterministic empty/wrong Default and Value between scans).
func buildAdvancedSetting(val map[string][]string) EsxiAdvancedSetting {
	setting := EsxiAdvancedSetting{
		Description: esxiColumn(val, "Description"),
	}
	if path := esxiColumn(val, "Path"); path != "" {
		setting.Path = path
		setting.Key = strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", ".")
	}
	if esxiColumn(val, "Type") == "string" {
		setting.Default = esxiColumn(val, "DefaultStringValue")
		setting.Value = esxiColumn(val, "StringValue")
	} else {
		// integer (the only other advertised type) uses the numeric columns
		setting.Default = esxiColumn(val, "DefaultIntValue")
		setting.Value = esxiColumn(val, "IntValue")
	}
	return setting
}

// $ESXCli.system.settings.advanced.list()
// DefaultIntValue    : 1
// DefaultStringValue :
// Description        : Enable hardware accelerated VMFS data movement (requires compliant hardware)
// IntValue           : 1
// MaxValue           : 1
// MinValue           : 0
// Path               : /DataMover/HardwareAcceleratedMove
// StringValue        :
// Type               : integer
// ValidCharacters    :
//
// supported types are `integer` and `string`, both are converted to string
func (esxi *Esxi) AdvancedSettings() ([]EsxiAdvancedSetting, error) {
	// fetch system settings
	res, err := esxi.runEsxCli("system", "settings", "advanced", "list")
	if err != nil {
		return nil, err
	}

	settings := []EsxiAdvancedSetting{}
	for _, val := range res.Values {
		settings = append(settings, buildAdvancedSetting(val))
	}

	// fetch kernel settings
	// $ESXCli.system.settings.kernel.list()
	res, err = esxi.runEsxCli("system", "settings", "kernel", "list")
	if err != nil {
		return nil, err
	}

	for _, val := range res.Values {
		setting := EsxiAdvancedSetting{}

		for k := range val {
			if len(val[k]) == 1 {
				value := val[k][0]
				switch k {
				case "Name":
					setting.Path = value
					setting.Key = "VMkernel.Boot." + value
				case "Description":
					setting.Description = value
				case "Default":
					setting.Default = value
				case "Configured":
					setting.Value = value
				}
			} else {
				log.Error().Str("key", k).Msg("Vibs> unsupported key")
			}
		}
		settings = append(settings, setting)
	}

	return settings, nil
}

func (esxi *Esxi) Snmp() (map[string]any, error) {
	res, err := esxi.runEsxCli("system", "snmp", "get")
	if err != nil {
		return nil, err
	}

	if len(res.Values) == 0 {
		return nil, errors.New("could not detect esxi system version ")
	}

	if len(res.Values) > 1 {
		return nil, errors.New("ambiguous esxi system version")
	}

	snmp := map[string]any{}
	val := res.Values[0]
	for k := range val {
		if len(val[k]) == 1 {
			value := val[k][0]
			snmp[k] = value
		} else {
			log.Error().Str("key", k).Msg("snmp> unsupported key")
		}
	}
	return snmp, nil
}

// esxcliNamespaceUnavailableRegex matches the esxcli error returned by hosts
// where a namespace is absent because the feature is too new for the running
// ESXi release (e.g. `system security keypersistence` needs 7.0 Update 2,
// `system tls server` needs 8.0) or the hardware lacks a prerequisite such as
// a TPM. On those hosts we treat the namespace as "not configured" rather than
// failing the whole host query.
var esxcliNamespaceUnavailableRegex = regexp.MustCompile(`(?i)(not supported|unknown command|invalid namespace|tpm)`)

// KeyPersistenceEnabled reports whether TPM-backed key persistence is enabled
// on the host.
//
// ($ESXCli).system.security.keypersistence.get()
//
//	Enabled: false
//
// Hosts that do not support the feature (pre-7.0 Update 2 or no TPM) make the
// namespace unavailable; we treat that as "not enabled" rather than failing the
// whole host query.
func (esxi *Esxi) KeyPersistenceEnabled() (bool, error) {
	res, err := esxi.runEsxCli("system", "security", "keypersistence", "get")
	if err != nil {
		if esxcliNamespaceUnavailableRegex.MatchString(err.Error()) {
			return false, nil
		}
		return false, err
	}

	for _, val := range res.Values {
		for k := range val {
			if !strings.EqualFold(k, "Enabled") {
				continue
			}
			if len(val[k]) > 0 {
				return strings.EqualFold(val[k][0], "true"), nil
			}
		}
	}

	return false, nil
}

// CertificateStore lists the trusted CA certificates installed in the host
// certificate store.
//
// ($ESXCli).system.security.certificatestore.list()
func (esxi *Esxi) CertificateStore() ([]map[string]any, error) {
	res, err := esxi.runEsxCli("system", "security", "certificatestore", "list")
	if err != nil {
		return nil, err
	}

	return esxiValuesSliceToDict(res.Values), nil
}

// esxcliKeyValueList runs an esxcli command that returns rows of Key/Value
// pairs (the shape used by `system ssh server config list` and friends) and
// flattens them into a single map. Hosts whose ESXi release lacks the
// namespace report an empty map rather than failing the whole host query, the
// same way TlsServerProfile and KeyPersistenceEnabled handle older releases.
func (esxi *Esxi) esxcliKeyValueList(args []string) (map[string]string, error) {
	res, err := esxi.runEsxCli(args...)
	if err != nil {
		if esxcliNamespaceUnavailableRegex.MatchString(err.Error()) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	config := map[string]string{}
	for _, val := range res.Values {
		keyCol := val["Key"]
		valueCol := val["Value"]
		if len(keyCol) == 0 || keyCol[0] == "" {
			continue
		}
		value := ""
		if len(valueCol) > 0 {
			value = valueCol[0]
		}
		config[keyCol[0]] = value
	}
	return config, nil
}

// SshServerConfig returns the ESXi SSH server configuration as a key/value map
// (ciphers, gatewayports, hostbasedauthentication, permitrootlogin, banner, …).
//
// ($ESXCli).system.ssh.server.config.list()
func (esxi *Esxi) SshServerConfig() (map[string]string, error) {
	return esxi.esxcliKeyValueList([]string{"system", "ssh", "server", "config", "list"})
}

// SshClientConfig returns the ESXi SSH client configuration as a key/value map.
//
// ($ESXCli).system.ssh.client.config.list()
func (esxi *Esxi) SshClientConfig() (map[string]string, error) {
	return esxi.esxcliKeyValueList([]string{"system", "ssh", "client", "config", "list"})
}

// TlsServerProfile returns the configured TLS security profile for the host.
//
// ($ESXCli).system.tls.server.get()
//
//	Profile: NIST_2024
//
// The `system tls server` namespace was introduced in ESXi 8.0; on older
// hosts it is unavailable, which we report as an empty profile rather than an
// error.
func (esxi *Esxi) TlsServerProfile() (string, error) {
	res, err := esxi.runEsxCli("system", "tls", "server", "get")
	if err != nil {
		if esxcliNamespaceUnavailableRegex.MatchString(err.Error()) {
			return "", nil
		}
		return "", err
	}

	for _, val := range res.Values {
		for k := range val {
			if !strings.EqualFold(k, "Profile") {
				continue
			}
			if len(val[k]) > 0 {
				return val[k][0], nil
			}
		}
	}

	return "", nil
}
