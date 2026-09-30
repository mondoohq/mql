// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Every firewall query reads the ActiveStore, the policy the firewall
// enforces: local rules and settings merged with those delivered by Group
// Policy. The cmdlets default to the PersistentStore, which holds only what
// was configured locally, so every rule delivered by Group Policy was missing
// and profile settings showed the local value even where a policy overrides
// it (for example AllowLocalFirewallRules, the AllowLocalPolicyMerge policy,
// which voids the local rules when a policy sets it to false).
const (
	FIREWALL_PROFILES = "Get-NetFirewallProfile -PolicyStore ActiveStore | ConvertTo-Json"
	// Profile is a flags enum. It is cast to a string on the host so the
	// flag names come back instead of a bit mask, which is what a policy
	// matches on and what the firewall UI shows.
	// -TracePolicyStore fills PolicyStoreSource and PolicyStoreSourceType with
	// where each rule came from (a GPO's name, or PersistentStore). In the
	// ActiveStore, EnforcementStatus holds several values for some rules
	// (DisabledInProfile, ProfileInactive, Enforced); they are joined on the
	// host, so the field stays one string.
	FIREWALL_RULES    = "Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore | Select-Object InstanceID,Name,DisplayName,Description,DisplayGroup,Enabled,Direction,Action,EdgeTraversalPolicy,LooseSourceMapping,LocalOnlyMapping,PrimaryStatus,Status,@{n='EnforcementStatus';e={@($_.EnforcementStatus) -join ', '}},PolicyStoreSource,PolicyStoreSourceType,@{n='Profiles';e={[string]$_.Profile}} | ConvertTo-Json"
	FIREWALL_SETTINGS = "Get-NetFirewallSetting -PolicyStore ActiveStore | ConvertTo-Json"
)

type WindowsFirewallRule struct {
	InstanceID            string `json:"InstanceID"`
	Name                  string `json:"Name"`
	DisplayName           string `json:"DisplayName"`
	Description           string `json:"Description"`
	DisplayGroup          string `json:"DisplayGroup"`
	Enabled               int64  `json:"Enabled"`
	Direction             int64  `json:"Direction"`
	Action                int64  `json:"Action"`
	EdgeTraversalPolicy   int64  `json:"EdgeTraversalPolicy"`
	LooseSourceMapping    bool   `json:"LooseSourceMapping"`
	LocalOnlyMapping      bool   `json:"LocalOnlyMapping"`
	PrimaryStatus         int64  `json:"PrimaryStatus"`
	Status                string `json:"Status"`
	EnforcementStatus     string `json:"EnforcementStatus"`
	PolicyStoreSource     string `json:"PolicyStoreSource"`
	PolicyStoreSourceType int64  `json:"PolicyStoreSourceType"`
	// Profiles carries the rule's Profile flags enum, split into flag names.
	Profiles PSFlagList `json:"Profiles"`
}

// streamDecodeJSONArray stream-decodes a JSON array from input, returning
// elements one at a time to avoid buffering the entire payload. It also
// handles the PowerShell quirk where a single-element result is emitted as
// a bare object instead of a one-element array.
func streamDecodeJSONArray[T any](input io.Reader) ([]T, error) {
	dec := json.NewDecoder(input)

	// Read the opening token of the JSON value.
	tok, err := dec.Token()
	if err == io.EOF {
		return []T{}, nil
	}
	if err != nil {
		return nil, err
	}

	delim, isDelim := tok.(json.Delim)

	// PowerShell emits a bare object when there is exactly one element.
	if isDelim && delim == '{' {
		var item T
		if err := json.NewDecoder(io.MultiReader(
			bytes.NewReader([]byte{'{'}),
			dec.Buffered(),
			input,
		)).Decode(&item); err != nil {
			return nil, err
		}
		return []T{item}, nil
	}

	if !isDelim || delim != '[' {
		return nil, fmt.Errorf("unexpected JSON token %v; expected '[' or '{'", tok)
	}

	// Stream-decode array elements one at a time.
	var items []T
	for dec.More() {
		var item T
		if err := dec.Decode(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

func ParseWindowsFirewallRules(input io.Reader) ([]WindowsFirewallRule, error) {
	return streamDecodeJSONArray[WindowsFirewallRule](input)
}

type WindowsFirewallSettings struct {
	Name                   string `json:"Name"`
	Exemptions             int64  `json:"Exemptions"`
	EnableStatefulFtp      int64  `json:"EnableStatefulFtp"`
	EnableStatefulPptp     int64  `json:"EnableStatefulPptp"`
	ActiveProfile          int64  `json:"ActiveProfile"`
	RequireFullAuthSupport int64  `json:"RequireFullAuthSupport"`
	CertValidationLevel    int64  `json:"CertValidationLevel"`
	AllowIPsecThroughNAT   int64  `json:"AllowIPsecThroughNAT"`
	// NotConfigured in the PersistentStore, the effective number of seconds
	// in the ActiveStore.
	MaxSAIdleTimeSeconds                    PSFlexString `json:"MaxSAIdleTimeSeconds"`
	KeyEncoding                             int64        `json:"KeyEncoding"`
	EnablePacketQueuing                     int64        `json:"EnablePacketQueuing"`
	ElementName                             string       `json:"ElementName"`
	InstanceID                              string       `json:"InstanceID"`
	Profile                                 int64        `json:"Profile"`
	RemoteMachineTransportAuthorizationList string       `json:"RemoteMachineTransportAuthorizationList"`
	RemoteMachineTunnelAuthorizationList    string       `json:"RemoteMachineTunnelAuthorizationList"`
	RemoteUserTransportAuthorizationList    string       `json:"RemoteUserTransportAuthorizationList"`
	RemoteUserTunnelAuthorizationList       string       `json:"RemoteUserTunnelAuthorizationList"`
}

func ParseWindowsFirewallSettings(input io.Reader) (*WindowsFirewallSettings, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	// for empty result set do not get the '{}', therefore lets abort here
	if len(data) == 0 {
		return &WindowsFirewallSettings{}, nil
	}

	var winFirewallSettings WindowsFirewallSettings
	err = json.Unmarshal(data, &winFirewallSettings)
	if err != nil {
		return nil, err
	}

	return &winFirewallSettings, nil
}

type WindowsFirewallProfile struct {
	Profile                         string  `json:"Profile"`
	Enabled                         int64   `json:"Enabled"`
	DefaultInboundAction            int64   `json:"DefaultInboundAction"`
	DefaultOutboundAction           int64   `json:"DefaultOutboundAction"`
	AllowInboundRules               int64   `json:"AllowInboundRules"`
	AllowLocalFirewallRules         int64   `json:"AllowLocalFirewallRules"`
	AllowLocalIPsecRules            int64   `json:"AllowLocalIPsecRules"`
	AllowUserApps                   int64   `json:"AllowUserApps"`
	AllowUserPorts                  int64   `json:"AllowUserPorts"`
	AllowUnicastResponseToMulticast int64   `json:"AllowUnicastResponseToMulticast"`
	NotifyOnListen                  int64   `json:"NotifyOnListen"`
	EnableStealthModeForIPsec       int64   `json:"EnableStealthModeForIPsec"`
	LogMaxSizeKilobytes             int64   `json:"LogMaxSizeKilobytes"`
	LogAllowed                      int64   `json:"LogAllowed"`
	LogBlocked                      int64   `json:"LogBlocked"`
	LogIgnored                      int64   `json:"LogIgnored"`
	Caption                         *string `json:"Caption"`
	Description                     *string `json:"Description"`
	InstanceID                      string  `json:"InstanceID"`
	LogFileName                     string  `json:"LogFileName"`
	Name                            string  `json:"Name"`
}

func ParseWindowsFirewallProfiles(input io.Reader) ([]WindowsFirewallProfile, error) {
	return streamDecodeJSONArray[WindowsFirewallProfile](input)
}

// Firewall rule conditions (ports, addresses, program, service, interface
// types, authorized principals) are not properties of the rule object. The
// NetSecurity module keeps each group in a separate filter object with a
// one-to-one relationship to the rule, joined on InstanceID, so reporting
// what a rule permits means fetching every filter collection and joining it
// against the rules in memory. Calling a filter cmdlet per rule would be six
// extra round trips for each of the several hundred rules a stock Windows
// install ships with.
//
// The whole join is one script so that it costs one round trip. It stays
// well inside PSMaxScriptLength; -Depth is mandatory because the default of
// 2 renders the multi-valued port and address properties as type names
// instead of arrays. The filters are read from the ActiveStore too, so the
// rules delivered by Group Policy get their conditions.
const FIREWALL_RULE_FILTERS = `$o=@{PolicyStore='ActiveStore'}
$p=@(Get-NetFirewallPortFilter @o|Select-Object InstanceID,Protocol,LocalPort,RemotePort,IcmpType)
$a=@(Get-NetFirewallAddressFilter @o|Select-Object InstanceID,LocalAddress,RemoteAddress)
$ap=@(Get-NetFirewallApplicationFilter @o|Select-Object InstanceID,Program)
$s=@(Get-NetFirewallServiceFilter @o|Select-Object InstanceID,Service)
$i=@(Get-NetFirewallInterfaceTypeFilter @o|Select-Object InstanceID,@{n='InterfaceType';e={[string]$_.InterfaceType}})
$c=@(Get-NetFirewallSecurityFilter @o|Select-Object InstanceID,RemoteUser,RemoteMachine)
[PSCustomObject]@{Port=$p;Address=$a;Application=$ap;Service=$s;InterfaceType=$i;Security=$c}|ConvertTo-Json -Depth 5 -Compress`

// PSFlexString decodes a scalar PowerShell property that does not always
// arrive as a JSON string. A calculated property yielding nothing serializes
// as {} rather than as null, and a property PowerShell holds as a number
// (a firewall protocol with no well-known name, for example) serializes
// unquoted. Either one fails a plain string tag and takes the whole payload
// down with it, so both are accepted and a number keeps its literal text.
type PSFlexString string

func (s *PSFlexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) || data[0] == '{' || data[0] == '[' {
		*s = ""
		return nil
	}
	if data[0] == '"' {
		var v string
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		*s = PSFlexString(v)
		return nil
	}
	*s = PSFlexString(data)
	return nil
}

// PSFlagList decodes a .NET flags enum that PowerShell has rendered as a
// string: "Any", or "Domain, Private" when several flags are set. The
// individual flag names are what a policy wants to match on, so the string
// is split into them. A value that arrives as a bare number is reported as
// its literal text rather than silently as an empty list, because an empty
// list would read as "this rule applies to no profile at all".
type PSFlagList []string

func (f *PSFlagList) UnmarshalJSON(data []byte) error {
	var raw PSFlexString
	if err := raw.UnmarshalJSON(data); err != nil {
		return err
	}
	*f = splitFlagString(string(raw))
	return nil
}

func splitFlagString(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// decodePSObjectList decodes a list of objects out of the shapes PowerShell
// produces for one. An empty collection assigned into a PSCustomObject
// serializes as "" on Windows PowerShell 5.1 rather than as [], a
// single-element collection can flatten to a bare object, and a collection
// built by Select-Object can arrive wrapped as {"value":[...],"Count":n}.
// Only the first of those is a JSON array, so a plain []T tag reports "no
// filters" on a host that has hundreds.
func decodePSObjectList[T any](raw json.RawMessage) ([]T, error) {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) || bytes.Equal(data, []byte(`""`)) {
		return nil, nil
	}

	switch data[0] {
	case '[':
		var list []T
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		return list, nil
	case '{':
		// Distinguish a wrapper from a single flattened object by whether the
		// object carries the wrapper's own keys, not by whether "value" holds
		// anything. A wrapper whose collection is empty still IS a wrapper, and
		// decoding it as a T would yield a record with every field at its zero
		// value: a fabricated filter with an empty InstanceID that joins to no
		// rule, reported as though PowerShell had returned it.
		var wrapped struct {
			Value *json.RawMessage `json:"value"`
			Count *json.RawMessage `json:"Count"`
		}
		if err := json.Unmarshal(data, &wrapped); err == nil && (wrapped.Value != nil || wrapped.Count != nil) {
			if wrapped.Value == nil {
				return nil, nil
			}
			inner := bytes.TrimSpace(*wrapped.Value)
			if len(inner) == 0 || bytes.Equal(inner, []byte("null")) {
				return nil, nil
			}
			var list []T
			if err := json.Unmarshal(inner, &list); err != nil {
				return nil, err
			}
			return list, nil
		}
		var single T
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, err
		}
		return []T{single}, nil
	}

	return nil, fmt.Errorf("unexpected JSON token %q; expected an object list", data[0])
}

type WindowsFirewallPortFilter struct {
	InstanceID string        `json:"InstanceID"`
	Protocol   PSFlexString  `json:"Protocol"`
	LocalPort  PSStringArray `json:"LocalPort"`
	RemotePort PSStringArray `json:"RemotePort"`
	IcmpType   PSStringArray `json:"IcmpType"`
}

type WindowsFirewallAddressFilter struct {
	InstanceID    string        `json:"InstanceID"`
	LocalAddress  PSStringArray `json:"LocalAddress"`
	RemoteAddress PSStringArray `json:"RemoteAddress"`
}

type WindowsFirewallApplicationFilter struct {
	InstanceID string       `json:"InstanceID"`
	Program    PSFlexString `json:"Program"`
}

type WindowsFirewallServiceFilter struct {
	InstanceID string       `json:"InstanceID"`
	Service    PSFlexString `json:"Service"`
}

type WindowsFirewallInterfaceTypeFilter struct {
	InstanceID    string     `json:"InstanceID"`
	InterfaceType PSFlagList `json:"InterfaceType"`
}

type WindowsFirewallSecurityFilter struct {
	InstanceID    string       `json:"InstanceID"`
	RemoteUser    PSFlexString `json:"RemoteUser"`
	RemoteMachine PSFlexString `json:"RemoteMachine"`
}

// WindowsFirewallRuleFilters holds the conditions attached to one rule. A
// member is nil when the host reported no filter of that kind for the rule,
// which is not the same as a filter that reports "Any": the first means the
// condition was never read, the second means the rule genuinely matches
// anything. Callers must keep them apart, or a rule with no application
// filter reports an empty program as if that were a fact about the rule.
type WindowsFirewallRuleFilters struct {
	Port          *WindowsFirewallPortFilter
	Address       *WindowsFirewallAddressFilter
	Application   *WindowsFirewallApplicationFilter
	Service       *WindowsFirewallServiceFilter
	InterfaceType *WindowsFirewallInterfaceTypeFilter
	Security      *WindowsFirewallSecurityFilter
}

// ParseWindowsFirewallRuleFilters decodes the combined filter payload and
// joins every filter collection onto its rule by InstanceID. The result is
// keyed by rule InstanceID.
func ParseWindowsFirewallRuleFilters(input io.Reader) (map[string]*WindowsFirewallRuleFilters, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	joined := map[string]*WindowsFirewallRuleFilters{}
	if len(bytes.TrimSpace(data)) == 0 {
		return joined, nil
	}

	var payload struct {
		Port          json.RawMessage `json:"Port"`
		Address       json.RawMessage `json:"Address"`
		Application   json.RawMessage `json:"Application"`
		Service       json.RawMessage `json:"Service"`
		InterfaceType json.RawMessage `json:"InterfaceType"`
		Security      json.RawMessage `json:"Security"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	entry := func(instanceID string) *WindowsFirewallRuleFilters {
		if instanceID == "" {
			return nil
		}
		f, ok := joined[instanceID]
		if !ok {
			f = &WindowsFirewallRuleFilters{}
			joined[instanceID] = f
		}
		return f
	}

	ports, err := decodePSObjectList[WindowsFirewallPortFilter](payload.Port)
	if err != nil {
		return nil, err
	}
	for i := range ports {
		if f := entry(ports[i].InstanceID); f != nil {
			f.Port = &ports[i]
		}
	}

	addresses, err := decodePSObjectList[WindowsFirewallAddressFilter](payload.Address)
	if err != nil {
		return nil, err
	}
	for i := range addresses {
		if f := entry(addresses[i].InstanceID); f != nil {
			f.Address = &addresses[i]
		}
	}

	applications, err := decodePSObjectList[WindowsFirewallApplicationFilter](payload.Application)
	if err != nil {
		return nil, err
	}
	for i := range applications {
		if f := entry(applications[i].InstanceID); f != nil {
			f.Application = &applications[i]
		}
	}

	services, err := decodePSObjectList[WindowsFirewallServiceFilter](payload.Service)
	if err != nil {
		return nil, err
	}
	for i := range services {
		if f := entry(services[i].InstanceID); f != nil {
			f.Service = &services[i]
		}
	}

	interfaceTypes, err := decodePSObjectList[WindowsFirewallInterfaceTypeFilter](payload.InterfaceType)
	if err != nil {
		return nil, err
	}
	for i := range interfaceTypes {
		if f := entry(interfaceTypes[i].InstanceID); f != nil {
			f.InterfaceType = &interfaceTypes[i]
		}
	}

	securities, err := decodePSObjectList[WindowsFirewallSecurityFilter](payload.Security)
	if err != nil {
		return nil, err
	}
	for i := range securities {
		if f := entry(securities[i].InstanceID); f != nil {
			f.Security = &securities[i]
		}
	}

	return joined, nil
}
