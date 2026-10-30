// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// PSGetWinRMListeners enumerates the configured WS-Management listeners.
//
// The listener configuration is not in the registry with the rest of the WinRM
// policy, so it is read through the WSMan provider. Each listener is a
// container whose children are the individual settings, which is why the
// settings are collected into a hashtable rather than selected directly.
//
// $ErrorActionPreference is Stop deliberately. A host with no listener
// configured is a normal, common state and yields an empty array; a
// configuration that cannot be read at all (the WinRM service is stopped) has
// to fail loudly instead, because an empty listener list satisfies every
// assertion an audit makes about listeners.
//
// Every value is emitted as a string and converted in Go. The WSMan provider
// reports Port and Enabled as strings already, and keeping the conversion on
// this side of the wire is what makes it testable without a Windows host.
const PSGetWinRMListeners = `$ErrorActionPreference='Stop'
$res=@()
foreach($l in @(Get-ChildItem -Path WSMan:\localhost\Listener)){
$h=@{}
foreach($i in @(Get-ChildItem -Path $l.PSPath)){$h[[string]$i.Name]=[string]$i.Value}
$res+=[ordered]@{Address=[string]$h['Address'];Transport=[string]$h['Transport'];Port=[string]$h['Port'];Hostname=[string]$h['Hostname'];Enabled=[string]$h['Enabled'];CertificateThumbprint=[string]$h['CertificateThumbprint']}
}
ConvertTo-Json -InputObject @($res) -Depth 4 -Compress`

// PSGetWinRMConfig reads the live WS-Management client, service and shell
// settings.
//
// These are the effective values, which already carry any Group Policy
// setting: the WinRM service applies the policy key to its own configuration.
// Reading the policy key instead gets two things wrong. It misses a value set
// locally with `winrm set winrm/config/client`, which is exactly the
// configuration worth finding. And when the policy key is absent, which is the
// normal state of a machine nobody has applied a WinRM GPO to, it has nothing
// to report but a guess at what Windows would do, and the guess does not match
// what Windows actually does: a stock Server 2016, 2019 and 2022 all report
// Basic authentication and unencrypted traffic as off on the service, and
// unencrypted traffic as off on the client.
//
// $ErrorActionPreference is Stop deliberately. Every one of these values
// exists on a supported host, so a read that fails means the configuration
// could not be reached, and reporting a default in its place would state as
// fact something nobody managed to check.
const PSGetWinRMConfig = `$ErrorActionPreference='Stop'
function V($p){[string](Get-Item -Path ("WSMan:\localhost\"+$p)).Value}
[ordered]@{
Client=[ordered]@{TrustedHosts=V 'Client\TrustedHosts';AllowBasic=V 'Client\Auth\Basic';AllowDigest=V 'Client\Auth\Digest';AllowUnencrypted=V 'Client\AllowUnencrypted'}
Service=[ordered]@{IPv4Filter=V 'Service\IPv4Filter';IPv6Filter=V 'Service\IPv6Filter';AllowBasic=V 'Service\Auth\Basic';AllowUnencrypted=V 'Service\AllowUnencrypted'}
Shell=[ordered]@{AllowRemoteShellAccess=V 'Shell\AllowRemoteShellAccess'}
}|ConvertTo-Json -Depth 4 -Compress`

// PSScalar decodes a WS-Management setting value.
//
// The WSMan provider reports every setting as a string, but ConvertTo-Json
// renders a value that reached it as a number or a boolean without quotes. A
// plain string tag fails the decode of the whole payload on one such value, so
// the number or boolean is kept verbatim instead. An absent value serializes
// as an empty object rather than as null, which is also flattened to empty.
type PSScalar string

func (s *PSScalar) UnmarshalJSON(data []byte) error {
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
		*s = PSScalar(v)
		return nil
	}
	*s = PSScalar(string(data))
	return nil
}

// WinRMListener is one configured WS-Management listener.
type WinRMListener struct {
	Address               PSScalar `json:"Address"`
	Transport             PSScalar `json:"Transport"`
	Port                  PSScalar `json:"Port"`
	Hostname              PSScalar `json:"Hostname"`
	Enabled               PSScalar `json:"Enabled"`
	CertificateThumbprint PSScalar `json:"CertificateThumbprint"`
}

// PortNumber returns the listener port, or 0 when it cannot be read. Reporting
// 0 rather than guessing 5985 keeps an unreadable port distinguishable from a
// listener that really is on the default port.
func (l WinRMListener) PortNumber() int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(string(l.Port)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// IsEnabled reports whether the listener is enabled. The WSMan provider writes
// the value as the string "true" or "false"; a value that is neither is read
// as disabled.
func (l WinRMListener) IsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(string(l.Enabled)), "true")
}

// Bool decodes a WS-Management boolean setting.
//
// The WSMan provider renders these as the strings "true" and "false".
// Anything else means the value read was not the setting expected, and it is
// reported as an error rather than quietly as false: "the service does not
// allow unencrypted traffic" is precisely the assertion an audit rests on, so
// a false here has to be a fact about the host and not a decode that missed.
func (s PSScalar) Bool() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(string(s))) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("expected a WS-Management boolean, got %q", string(s))
}

// ID builds the resource id of a listener.
//
// A listener is addressed by its address and transport together, which is also
// what makes the pair unique: one host can carry an HTTP and an HTTPS listener
// on the same address, and two listeners on different addresses with the same
// transport. Both dimensions are in the id, or the second listener reports the
// first one's port and certificate.
func (l WinRMListener) ID() string {
	return "windows.winrm.listener/" + string(l.Address) + "+" + string(l.Transport)
}

// ParseWinRMListeners decodes the listener list.
//
// It accepts every shape PowerShell produces for a list. An empty list is a
// bare [], a normal list is an array, and a single listener can arrive as a
// bare object when PowerShell flattens the one-element array away. A list that
// passed through a calculated property arrives as {"value":[...],"Count":n},
// which a plain slice tag would decode to empty and report as "no listeners"
// on a host that has one.
func ParseWinRMListeners(r io.Reader) ([]WinRMListener, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return []WinRMListener{}, nil
	}

	if data[0] == '{' {
		// tell the Count-wrapped list apart from a single flattened listener:
		// only the wrapper carries a "value" key holding an array
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(data, &probe); err != nil {
			return nil, err
		}
		if raw, ok := probe["value"]; ok {
			if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '[' {
				data = trimmed
			}
		}
		if data[0] == '{' {
			var single WinRMListener
			if err := json.Unmarshal(data, &single); err != nil {
				return nil, err
			}
			return []WinRMListener{single}, nil
		}
	}

	res := []WinRMListener{}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// WinRMConfig is the parsed result of PSGetWinRMConfig.
type WinRMConfig struct {
	Client  WinRMClientConfig  `json:"Client"`
	Service WinRMServiceConfig `json:"Service"`
	Shell   WinRMShellConfig   `json:"Shell"`
}

// WinRMClientConfig is the WS-Management client configuration.
type WinRMClientConfig struct {
	TrustedHosts     PSScalar `json:"TrustedHosts"`
	AllowBasic       PSScalar `json:"AllowBasic"`
	AllowDigest      PSScalar `json:"AllowDigest"`
	AllowUnencrypted PSScalar `json:"AllowUnencrypted"`
}

// WinRMServiceConfig is the WS-Management service configuration.
type WinRMServiceConfig struct {
	IPv4Filter       PSScalar `json:"IPv4Filter"`
	IPv6Filter       PSScalar `json:"IPv6Filter"`
	AllowBasic       PSScalar `json:"AllowBasic"`
	AllowUnencrypted PSScalar `json:"AllowUnencrypted"`
}

// WinRMShellConfig is the WS-Management shell (WinRS) configuration.
type WinRMShellConfig struct {
	AllowRemoteShellAccess PSScalar `json:"AllowRemoteShellAccess"`
}

// ParseWinRMConfig decodes the WS-Management client and service settings.
func ParseWinRMConfig(r io.Reader) (*WinRMConfig, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return &WinRMConfig{}, nil
	}

	var res WinRMConfig
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
