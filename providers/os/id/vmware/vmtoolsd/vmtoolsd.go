// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vmtoolsd

import (
	"fmt"
	"io"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/hostname"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type InstanceIdentifier interface {
	Identify() (Identity, error)
	RawMetadata() (any, error)
}

type Identity struct {
	UUID        string
	VCenterMOID string
	VSphereMOID string
}

func Resolve(conn shared.Connection, pf *inventory.Platform) (InstanceIdentifier, error) {
	if pf.IsFamily(inventory.FAMILY_UNIX) || pf.IsFamily(inventory.FAMILY_WINDOWS) {
		return &CommandInstanceMetadata{
			connection: conn,
			platform:   pf,
		}, nil
	}

	return nil, fmt.Errorf(
		"vmtoolsd id detector is not supported for your asset: %s %s",
		pf.Name, pf.Version,
	)
}

type CommandInstanceMetadata struct {
	connection shared.Connection
	platform   *inventory.Platform
}

func (m *CommandInstanceMetadata) RawMetadata() (any, error) {
	raw := map[string]any{}

	ovfEnv, err := m.OVFEnv()
	if err == nil {
		// not all VMs have this setting enabled
		raw["ovf"] = ovfEnv
	}

	ipv4, err := m.IPv4()
	if err == nil {
		// we might not be able to detect the ipv4
		raw["ipv4"] = ipv4
	}

	hostname, err := m.Hostname()
	if err != nil {
		return raw, err
	}
	raw["hostname"] = hostname

	// TODO look into more metadata

	return raw, nil
}

func (m *CommandInstanceMetadata) Identify() (Identity, error) {
	identt := Identity{}

	// collecting the UUID from the virtual machine may require 'sudo' access
	uuid, err := m.UUID()
	if err != nil {
		return identt, err
	}

	identt.UUID = "//platformid.api.mondoo.app/runtime/vmware/uuid/" + uuid

	// only if OVF settings are enabled
	ovfEnv, err := m.OVFEnv()
	if err == nil {
		if ovfEnv.EsxID != "" {
			identt.VSphereMOID = "//platformid.api.mondoo.app/runtime/vsphere/moid/" + ovfEnv.EsxID
		}
		if ovfEnv.VCenterID != "" {
			identt.VCenterMOID = "//platformid.api.mondoo.app/runtime/vcenter/moid/" + ovfEnv.VCenterID
		}
	}

	return identt, nil
}

func (m *CommandInstanceMetadata) UUID() (string, error) {
	uuid, err := m.vmtoolsdGuestInfo("uuid")
	if err == nil && uuid != "" {
		return uuid, nil
	}

	vmid, err := m.vmtoolsdGuestInfo("vmid")
	if err == nil && vmid != "" {
		return vmid, nil
	}

	// try to get this information from the os directly
	switch {
	case m.platform.IsFamily(inventory.FAMILY_UNIX):
		content, err := afero.ReadFile(m.connection.FileSystem(), "/sys/class/dmi/id/product_uuid")
		return strings.TrimSpace(string(content)), errors.Wrap(err, "unable to detect vm uuid")
	case m.platform.IsFamily(inventory.FAMILY_WINDOWS):
		rawUUID, err := m.RunCommand("(Get-WmiObject Win32_ComputerSystemProduct).UUID")
		return strings.TrimSpace(string(rawUUID)), errors.Wrap(err, "unable to detect vm uuid")
	}

	return "", errors.New("unable to detect vm uuid")
}

func (m *CommandInstanceMetadata) Hostname() (string, error) {
	name, err := m.vmtoolsdGuestInfo("hostname")
	if err == nil && name != "" {
		return name, nil
	}

	dnsName, err := m.vmtoolsdGuestInfo("dns-name")
	if err == nil && dnsName != "" {
		return dnsName, nil
	}

	// try to get this information from the os directly
	rawHostname, ok := hostname.Hostname(m.connection, m.platform)
	if ok && rawHostname != "" {
		return rawHostname, nil
	}

	return "", errors.New("unable to detect vm hostname")
}

func (m *CommandInstanceMetadata) IPv4() (string, error) {
	ip, err := m.vmtoolsdGuestInfo("ip")
	if err == nil && ip != "" {
		return ip, nil
	}

	log.Debug().Err(err).Msg("unable to get vmtoolsd ip data")

	ipv4, err := m.vmtoolsdGuestInfo("ipv4")
	if err == nil && ipv4 != "" {
		return ipv4, nil
	}

	log.Debug().Err(err).Msg("unable to get vmtoolsd ipv4 data")

	// TODO maybe try to get this information from the os directly
	//
	// interfaces, err := network.Interfaces()

	return "", errors.New("unable to detect ipv4")
}

// RunCommand is a wrapper around connection.RunCommand that helps execute commands
// and read the standard output for unix and windows systems.
func (m *CommandInstanceMetadata) RunCommand(commandString string) (string, error) {
	if m.platform.IsFamily(inventory.FAMILY_WINDOWS) {
		commandString = powershell.Encode(commandString)
	}
	cmd, err := m.connection.RunCommand(commandString)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// vmtoolsdGuestInfo runs vmtoolsd to fetch guest info with the provided key
func (m *CommandInstanceMetadata) vmtoolsdGuestInfo(key string) (string, error) {
	return m.RunCommand(fmt.Sprintf("%s --cmd \"info-get guestinfo.%s\"", m.vmtoolsd(), key))
}

func (m *CommandInstanceMetadata) vmtoolsd() string {
	if m.platform.IsFamily(inventory.FAMILY_WINDOWS) {
		return `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`
	}
	return "vmtoolsd"
}
