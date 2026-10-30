// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hetznercloud

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"gopkg.in/yaml.v3"
)

const (
	metadataSvcURL = "http://169.254.169.254/hetzner/v1/metadata"
)

func MondooHetznerInstanceID(instanceID string) string {
	return "//platformid.api.mondoo.app/runtime/hetzner/instances/" + instanceID
}

type Identity struct {
	InstanceID string
	Hostname   string
	Region     string
}

type InstanceIdentifier interface {
	Identify() (Identity, error)
	RawMetadata() (any, error)
}

func Resolve(conn shared.Connection, pf *inventory.Platform) (InstanceIdentifier, error) {
	if pf.IsFamily(inventory.FAMILY_UNIX) || pf.IsFamily(inventory.FAMILY_WINDOWS) {
		return &commandInstanceMetadata{conn, pf}, nil
	}
	return nil, fmt.Errorf(
		"hetzner cloud id detector is not supported for your asset: %s %s",
		pf.Name, pf.Version,
	)
}

// hetznerMetadata represents the YAML structure returned by the Hetzner metadata service
type hetznerMetadata struct {
	InstanceID       int    `yaml:"instance-id"`
	Hostname         string `yaml:"hostname"`
	Region           string `yaml:"region"`
	AvailabilityZone string `yaml:"availability-zone"`
	LocalIPv4        string `yaml:"local-ipv4"`
	PublicIPv4       string `yaml:"public-ipv4"`
}

type commandInstanceMetadata struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (m *commandInstanceMetadata) RawMetadata() (any, error) {
	data, err := m.fetchMetadata()
	if err != nil {
		return nil, err
	}

	var rawMap map[string]any
	if err := yaml.Unmarshal(data, &rawMap); err != nil {
		return nil, err
	}
	return rawMap, nil
}

func (m *commandInstanceMetadata) Identify() (Identity, error) {
	data, err := m.fetchMetadata()
	if err != nil {
		return Identity{}, err
	}

	md := hetznerMetadata{}
	if err := yaml.Unmarshal(data, &md); err != nil {
		return Identity{}, fmt.Errorf("failed to decode Hetzner metadata: %w", err)
	}

	if md.InstanceID == 0 {
		return Identity{}, errors.New("hetzner metadata did not contain an instance-id")
	}

	return Identity{
		InstanceID: MondooHetznerInstanceID(fmt.Sprintf("%d", md.InstanceID)),
		Hostname:   md.Hostname,
		Region:     md.Region,
	}, nil
}

// windowsMetadataScript reads the metadata document on Windows. Windows
// PowerShell 5.1 aliases `curl` to Invoke-WebRequest, which rejects curl's
// flags, so the Unix command cannot be reused. It retries like the Unix
// command (three attempts, a two-second timeout each), returns the raw YAML
// document, and exits non-zero when the service does not answer.
//
// Invoke-WebRequest returns Content as a string only for a text content
// type. For any other, or none, it is the raw bytes, and writing those would
// print "System.Byte[]" and exit 0, so the bytes are decoded first.
const windowsMetadataScript = `$ErrorActionPreference = 'Stop'
# no proxy for the link-local metadata service (curl's --noproxy '*')
[System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy
$uri = '` + metadataSvcURL + `'
for ($i = 1; $i -le 3; $i++) {
  try {
    $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 2
    $content = $r.Content
    if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
    [Console]::Out.Write($content)
    exit 0
  } catch {
    if ($i -eq 3) { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
    Start-Sleep -Seconds 1
  }
}`

func (m *commandInstanceMetadata) metadataCommand() string {
	if m.platform.IsFamily(inventory.FAMILY_WINDOWS) {
		return powershell.Encode(windowsMetadataScript)
	}
	return fmt.Sprintf("curl --retry 3 --retry-delay 1 --connect-timeout 1 --retry-max-time 5 --max-time 10 --noproxy '*' %s", metadataSvcURL)
}

func (m *commandInstanceMetadata) fetchMetadata() ([]byte, error) {
	cmd, err := m.conn.RunCommand(m.metadataCommand())
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("hetzner metadata request failed with exit status %d", cmd.ExitStatus)
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, errors.New("empty response from Hetzner metadata service")
	}

	return []byte(content), nil
}
