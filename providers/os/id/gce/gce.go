// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gce

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/metadata"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// deprecated: use MondooGcpInstancePlatformMrn
func MondooGcpInstanceID(project string, zone string, instanceID uint64) string {
	return "//platformid.api.mondoo.app/runtime/gcp/compute/v1/projects/" + project + "/zones/" + zone + "/instances/" + strconv.FormatUint(uint64(instanceID), 10)
}

func MondooGcpInstancePlatformMrn(project string, zone string, instanceName string) string {
	return "//platformid.api.mondoo.app/runtime/gcp/compute/v1/projects/" + project + "/zones/" + zone + "/instances/" + instanceName
}

type Identity struct {
	ProjectID string
	// deprecated: use PlatformMrn
	InstanceID  string
	PlatformMrn string
}
type InstanceIdentifier interface {
	Identify() (Identity, error)
	RawMetadata() (any, error)
}

func Resolve(conn shared.Connection, pf *inventory.Platform) (InstanceIdentifier, error) {
	if pf.IsFamily(inventory.FAMILY_UNIX) || pf.IsFamily(inventory.FAMILY_WINDOWS) {
		return NewCommandInstanceMetadata(conn, pf), nil
	}
	return nil, fmt.Errorf(
		"gce id detector is not supported for your asset: %s %s",
		pf.Name, pf.Version,
	)
}

const (
	metadataSvcURL                = "http://metadata.google.internal/computeMetadata/v1/"
	metadataIdentityScriptWindows = `
$projectID = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Method GET -URI http://metadata.google.internal/computeMetadata/v1/project/project-id?alt=json -UseBasicParsing
$instanceID = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Method GET -URI http://metadata.google.internal/computeMetadata/v1/instance/id?alt=json -UseBasicParsing
$instanceName = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Method GET -URI http://metadata.google.internal/computeMetadata/v1/instance/name?alt=json -UseBasicParsing
$zone = Invoke-RestMethod -Headers @{"Metadata-Flavor"="Google"} -Method GET -URI http://metadata.google.internal/computeMetadata/v1/instance/zone?alt=json -UseBasicParsing

$doc = New-Object -TypeName PSObject
$doc | Add-Member -MemberType NoteProperty -Value $projectID -Name ProjectID
$doc | Add-Member -MemberType NoteProperty -Value $instanceID -Name InstanceID
$doc | Add-Member -MemberType NoteProperty -Value $instanceName -Name InstanceName
$doc | Add-Member -MemberType NoteProperty -Value $zone -Name ZoneInfo

$doc | ConvertTo-Json
`
)

func NewCommandInstanceMetadata(conn shared.Connection, platform *inventory.Platform) *CommandInstanceMetadata {
	return &CommandInstanceMetadata{
		connection: conn,
		platform:   platform,
	}
}

type CommandInstanceMetadata struct {
	connection shared.Connection
	platform   *inventory.Platform
}

func (m *CommandInstanceMetadata) RawMetadata() (any, error) {
	return metadata.Crawl(m, "instance/")
}

// GetMetadataValue implements metadata.recursive interface used to crawl the instance metadata service
func (m *CommandInstanceMetadata) GetMetadataValue(path string) (string, error) {
	return m.curl(path)
}

func (m *CommandInstanceMetadata) curlDecode(key string, v any) error {
	cmd, err := m.connection.RunCommand("curl --noproxy '*' -H Metadata-Flavor:Google " + metadataSvcURL + key + "?alt=json")
	if err != nil {
		return err
	}

	return json.NewDecoder(cmd.Stdout).Decode(v)
}

func (m *CommandInstanceMetadata) Identify() (Identity, error) {
	switch {
	case m.platform.IsFamily(inventory.FAMILY_UNIX):
		var projectID string
		var instanceID uint64
		var instanceName string
		var zoneInfo string

		if err := m.curlDecode("project/project-id", &projectID); err != nil {
			return Identity{}, err
		}

		if err := m.curlDecode("instance/id", &instanceID); err != nil {
			return Identity{}, err
		}

		if err := m.curlDecode("instance/name", &instanceName); err != nil {
			return Identity{}, err
		}

		if err := m.curlDecode("instance/zone", &zoneInfo); err != nil {
			return Identity{}, err
		}

		zone := zoneInfo[strings.LastIndex(zoneInfo, "/")+1:]
		return Identity{
			ProjectID:   "//platformid.api.mondoo.app/runtime/gcp/projects/" + projectID,
			InstanceID:  MondooGcpInstanceID(projectID, zone, instanceID),
			PlatformMrn: MondooGcpInstancePlatformMrn(projectID, zone, instanceName),
		}, nil
	case m.platform.IsFamily(inventory.FAMILY_WINDOWS):
		cmd, err := m.connection.RunCommand(powershell.Encode(metadataIdentityScriptWindows))
		if err != nil {
			return Identity{}, err
		}
		data, err := io.ReadAll(cmd.Stdout)
		if err != nil {
			return Identity{}, err
		}

		instanceDocument := strings.TrimSpace(string(data))
		doc := struct {
			ProjectID    string `json:"ProjectID"`
			InstanceID   uint64 `json:"InstanceID"`
			InstanceName string `json:"InstanceName"`
			ZoneInfo     string `json:"ZoneInfo"`
		}{}
		err = json.Unmarshal([]byte(instanceDocument), &doc)
		if err != nil {
			return Identity{}, errors.New("failed to parse JSON instance document")
		}
		zone := doc.ZoneInfo[strings.LastIndex(doc.ZoneInfo, "/")+1:]

		return Identity{
			ProjectID:   "//platformid.api.mondoo.app/runtime/gcp/projects/" + doc.ProjectID,
			InstanceID:  MondooGcpInstanceID(doc.ProjectID, zone, doc.InstanceID),
			PlatformMrn: MondooGcpInstancePlatformMrn(doc.ProjectID, zone, doc.InstanceName),
		}, nil
	default:
		return Identity{}, errors.New("your platform is not supported by gce metadata identifier resource")
	}
}
