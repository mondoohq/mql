// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ibmcompute

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// By default, instances are created with the metadata service endpoint disabled. You can
// enable the metadata service either when creating a VPC instance or by updating the VPC
// instance after creation.
//
// https://cloud.ibm.com/docs/apis/vpc-metadata/latest
//

const identityURLPath = "/metadata/v1/instance?version=2025-05-20"

type Identity struct {
	InstanceName string
	InstanceID   string
	PlatformMrns []string
}

type InstanceIdentifier interface {
	Identify() (Identity, error)
	RawMetadata() (any, error)
}

type commandInstanceMetadata struct {
	conn     shared.Connection
	platform *inventory.Platform

	// used internally to avoid fetching a token multiple times
	token string
}

func Resolve(conn shared.Connection, pf *inventory.Platform) (InstanceIdentifier, error) {
	return &commandInstanceMetadata{conn, pf, ""}, nil
}

func (m *commandInstanceMetadata) Identify() (Identity, error) {
	instance, err := m.instanceIdentity()
	if err != nil {
		return Identity{}, err
	}

	log.Debug().Interface("instance", instance).Msg("identity")

	platformMrns := []string{}
	mondooInstanceID := "//platformid.api.mondoo.app/runtime/ibm/compute/v1"

	// Add the scope if we can find it
	if scope, ok := instance.Scope(); ok {
		mondooInstanceID += "/" + scope.String()

		// Add the owner of the resource to the platform MRNs
		platformMrns = append(platformMrns, "//platformid.api.mondoo.app/runtime/ibm/compute/v1/"+scope.String())
	}

	// Add the location if we can find it
	if location, ok := instance.Location(); ok {
		mondooInstanceID += "/location/" + location
	}

	// finally, add the instance id
	mondooInstanceID += "/instances/" + instance.ID

	return Identity{
		InstanceID:   mondooInstanceID,
		InstanceName: instance.Name,
		PlatformMrns: platformMrns,
	}, nil
}

func (m *commandInstanceMetadata) RawMetadata() (any, error) {
	return m.instanceIdentity()
}

func (m *commandInstanceMetadata) GetMetadataValue(path string) (string, error) {
	return m.curlDocument(path)
}

func (m *commandInstanceMetadata) getToken() (string, error) {
	if m.token != "" {
		return m.token, nil
	}

	var commandString string
	switch {
	case m.platform.IsFamily(inventory.FAMILY_UNIX):
		commandString = unixTokenCmdString()
	case m.platform.IsFamily(inventory.FAMILY_WINDOWS):
		commandString = windowsTokenCmdString()
	default:
		return "", errors.New("your platform is not supported by ibm metadata identifier resource")
	}

	cmd, err := m.conn.RunCommand(commandString)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	var tokenResponse struct {
		AccessToken string    `json:"access_token"`
		CreatedAt   time.Time `json:"created_at"`
		ExpiresAt   time.Time `json:"expires_at"`
		ExpiresIn   int       `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &tokenResponse); err != nil {
		return "", err
	}

	m.token = tokenResponse.AccessToken

	return m.token, err
}

func (m *commandInstanceMetadata) curlDocument(metadataPath string) (string, error) {
	token, err := m.getToken()
	if err != nil {
		return "", err
	}

	var commandString string
	switch {
	case m.platform.IsFamily(inventory.FAMILY_UNIX):
		commandString = unixMetadataCmdString(token, metadataPath)
	case m.platform.IsFamily(inventory.FAMILY_WINDOWS):
		commandString = windowsMetadataCmdString(token, metadataPath)
	default:
		return "", errors.New("your platform is not supported by aws metadata identifier resource")
	}

	log.Debug().Str("command_string", commandString).Msg("running os command")
	cmd, err := m.conn.RunCommand(commandString)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(cmd.Stdout)
	return strings.TrimSpace(string(data)), err
}

func (m *commandInstanceMetadata) instanceIdentity() (*Instance, error) {
	doc, err := m.curlDocument(identityURLPath)
	if err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, errors.New("metadata service returned an empty response")
	}

	instance := Instance{}
	if err := json.NewDecoder(strings.NewReader(doc)).Decode(&instance); err != nil {
		return nil, errors.Wrap(err, "failed to decode IBM instance identity response")
	}

	return &instance, nil
}

type Instance struct {
	BootVolumeAttachment struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
		ID     string `json:"id"`
		Name   string `json:"name"`
		Volume struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"volume"`
	} `json:"boot_volume_attachment"`
	ClusterNetworkAttachments []any     `json:"cluster_network_attachments"`
	ConfidentialComputeMode   string    `json:"confidential_compute_mode"`
	CreatedAt                 time.Time `json:"created_at"`
	CRN                       string    `json:"crn"`
	DedicatedHost             struct {
		CRN          string `json:"crn"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		ResourceType string `json:"resource_type"`
	} `json:"dedicated_host"`
	Disks            []any  `json:"disks"`
	EnableSecureBoot bool   `json:"enable_secure_boot"`
	HealthReasons    []any  `json:"health_reasons"`
	HealthState      string `json:"health_state"`
	ID               string `json:"id"`
	Image            struct {
		CRN          string `json:"crn"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		ResourceType string `json:"resource_type"`
	} `json:"image"`
	LifecycleReasons []any  `json:"lifecycle_reasons"`
	LifecycleState   string `json:"lifecycle_state"`
	Memory           int    `json:"memory"`
	MetadataService  struct {
		Enabled          bool   `json:"enabled"`
		Protocol         string `json:"protocol"`
		ResponseHopLimit int    `json:"response_hop_limit"`
	} `json:"metadata_service"`
	Name               string `json:"name"`
	NetworkAttachments []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		PrimaryIP struct {
			Address      string `json:"address"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"primary_ip"`
		ResourceType string `json:"resource_type"`
		Subnet       struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"subnet"`
		VirtualNetworkInterface struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"virtual_network_interface"`
	} `json:"network_attachments"`
	NetworkInterfaces []struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		PrimaryIpv4Address string `json:"primary_ipv4_address"`
		ResourceType       string `json:"resource_type"`
		Subnet             struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"subnet"`
	} `json:"network_interfaces"`
	NumaCount       int `json:"numa_count"`
	PlacementTarget struct {
		CRN          string `json:"crn"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		ResourceType string `json:"resource_type"`
	} `json:"placement_target"`
	PrimaryNetworkAttachment struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		PrimaryIP struct {
			Address      string `json:"address"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"primary_ip"`
		ResourceType string `json:"resource_type"`
		Subnet       struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"subnet"`
		VirtualNetworkInterface struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"virtual_network_interface"`
	} `json:"primary_network_attachment"`
	PrimaryNetworkInterface struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		PrimaryIpv4Address string `json:"primary_ipv4_address"`
		ResourceType       string `json:"resource_type"`
		Subnet             struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"subnet"`
	} `json:"primary_network_interface"`
	Profile struct {
		Name         string `json:"name"`
		ResourceType string `json:"resource_type"`
	} `json:"profile"`
	ReservationAffinity struct {
		Policy string `json:"policy"`
		Pool   []any  `json:"pool"`
	} `json:"reservation_affinity"`
	ResourceGroup struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"resource_group"`
	ResourceType          string `json:"resource_type"`
	Startable             bool   `json:"startable"`
	Status                string `json:"status"`
	StatusReasons         []any  `json:"status_reasons"`
	TotalNetworkBandwidth int    `json:"total_network_bandwidth"`
	TotalVolumeBandwidth  int    `json:"total_volume_bandwidth"`
	Vcpu                  struct {
		Architecture string `json:"architecture"`
		Count        int    `json:"count"`
		Manufacturer string `json:"manufacturer"`
	} `json:"vcpu"`
	VolumeAttachments []struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
		ID     string `json:"id"`
		Name   string `json:"name"`
		Volume struct {
			CRN          string `json:"crn"`
			ID           string `json:"id"`
			Name         string `json:"name"`
			ResourceType string `json:"resource_type"`
		} `json:"volume"`
	} `json:"volume_attachments"`
	Vpc struct {
		CRN          string `json:"crn"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		ResourceType string `json:"resource_type"`
	} `json:"vpc"`
	Zone struct {
		Name string `json:"name"`
	} `json:"zone"`
}

// CRN format
//
// The base canonical format of a CRN is:
//
//	crn:version:cname:ctype:service-name:location:scope:service-instance:resource-type:resource
//
// https://cloud.ibm.com/docs/account?topic=account-crn
var crnRegex = regexp.MustCompile(`^crn:([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$`)

type CRN struct {
	Version         string // e.g., "v1"
	CName           string // Cloud name, e.g., "bluemix"
	CType           string // Cloud type, e.g., "public"
	ServiceName     string // e.g., "iam"
	Location        string // e.g., "us-south"
	Scope           string // e.g., ""
	ServiceInstance string // e.g., "a/123456"
	ResourceType    string // e.g., "resource-type"
	Resource        string // e.g., "resource-id"
}

func ParseCRN(input string) (*CRN, error) {
	matches := crnRegex.FindStringSubmatch(input)
	if matches == nil {
		return nil, fmt.Errorf("invalid CRN format")
	}
	return &CRN{
		Version:         matches[1],
		CName:           matches[2],
		CType:           matches[3],
		ServiceName:     matches[4],
		Location:        matches[5],
		Scope:           matches[6],
		ServiceInstance: matches[7],
		ResourceType:    matches[8],
		Resource:        matches[9],
	}, nil
}

func (i *Instance) ParsedCRN() (*CRN, error) {
	return ParseCRN(i.CRN)
}

// The cloud geography/region/zone/data center that the resource resides.
//
// https://cloud.ibm.com/docs/account?topic=account-crn
func (i *Instance) Location() (string, bool) {
	if crn, err := i.ParsedCRN(); err == nil {
		return crn.Location, true
	}
	return "", false
}

type Scope struct {
	Prefix string // "a", "o", "s" or other custom scope types
	ID     string // the identifier (e.g., account ID, org GUID, space GUID)
}

var scopeRegex = regexp.MustCompile(`^(?:(a|o|s)/([^/]+))?$`)

func ParseScope(scopeStr string) (*Scope, error) {
	if scopeStr == "" {
		return nil, nil // Global scope (no owner)
	}

	matches := scopeRegex.FindStringSubmatch(scopeStr)
	if matches == nil {
		return nil, fmt.Errorf("invalid scope format")
	}

	return &Scope{
		Prefix: matches[1],
		ID:     matches[2],
	}, nil
}

func (s *Scope) String() string {
	// https://cloud.ibm.com/docs/account?topic=account-crn
	switch s.Prefix {
	case "a":
		return "accounts/" + s.ID
	case "o":
		return "organizations/" + s.ID
	case "s":
		return "spaces/" + s.ID
	}

	return "global/" + s.ID
}

// The scope segment identifies the containment or owner of the resource. Some
// resources do not require an owner (they can be considered global). In this
// case, the scope segment is empty (a blank string).
//
// The value of the scope segment must be formatted as {scopePrefix}/{id}. The
// scopePrefix represents the format that is used to identify the owner or
// containment. The id represents the identity of the owner or containment in
// a format that is specific to the scopePrefix.
//
// https://cloud.ibm.com/docs/account?topic=account-crn
func (i *Instance) Scope() (*Scope, bool) {
	if crn, err := i.ParsedCRN(); err == nil {
		if scope, err := ParseScope(crn.Scope); err == nil {
			return scope, true
		}
		log.Debug().Err(err).
			Str("scope_string", crn.Scope).
			Msg("id.ibmcompute> unable to parse CRN scope")
	}
	return nil, false
}
