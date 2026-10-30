// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/awsebs"
	"go.mondoo.com/mql/providers/os/id/awsec2"
)

const AWS Provider = "AWS"

// aws implements the OSCloud interface for Amazon Web Services
type aws struct {
	conn shared.Connection
}

func (a *aws) Provider() Provider {
	return AWS
}

func (a *aws) getAwsEC2Metadata() (any, error) {
	mdsvc, err := awsec2.Resolve(a.conn, a.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).
			Str("method", "awsec2").
			Msg("os.cloud.aws> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := mdsvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).
			Str("method", "awsec2").
			Msg("os.cloud.aws> failed to get raw metadata")
		return nil, err
	}

	return metadata, nil
}

func (a *aws) getAwsEBSMetadata() (any, error) {
	mdsvc, err := awsebs.Resolve(a.conn, a.conn.Asset().GetPlatform())
	if err != nil {
		log.Debug().Err(err).
			Str("method", "awsebs").
			Msg("os.cloud.aws> failed to get metadata resolver")
		return nil, err
	}
	metadata, err := mdsvc.RawMetadata()
	if err != nil {
		log.Debug().Err(err).
			Str("method", "awsebs").
			Msg("os.cloud.aws> failed to get raw metadata")
		return nil, err
	}
	return metadata, nil
}

func (a *aws) Instance() (*InstanceMetadata, error) {
	var metadata any
	var err, errEBS error
	metadata, err = a.getAwsEC2Metadata()
	if err != nil {
		// Special case for when we are running an EBS scan.
		metadata, errEBS = a.getAwsEBSMetadata()
		if errEBS != nil {
			// we have no other way to detect instance information
			return nil, errors.New("failed to get instance metadata")
		}
	}

	if metadata == nil {
		log.Debug().Msg("os.cloud.aws> no metadata found")
		return nil, errors.New("no metadata")
	}

	instanceMd := InstanceMetadata{Metadata: metadata}

	m, ok := metadata.(map[string]any)
	if !ok {
		return &instanceMd, errors.New("unexpected raw metadata")
	}

	if value, ok := m["public-hostname"]; ok {
		instanceMd.PublicHostname = value.(string)
	}
	if value, ok := m["hostname"]; ok {
		instanceMd.PrivateHostname = value.(string)
	}

	if value, ok := m["network"]; ok {
		if byteData, err := json.Marshal(value); err != nil {
			log.Warn().Err(err).
				Msg("os.cloud.aws> failed to marshal network metadata, continuing with raw metadata only")
		} else {
			var network AWSNetwork
			if err := json.Unmarshal(byteData, &network); err != nil {
				// A single unexpected field must not blank out the entire
				// cloud.instance resource (including public/private IPs and the
				// raw metadata dict), so log and continue instead of returning
				// an error here.
				log.Warn().Err(err).
					Msg("os.cloud.aws> failed to parse network metadata, continuing with raw metadata only")
			} else {
				// all network interfaces
				instanceMd.PublicIpv4 = make([]Ipv4Address, 0)
				instanceMd.PrivateIpv4 = make([]Ipv4Address, 0)
				for mac, details := range network.Interfaces.Macs {
					ignored := true

					if ip, ok := details.PublicIP(); ok {
						instanceMd.PublicIpv4 = append(instanceMd.PublicIpv4, ip)
						ignored = false
					}

					if ip, ok := details.PrivateIP(); ok {
						instanceMd.PrivateIpv4 = append(instanceMd.PrivateIpv4, ip)
						ignored = false
					}

					if ignored {
						log.Debug().
							Str("mac", mac).
							Interface("interface_details", details).
							Msg("no valid public or private ipaddress, skipping")
					}
				}
			}
		}
	}

	return &instanceMd, nil
}

// AWSNetwork structure for AWS
type AWSNetwork struct {
	Interfaces AWSInterfaces `json:"interfaces"`
}

// AWSInterfaces structure for AWS
type AWSInterfaces struct {
	Macs map[string]MacDetails `json:"macs"`
}

// MacDetails structure
//
// Several IMDS fields are lists that the metadata service returns
// newline-separated (e.g. `security-group-ids`, `vpc-ipv4-cidr-blocks`,
// `local-ipv4s`). When an interface has more than one value the metadata
// crawler renders them as a JSON array (or, historically, an object), so those
// fields use `stringList` rather than a plain string. `owner-id` may be a
// numeric account id or a string such as `amazon-elb` for service-managed ENIs,
// so it uses `flexString`. This keeps a multi-valued interface from breaking
// deserialization of the whole instance metadata.
type MacDetails struct {
	DeviceNumber        int64      `json:"device-number"`
	InterfaceID         string     `json:"interface-id"`
	IPv4Associations    stringList `json:"ipv4-associations"`
	LocalHostname       string     `json:"local-hostname"`
	LocalIPv4s          stringList `json:"local-ipv4s"`
	Mac                 string     `json:"mac"`
	OwnerID             flexString `json:"owner-id"`
	PublicHostname      string     `json:"public-hostname"`
	PublicIPv4s         stringList `json:"public-ipv4s"`
	SecurityGroupIDs    stringList `json:"security-group-ids"`
	SecurityGroups      stringList `json:"security-groups"`
	SubnetID            string     `json:"subnet-id"`
	SubnetIPv4CIDRBlock string     `json:"subnet-ipv4-cidr-block"`
	VPCID               string     `json:"vpc-id"`
	VPCIPv4CIDRBlock    string     `json:"vpc-ipv4-cidr-block"`
	VPCIPv4CIDRBlocks   stringList `json:"vpc-ipv4-cidr-blocks"`
}

// PublicIP detects if the network interface has a public ip address,
// if so it initializes an Ipv4Address struct and return true.
func (d MacDetails) PublicIP() (Ipv4Address, bool) {
	ip := d.PublicIPv4s.First()
	return Ipv4Address{IP: ip}, ip != ""
}

// PrivateIP detects if the network interface has a private ip address,
// if so it initializes an Ipv4Address structure and return true.
func (d MacDetails) PrivateIP() (Ipv4Address, bool) {
	// Note that AWS has two IP ranges, the VPC (`VPCIPv4CIDRBlock`) and the
	// Subnet (`SubnetIPv4CIDRBlock`), we use the logical segment since there
	// are cases where the subnet might have additional configuration like ACLs,
	// route tables, etc. that we can't detect from within the os
	ip := d.LocalIPv4s.First()
	return NewIpv4WithSubnet(ip, d.SubnetIPv4CIDRBlock), ip != ""
}

// stringList normalizes EC2 IMDS metadata fields that may arrive as a single
// scalar string, a bare scalar (e.g. a number), a JSON array, or—when the
// field holds multiple newline-separated values—an object produced by the
// metadata crawler. All shapes are flattened to a []string so a multi-valued
// interface no longer breaks deserialization of the whole instance metadata.
type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}

	switch data[0] {
	case '"':
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		if str != "" {
			*s = stringList{str}
		}
	case '[':
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*s = stringList(arr)
	case '{':
		// Older metadata crawlers render a newline-separated value list as an
		// object keyed by the values; recover the values as the list entries.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		*s = stringList(keys)
	default:
		// bare scalar (e.g. a number); keep its textual representation
		*s = stringList{string(data)}
	}
	return nil
}

// First returns the first value of the list, or an empty string if the list is
// empty. Most consumers expect a single primary value (e.g. the primary IP).
func (s stringList) First() string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// flexString accepts a value that AWS IMDS may return either as a JSON number
// (e.g. an account-owned `owner-id`) or as a string (e.g. `amazon-elb` for
// service-managed ENIs) and stores it as a string.
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*f = flexString(str)
		return nil
	}
	*f = flexString(string(data))
	return nil
}
