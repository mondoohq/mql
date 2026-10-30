// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2

import (
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
)

// Compiled once: applied to each platform id being parsed.
var awsec2 = regexp.MustCompile(`^\/\/platformid.api.mondoo.app\/runtime\/aws\/ec2\/v1\/accounts\/(.*)\/regions\/(.*)\/instances\/(.*)$`)

// aws://ec2/v1/accounts/{account}/regions/{region}/instances/{instanceid}
func MondooInstanceID(account string, region string, instanceid string) string {
	return "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/" + account + "/regions/" + region + "/instances/" + instanceid
}

type MondooInstanceId struct {
	Account string
	Region  string
	Id      string
}

var VALID_MONDOO_INSTANCE_ID = regexp.MustCompile(`^//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/\d{12}/regions\/(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d\/instances\/.+$`)

func ParseMondooInstanceID(path string) (*MondooInstanceId, error) {
	if !IsValidMondooInstanceId(path) {
		return nil, errors.New("invalid aws ec2 instance id")
	}
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 13 {
		return nil, errors.New("invalid instance id")
	}
	return &MondooInstanceId{Account: keyValues[8], Region: keyValues[10], Id: keyValues[12]}, nil
}

func IsValidMondooInstanceId(path string) bool {
	return VALID_MONDOO_INSTANCE_ID.MatchString(path)
}

// aws://ec2/v1/accounts/{account}/regions/{region}/volumes/{volumeid}
func MondooVolumeID(account string, region string, volumeid string) string {
	return "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/" + account + "/regions/" + region + "/volumes/" + volumeid
}

type MondooVolumeId struct {
	Account string
	Region  string
	Id      string
}

var VALID_MONDOO_VOLUME_ID = regexp.MustCompile(`^//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/\d{12}/regions\/(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d\/volumes\/.+$`)

func ParseMondooVolumeID(path string) (*MondooVolumeId, error) {
	if !IsValidMondooVolumeId(path) {
		return nil, errors.New("invalid aws ec2 volume id")
	}
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 13 {
		return nil, errors.New("invalid volume id")
	}
	return &MondooVolumeId{Account: keyValues[8], Region: keyValues[10], Id: keyValues[12]}, nil
}

func IsValidMondooVolumeId(path string) bool {
	return VALID_MONDOO_VOLUME_ID.MatchString(path)
}

// aws://ec2/v1/accounts/{account}/regions/{region}/snapshots/{snapshotid}
func MondooSnapshotID(account string, region string, snapshotid string) string {
	return "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/" + account + "/regions/" + region + "/snapshots/" + snapshotid
}

type MondooSnapshotId struct {
	Account string
	Region  string
	Id      string
}

var VALID_MONDOO_SNAPSHOT_ID = regexp.MustCompile(`^//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/\d{12}/regions\/(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d\/snapshots\/.+$`)

func ParseMondooSnapshotID(path string) (*MondooSnapshotId, error) {
	if !IsValidMondooSnapshotId(path) {
		return nil, errors.New("invalid aws ec2 snapshot id")
	}
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 13 {
		return nil, errors.New("invalid snapshot id")
	}
	return &MondooSnapshotId{Account: keyValues[8], Region: keyValues[10], Id: keyValues[12]}, nil
}

func IsValidMondooSnapshotId(path string) bool {
	return VALID_MONDOO_SNAPSHOT_ID.MatchString(path)
}

var VALID_MONDOO_ACCOUNT_ID = regexp.MustCompile(`^//platformid.api.mondoo.app/runtime/aws/accounts/\d{12}$`)

func ParseMondooAccountID(path string) (string, error) {
	if !IsValidMondooAccountId(path) {
		return "", errors.New("invalid aws account id")
	}
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 7 {
		return "", errors.New("invalid aws account id")
	}
	return keyValues[6], nil
}

func IsValidMondooAccountId(path string) bool {
	return VALID_MONDOO_ACCOUNT_ID.MatchString(path)
}

func ParseEc2PlatformID(uri string) *MondooInstanceId {
	// aws://ec2/v1/accounts/{account}/regions/{region}/instances/{instanceid}
	m := awsec2.FindStringSubmatch(uri)
	if len(m) == 0 {
		return nil
	}

	return &MondooInstanceId{
		Account: m[1],
		Region:  m[2],
		Id:      m[3],
	}
}
