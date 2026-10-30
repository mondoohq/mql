// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsecs

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/id/containerid"
)

const (
	identityUrl = "${ECS_CONTAINER_METADATA_URI_V4}"
)

func MondooECSContainerID(containerArn string) string {
	var account, region, id string
	if arn.IsARN(containerArn) {
		if p, err := arn.Parse(containerArn); err == nil {
			account = p.AccountID
			region = p.Region
			id = p.Resource
		}
	}
	return "//platformid.api.mondoo.app/runtime/aws/ecs/v1/accounts/" + account + "/regions/" + region + "/" + id
}

var VALID_MONDOO_ECSCONTAINER_ID = regexp.MustCompile(`^//platformid.api.mondoo.app/runtime/aws/ecs/v1/accounts/\d{12}/regions\/(us(-gov)?|ap|ca|cn|eu|sa)-(central|(north|south)?(east|west)?)-\d\/container\/.+$`)

type ECSContainer struct {
	Account string
	Region  string
	Id      string
}

func ParseMondooECSContainerId(path string) (*ECSContainer, error) {
	if !IsValidMondooECSContainerId(path) {
		return nil, errors.New("invalid aws ecs container id")
	}
	keyValues := strings.Split(path, "/")
	if len(keyValues) != 15 {
		return nil, errors.New("invalid ecs container id length")
	}
	return &ECSContainer{Account: keyValues[8], Region: keyValues[10], Id: strings.Join(keyValues[12:], "/")}, nil
}

func IsValidMondooECSContainerId(path string) bool {
	return VALID_MONDOO_ECSCONTAINER_ID.MatchString(path)
}

type Identity struct {
	ContainerArn      string
	Name              string
	RuntimeID         string
	PlatformIds       []string
	AccountPlatformID string
}
type InstanceIdentifier interface {
	Identify() (Identity, error)
}

func Resolve(conn shared.Connection, pf *inventory.Platform) (InstanceIdentifier, error) {
	return &containerMetadata{conn, pf}, nil
}

type containerMetadata struct {
	conn     shared.Connection
	platform *inventory.Platform
}

func (m *containerMetadata) Identify() (Identity, error) {
	log.Debug().Msg("getting ecs container identity")

	containerDocument, err := m.containerIdentityDocument()
	if err != nil {
		return Identity{}, err
	}
	// parse into struct
	doc := EcrContainerIdentityDoc{}
	if err := json.NewDecoder(strings.NewReader(containerDocument)).Decode(&doc); err != nil {
		return Identity{}, errors.Wrap(err, "failed to decode ECS container identity document")
	}
	var accountID string
	if arn.IsARN(doc.ContainerArn) {
		if p, err := arn.Parse(doc.ContainerArn); err == nil {
			accountID = p.AccountID
		}
	}
	return Identity{
		Name:              doc.Name,
		ContainerArn:      doc.ContainerArn,
		RuntimeID:         doc.DockerId,
		AccountPlatformID: "//platformid.api.mondoo.app/runtime/aws/accounts/" + accountID,
		PlatformIds:       []string{MondooECSContainerID(doc.ContainerArn), containerid.MondooContainerID(doc.DockerId)},
	}, nil
}

func (m *containerMetadata) curlDocument(url string) (string, error) {
	cmd, err := m.conn.RunCommand("curl " + url)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

func (m *containerMetadata) containerIdentityDocument() (string, error) {
	return m.curlDocument(identityUrl)
}

type EcrContainerIdentityDoc struct {
	DockerId     string `json:"DockerId"`
	Name         string `json:"Name"`
	ContainerArn string `json:"ContainerARN"`
}
