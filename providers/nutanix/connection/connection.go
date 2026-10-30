// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"sync"

	clustermgmtapi "github.com/nutanix/ntnx-api-golang-clients/clustermgmt-go-client/v4/api"
	clustermgmtclient "github.com/nutanix/ntnx-api-golang-clients/clustermgmt-go-client/v4/client"
	iamapi "github.com/nutanix/ntnx-api-golang-clients/iam-go-client/v4/api"
	iamclient "github.com/nutanix/ntnx-api-golang-clients/iam-go-client/v4/client"
	netapi "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/api"
	netclient "github.com/nutanix/ntnx-api-golang-clients/networking-go-client/v4/client"
	vmmapi "github.com/nutanix/ntnx-api-golang-clients/vmm-go-client/v4/api"
	vmmclient "github.com/nutanix/ntnx-api-golang-clients/vmm-go-client/v4/client"
	volapi "github.com/nutanix/ntnx-api-golang-clients/volumes-go-client/v4/api"
	volclient "github.com/nutanix/ntnx-api-golang-clients/volumes-go-client/v4/client"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const defaultPort = 9440

type NutanixConnection struct {
	plugin.Connection
	Conf     *inventory.Config
	asset    *inventory.Asset
	endpoint string
	port     int
	// SDK clients, one per API namespace
	cmgClient *clustermgmtclient.ApiClient
	vmmClient *vmmclient.ApiClient
	iamClient *iamclient.ApiClient
	netClient *netclient.ApiClient
	volClient *volclient.ApiClient
	// The v4 SDK ApiClient mutates per-request state (auth header, session
	// cookie, negotiated API version) on every call without any internal
	// locking, so a client shared across mql's concurrent field resolution is
	// not safe for concurrent use. Each namespace client is guarded by its own
	// mutex; calls in different namespaces still run in parallel.
	cmgMu sync.Mutex
	vmmMu sync.Mutex
	iamMu sync.Mutex
	netMu sync.Mutex
	volMu sync.Mutex
}

// CmgMu guards the cluster-management namespace client.
func (c *NutanixConnection) CmgMu() *sync.Mutex { return &c.cmgMu }

// VmmMu guards the VM-management namespace client.
func (c *NutanixConnection) VmmMu() *sync.Mutex { return &c.vmmMu }

// IamMu guards the IAM namespace client.
func (c *NutanixConnection) IamMu() *sync.Mutex { return &c.iamMu }

// NetMu guards the networking namespace client.
func (c *NutanixConnection) NetMu() *sync.Mutex { return &c.netMu }

// VolMu guards the volumes namespace client.
func (c *NutanixConnection) VolMu() *sync.Mutex { return &c.volMu }

func NewNutanixConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*NutanixConnection, error) {
	endpoint := conf.Host
	if endpoint == "" {
		endpoint = conf.Options["endpoint"]
	}
	if endpoint == "" {
		return nil, errors.New("missing Prism Central endpoint, use --endpoint")
	}

	port := defaultPort
	if p, ok := conf.Options["port"]; ok && p != "" {
		if _, err := fmt.Sscanf(p, "%d", &port); err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
	}

	user := conf.Options["user"]
	apiKey := conf.Options["api-key"]

	var password string
	for _, cred := range conf.Credentials {
		switch cred.Type {
		case vault.CredentialType_password:
			if cred.User != "" {
				user = cred.User
			}
			password = string(cred.Secret)
		case vault.CredentialType_bearer:
			if apiKey == "" {
				if len(cred.Secret) > 0 {
					apiKey = string(cred.Secret)
				} else {
					apiKey = cred.Password
				}
			}
		}
	}

	if apiKey == "" && (user == "" || password == "") {
		return nil, errors.New("missing credentials: provide --user with --password/--ask-pass, or --api-key")
	}

	conn := &NutanixConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		endpoint:   endpoint,
		port:       port,
	}

	// Each v4 namespace ships its own ApiClient type with identical configuration
	// surface; they are configured the same way against the Prism Central endpoint.
	conn.cmgClient = clustermgmtclient.NewApiClient()
	conn.cmgClient.Host = endpoint
	conn.cmgClient.Port = port
	conn.cmgClient.SetVerifySSL(!conf.Insecure)

	conn.vmmClient = vmmclient.NewApiClient()
	conn.vmmClient.Host = endpoint
	conn.vmmClient.Port = port
	conn.vmmClient.SetVerifySSL(!conf.Insecure)

	conn.iamClient = iamclient.NewApiClient()
	conn.iamClient.Host = endpoint
	conn.iamClient.Port = port
	conn.iamClient.SetVerifySSL(!conf.Insecure)

	conn.netClient = netclient.NewApiClient()
	conn.netClient.Host = endpoint
	conn.netClient.Port = port
	conn.netClient.SetVerifySSL(!conf.Insecure)

	conn.volClient = volclient.NewApiClient()
	conn.volClient.Host = endpoint
	conn.volClient.Port = port
	conn.volClient.SetVerifySSL(!conf.Insecure)

	if apiKey != "" {
		if err := conn.cmgClient.SetApiKey(apiKey); err != nil {
			return nil, err
		}
		if err := conn.vmmClient.SetApiKey(apiKey); err != nil {
			return nil, err
		}
		if err := conn.iamClient.SetApiKey(apiKey); err != nil {
			return nil, err
		}
		if err := conn.netClient.SetApiKey(apiKey); err != nil {
			return nil, err
		}
		if err := conn.volClient.SetApiKey(apiKey); err != nil {
			return nil, err
		}
	} else {
		conn.cmgClient.Username, conn.cmgClient.Password = user, password
		conn.vmmClient.Username, conn.vmmClient.Password = user, password
		conn.iamClient.Username, conn.iamClient.Password = user, password
		conn.netClient.Username, conn.netClient.Password = user, password
		conn.volClient.Username, conn.volClient.Password = user, password
	}

	return conn, nil
}

func (c *NutanixConnection) Name() string {
	return "nutanix"
}

func (c *NutanixConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *NutanixConnection) Endpoint() string {
	return c.endpoint
}

// ClustersApi returns the cluster-management API for clusters and hosts.
func (c *NutanixConnection) ClustersApi() *clustermgmtapi.ClustersApi {
	return clustermgmtapi.NewClustersApi(c.cmgClient)
}

// VmApi returns the VM-management API for virtual machines.
func (c *NutanixConnection) VmApi() *vmmapi.VmApi {
	return vmmapi.NewVmApi(c.vmmClient)
}

// ImagesApi returns the VMM images API.
func (c *NutanixConnection) ImagesApi() *vmmapi.ImagesApi {
	return vmmapi.NewImagesApi(c.vmmClient)
}

// UsersApi returns the IAM users API.
func (c *NutanixConnection) UsersApi() *iamapi.UsersApi {
	return iamapi.NewUsersApi(c.iamClient)
}

// UserGroupsApi returns the IAM user-groups API.
func (c *NutanixConnection) UserGroupsApi() *iamapi.UserGroupsApi {
	return iamapi.NewUserGroupsApi(c.iamClient)
}

// RolesApi returns the IAM roles API.
func (c *NutanixConnection) RolesApi() *iamapi.RolesApi {
	return iamapi.NewRolesApi(c.iamClient)
}

// AuthorizationPoliciesApi returns the IAM authorization-policies API.
func (c *NutanixConnection) AuthorizationPoliciesApi() *iamapi.AuthorizationPoliciesApi {
	return iamapi.NewAuthorizationPoliciesApi(c.iamClient)
}

// DirectoryServicesApi returns the IAM directory-services API.
func (c *NutanixConnection) DirectoryServicesApi() *iamapi.DirectoryServicesApi {
	return iamapi.NewDirectoryServicesApi(c.iamClient)
}

// SamlIdentityProvidersApi returns the IAM SAML identity-providers API.
func (c *NutanixConnection) SamlIdentityProvidersApi() *iamapi.SAMLIdentityProvidersApi {
	return iamapi.NewSAMLIdentityProvidersApi(c.iamClient)
}

// VpcsApi returns the networking VPCs API.
func (c *NutanixConnection) VpcsApi() *netapi.VpcsApi {
	return netapi.NewVpcsApi(c.netClient)
}

// SubnetsApi returns the networking subnets API.
func (c *NutanixConnection) SubnetsApi() *netapi.SubnetsApi {
	return netapi.NewSubnetsApi(c.netClient)
}

// FloatingIpsApi returns the networking floating-IPs API.
func (c *NutanixConnection) FloatingIpsApi() *netapi.FloatingIpsApi {
	return netapi.NewFloatingIpsApi(c.netClient)
}

// StorageContainersApi returns the cluster-management storage-containers API.
func (c *NutanixConnection) StorageContainersApi() *clustermgmtapi.StorageContainersApi {
	return clustermgmtapi.NewStorageContainersApi(c.cmgClient)
}

// VolumeGroupsApi returns the volumes volume-groups API.
func (c *NutanixConnection) VolumeGroupsApi() *volapi.VolumeGroupsApi {
	return volapi.NewVolumeGroupsApi(c.volClient)
}
