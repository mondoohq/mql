// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/ssoadmin"
	"github.com/vmware/govmomi/sts"
	"github.com/vmware/govmomi/vapi/rest"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vsan"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

type VsphereConnection struct {
	plugin.Connection
	Conf               *inventory.Config
	asset              *inventory.Asset
	client             *govmomi.Client
	selectedPlatformID string

	restMu     sync.Mutex
	restClient *rest.Client

	ssoMu     sync.Mutex
	ssoClient *ssoadmin.Client

	vsanMu     sync.Mutex
	vsanClient *vsan.Client
}

func vSphereConnectionURL(hostname string, port int32, user string, password string) (*url.URL, error) {
	host := hostname
	if port > 0 {
		host = hostname + ":" + strconv.Itoa(int(port))
	}

	u, err := url.Parse("https://" + host + "/sdk")
	if err != nil {
		return nil, err
	}
	u.User = url.UserPassword(user, password)
	return u, nil
}

func NewVsphereConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*VsphereConnection, error) {
	conn := &VsphereConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// initialize vSphere connection
	if conf.Type != "vsphere" {
		return nil, plugin.ErrUnsupportedProvider
	}

	// search for password secret
	c, err := vault.GetPassword(conf.Credentials)
	if err != nil {
		return nil, errors.New("missing password for vSphere transport")
	}

	// derive vsphere connection url from Provider Config
	vsphereUrl, err := vSphereConnectionURL(conf.Host, conf.Port, c.User, string(c.Secret))
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := govmomi.NewClient(ctx, vsphereUrl, true)
	if err != nil {
		return nil, err
	}
	conn.client = client
	conn.selectedPlatformID = conf.PlatformId

	return conn, nil
}

func (c *VsphereConnection) Name() string {
	return "vsphere"
}

func (c *VsphereConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *VsphereConnection) Client() *govmomi.Client {
	return c.client
}

// RestClient returns a logged-in vAPI REST client for this connection,
// creating it on the first call. The same client is reused for every
// vAPI request from this connection (tag lookups, etc.), so a single
// `mql run` doesn't pay the ~800ms vAPI login cost more than once per
// connection.
func (c *VsphereConnection) RestClient(ctx context.Context) (*rest.Client, error) {
	c.restMu.Lock()
	defer c.restMu.Unlock()
	if c.restClient != nil {
		return c.restClient, nil
	}
	creds, err := vault.GetPassword(c.Conf.Credentials)
	if err != nil {
		return nil, err
	}
	rc := rest.NewClient(c.client.Client)
	if err := rc.Login(ctx, url.UserPassword(creds.User, string(creds.Secret))); err != nil {
		return nil, err
	}
	c.restClient = rc
	return rc, nil
}

// SsoAdminClient returns a logged-in SSO admin client for this connection,
// creating it on the first call. SSO admin uses its own session manager
// (not the SOAP cookie), so we issue an STS bearer token signed with the
// vSphere host certificate and use that to authenticate. The same client
// is reused for the lifetime of the connection.
func (c *VsphereConnection) SsoAdminClient(ctx context.Context) (*ssoadmin.Client, error) {
	c.ssoMu.Lock()
	defer c.ssoMu.Unlock()
	if c.ssoClient != nil {
		return c.ssoClient, nil
	}
	creds, err := vault.GetPassword(c.Conf.Credentials)
	if err != nil {
		return nil, err
	}

	vc := c.client.Client
	admin, err := ssoadmin.NewClient(ctx, vc)
	if err != nil {
		return nil, err
	}

	tokens, err := sts.NewClient(ctx, vc)
	if err != nil {
		return nil, err
	}
	signer, err := tokens.Issue(ctx, sts.TokenRequest{
		Certificate: vc.Certificate(),
		Userinfo:    url.UserPassword(creds.User, string(creds.Secret)),
	})
	if err != nil {
		return nil, err
	}

	header := soap.Header{Security: signer}
	if err := admin.Login(admin.WithHeader(ctx, header)); err != nil {
		return nil, err
	}

	c.ssoClient = admin
	return admin, nil
}

// VsanClient returns a vSAN management client for this connection, creating
// it on the first call. The vSAN API lives at a separate (/vsanHealth) SOAP
// endpoint but reuses the existing vim25 session, so there's no extra login
// and nothing to log out — the client is just memoized to avoid rebuilding
// the SOAP stub on every cluster/host lookup.
func (c *VsphereConnection) VsanClient(ctx context.Context) (*vsan.Client, error) {
	c.vsanMu.Lock()
	defer c.vsanMu.Unlock()
	if c.vsanClient != nil {
		return c.vsanClient, nil
	}
	vc, err := vsan.NewClient(ctx, c.client.Client)
	if err != nil {
		return nil, err
	}
	c.vsanClient = vc
	return vc, nil
}

func (c *VsphereConnection) Close() {
	c.restMu.Lock()
	rc := c.restClient
	c.restClient = nil
	c.restMu.Unlock()
	if rc != nil {
		if err := rc.Logout(context.Background()); err != nil {
			log.Error().Err(err).Msg("failed to logout from vSphere REST session")
		}
	}

	c.ssoMu.Lock()
	sc := c.ssoClient
	c.ssoClient = nil
	c.ssoMu.Unlock()
	if sc != nil {
		if err := sc.Logout(context.Background()); err != nil {
			log.Error().Err(err).Msg("failed to logout from vSphere SSO admin session")
		}
	}

	if c.client != nil {
		if err := c.client.Logout(context.Background()); err != nil {
			log.Error().Err(err).Msg("failed to logout from vSphere connection")
		}
	}
}
