// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"strings"
	"sync"

	credential "github.com/aliyun/credentials-go/credentials"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// DefaultRegion is used to resolve the account identity and to enumerate
	// the available regions when the caller does not pin one.
	DefaultRegion = "cn-hangzhou"

	OptionRegion          = "region"
	OptionRegions         = "regions"
	OptionRoleArn         = "role-arn"
	OptionRoleSessionName = "role-session-name"
	OptionAccessKeyID     = "access-key-id"
)

// AlicloudConnection holds the resolved Alibaba Cloud credential and the
// per-service, per-region OpenAPI clients built from it. Clients are cached so
// that repeated field access across a scan reuses a single client per region.
type AlicloudConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// cred is the Darabonba credential used by every service client except OSS.
	cred credential.Credential
	// accessKeyID/accessKeySecret/securityToken are retained so the OSS SDK
	// (which uses its own credential provider type) can be constructed from the
	// same static credential. They are empty when a non-static credential
	// provider (e.g. an ECS instance RAM role) is in use.
	accessKeyID     string
	accessKeySecret string
	securityToken   string

	// region is the default region used for account resolution and for global
	// services. regionFilter, when non-empty, restricts multi-region fan-out.
	region       string
	regionFilter []string

	// Filters narrows which objects the listers return, and therefore which
	// objects discovery turns into assets.
	Filters DiscoveryFilters

	accountID string

	clientLock sync.Mutex
	clients    map[string]any
}

// NewAlicloudConnection resolves credentials from the CLI flags (falling back
// to the standard Alibaba Cloud environment variables and default credential
// chain) and prepares the client cache.
func NewAlicloudConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*AlicloudConnection, error) {
	conn := &AlicloudConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		clients:    map[string]any{},
	}

	opts := conf.Options
	if opts == nil {
		opts = map[string]string{}
	}

	conn.region = firstNonEmpty(opts[OptionRegion], os.Getenv("ALIBABA_CLOUD_REGION"), os.Getenv("ALIBABA_CLOUD_REGION_ID"), DefaultRegion)
	if regions := opts[OptionRegions]; regions != "" {
		for r := range strings.SplitSeq(regions, ",") {
			if r = strings.TrimSpace(r); r != "" {
				conn.regionFilter = append(conn.regionFilter, r)
			}
		}
	}

	conn.Filters = DiscoveryFiltersFromOpts(opts)

	accessKeyID := firstNonEmpty(opts[OptionAccessKeyID], os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"), os.Getenv("ALICLOUD_ACCESS_KEY"))
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	if accessKeySecret == "" {
		accessKeySecret = os.Getenv("ALICLOUD_SECRET_KEY")
	}
	securityToken := firstNonEmpty(os.Getenv("ALIBABA_CLOUD_SECURITY_TOKEN"), os.Getenv("ALICLOUD_SECURITY_TOKEN"))

	// A secret passed through the inventory credential vault takes precedence
	// over the environment for the access-key secret.
	for _, c := range conf.Credentials {
		if c != nil && c.Type == vault.CredentialType_password && len(c.Secret) > 0 {
			accessKeySecret = string(c.Secret)
		}
	}

	cred, err := resolveCredential(opts, accessKeyID, accessKeySecret, securityToken)
	if err != nil {
		return nil, err
	}

	conn.cred = cred
	conn.accessKeyID = accessKeyID
	conn.accessKeySecret = accessKeySecret
	conn.securityToken = securityToken

	return conn, nil
}

// resolveCredential builds a Darabonba credential from the supplied static
// values. When a role ARN is present it assumes that role; when an access key
// pair is present it uses it directly (with an optional STS token); otherwise it
// falls back to the default credential chain (environment, profile, or an ECS
// instance RAM role).
func resolveCredential(opts map[string]string, accessKeyID, accessKeySecret, securityToken string) (credential.Credential, error) {
	roleArn := opts[OptionRoleArn]

	switch {
	case roleArn != "" && accessKeyID != "" && accessKeySecret != "":
		sessionName := firstNonEmpty(opts[OptionRoleSessionName], "mondoo")
		return credential.NewCredential(&credential.Config{
			Type:            new("ram_role_arn"),
			AccessKeyId:     new(accessKeyID),
			AccessKeySecret: new(accessKeySecret),
			RoleArn:         new(roleArn),
			RoleSessionName: new(sessionName),
		})
	case accessKeyID != "" && accessKeySecret != "" && securityToken != "":
		return credential.NewCredential(&credential.Config{
			Type:            new("sts"),
			AccessKeyId:     new(accessKeyID),
			AccessKeySecret: new(accessKeySecret),
			SecurityToken:   new(securityToken),
		})
	case accessKeyID != "" && accessKeySecret != "":
		return credential.NewCredential(&credential.Config{
			Type:            new("access_key"),
			AccessKeyId:     new(accessKeyID),
			AccessKeySecret: new(accessKeySecret),
		})
	default:
		// Default credential chain: environment variables, the shared
		// credentials file (~/.alibabacloud/credentials), or an ECS instance
		// RAM role when running inside Alibaba Cloud.
		return credential.NewCredential(nil)
	}
}

func (c *AlicloudConnection) Name() string {
	return "alicloud"
}

func (c *AlicloudConnection) Asset() *inventory.Asset {
	return c.asset
}

// Region returns the default region for global services and account resolution.
func (c *AlicloudConnection) Region() string {
	return c.region
}

// AccountID returns the Alibaba Cloud account (UID) the credential belongs to.
// It is populated during asset detection via the STS caller identity.
func (c *AlicloudConnection) AccountID() string {
	return c.accountID
}

// ScopedObject returns the object id and region a discovered child asset is
// pinned to for the given scope option (OptionClusterID, OptionAlbID, ...). Fine-
// grained discovery stamps the object id under the scope key and the object's
// region under OptionRegions, so a singular resource's init can resolve itself
// from the connection when invoked with no identifying arguments. ok is false on
// the account root asset (or any asset not scoped to this kind of object), where
// callers must fall back to explicit arguments.
func (c *AlicloudConnection) ScopedObject(option string) (id, region string, ok bool) {
	if c.Conf == nil || c.Conf.Options == nil {
		return "", "", false
	}
	id = c.Conf.Options[option]
	if id == "" {
		return "", "", false
	}
	if len(c.regionFilter) > 0 {
		region = c.regionFilter[0]
	} else {
		region = c.region
	}
	return id, region, true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

//go:fix inline
func strPtr(s string) *string { return new(s) }
