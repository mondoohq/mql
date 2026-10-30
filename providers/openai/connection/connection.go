// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	TokenOption        = "token"
	AdminTokenOption   = "admin-token"
	OrganizationOption = "organization"
	ProjectOption      = "project"
	BaseURLOption      = "base-url"

	PlatformIdPrefix = "//platformid.api.mondoo.app/runtime/openai"

	maxAccountInfoBody = 1 << 20
)

type OpenaiConnection struct {
	plugin.Connection
	Conf             *inventory.Config
	asset            *inventory.Asset
	client           *openai.Client
	adminClient      *openai.Client
	organization     string
	organizationName string
	project          string
	tokenHash        string
	isAdminKey       bool
}

func isAdminToken(token string) bool {
	return strings.HasPrefix(token, "sk-admin-")
}

// resolveTokens sorts the configured credentials into the two planes an OpenAI
// account exposes. A project key reads models, files, vector stores, batches
// and fine-tuning; an admin key reads organization configuration, membership
// and projects. Several reads need both halves at once: listing the
// checkpoints of a fine-tuning job is a project-key call while reading which
// projects those checkpoints are shared into is an admin-key one.
//
// --admin-token names the plane outright, so its value is used as the admin
// key whatever its prefix. --token keeps the behavior it has always had and
// auto-detects an admin key from its prefix, which is why a key passed there
// still lands in the admin slot rather than being sent to endpoints it cannot
// read.
func resolveTokens(tokenFlag, adminFlag, tokenEnv, adminEnv string) (projectToken string, adminToken string) {
	adminToken = firstNonEmpty(adminFlag, adminEnv)
	projectToken = firstNonEmpty(tokenFlag, tokenEnv)

	if isAdminToken(projectToken) {
		if adminToken == "" {
			adminToken = projectToken
		}
		projectToken = ""
	}
	return projectToken, adminToken
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func NewOpenaiConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OpenaiConnection, error) {
	projectToken, adminToken := resolveTokens(
		conf.Options[TokenOption],
		conf.Options[AdminTokenOption],
		os.Getenv("OPENAI_API_KEY"),
		os.Getenv("OPENAI_ADMIN_KEY"),
	)
	// the org probe and the platform id are keyed off one credential; prefer
	// the project key so a connection that gains an admin key keeps the
	// platform id it already had
	token := firstNonEmpty(projectToken, adminToken)

	org := conf.Options[OrganizationOption]
	if org == "" {
		org = os.Getenv("OPENAI_ORG_ID")
	}

	project := conf.Options[ProjectOption]
	if project == "" {
		project = os.Getenv("OPENAI_PROJECT_ID")
	}

	baseURL := conf.Options[BaseURLOption]
	if baseURL == "" {
		baseURL = os.Getenv("OPENAI_BASE_URL")
	}

	var sharedOpts []option.RequestOption
	if org != "" {
		sharedOpts = append(sharedOpts, option.WithHeader("OpenAI-Organization", org))
	}
	if project != "" {
		sharedOpts = append(sharedOpts, option.WithHeader("OpenAI-Project", project))
	}
	if baseURL != "" {
		sharedOpts = append(sharedOpts, option.WithBaseURL(baseURL))
	}

	var tokenHash string
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		tokenHash = hex.EncodeToString(sum[:8])
	}

	var client *openai.Client
	var adminClient *openai.Client

	// One client carries both credentials. Every generated method marks which
	// credential its endpoint accepts, so the SDK sends the admin key to the
	// organization endpoints and the project key to the rest, and a connection
	// given both keys can walk a query that crosses the two planes.
	if projectToken != "" || adminToken != "" {
		opts := make([]option.RequestOption, 0, len(sharedOpts)+2)
		if projectToken != "" {
			opts = append(opts, option.WithAPIKey(projectToken))
		}
		if adminToken != "" {
			opts = append(opts, option.WithAdminAPIKey(adminToken))
		}
		opts = append(opts, sharedOpts...)
		c := openai.NewClient(opts...)
		if projectToken != "" {
			client = &c
		}
		if adminToken != "" {
			adminClient = &c
		}
	}

	conn := &OpenaiConnection{
		Connection:   plugin.NewConnection(id, asset),
		Conf:         conf,
		asset:        asset,
		client:       client,
		adminClient:  adminClient,
		organization: org,
		project:      project,
		tokenHash:    tokenHash,
		isAdminKey:   adminToken != "",
	}

	if conn.organization == "" && token != "" {
		apiBase := baseURL
		if apiBase == "" {
			apiBase = "https://api.openai.com"
		}
		if info, err := fetchAccountInfo(apiBase, token); err == nil {
			if info.OrgID != "" {
				conn.organization = info.OrgID
			}
			if info.OrgName != "" {
				conn.organizationName = info.OrgName
			}
		}
	}

	return conn, nil
}

type accountInfo struct {
	OrgID   string
	OrgName string
}

// fetchAccountInfo calls the undocumented /v1/me endpoint for best-effort org detection.
func fetchAccountInfo(baseURL string, token string) (*accountInfo, error) {
	req, err := http.NewRequest("GET", baseURL+"/v1/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// /v1/me is undocumented and answers with a short account record. Cap the
	// read so a wrong or misbehaving endpoint cannot make connect-time org
	// detection allocate without limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAccountInfoBody))
	if err != nil {
		return nil, err
	}
	// A capped read hands json.Unmarshal a truncated document, which fails with
	// a generic syntax error that reads like the endpoint returned garbage. Say
	// which of the two actually happened.
	if len(body) >= maxAccountInfoBody {
		return nil, fmt.Errorf("/v1/me response exceeded the %d byte limit", maxAccountInfoBody)
	}

	var result struct {
		Orgs struct {
			Data []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				IsDefault bool   `json:"is_default"`
			} `json:"data"`
		} `json:"orgs"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	info := &accountInfo{}
	for _, org := range result.Orgs.Data {
		if info.OrgID == "" || org.IsDefault {
			info.OrgID = org.ID
			info.OrgName = org.Name
		}
	}

	return info, nil
}

func (c *OpenaiConnection) Name() string {
	return "openai"
}

func (c *OpenaiConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *OpenaiConnection) Client() *openai.Client {
	return c.client
}

func (c *OpenaiConnection) AdminClient() *openai.Client {
	return c.adminClient
}

func (c *OpenaiConnection) Organization() string {
	return c.organization
}

func (c *OpenaiConnection) OrganizationName() string {
	return c.organizationName
}

func (c *OpenaiConnection) Project() string {
	return c.project
}

func (c *OpenaiConnection) IsAdminKey() bool {
	return c.isAdminKey
}

func (c *OpenaiConnection) PlatformId() string {
	if c.project != "" {
		return PlatformIdPrefix + "/project/" + c.project
	}
	if c.organization != "" {
		return PlatformIdPrefix + "/org/" + c.organization
	}
	if c.tokenHash != "" {
		return PlatformIdPrefix + "/key/" + c.tokenHash
	}
	return PlatformIdPrefix
}

func (c *OpenaiConnection) Identifier() string {
	if c.project != "" {
		return c.project
	}
	if c.organization != "" {
		return c.organization
	}
	return c.tokenHash
}
