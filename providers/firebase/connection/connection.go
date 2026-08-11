// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

type FirebaseConnection struct {
	plugin.Connection
	Conf       *inventory.Config
	asset      *inventory.Asset
	projectId  string
	apiKey     string
	authDomain string
	domain     string
	httpClient *http.Client
}

func NewFirebaseConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*FirebaseConnection, error) {
	conn := &FirebaseConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
	}

	if conf.Options != nil {
		conn.projectId = conf.Options["project-id"]
		conn.apiKey = conf.Options["api-key"]
		conn.domain = conf.Options["domain"]
	}

	// If we have a domain but no project ID, try to resolve Firebase config from the domain
	if conn.domain != "" && conn.projectId == "" {
		if err := conn.resolveFromDomain(); err != nil {
			return nil, errors.Newf("could not discover Firebase config from domain %q: %v", conn.domain, err)
		}
	}

	if conn.projectId == "" && conn.domain == "" {
		return nil, errors.New("either --project-id or --domain must be provided")
	}

	// Derive authDomain if not set
	if conn.authDomain == "" && conn.projectId != "" {
		conn.authDomain = conn.projectId + ".firebaseapp.com"
	}

	return conn, nil
}

// resolveFromDomain attempts to discover Firebase project configuration from a domain.
// It tries multiple strategies:
// 1. Firebase Hosting /__/firebase/init.js (only works for Firebase-hosted sites)
// 2. Inline HTML/JS scraping of the main page
// 3. Fetching linked JavaScript bundles and scanning them for Firebase config
func (c *FirebaseConnection) resolveFromDomain() error {
	domain := c.domain
	if !strings.Contains(domain, "://") {
		domain = "https://" + domain
	}
	domain = strings.TrimRight(domain, "/")

	// Strategy 1: Try /__/firebase/init.js (Firebase Hosting auto-serves this)
	initURL := domain + "/__/firebase/init.js"
	log.Debug().Str("url", initURL).Msg("trying Firebase Hosting init.js")
	if err := c.extractConfigFromBody(initURL); err == nil && c.projectId != "" {
		log.Info().Str("projectId", c.projectId).Msg("resolved Firebase config from init.js")
		return nil
	}

	// Strategy 2: Fetch main page HTML, scan inline scripts and discover JS bundle URLs
	log.Debug().Str("url", domain).Msg("fetching main page for Firebase config discovery")
	resp, err := c.httpClient.Get(domain)
	if err != nil {
		return errors.Wrap(err, "failed to fetch domain")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit for HTML
	if err != nil {
		return errors.Wrap(err, "failed to read page body")
	}

	html := string(body)

	// Check inline scripts in the HTML for Firebase config
	c.extractConfigFromContent(html)
	if c.projectId != "" {
		log.Info().Str("projectId", c.projectId).Msg("resolved Firebase config from inline HTML")
		return nil
	}

	// Strategy 3: Find linked JS files and scan them for Firebase config.
	// Apps using Firebase Auth typically bundle the config in their JS.
	scriptURLs := extractScriptSrcs(html, domain)
	if len(scriptURLs) > 15 {
		scriptURLs = scriptURLs[:15]
	}
	log.Debug().Int("count", len(scriptURLs)).Msg("found linked script URLs to scan")

	for _, scriptURL := range scriptURLs {
		log.Debug().Str("url", scriptURL).Msg("scanning JS bundle for Firebase config")
		if err := c.extractConfigFromBody(scriptURL); err != nil {
			log.Debug().Err(err).Str("url", scriptURL).Msg("failed to fetch JS bundle")
			continue
		}
		if c.projectId != "" {
			log.Info().Str("projectId", c.projectId).Str("source", scriptURL).Msg("resolved Firebase config from JS bundle")
			return nil
		}
	}

	if c.projectId == "" {
		return errors.New("could not find Firebase configuration (projectId/apiKey) in domain content or linked scripts")
	}

	return nil
}

var (
	// Match Firebase config patterns in JS — handles both quoted keys and unquoted keys,
	// property assignment and object literal styles
	// GCP project IDs: 6-30 chars, lowercase + digits + hyphens, must start with a letter
	reProjectId  = regexp.MustCompile(`(?:["']?projectId["']?\s*[:=]\s*["']|FIREBASE_PROJECT_ID["']?\s*[:=]\s*["'])([a-z][a-z0-9-]{5,29})["']`)
	reApiKey     = regexp.MustCompile(`(?:["']?apiKey["']?\s*[:=]\s*["']|FIREBASE_API_KEY["']?\s*[:=]\s*["'])(AIza[a-zA-Z0-9_-]+)["']`)
	reAuthDomain = regexp.MustCompile(`(?:["']?authDomain["']?\s*[:=]\s*["']|FIREBASE_AUTH_DOMAIN["']?\s*[:=]\s*["'])([a-zA-Z0-9._-]+)["']`)

	// Match <script src="..."> tags in HTML
	reScriptSrc = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
)

// extractConfigFromBody fetches a URL and scans its body for Firebase config.
func (c *FirebaseConnection) extractConfigFromBody(url string) error {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit for JS bundles
	if err != nil {
		return err
	}

	c.extractConfigFromContent(string(body))
	return nil
}

// extractConfigFromContent scans text content for Firebase config patterns.
func (c *FirebaseConnection) extractConfigFromContent(content string) {
	if m := reProjectId.FindStringSubmatch(content); len(m) > 1 && c.projectId == "" {
		c.projectId = m[1]
	}
	if m := reApiKey.FindStringSubmatch(content); len(m) > 1 && c.apiKey == "" {
		c.apiKey = m[1]
	}
	if m := reAuthDomain.FindStringSubmatch(content); len(m) > 1 && c.authDomain == "" {
		c.authDomain = m[1]
	}
}

// extractScriptSrcs finds all <script src="..."> URLs in HTML, resolving relative paths.
func extractScriptSrcs(html string, baseURL string) []string {
	matches := reScriptSrc.FindAllStringSubmatch(html, -1)
	var urls []string
	seen := map[string]bool{}

	for _, m := range matches {
		src := m[1]

		// Resolve relative URLs
		if strings.HasPrefix(src, "//") {
			src = "https:" + src
		} else if strings.HasPrefix(src, "/") {
			src = baseURL + src
		} else if !strings.HasPrefix(src, "http") {
			src = baseURL + "/" + src
		}

		// Skip external CDNs that won't have app-specific Firebase config
		if strings.Contains(src, "googleapis.com") ||
			strings.Contains(src, "gstatic.com") ||
			strings.Contains(src, "google-analytics.com") ||
			strings.Contains(src, "googletagmanager.com") {
			continue
		}

		if !seen[src] {
			seen[src] = true
			urls = append(urls, src)
		}
	}

	return urls
}

func (c *FirebaseConnection) Name() string {
	return "firebase"
}

func (c *FirebaseConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *FirebaseConnection) ProjectId() string {
	return c.projectId
}

func (c *FirebaseConnection) ApiKey() string {
	return c.apiKey
}

func (c *FirebaseConnection) AuthDomain() string {
	return c.authDomain
}

func (c *FirebaseConnection) Domain() string {
	return c.domain
}

func (c *FirebaseConnection) HttpClient() *http.Client {
	return c.httpClient
}

func (c *FirebaseConnection) PlatformInfo() *inventory.Platform {
	return &inventory.Platform{
		Name:   "firebase-project",
		Family: []string{"firebase"},
		Kind:   "api",
		Title:  "Firebase Project",
	}
}

func (c *FirebaseConnection) Identifier() string {
	id := c.projectId
	if id == "" {
		id = c.domain
	}
	return "//platformid.api.mondoo.app/runtime/firebase/project/" + id
}
