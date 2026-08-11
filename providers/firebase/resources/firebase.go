// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/firebase/connection"
	"go.mondoo.com/mql/v13/types"
)

// drainAndClose reads any remaining data from the response body and closes it,
// allowing the underlying TCP connection to be reused by the HTTP client pool.
func drainAndClose(body io.ReadCloser) {
	io.Copy(io.Discard, body)
	body.Close()
}

func initFirebaseProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.FirebaseConnection)

	args["projectId"] = llx.StringData(conn.ProjectId())
	args["apiKey"] = llx.StringData(conn.ApiKey())
	args["authDomain"] = llx.StringData(conn.AuthDomain())
	args["domain"] = llx.StringData(conn.Domain())

	return args, nil, nil
}

func (c *mqlFirebaseProject) id() (string, error) {
	id := c.ProjectId.Data
	if id == "" {
		id = c.Domain.Data
	}
	return "firebase/project/" + id, nil
}

// ---------------------------------------------------------------------------
// Realtime Database
// ---------------------------------------------------------------------------

func (p *mqlFirebaseProject) realtimeDatabase() (*mqlFirebaseProjectRealtimeDatabase, error) {
	conn := p.MqlRuntime.Connection.(*connection.FirebaseConnection)
	if conn.ProjectId() == "" {
		p.RealtimeDatabase.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(p.MqlRuntime, "firebase.project.realtimeDatabase", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFirebaseProjectRealtimeDatabase), nil
}

func initFirebaseProjectRealtimeDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.FirebaseConnection)
	projectId := conn.ProjectId()

	urls := []string{
		fmt.Sprintf("https://%s-default-rtdb.firebaseio.com", projectId),
		fmt.Sprintf("https://%s.firebaseio.com", projectId),
	}

	client := conn.HttpClient()
	publiclyReadable := false
	structureExposed := false
	testedURL := ""

	for _, baseURL := range urls {
		url := baseURL + "/.json"
		log.Debug().Str("url", url).Msg("checking Realtime Database readability")

		resp, err := client.Get(url)
		if err != nil {
			log.Debug().Err(err).Str("url", url).Msg("failed to reach Realtime Database")
			continue
		}
		drainAndClose(resp.Body)

		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		testedURL = baseURL

		if resp.StatusCode == http.StatusOK {
			publiclyReadable = true
		}

		shallowURL := baseURL + "/.json?shallow=true"
		shallowResp, err := client.Get(shallowURL)
		if err == nil {
			if shallowResp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(shallowResp.Body, 1<<16))
				if string(body) != "null" {
					structureExposed = true
				}
			}
			drainAndClose(shallowResp.Body)
		}

		break
	}

	if testedURL == "" {
		testedURL = urls[0]
	}

	args["url"] = llx.StringData(testedURL)
	args["publiclyReadable"] = llx.BoolData(publiclyReadable)
	args["structureExposed"] = llx.BoolData(structureExposed)

	return args, nil, nil
}

func (c *mqlFirebaseProjectRealtimeDatabase) id() (string, error) {
	return "firebase/realtimeDatabase/" + c.Url.Data, nil
}

// ---------------------------------------------------------------------------
// Auth Config
// ---------------------------------------------------------------------------

func (p *mqlFirebaseProject) authConfig() (*mqlFirebaseProjectAuthConfig, error) {
	conn := p.MqlRuntime.Connection.(*connection.FirebaseConnection)
	if conn.ApiKey() == "" {
		p.AuthConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(p.MqlRuntime, "firebase.project.authConfig", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFirebaseProjectAuthConfig), nil
}

func initFirebaseProjectAuthConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.FirebaseConnection)
	apiKey := conn.ApiKey()

	url := "https://identitytoolkit.googleapis.com/v1/projects?key=" + apiKey
	log.Debug().Str("url", url).Msg("checking Firebase auth config")

	client := conn.HttpClient()
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query Identity Toolkit API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read Identity Toolkit response: %w", err)
	}

	signInProviders := []interface{}{}
	anonymousAuthEnabled := false
	authorizedDomains := []interface{}{}
	emailEnumerationProtection := false

	if resp.StatusCode == http.StatusOK {
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, nil, fmt.Errorf("failed to parse Identity Toolkit response: %w", err)
		}

		log.Debug().Str("response", string(body)).Msg("Identity Toolkit API response")

		if domains, ok := result["authorizedDomains"].([]interface{}); ok {
			authorizedDomains = domains
		}

		// Check email enumeration protection (emailPrivacyConfig.enableImprovedEmailPrivacy)
		if emailPrivacy, ok := result["emailPrivacyConfig"].(map[string]interface{}); ok {
			if enabled, ok := emailPrivacy["enableImprovedEmailPrivacy"].(bool); ok {
				emailEnumerationProtection = enabled
			}
		}

		// Try v1 response structure
		if idps, ok := result["signInConfig"].(map[string]interface{}); ok {
			if methods, ok := idps["allowedMethods"].([]interface{}); ok {
				signInProviders = methods
			}
		}

		// Check for anonymous auth
		for _, p := range signInProviders {
			if str, ok := p.(string); ok && strings.EqualFold(str, "anonymous") {
				anonymousAuthEnabled = true
				break
			}
		}
	}

	// If we didn't find providers in the v1 format, try legacy format
	if len(signInProviders) == 0 && resp.StatusCode == http.StatusOK {
		var legacyResult map[string]interface{}
		if err := json.Unmarshal(body, &legacyResult); err == nil {
			if idps, ok := legacyResult["idpConfig"].([]interface{}); ok {
				for _, idp := range idps {
					if idpMap, ok := idp.(map[string]interface{}); ok {
						if provider, ok := idpMap["provider"].(string); ok {
							signInProviders = append(signInProviders, provider)
						}
					}
				}
			}
			if domains, ok := legacyResult["authorizedDomains"].([]interface{}); ok && len(authorizedDomains) == 0 {
				authorizedDomains = domains
			}
		}
	}

	// If not found in the config response, probe for email enumeration directly
	// using the createAuthUri endpoint (read-only email lookup, no auth attempt).
	if !emailEnumerationProtection && apiKey != "" {
		emailEnumerationProtection = probeEmailEnumerationProtection(client, apiKey)
	}

	args["signInProviders"] = llx.ArrayData(signInProviders, types.String)
	args["anonymousAuthEnabled"] = llx.BoolData(anonymousAuthEnabled)
	args["authorizedDomains"] = llx.ArrayData(authorizedDomains, types.String)
	args["emailEnumerationProtection"] = llx.BoolData(emailEnumerationProtection)

	return args, nil, nil
}

// probeEmailEnumerationProtection tests whether email enumeration protection is enabled
// by calling the createAuthUri endpoint (read-only email lookup used by Firebase's own
// console). This does NOT trigger sign-in attempts or write to the target's auth audit log.
// When protection is ON, the API returns an empty response; when OFF, it reveals whether
// the email is registered.
func probeEmailEnumerationProtection(client *http.Client, apiKey string) bool {
	url := "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=" + apiKey
	payload := `{"identifier":"mql-probe-nonexistent@test.invalid","continueUri":"https://localhost"}`

	resp, err := client.Post(url, "application/json", strings.NewReader(payload))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return false
	}

	// When email enumeration protection is OFF, the response includes a "registered"
	// field that reveals whether the email exists. When protection is ON, the
	// "registered" field is absent — the API refuses to disclose account existence.
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}

	if _, hasRegistered := result["registered"]; hasRegistered {
		// The API reveals account existence → protection is OFF
		return false
	}

	// No "registered" field and a successful response → protection is ON
	if resp.StatusCode == http.StatusOK {
		return true
	}

	// Unable to determine — assume not protected
	return false
}

func (c *mqlFirebaseProjectAuthConfig) id() (string, error) {
	return "firebase/authConfig", nil
}

// ---------------------------------------------------------------------------
// Hosting
// ---------------------------------------------------------------------------

var reScriptSrcTag = regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js)["']`)

func (p *mqlFirebaseProject) hosting() (*mqlFirebaseProjectHosting, error) {
	conn := p.MqlRuntime.Connection.(*connection.FirebaseConnection)
	if conn.Domain() == "" {
		p.Hosting.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(p.MqlRuntime, "firebase.project.hosting", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFirebaseProjectHosting), nil
}

func initFirebaseProjectHosting(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.FirebaseConnection)
	domain := conn.Domain()

	domainURL := domain
	if !strings.Contains(domainURL, "://") {
		domainURL = "https://" + domainURL
	}
	domainURL = strings.TrimRight(domainURL, "/")

	client := conn.HttpClient()

	// Check Apple App Site Association
	var appleData interface{}
	appleURL := domainURL + "/.well-known/apple-app-site-association"
	log.Debug().Str("url", appleURL).Msg("checking Apple App Site Association")

	if resp, err := client.Get(appleURL); err == nil {
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			var parsed interface{}
			if json.Unmarshal(body, &parsed) == nil {
				appleData = parsed
			}
		}
		drainAndClose(resp.Body)
	}

	// Check Android Asset Links
	var androidData interface{}
	androidURL := domainURL + "/.well-known/assetlinks.json"
	log.Debug().Str("url", androidURL).Msg("checking Android Asset Links")

	if resp, err := client.Get(androidURL); err == nil {
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			var parsed interface{}
			if json.Unmarshal(body, &parsed) == nil {
				androidData = parsed
			}
		}
		drainAndClose(resp.Body)
	}

	// Check for exposed source maps
	exposedSourceMaps := []interface{}{}
	sourceMapExposed := false

	// Fetch main page to discover JS bundles and check their .map files
	if resp, err := client.Get(domainURL); err == nil {
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			html := string(body)

			// Find script tags and check for .js.map files
			matches := reScriptSrcTag.FindAllStringSubmatch(html, -1)
			checked := 0
			for _, m := range matches {
				if checked >= 10 {
					break
				}
				src := m[1]

				// Resolve relative URLs
				if strings.HasPrefix(src, "//") {
					src = "https:" + src
				} else if strings.HasPrefix(src, "/") {
					src = domainURL + src
				} else if !strings.HasPrefix(src, "http") {
					src = domainURL + "/" + src
				}

				// Skip external CDNs
				if strings.Contains(src, "googleapis.com") ||
					strings.Contains(src, "gstatic.com") ||
					strings.Contains(src, "google-analytics.com") ||
					strings.Contains(src, "googletagmanager.com") {
					continue
				}

				mapURL := src + ".map"
				log.Debug().Str("url", mapURL).Msg("checking source map exposure")

				mapResp, err := client.Get(mapURL)
				if err == nil {
					if mapResp.StatusCode == http.StatusOK {
						// Verify it's actually a source map (should contain "sources" key)
						mapBody, _ := io.ReadAll(io.LimitReader(mapResp.Body, 1<<10)) // Just peek
						if strings.Contains(string(mapBody), "\"sources\"") ||
							strings.Contains(string(mapBody), "\"mappings\"") {
							sourceMapExposed = true
							exposedSourceMaps = append(exposedSourceMaps, mapURL)
						}
					}
					drainAndClose(mapResp.Body)
					checked++
				}
			}
		}
		drainAndClose(resp.Body)
	}

	args["domain"] = llx.StringData(domain)
	args["appleAppSiteAssociation"] = llx.DictData(appleData)
	args["androidAssetLinks"] = llx.DictData(androidData)
	args["sourceMapExposed"] = llx.BoolData(sourceMapExposed)
	args["exposedSourceMaps"] = llx.ArrayData(exposedSourceMaps, types.String)

	return args, nil, nil
}

func (c *mqlFirebaseProjectHosting) id() (string, error) {
	return "firebase/hosting/" + c.Domain.Data, nil
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

func (p *mqlFirebaseProject) storage() (*mqlFirebaseProjectStorage, error) {
	conn := p.MqlRuntime.Connection.(*connection.FirebaseConnection)
	if conn.ProjectId() == "" {
		p.Storage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(p.MqlRuntime, "firebase.project.storage", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFirebaseProjectStorage), nil
}

func initFirebaseProjectStorage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.FirebaseConnection)
	projectId := conn.ProjectId()

	bucketURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o", projectId)
	log.Debug().Str("url", bucketURL).Msg("checking Firebase Storage public listing")

	client := conn.HttpClient()
	publiclyListable := false

	resp, err := client.Get(bucketURL)
	if err == nil {
		if resp.StatusCode == http.StatusOK {
			publiclyListable = true
		}
		drainAndClose(resp.Body)
	}

	args["bucketUrl"] = llx.StringData(bucketURL)
	args["publiclyListable"] = llx.BoolData(publiclyListable)

	return args, nil, nil
}

func (c *mqlFirebaseProjectStorage) id() (string, error) {
	return "firebase/storage/" + c.BucketUrl.Data, nil
}

// ---------------------------------------------------------------------------
// Firestore
// ---------------------------------------------------------------------------

func (p *mqlFirebaseProject) firestore() (*mqlFirebaseProjectFirestore, error) {
	conn := p.MqlRuntime.Connection.(*connection.FirebaseConnection)
	if conn.ProjectId() == "" {
		p.Firestore.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(p.MqlRuntime, "firebase.project.firestore", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFirebaseProjectFirestore), nil
}

func initFirebaseProjectFirestore(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.FirebaseConnection)
	projectId := conn.ProjectId()

	firestoreURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents", projectId)
	log.Debug().Str("url", firestoreURL).Msg("checking Firestore public access")

	client := conn.HttpClient()
	publiclyReadable := false
	structureExposed := false
	exposedCollections := []interface{}{}

	// Check 1: Can we read documents directly?
	resp, err := client.Get(firestoreURL)
	if err == nil {
		if resp.StatusCode == http.StatusOK {
			publiclyReadable = true

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			var result map[string]interface{}
			if json.Unmarshal(body, &result) == nil {
				if docs, ok := result["documents"].([]interface{}); ok {
					seen := map[string]bool{}
					for _, doc := range docs {
						if docMap, ok := doc.(map[string]interface{}); ok {
							if name, ok := docMap["name"].(string); ok {
								// Document name: projects/{proj}/databases/(default)/documents/{collection}/{docId}
								parts := strings.Split(name, "/")
								if len(parts) >= 6 {
									collectionId := parts[5]
									if !seen[collectionId] {
										seen[collectionId] = true
										exposedCollections = append(exposedCollections, collectionId)
									}
								}
							}
						}
					}
				}
			}
		}
		drainAndClose(resp.Body)
	}

	// Check 2: listCollectionIds — often allowed even when document reads are blocked.
	// This reveals the database structure (top-level collection names) but not document data.
	listURL := firestoreURL + ":listCollectionIds"
	log.Debug().Str("url", listURL).Msg("checking Firestore listCollectionIds")

	listResp, err := client.Post(listURL, "application/json", strings.NewReader("{}"))
	if err == nil {
		if listResp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(listResp.Body, 1<<20))
			var listResult map[string]interface{}
			if json.Unmarshal(body, &listResult) == nil {
				if collIds, ok := listResult["collectionIds"].([]interface{}); ok {
					structureExposed = true
					// Merge with any collections found from document reads
					seen := map[string]bool{}
					for _, c := range exposedCollections {
						seen[c.(string)] = true
					}
					for _, id := range collIds {
						if s, ok := id.(string); ok && !seen[s] {
							seen[s] = true
							exposedCollections = append(exposedCollections, id)
						}
					}
				}
			}
		}
		drainAndClose(listResp.Body)
	}

	args["url"] = llx.StringData(firestoreURL)
	args["publiclyReadable"] = llx.BoolData(publiclyReadable)
	args["structureExposed"] = llx.BoolData(structureExposed)
	args["exposedCollections"] = llx.ArrayData(exposedCollections, types.String)

	return args, nil, nil
}

func (c *mqlFirebaseProjectFirestore) id() (string, error) {
	return "firebase/firestore/" + c.Url.Data, nil
}
