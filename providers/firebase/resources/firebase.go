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
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/firebase/connection"
	"go.mondoo.com/mql/types"
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

	cfg := authConfig{}
	if resp.StatusCode == http.StatusOK {
		// The parsed result is what matters; only a head of the raw body is
		// logged, so a large answer cannot produce an unbounded log line.
		snippet := string(body[:min(len(body), 2048)])
		if snippet == "" {
			snippet = "(empty)"
		}
		log.Debug().Str("response", snippet).Msg("Identity Toolkit API response")
		cfg, err = parseAuthConfig(body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Identity Toolkit response: %w", err)
		}
	}

	// If not found in the config response, probe for email enumeration directly
	// using the createAuthUri endpoint (read-only email lookup, no auth attempt).
	if !cfg.emailEnumerationProtection && apiKey != "" {
		cfg.emailEnumerationProtection = probeEmailEnumerationProtection(client, identityToolkitURL, apiKey)
	}

	args["signInProviders"] = llx.ArrayData(anyOf(cfg.signInProviders), types.String)
	args["anonymousAuthEnabled"] = llx.BoolData(cfg.anonymousAuthEnabled)
	args["authorizedDomains"] = llx.ArrayData(anyOf(cfg.authorizedDomains), types.String)
	args["emailEnumerationProtection"] = llx.BoolData(cfg.emailEnumerationProtection)

	return args, nil, nil
}

// identityToolkitURL is the public Identity Toolkit endpoint; the probe takes
// it as a parameter so a test can stand in a local server.
const identityToolkitURL = "https://identitytoolkit.googleapis.com"

// authConfig is what the public project config discloses about sign-in.
type authConfig struct {
	signInProviders            []string
	anonymousAuthEnabled       bool
	authorizedDomains          []string
	emailEnumerationProtection bool
}

// parseAuthConfig reads the two shapes the project config comes in: the v1
// shape (signInConfig.allowedMethods and emailPrivacyConfig) and the legacy
// shape (idpConfig[].provider), which is consulted only when the v1 shape
// lists no method. authorizedDomains sits at the top level in both. Anonymous
// sign-in is derived from the provider list, case-insensitively.
func parseAuthConfig(body []byte) (authConfig, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return authConfig{}, err
	}

	cfg := authConfig{}
	if domains, ok := result["authorizedDomains"].([]interface{}); ok {
		cfg.authorizedDomains = stringsOf(domains)
	}
	if emailPrivacy, ok := result["emailPrivacyConfig"].(map[string]interface{}); ok {
		if enabled, ok := emailPrivacy["enableImprovedEmailPrivacy"].(bool); ok {
			cfg.emailEnumerationProtection = enabled
		}
	}
	if signIn, ok := result["signInConfig"].(map[string]interface{}); ok {
		if methods, ok := signIn["allowedMethods"].([]interface{}); ok {
			cfg.signInProviders = stringsOf(methods)
		}
	}
	if len(cfg.signInProviders) == 0 {
		if idps, ok := result["idpConfig"].([]interface{}); ok {
			for _, idp := range idps {
				if idpMap, ok := idp.(map[string]interface{}); ok {
					if provider, ok := idpMap["provider"].(string); ok {
						cfg.signInProviders = append(cfg.signInProviders, provider)
					}
				}
			}
		}
	}
	for _, p := range cfg.signInProviders {
		if strings.EqualFold(p, "anonymous") {
			cfg.anonymousAuthEnabled = true
			break
		}
	}
	return cfg, nil
}

// stringsOf keeps the string members of a decoded JSON array.
func stringsOf(vals []interface{}) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// anyOf widens a string slice for llx.ArrayData.
func anyOf(vals []string) []interface{} {
	out := make([]interface{}, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

// probeEmailEnumerationProtection tests whether email enumeration protection is enabled
// by calling the createAuthUri endpoint (read-only email lookup used by Firebase's own
// console). This does NOT trigger sign-in attempts or write to the target's auth audit log.
// When protection is ON, the API returns an empty response; when OFF, it reveals whether
// the email is registered.
func probeEmailEnumerationProtection(client *http.Client, baseURL, apiKey string) bool {
	url := baseURL + "/v1/accounts:createAuthUri?key=" + apiKey
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
	return emailEnumerationProtected(resp.StatusCode, body)
}

// emailEnumerationProtected classifies a createAuthUri answer for an address
// that cannot exist. With protection off the API says whether the address is
// registered; with protection on it answers 200 and withholds that field.
// Anything else (an error status, a body that is not JSON) reads as not
// protected, so an audit fails closed rather than passing on an unread value.
func emailEnumerationProtected(status int, body []byte) bool {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}
	if _, hasRegistered := result["registered"]; hasRegistered {
		return false
	}
	return status == http.StatusOK
}

// id is qualified by the project so two projects scanned through one runtime
// cannot share a cached auth config. The API key stands in when the project
// was reached by key alone.
func (c *mqlFirebaseProjectAuthConfig) id() (string, error) {
	conn := c.MqlRuntime.Connection.(*connection.FirebaseConnection)
	qualifier := conn.ProjectId()
	if qualifier == "" {
		qualifier = conn.ApiKey()
	}
	return "firebase/authConfig/" + qualifier, nil
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
				src := resolveScriptURL(m[1], domainURL)
				if isExternalScript(src) {
					continue
				}
				// Count the attempt, not the result: a page with hundreds of
				// scripts whose maps all time out must still stop at the cap.
				checked++

				mapURL := src + ".map"
				log.Debug().Str("url", mapURL).Msg("checking source map exposure")

				mapResp, err := client.Get(mapURL)
				if err == nil {
					if mapResp.StatusCode == http.StatusOK {
						mapBody, _ := io.ReadAll(io.LimitReader(mapResp.Body, 1<<10)) // Just peek
						if looksLikeSourceMap(mapBody) {
							sourceMapExposed = true
							exposedSourceMaps = append(exposedSourceMaps, mapURL)
						}
					}
					drainAndClose(mapResp.Body)
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

// resolveScriptURL turns a script src as written in the page into an absolute
// URL: protocol-relative gets https, root-relative and bare paths hang off the
// page, absolute URLs pass through.
func resolveScriptURL(src, pageURL string) string {
	switch {
	case strings.HasPrefix(src, "//"):
		return "https:" + src
	case strings.HasPrefix(src, "/"):
		return pageURL + src
	case strings.HasPrefix(src, "http"):
		return src
	default:
		return pageURL + "/" + src
	}
}

// externalScriptHosts are Google-served bundles a page pulls in that are not
// the project's own build output, so their maps say nothing about the project.
var externalScriptHosts = []string{
	"googleapis.com",
	"gstatic.com",
	"google-analytics.com",
	"googletagmanager.com",
}

func isExternalScript(url string) bool {
	for _, host := range externalScriptHosts {
		if strings.Contains(url, host) {
			return true
		}
	}
	return false
}

// looksLikeSourceMap sniffs the first bytes of a 200 answer for foo.js.map. A
// 200 alone proves nothing: hosting configured for a single-page app answers
// every path with index.html. Only a body carrying a sources or mappings key
// is a map.
func looksLikeSourceMap(body []byte) bool {
	s := string(body)
	return strings.Contains(s, `"sources"`) || strings.Contains(s, `"mappings"`)
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
	var exposedCollections []string

	// Check 1: Can we read documents directly?
	resp, err := client.Get(firestoreURL)
	if err == nil {
		if resp.StatusCode == http.StatusOK {
			publiclyReadable = true
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			exposedCollections = collectionIDsFromDocuments(body)
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
			if ids, ok := listedCollectionIDs(body); ok {
				structureExposed = true
				exposedCollections = mergeUnique(exposedCollections, ids)
			}
		}
		drainAndClose(listResp.Body)
	}

	args["url"] = llx.StringData(firestoreURL)
	args["publiclyReadable"] = llx.BoolData(publiclyReadable)
	args["structureExposed"] = llx.BoolData(structureExposed)
	args["exposedCollections"] = llx.ArrayData(anyOf(exposedCollections), types.String)

	return args, nil, nil
}

// collectionIDsFromDocuments pulls the top-level collection of every document
// in a documents.list answer. A name reads
// projects/{p}/databases/(default)/documents/{collection}/{doc}, so the
// collection is the sixth segment. First-seen order is kept, duplicates and
// names too short to carry a collection are dropped, and a body that is not
// the expected shape yields nothing.
func collectionIDsFromDocuments(body []byte) []string {
	var result struct {
		Documents []struct {
			Name string `json:"name"`
		} `json:"documents"`
	}
	if json.Unmarshal(body, &result) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, d := range result.Documents {
		parts := strings.Split(d.Name, "/")
		if len(parts) < 6 || parts[5] == "" || seen[parts[5]] {
			continue
		}
		seen[parts[5]] = true
		out = append(out, parts[5])
	}
	return out
}

// listedCollectionIDs reads a listCollectionIds answer. ok is false when the
// body carries no collectionIds key at all, which means the call disclosed
// nothing; an empty list still counts as the structure being readable.
func listedCollectionIDs(body []byte) ([]string, bool) {
	var result map[string]interface{}
	if json.Unmarshal(body, &result) != nil {
		return nil, false
	}
	ids, ok := result["collectionIds"].([]interface{})
	if !ok {
		return nil, false
	}
	return stringsOf(ids), true
}

// mergeUnique appends the members of b that a does not already hold.
func mergeUnique(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, v := range a {
		seen[v] = true
	}
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			a = append(a, v)
		}
	}
	return a
}

func (c *mqlFirebaseProjectFirestore) id() (string, error) {
	return "firebase/firestore/" + c.Url.Data, nil
}
