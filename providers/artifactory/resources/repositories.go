// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/artifactory/connection"
)

// repositoryRecord is what the repository list reports. It carries the fields
// that identify a repository and, for a remote one, the upstream it proxies.
type repositoryRecord struct {
	Key         string `json:"key"`
	Type        string `json:"type"`
	PackageType string `json:"packageType"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// repositoryDetailRecord is the configuration of a single repository.
type repositoryDetailRecord struct {
	Key             string   `json:"key"`
	RClass          string   `json:"rclass"`
	PackageType     string   `json:"packageType"`
	Description     string   `json:"description"`
	Notes           string   `json:"notes"`
	URL             string   `json:"url"`
	Repositories    []string `json:"repositories"`
	XrayIndex       *bool    `json:"xrayIndex"`
	BlackedOut      *bool    `json:"blackedOut"`
	Offline         *bool    `json:"offline"`
	IncludesPattern string   `json:"includesPattern"`
	ExcludesPattern string   `json:"excludesPattern"`
	RepoLayoutRef   string   `json:"repoLayoutRef"`
	ProjectKey      string   `json:"projectKey"`
	PropertySets    []string `json:"propertySets"`

	// Remote repository settings. They are absent on a repository type that
	// does not proxy an upstream.
	AllowAnyHostAuth            *bool  `json:"allowAnyHostAuth"`
	ExternalDependenciesEnabled *bool  `json:"externalDependenciesEnabled"`
	StoreArtifactsLocally       *bool  `json:"storeArtifactsLocally"`
	BypassHeadRequests          *bool  `json:"bypassHeadRequests"`
	Username                    string `json:"username"`
	ContentSynchronisation      *struct {
		Enabled *bool `json:"enabled"`
	} `json:"contentSynchronisation"`

	// Package-format settings that decide what a client may push or pull.
	BlockPushingSchema1       *bool `json:"blockPushingSchema1"`
	ForceNugetAuthentication  *bool `json:"forceNugetAuthentication"`
	EnableTokenAuthentication *bool `json:"enableTokenAuthentication"`

	// Delivery settings that move a download off the instance.
	DownloadRedirect       *bool  `json:"downloadRedirect"`
	CdnRedirect            *bool  `json:"cdnRedirect"`
	ArchiveBrowsingEnabled *bool  `json:"archiveBrowsingEnabled"`
	PriorityResolution     *bool  `json:"priorityResolution"`
	SignedURLTTL           *int64 `json:"signedUrlTtl"`
	XrayDataTTL            *int64 `json:"xrayDataTtl"`
}

// repositoryConfigurations is the batched configuration response. The
// instance groups every repository under its class, so one call replaces one
// call per repository.
type repositoryConfigurations struct {
	Local         []repositoryDetailRecord `json:"LOCAL"`
	Remote        []repositoryDetailRecord `json:"REMOTE"`
	Virtual       []repositoryDetailRecord `json:"VIRTUAL"`
	Federated     []repositoryDetailRecord `json:"FEDERATED"`
	ReleaseBundle []repositoryDetailRecord `json:"RELEASE_BUNDLE"`
	Distribution  []repositoryDetailRecord `json:"DISTRIBUTION"`
}

// all flattens the grouped response. The class keys are read in a fixed order
// so that two scans of the same instance report the same list.
func (c *repositoryConfigurations) all() []repositoryDetailRecord {
	groups := [][]repositoryDetailRecord{
		c.Local, c.Remote, c.Virtual, c.Federated, c.ReleaseBundle, c.Distribution,
	}

	total := 0
	for _, group := range groups {
		total += len(group)
	}

	res := make([]repositoryDetailRecord, 0, total)
	for _, group := range groups {
		res = append(res, group...)
	}
	return res
}

type mqlArtifactoryRepositoryInternal struct {
	// lock guards the single configuration read that backs every detail-only
	// field, so asking for several of them costs one call. Only a successful
	// read is kept, so a transient failure is retried rather than failing every
	// later field for the rest of the scan.
	lock   sync.Mutex
	detail *repositoryDetailRecord
	// detailLoaded is read on the fast path without the lock, so it is atomic.
	// A plain bool there would be an unsynchronized read against the write the
	// lock holder makes, which is a data race whatever the value happens to be.
	detailLoaded atomic.Bool
}

func (a *mqlArtifactory) repositories() ([]any, error) {
	conn := artifactoryConn(a.MqlRuntime)
	ctx := context.Background()

	var records []repositoryRecord
	if err := conn.GetJSON(ctx, conn.ArtifactoryURL("/api/repositories"), &records); err != nil {
		return nil, err
	}

	// One call returns the configuration of every repository. Seeding the
	// resources from it keeps a query over the whole instance at two calls
	// rather than one call per repository. The endpoint needs an administrator
	// and a recent product version, so a scan that cannot use it falls back to
	// reading each configuration on demand.
	configured := fetchRepositoryConfigurations(ctx, conn)

	res := make([]any, 0, len(records))
	for i := range records {
		repo, err := newArtifactoryRepository(a.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		if detail, ok := configured[records[i].Key]; ok {
			repo.seedConfig(detail)
		}
		res = append(res, repo)
	}
	return res, nil
}

// fetchRepositoryConfigurations reads every repository configuration in one
// call, keyed by repository key. It reports an empty map when the instance does
// not serve the endpoint or denies it, which leaves each repository to read its
// own configuration on demand.
func fetchRepositoryConfigurations(ctx context.Context, conn *connection.ArtifactoryConnection) map[string]*repositoryDetailRecord {
	var configurations repositoryConfigurations
	if err := conn.GetJSON(ctx, conn.ArtifactoryURL("/api/repositories/configurations"), &configurations); err != nil {
		if connection.IsNotFound(err) || connection.IsForbidden(err) {
			// The instance does not serve the endpoint, or the token is not an
			// administrator. Both are expected, so the fallback is not worth a
			// warning.
			log.Debug().Err(err).Msg("artifactory> batched repository configurations are unavailable; reading them per repository")
			return nil
		}
		// Any other failure is survivable, because every field this would have
		// filled can still be read per repository. It is not expected, though,
		// so it is reported loudly enough that an operator sees why the scan
		// became one call per repository.
		log.Warn().Err(err).Msg("artifactory> could not read the batched repository configurations; reading them per repository")
		return nil
	}

	records := configurations.all()
	byKey := make(map[string]*repositoryDetailRecord, len(records))
	for i := range records {
		if records[i].Key == "" {
			continue
		}
		byKey[records[i].Key] = &records[i]
	}
	return byKey
}

func newArtifactoryRepository(runtime *plugin.Runtime, rec *repositoryRecord) (*mqlArtifactoryRepository, error) {
	res, err := CreateResource(runtime, "artifactory.repository", map[string]*llx.RawData{
		"key":         llx.StringData(rec.Key),
		"type":        llx.StringData(strings.ToLower(rec.Type)),
		"packageType": llx.StringData(strings.ToLower(rec.PackageType)),
		"description": optionalString(rec.Description),
		"url":         optionalString(rec.URL),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlArtifactoryRepository), nil
}

// initArtifactoryRepository resolves a repository by its key, so that
// `artifactory.repository(key: "example-docker")` works without listing every
// repository first.
func initArtifactoryRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	key := ""
	if data, ok := args["key"]; ok {
		if s, ok := data.Value.(string); ok {
			key = s
		}
	}
	if key == "" {
		return nil, nil, errors.New("artifactory.repository requires a key")
	}

	conn := artifactoryConn(runtime)

	var detail repositoryDetailRecord
	if err := conn.GetJSON(context.Background(), repositoryDetailURL(runtime, key), &detail); err != nil {
		return nil, nil, err
	}

	repo, err := newArtifactoryRepository(runtime, &repositoryRecord{
		Key:         key,
		Type:        detail.RClass,
		PackageType: detail.PackageType,
		Description: detail.Description,
		URL:         detail.URL,
	})
	if err != nil {
		return nil, nil, err
	}

	// The configuration was just read, so record it rather than fetching it
	// again the first time a detail field is queried.
	repo.seedConfig(&detail)

	return args, repo, nil
}

func repositoryDetailURL(runtime *plugin.Runtime, key string) string {
	conn := artifactoryConn(runtime)
	return conn.ArtifactoryURL("/api/repositories/" + url.PathEscape(key))
}

func (r *mqlArtifactoryRepository) id() (string, error) {
	return "artifactory.repository/" + r.Key.Data, r.Key.Error
}

// seedConfig records a configuration that was already read in bulk, so the
// per-repository read never happens.
func (r *mqlArtifactoryRepository) seedConfig(detail *repositoryDetailRecord) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.detailLoaded.Load() {
		return
	}
	r.detail = detail
	r.detailLoaded.Store(true)
}

// config reads the repository's configuration once and shares it with every
// field that needs it.
func (r *mqlArtifactoryRepository) config() (*repositoryDetailRecord, error) {
	if r.detailLoaded.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.detailLoaded.Load() {
		return r.detail, nil
	}

	conn := artifactoryConn(r.MqlRuntime)
	var detail repositoryDetailRecord
	if err := conn.GetJSON(context.Background(), repositoryDetailURL(r.MqlRuntime, r.Key.Data), &detail); err != nil {
		return nil, err
	}

	r.detail = &detail
	r.detailLoaded.Store(true)
	return r.detail, nil
}

func (r *mqlArtifactoryRepository) memberRepositories() ([]any, error) {
	detail, err := r.config()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(detail.Repositories), nil
}

// memberRepositoryRefs resolves the members of a virtual repository against
// the instance's repository list, so the whole set costs one list call rather
// than one call per member.
func (r *mqlArtifactoryRepository) memberRepositoryRefs() ([]any, error) {
	members, err := r.memberRepositories()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(members))
	for _, m := range members {
		if key, ok := m.(string); ok {
			keys = append(keys, key)
		}
	}
	return resolveRepositories(r.MqlRuntime, keys)
}

func (r *mqlArtifactoryRepository) xrayIndex() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.XrayIndex }, &r.XrayIndex)
}

func (r *mqlArtifactoryRepository) blackedOut() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.BlackedOut }, &r.BlackedOut)
}

func (r *mqlArtifactoryRepository) offline() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.Offline }, &r.Offline)
}

func (r *mqlArtifactoryRepository) allowAnyHostAuth() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.AllowAnyHostAuth }, &r.AllowAnyHostAuth)
}

func (r *mqlArtifactoryRepository) externalDependenciesEnabled() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.ExternalDependenciesEnabled }, &r.ExternalDependenciesEnabled)
}

// optionalBool reports a setting the instance omits for repository types it
// does not apply to. Such a setting stays null, so a repository that cannot
// carry it is distinguishable from one that has it turned off.
func (r *mqlArtifactoryRepository) optionalBool(pick func(*repositoryDetailRecord) *bool, field *plugin.TValue[bool]) (bool, error) {
	detail, err := r.config()
	if err != nil {
		return false, err
	}
	value := pick(detail)
	if value == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return *value, nil
}

func (r *mqlArtifactoryRepository) includesPattern() (string, error) {
	detail, err := r.config()
	if err != nil {
		return "", err
	}
	return detail.IncludesPattern, nil
}

func (r *mqlArtifactoryRepository) excludesPattern() (string, error) {
	detail, err := r.config()
	if err != nil {
		return "", err
	}
	return detail.ExcludesPattern, nil
}

func (r *mqlArtifactoryRepository) repoLayoutRef() (string, error) {
	detail, err := r.config()
	if err != nil {
		return "", err
	}
	return detail.RepoLayoutRef, nil
}

// permissionTargets reports every target whose repository scope covers this
// repository, including the ones that reach it through a wildcard key.
func (r *mqlArtifactoryRepository) permissionTargets() ([]any, error) {
	targets, err := allPermissionTargets(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, target := range targets {
		covers, err := target.coversRepository(r.Key.Data, r.Type.Data)
		if err != nil {
			return nil, err
		}
		if covers {
			res = append(res, target)
		}
	}
	return res, nil
}

// anonymousActions unions what every permission target gives the anonymous
// user over this repository. It answers the question a policy asks about a
// publishing repository: what can somebody with no credential do here.
func (r *mqlArtifactoryRepository) anonymousActions() ([]any, error) {
	targets, err := allPermissionTargets(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	actions := []string{}
	for _, target := range targets {
		covers, err := target.coversRepository(r.Key.Data, r.Type.Data)
		if err != nil {
			return nil, err
		}
		if !covers {
			continue
		}
		scope := target.recordScope(scopeRepo)
		if scope == nil {
			continue
		}
		for _, action := range scope.Actions.Users[AnonymousUser] {
			if seen[action] {
				continue
			}
			seen[action] = true
			actions = append(actions, action)
		}
	}
	return strSliceToAny(actions), nil
}

// resolveRepositories turns repository keys into repository resources by
// scanning the instance's repository list, which is fetched once and cached on
// the root resource. A key that names no repository on the instance, such as
// one of the wildcard keys a permission target may use, is skipped.
func resolveRepositories(runtime *plugin.Runtime, keys []string) ([]any, error) {
	if len(keys) == 0 {
		return []any{}, nil
	}

	root, err := getArtifactory(runtime)
	if err != nil {
		return nil, err
	}
	repositories := root.GetRepositories()
	if repositories.Error != nil {
		return nil, repositories.Error
	}

	byKey := make(map[string]*mqlArtifactoryRepository, len(repositories.Data))
	for _, it := range repositories.Data {
		if repo, ok := it.(*mqlArtifactoryRepository); ok {
			byKey[repo.Key.Data] = repo
		}
	}

	res := []any{}
	for _, key := range keys {
		if repo, ok := byKey[key]; ok {
			res = append(res, repo)
		}
	}
	return res, nil
}

// --- settings that decide what a client may push, pull, or resolve ---------

func (r *mqlArtifactoryRepository) blockPushingSchema1() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.BlockPushingSchema1 }, &r.BlockPushingSchema1)
}

func (r *mqlArtifactoryRepository) forceNugetAuthentication() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.ForceNugetAuthentication }, &r.ForceNugetAuthentication)
}

func (r *mqlArtifactoryRepository) enableTokenAuthentication() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.EnableTokenAuthentication }, &r.EnableTokenAuthentication)
}

func (r *mqlArtifactoryRepository) storeArtifactsLocally() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.StoreArtifactsLocally }, &r.StoreArtifactsLocally)
}

func (r *mqlArtifactoryRepository) bypassHeadRequests() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.BypassHeadRequests }, &r.BypassHeadRequests)
}

func (r *mqlArtifactoryRepository) downloadRedirect() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.DownloadRedirect }, &r.DownloadRedirect)
}

func (r *mqlArtifactoryRepository) cdnRedirect() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.CdnRedirect }, &r.CdnRedirect)
}

func (r *mqlArtifactoryRepository) archiveBrowsingEnabled() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.ArchiveBrowsingEnabled }, &r.ArchiveBrowsingEnabled)
}

func (r *mqlArtifactoryRepository) priorityResolution() (bool, error) {
	return r.optionalBool(func(d *repositoryDetailRecord) *bool { return d.PriorityResolution }, &r.PriorityResolution)
}

// hasUpstreamCredential reports whether a credential is stored for the
// upstream, without exposing it. Only a repository that proxies can hold one,
// so the field stays null on every other type.
func (r *mqlArtifactoryRepository) hasUpstreamCredential() (bool, error) {
	detail, err := r.config()
	if err != nil {
		return false, err
	}
	if !repositoryProxies(detail) {
		r.HasUpstreamCredential.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return detail.Username != "", nil
}

// contentSynchronisationEnabled reads the nested setting, which is absent
// altogether on a repository that does not carry it.
func (r *mqlArtifactoryRepository) contentSynchronisationEnabled() (bool, error) {
	detail, err := r.config()
	if err != nil {
		return false, err
	}
	if detail.ContentSynchronisation == nil || detail.ContentSynchronisation.Enabled == nil {
		r.ContentSynchronisationEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return *detail.ContentSynchronisation.Enabled, nil
}

// repositoryProxies reports whether the configuration describes a repository
// that fetches from an upstream. The remote-only settings are read from it and
// stay null everywhere else.
func repositoryProxies(detail *repositoryDetailRecord) bool {
	return strings.EqualFold(detail.RClass, "remote")
}

func (r *mqlArtifactoryRepository) signedUrlTtl() (int64, error) {
	return r.optionalInt(func(d *repositoryDetailRecord) *int64 { return d.SignedURLTTL }, &r.SignedUrlTtl)
}

func (r *mqlArtifactoryRepository) xrayDataTtl() (int64, error) {
	return r.optionalInt(func(d *repositoryDetailRecord) *int64 { return d.XrayDataTTL }, &r.XrayDataTtl)
}

// optionalInt reports a setting the instance omits for repository types it does
// not apply to, so an absent limit stays null rather than reading as zero.
func (r *mqlArtifactoryRepository) optionalInt(pick func(*repositoryDetailRecord) *int64, field *plugin.TValue[int64]) (int64, error) {
	detail, err := r.config()
	if err != nil {
		return 0, err
	}
	value := pick(detail)
	if value == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return *value, nil
}

func (r *mqlArtifactoryRepository) projectKey() (string, error) {
	detail, err := r.config()
	if err != nil {
		return "", err
	}
	return nullableString(detail.ProjectKey, &r.ProjectKey)
}

func (r *mqlArtifactoryRepository) notes() (string, error) {
	detail, err := r.config()
	if err != nil {
		return "", err
	}
	return nullableString(detail.Notes, &r.Notes)
}

func (r *mqlArtifactoryRepository) propertySets() ([]any, error) {
	detail, err := r.config()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(detail.PropertySets), nil
}
