// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// Scope names as they appear on the permissionTarget resource and in the
// principal's scope field.
const (
	scopeRepo          = "repo"
	scopeBuild         = "build"
	scopeReleaseBundle = "releaseBundle"
)

// Principal kinds.
const (
	principalUser  = "user"
	principalGroup = "group"
)

// Wildcard repository keys a permission target may name instead of a real
// repository. They cover repositories that did not exist when the target was
// written, which is what makes a target holding one hard to review.
const (
	wildcardAny             = "ANY"
	wildcardAnyLocal        = "ANY LOCAL"
	wildcardAnyRemote       = "ANY REMOTE"
	wildcardAnyVirtual      = "ANY VIRTUAL"
	wildcardAnyFederated    = "ANY FEDERATED"
	wildcardAnyDistribution = "ANY DISTRIBUTION"
)

// wildcardRepositoryTypes maps each class wildcard onto the repository type it
// covers. A wildcard the instance introduces later and this map does not hold
// would make a grant read as covering nothing, so the map is deliberately
// wider than the wildcards seen in practice.
var wildcardRepositoryTypes = map[string]string{
	wildcardAnyLocal:        "local",
	wildcardAnyRemote:       "remote",
	wildcardAnyVirtual:      "virtual",
	wildcardAnyFederated:    "federated",
	wildcardAnyDistribution: "distribution",
}

// matchEverythingPatterns are the include patterns that leave a grant
// unnarrowed, so the scope covers every path of the repositories it names.
var matchEverythingPatterns = map[string]bool{
	"**":    true,
	"**/*":  true,
	"*":     true,
	"**/**": true,
}

// permissionActions holds the actions a scope gives to each user and group.
type permissionActions struct {
	Users  map[string][]string `json:"users"`
	Groups map[string][]string `json:"groups"`
}

// permissionScopeRecord is one of the three areas a permission target grants
// over. The pattern keys are hyphenated in the API.
type permissionScopeRecord struct {
	IncludePatterns []string          `json:"include-patterns"`
	ExcludePatterns []string          `json:"exclude-patterns"`
	Repositories    []string          `json:"repositories"`
	Actions         permissionActions `json:"actions"`
}

type permissionTargetRecord struct {
	Name          string                 `json:"name"`
	Repo          *permissionScopeRecord `json:"repo"`
	Build         *permissionScopeRecord `json:"build"`
	ReleaseBundle *permissionScopeRecord `json:"releaseBundle"`
}

type permissionTargetListEntry struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type mqlArtifactoryPermissionTargetInternal struct {
	record *permissionTargetRecord
}

type mqlArtifactoryPermissionTargetScopeInternal struct {
	targetName string
	record     *permissionScopeRecord
}

func (a *mqlArtifactory) permissionTargets() ([]any, error) {
	conn := artifactoryConn(a.MqlRuntime)
	ctx := context.Background()

	var entries []permissionTargetListEntry
	if err := conn.GetJSON(ctx, conn.ArtifactoryURL("/api/v2/security/permissions"), &entries); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		// The list reports only names, so the grant itself is read per target.
		// A target that cannot be read fails the field rather than being
		// dropped, because a permission review that silently skips a target is
		// worse than one that reports it could not read it.
		var record permissionTargetRecord
		if err := conn.GetJSON(ctx, permissionTargetURL(a.MqlRuntime, entry.Name), &record); err != nil {
			return nil, err
		}
		if record.Name == "" {
			record.Name = entry.Name
		}

		target, err := newArtifactoryPermissionTarget(a.MqlRuntime, &record)
		if err != nil {
			return nil, err
		}
		res = append(res, target)
	}
	return res, nil
}

func permissionTargetURL(runtime *plugin.Runtime, name string) string {
	conn := artifactoryConn(runtime)
	return conn.ArtifactoryURL("/api/v2/security/permissions/" + url.PathEscape(name))
}

func newArtifactoryPermissionTarget(runtime *plugin.Runtime, record *permissionTargetRecord) (*mqlArtifactoryPermissionTarget, error) {
	anonymousActions := []string{}
	if record.Repo != nil {
		anonymousActions = record.Repo.Actions.Users[AnonymousUser]
	}

	res, err := CreateResource(runtime, "artifactory.permissionTarget", map[string]*llx.RawData{
		"name":                  llx.StringData(record.Name),
		"grantsAnonymousRead":   llx.BoolData(containsAction(anonymousActions, "read")),
		"grantsAnonymousDeploy": llx.BoolData(containsDeployAction(anonymousActions)),
	})
	if err != nil {
		return nil, err
	}

	target := res.(*mqlArtifactoryPermissionTarget)
	target.record = record
	return target, nil
}

// initArtifactoryPermissionTarget resolves a permission target by name.
func initArtifactoryPermissionTarget(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	name := ""
	if data, ok := args["name"]; ok {
		if s, ok := data.Value.(string); ok {
			name = s
		}
	}
	if name == "" {
		return nil, nil, errors.New("artifactory.permissionTarget requires a name")
	}

	conn := artifactoryConn(runtime)
	var record permissionTargetRecord
	if err := conn.GetJSON(context.Background(), permissionTargetURL(runtime, name), &record); err != nil {
		return nil, nil, err
	}
	if record.Name == "" {
		record.Name = name
	}

	target, err := newArtifactoryPermissionTarget(runtime, &record)
	if err != nil {
		return nil, nil, err
	}
	return args, target, nil
}

func (t *mqlArtifactoryPermissionTarget) id() (string, error) {
	return "artifactory.permissionTarget/" + t.Name.Data, t.Name.Error
}

func (t *mqlArtifactoryPermissionTarget) repo() (*mqlArtifactoryPermissionTargetScope, error) {
	return t.scope(scopeRepo, t.recordScope(scopeRepo), &t.Repo)
}

func (t *mqlArtifactoryPermissionTarget) build() (*mqlArtifactoryPermissionTargetScope, error) {
	return t.scope(scopeBuild, t.recordScope(scopeBuild), &t.Build)
}

func (t *mqlArtifactoryPermissionTarget) releaseBundle() (*mqlArtifactoryPermissionTargetScope, error) {
	return t.scope(scopeReleaseBundle, t.recordScope(scopeReleaseBundle), &t.ReleaseBundle)
}

func (t *mqlArtifactoryPermissionTarget) recordScope(name string) *permissionScopeRecord {
	if t.record == nil {
		return nil
	}
	switch name {
	case scopeRepo:
		return t.record.Repo
	case scopeBuild:
		return t.record.Build
	case scopeReleaseBundle:
		return t.record.ReleaseBundle
	}
	return nil
}

// scope builds the resource for one area of the target. A target that grants
// nothing over an area reports it as null, which keeps an absent grant
// distinguishable from one that names no repository.
func (t *mqlArtifactoryPermissionTarget) scope(name string, record *permissionScopeRecord, field *plugin.TValue[*mqlArtifactoryPermissionTargetScope]) (*mqlArtifactoryPermissionTargetScope, error) {
	if record == nil {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := CreateResource(t.MqlRuntime, "artifactory.permissionTarget.scope", map[string]*llx.RawData{
		"name":                     llx.StringData(name),
		"repositories":             llx.ArrayData(strSliceToAny(record.Repositories), types.String),
		"includePatterns":          llx.ArrayData(strSliceToAny(record.IncludePatterns), types.String),
		"excludePatterns":          llx.ArrayData(strSliceToAny(record.ExcludePatterns), types.String),
		"appliesToAllRepositories": llx.BoolData(hasWildcardRepository(record.Repositories)),
		"appliesToAllPaths":        llx.BoolData(appliesToAllPaths(record.IncludePatterns)),
	})
	if err != nil {
		return nil, err
	}

	scope := res.(*mqlArtifactoryPermissionTargetScope)
	scope.targetName = t.Name.Data
	scope.record = record
	return scope, nil
}

// principals flattens every principal of every scope, so one query lists
// everyone the target names without walking the three areas by hand.
func (t *mqlArtifactoryPermissionTarget) principals() ([]any, error) {
	res := []any{}
	for _, name := range []string{scopeRepo, scopeBuild, scopeReleaseBundle} {
		record := t.recordScope(name)
		if record == nil {
			continue
		}
		principals, err := newPrincipals(t.MqlRuntime, t.Name.Data, name, record)
		if err != nil {
			return nil, err
		}
		res = append(res, principals...)
	}
	return res, nil
}

// coversRepository reports whether the target's repository scope reaches the
// named repository, either by naming it or through a wildcard key.
func (t *mqlArtifactoryPermissionTarget) coversRepository(key string, repoType string) (bool, error) {
	record := t.recordScope(scopeRepo)
	if record == nil {
		return false, nil
	}
	return scopeCoversRepository(record.Repositories, key, repoType), nil
}

// scopeCoversRepository reports whether the scope reaches the named repository.
// Every entry is read before the answer is no, because the entries are
// alternatives and any one of them can be the wildcard that covers it.
func scopeCoversRepository(repositories []string, key string, repoType string) bool {
	for _, entry := range repositories {
		if entry == key {
			return true
		}

		upper := strings.ToUpper(strings.TrimSpace(entry))
		if upper == wildcardAny {
			return true
		}
		if covered, ok := wildcardRepositoryTypes[upper]; ok && strings.EqualFold(covered, repoType) {
			return true
		}
	}
	return false
}

// hasWildcardRepository reports whether the scope names a class wildcard rather
// than only real repositories. Every entry is read before the answer is no.
func hasWildcardRepository(repositories []string) bool {
	for _, entry := range repositories {
		upper := strings.ToUpper(strings.TrimSpace(entry))
		if upper == wildcardAny {
			return true
		}
		if _, ok := wildcardRepositoryTypes[upper]; ok {
			return true
		}
	}
	return false
}

// appliesToAllPaths reports whether the include patterns narrow the grant. No
// pattern at all leaves it unnarrowed, and so does a pattern that matches every
// path. An empty string is what the instance writes for "no pattern".
//
// The patterns are combined with OR, so every one of them is read before the
// grant is called narrowed. Stopping at the first narrow pattern would report
// ["example/**", "**"] as scoped, which is the dangerous direction to be wrong
// in.
func appliesToAllPaths(includePatterns []string) bool {
	narrowed := false
	for _, pattern := range includePatterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		if matchEverythingPatterns[trimmed] {
			return true
		}
		narrowed = true
	}
	return !narrowed
}

// allPermissionTargets returns the instance's permission targets from the root
// resource, so every reverse lookup shares one walk of the API rather than
// repeating it per repository, user, or group.
func allPermissionTargets(runtime *plugin.Runtime) ([]*mqlArtifactoryPermissionTarget, error) {
	root, err := getArtifactory(runtime)
	if err != nil {
		return nil, err
	}
	targets := root.GetPermissionTargets()
	if targets.Error != nil {
		return nil, targets.Error
	}

	res := make([]*mqlArtifactoryPermissionTarget, 0, len(targets.Data))
	for _, it := range targets.Data {
		if target, ok := it.(*mqlArtifactoryPermissionTarget); ok {
			res = append(res, target)
		}
	}
	return res, nil
}

// permissionTargetsFor returns every target that names the given principal.
func permissionTargetsFor(runtime *plugin.Runtime, kind string, name string) ([]any, error) {
	targets, err := allPermissionTargets(runtime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, target := range targets {
		if target.namesPrincipal(kind, name) {
			res = append(res, target)
		}
	}
	return res, nil
}

func (t *mqlArtifactoryPermissionTarget) namesPrincipal(kind string, name string) bool {
	for _, scopeName := range []string{scopeRepo, scopeBuild, scopeReleaseBundle} {
		record := t.recordScope(scopeName)
		if record == nil {
			continue
		}
		var actions map[string][]string
		if kind == principalUser {
			actions = record.Actions.Users
		} else {
			actions = record.Actions.Groups
		}
		if _, ok := actions[name]; ok {
			return true
		}
	}
	return false
}

// --- scope ----------------------------------------------------------------

func (s *mqlArtifactoryPermissionTargetScope) id() (string, error) {
	return "artifactory.permissionTarget/" + s.targetName + "/scope/" + s.Name.Data, s.Name.Error
}

func (s *mqlArtifactoryPermissionTargetScope) repositoryRefs() ([]any, error) {
	if s.record == nil {
		return []any{}, nil
	}
	return resolveRepositories(s.MqlRuntime, s.record.Repositories)
}

func (s *mqlArtifactoryPermissionTargetScope) principals() ([]any, error) {
	if s.record == nil {
		return []any{}, nil
	}
	return newPrincipals(s.MqlRuntime, s.targetName, s.Name.Data, s.record)
}

// --- principal ------------------------------------------------------------

type mqlArtifactoryPermissionTargetPrincipalInternal struct {
	targetName string
}

// newPrincipals builds the user and group principals of one scope. The order
// is stable so that a scan of the same instance twice reports the same list.
func newPrincipals(runtime *plugin.Runtime, targetName string, scopeName string, record *permissionScopeRecord) ([]any, error) {
	res := []any{}

	for _, kind := range []string{principalUser, principalGroup} {
		actions := record.Actions.Users
		if kind == principalGroup {
			actions = record.Actions.Groups
		}

		names := make([]string, 0, len(actions))
		for name := range actions {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			principal, err := newPrincipal(runtime, targetName, scopeName, kind, name, actions[name])
			if err != nil {
				return nil, err
			}
			res = append(res, principal)
		}
	}

	return res, nil
}

func newPrincipal(runtime *plugin.Runtime, targetName string, scopeName string, kind string, name string, actions []string) (*mqlArtifactoryPermissionTargetPrincipal, error) {
	res, err := CreateResource(runtime, "artifactory.permissionTarget.principal", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"type":      llx.StringData(kind),
		"scope":     llx.StringData(scopeName),
		"actions":   llx.ArrayData(strSliceToAny(actions), types.String),
		"canDeploy": llx.BoolData(containsDeployAction(actions)),
		"canManage": llx.BoolData(containsAction(actions, "manage")),
	})
	if err != nil {
		return nil, err
	}

	principal := res.(*mqlArtifactoryPermissionTargetPrincipal)
	principal.targetName = targetName
	return principal, nil
}

func (p *mqlArtifactoryPermissionTargetPrincipal) id() (string, error) {
	return "artifactory.permissionTarget/" + p.targetName + "/scope/" + p.Scope.Data + "/" + p.Type.Data + "/" + p.Name.Data, p.Name.Error
}

// user resolves a user principal against the instance's user list. A principal
// that names no account on the instance, such as the anonymous user or an
// account removed after the target was written, reports null.
func (p *mqlArtifactoryPermissionTargetPrincipal) user() (*mqlArtifactoryUser, error) {
	if p.Type.Data != principalUser {
		p.User.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	user, err := findUser(p.MqlRuntime, p.Name.Data)
	if err != nil {
		return nil, err
	}
	if user == nil {
		p.User.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return user, nil
}

// group resolves a group principal against the instance's group list.
func (p *mqlArtifactoryPermissionTargetPrincipal) group() (*mqlArtifactoryGroup, error) {
	if p.Type.Data != principalGroup {
		p.Group.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	group, err := findGroup(p.MqlRuntime, p.Name.Data)
	if err != nil {
		return nil, err
	}
	if group == nil {
		p.Group.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return group, nil
}
