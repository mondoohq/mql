// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"go.mondoo.com/mql/types"
)

// Watch resource types. The all-* entries are wildcards: they cover a whole
// class of resources rather than naming one, including resources created after
// the watch was written.
const (
	watchResourceRepository  = "repository"
	watchAllRepos            = "all-repos"
	watchAllBuilds           = "all-builds"
	watchAllReleaseBundles   = "all-releaseBundles"
	watchAllReleaseBundlesV2 = "all-releaseBundlesV2"
	watchAllProjects         = "all-projects"
)

// watchWildcardTypes are the resource types that cover a class rather than a
// named resource.
var watchWildcardTypes = map[string]bool{
	watchAllRepos:            true,
	watchAllBuilds:           true,
	watchAllReleaseBundles:   true,
	watchAllReleaseBundlesV2: true,
	watchAllProjects:         true,
}

// --- API records ----------------------------------------------------------

type xrayVersionRecord struct {
	XrayVersion  string `json:"xray_version"`
	XrayRevision string `json:"xray_revision"`
}

type xrayWatchRecord struct {
	GeneralData struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      *bool  `json:"active"`
	} `json:"general_data"`
	ProjectResources struct {
		Resources []xrayWatchResourceRecord `json:"resources"`
	} `json:"project_resources"`
	AssignedPolicies []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"assigned_policies"`
}

type xrayWatchResourceRecord struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	BinMgrID  string `json:"bin_mgr_id"`
	RepoType  string `json:"repo_type"`
	BuildRepo string `json:"build_repo"`
	Project   string `json:"project"`
	Filters   []struct {
		Type  string `json:"type"`
		Value any    `json:"value"`
	} `json:"filters"`
}

type xrayPolicyRecord struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Rules       []xrayPolicyRuleRecord `json:"rules"`
}

type xrayPolicyRuleRecord struct {
	Name     string `json:"name"`
	Priority *int64 `json:"priority"`
	Criteria struct {
		MinSeverity string `json:"min_severity"`
		CvssRange   *struct {
			From *float64 `json:"from"`
			To   *float64 `json:"to"`
		} `json:"cvss_range"`
		FixVersionDependant *bool    `json:"fix_version_dependant"`
		ApplicableCvesOnly  *bool    `json:"applicable_cves_only"`
		MaliciousPackage    *bool    `json:"malicious_package"`
		BannedLicenses      []string `json:"banned_licenses"`
		AllowedLicenses     []string `json:"allowed_licenses"`
		AllowUnknown        *bool    `json:"allow_unknown"`
	} `json:"criteria"`
	Actions struct {
		BlockDownload *struct {
			Unscanned *bool `json:"unscanned"`
			Active    *bool `json:"active"`
		} `json:"block_download"`
		BlockReleaseBundleDistribution *bool  `json:"block_release_bundle_distribution"`
		BlockReleaseBundlePromotion    *bool  `json:"block_release_bundle_promotion"`
		FailBuild                      *bool  `json:"fail_build"`
		BuildFailureGracePeriodInDays  *int64 `json:"build_failure_grace_period_in_days"`
		NotifyWatchRecipients          *bool  `json:"notify_watch_recipients"`
		NotifyDeployer                 *bool  `json:"notify_deployer"`
		CustomSeverity                 string `json:"custom_severity"`
	} `json:"actions"`
}

type xrayIgnoreRuleRecord struct {
	ID              string   `json:"id"`
	Author          string   `json:"author"`
	Notes           string   `json:"notes"`
	Created         isoTime  `json:"created"`
	ExpiresAt       isoTime  `json:"expires_at"`
	IsExpired       *bool    `json:"is_expired"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Licenses        []string `json:"licenses"`

	// IgnoreFilters is what the suppression is limited to. The platform also
	// nests watches, policies, builds, release bundles, and docker layers
	// here. Only the repository scope is decoded, because that is the one a
	// repository-level audit asks about; the others would need their own
	// resources to be worth reporting.
	IgnoreFilters struct {
		Repositories []string `json:"repositories"`
	} `json:"ignore_filters"`
}

// xrayIgnoreRulesResponse is one page of the ignore rule list.
type xrayIgnoreRulesResponse struct {
	Data       []xrayIgnoreRuleRecord `json:"data"`
	TotalCount int                    `json:"total_count"`
	PageNum    int                    `json:"page_num"`
	NumOfRows  int                    `json:"num_of_rows"`
}

// --- root -----------------------------------------------------------------

// xray reports the scanning service, or null when the platform has no reachable
// Xray. Null is a different answer from an Xray with no watch: the first means
// nothing scans, the second means nothing is enforced.
func (a *mqlArtifactory) xray() (*mqlArtifactoryXray, error) {
	conn := artifactoryConn(a.MqlRuntime)

	var version xrayVersionRecord
	if err := conn.GetJSON(context.Background(), conn.XrayURL("/api/v1/system/version"), &version); err != nil {
		if xrayIsAbsent(err) {
			log.Debug().Err(err).Msg("artifactory> the platform has no reachable Xray")
			a.Xray.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, xrayReadError(err)
	}

	res, err := CreateResource(a.MqlRuntime, "artifactory.xray", map[string]*llx.RawData{
		"version": llx.StringData(version.XrayVersion),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlArtifactoryXray), nil
}

// xrayIsAbsent reports whether the error means the platform serves no Xray at
// all. Only a 404 does.
//
// A denied read is deliberately not treated as an absent Xray. Reporting null
// there would say "this platform does not scan", and a policy asking whether a
// repository is protected would pass on an answer that was never read. The
// repository configuration endpoint may degrade to null because the same data
// is then read another way, so nothing is lost; here there is no second way,
// so a denial has to surface.
func xrayIsAbsent(err error) bool {
	return connection.IsNotFound(err)
}

// xrayReadError names the rights a denied read needs, so the failure reads as a
// permission problem rather than as a broken provider.
func xrayReadError(err error) error {
	if connection.IsForbidden(err) {
		return fmt.Errorf("the token may not read Xray; it needs a reachable Xray and the Manage Watches role: %w", err)
	}
	return err
}

func (x *mqlArtifactoryXray) id() (string, error) {
	return "artifactory.xray", nil
}

// --- watches --------------------------------------------------------------

type mqlArtifactoryXrayWatchInternal struct {
	// resourceRecords is named apart from the resources field so the embedded
	// struct does not collide with the generated accessor.
	resourceRecords []xrayWatchResourceRecord
}

func (x *mqlArtifactoryXray) watches() ([]any, error) {
	conn := artifactoryConn(x.MqlRuntime)

	var records []xrayWatchRecord
	if err := conn.GetJSON(context.Background(), conn.XrayURL("/api/v2/watches"), &records); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		watch, err := newXrayWatch(x.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, watch)
	}
	return res, nil
}

func newXrayWatch(runtime *plugin.Runtime, rec *xrayWatchRecord) (*mqlArtifactoryXrayWatch, error) {
	policyNames := make([]string, 0, len(rec.AssignedPolicies))
	for _, policy := range rec.AssignedPolicies {
		policyNames = append(policyNames, policy.Name)
	}

	created, err := CreateResource(runtime, "artifactory.xray.watch", map[string]*llx.RawData{
		"name":                  llx.StringData(rec.GeneralData.Name),
		"description":           optionalString(rec.GeneralData.Description),
		"active":                llx.BoolData(boolValue(rec.GeneralData.Active)),
		"policyNames":           llx.ArrayData(strSliceToAny(policyNames), types.String),
		"coversAllRepositories": llx.BoolData(watchCoversAllRepositories(rec.ProjectResources.Resources)),
	})
	if err != nil {
		return nil, err
	}

	watch := created.(*mqlArtifactoryXrayWatch)
	watch.resourceRecords = rec.ProjectResources.Resources
	return watch, nil
}

// watchCoversAllRepositories reports whether the watch reaches every
// repository through a wildcard entry. Every resource is read before the answer
// is no, because the entries are alternatives and any one of them can be the
// wildcard.
func watchCoversAllRepositories(resources []xrayWatchResourceRecord) bool {
	for _, resource := range resources {
		if resource.Type == watchAllRepos {
			return true
		}
	}
	return false
}

func (w *mqlArtifactoryXrayWatch) id() (string, error) {
	return "artifactory.xray.watch/" + w.Name.Data, w.Name.Error
}

func (w *mqlArtifactoryXrayWatch) resources() ([]any, error) {
	res := make([]any, 0, len(w.resourceRecords))
	for i := range w.resourceRecords {
		rec := w.resourceRecords[i]

		filters := make([]any, 0, len(rec.Filters))
		for _, filter := range rec.Filters {
			filters = append(filters, map[string]any{
				"type":  filter.Type,
				"value": filter.Value,
			})
		}

		created, err := CreateResource(w.MqlRuntime, "artifactory.xray.watch.resource", map[string]*llx.RawData{
			"type":       llx.StringData(rec.Type),
			"name":       optionalString(rec.Name),
			"repoType":   llx.StringData(rec.RepoType),
			"project":    optionalString(rec.Project),
			"isWildcard": llx.BoolData(watchWildcardTypes[rec.Type]),
			"filters":    llx.ArrayData(filters, types.Dict),
		})
		if err != nil {
			return nil, err
		}

		resource := created.(*mqlArtifactoryXrayWatchResource)
		resource.watchName = w.Name.Data
		resource.repositoryKey = watchResourceRepositoryKey(&rec)
		resource.position = i
		res = append(res, resource)
	}
	return res, nil
}

// policies resolves the policies the watch enforces. A watch that names a
// policy the platform does not hold reports fewer policies than it names, which
// is a watch that enforces less than it appears to.
func (w *mqlArtifactoryXrayWatch) policies() ([]any, error) {
	wanted := w.GetPolicyNames()
	if wanted.Error != nil {
		return nil, wanted.Error
	}

	policies, err := allXrayPolicies(w.MqlRuntime)
	if err != nil {
		return nil, err
	}

	byName := make(map[string]*mqlArtifactoryXrayPolicy, len(policies))
	for _, policy := range policies {
		byName[policy.Name.Data] = policy
	}

	res := []any{}
	for _, it := range wanted.Data {
		name, ok := it.(string)
		if !ok {
			continue
		}
		if policy, ok := byName[name]; ok {
			res = append(res, policy)
		}
	}
	return res, nil
}

// --- watch resources ------------------------------------------------------

type mqlArtifactoryXrayWatchResourceInternal struct {
	watchName     string
	repositoryKey string
	// position disambiguates two entries that carry the same type and no name,
	// for example a watch that names a wildcard class twice under different
	// project scopes. Without it the second entry would resolve to the cached
	// first one.
	position int
}

// watchResourceRepositoryKey reports the repository a resource entry names, or
// the empty string when it names none. A wildcard entry names no repository of
// its own even though it covers every one of them.
func watchResourceRepositoryKey(rec *xrayWatchResourceRecord) string {
	if rec.Type != watchResourceRepository {
		return ""
	}
	return rec.Name
}

func (r *mqlArtifactoryXrayWatchResource) id() (string, error) {
	name := r.Name.Data
	if name == "" {
		name = r.Type.Data
	}
	return "artifactory.xray.watch/" + r.watchName + "/resource/" +
		strconv.Itoa(r.position) + "/" + r.Type.Data + "/" + name, r.Type.Error
}

func (r *mqlArtifactoryXrayWatchResource) repository() (*mqlArtifactoryRepository, error) {
	if r.repositoryKey == "" {
		r.Repository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	repositories, err := resolveRepositories(r.MqlRuntime, []string{r.repositoryKey})
	if err != nil {
		return nil, err
	}
	if len(repositories) == 0 {
		r.Repository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return repositories[0].(*mqlArtifactoryRepository), nil
}

// --- policies -------------------------------------------------------------

type mqlArtifactoryXrayPolicyInternal struct {
	// ruleRecords is named apart from the rules field so the embedded struct
	// does not collide with the generated accessor.
	ruleRecords []xrayPolicyRuleRecord
}

func (x *mqlArtifactoryXray) policies() ([]any, error) {
	conn := artifactoryConn(x.MqlRuntime)

	var records []xrayPolicyRecord
	if err := conn.GetJSON(context.Background(), conn.XrayURL("/api/v2/policies"), &records); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		policy, err := newXrayPolicy(x.MqlRuntime, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, policy)
	}
	return res, nil
}

func newXrayPolicy(runtime *plugin.Runtime, rec *xrayPolicyRecord) (*mqlArtifactoryXrayPolicy, error) {
	created, err := CreateResource(runtime, "artifactory.xray.policy", map[string]*llx.RawData{
		"name":                            llx.StringData(rec.Name),
		"type":                            llx.StringData(rec.Type),
		"description":                     optionalString(rec.Description),
		"blocksDownload":                  llx.BoolData(policyBlocksDownload(rec.Rules)),
		"blocksUnscanned":                 llx.BoolData(policyBlocksUnscanned(rec.Rules)),
		"failsBuild":                      llx.BoolData(policyFailsBuild(rec.Rules)),
		"blocksReleaseBundleDistribution": llx.BoolData(policyBlocksReleaseBundleDistribution(rec.Rules)),
	})
	if err != nil {
		return nil, err
	}

	policy := created.(*mqlArtifactoryXrayPolicy)
	policy.ruleRecords = rec.Rules
	return policy, nil
}

// The rules of a policy are alternatives, so every rule is read before the
// answer is no. Stopping at the first rule that does not block would report a
// policy as toothless because of the order its rules happen to be in.

func policyBlocksDownload(rules []xrayPolicyRuleRecord) bool {
	for _, rule := range rules {
		if rule.Actions.BlockDownload != nil && boolValue(rule.Actions.BlockDownload.Active) {
			return true
		}
	}
	return false
}

func policyBlocksUnscanned(rules []xrayPolicyRuleRecord) bool {
	for _, rule := range rules {
		if rule.Actions.BlockDownload != nil && boolValue(rule.Actions.BlockDownload.Unscanned) {
			return true
		}
	}
	return false
}

func policyFailsBuild(rules []xrayPolicyRuleRecord) bool {
	for _, rule := range rules {
		if boolValue(rule.Actions.FailBuild) {
			return true
		}
	}
	return false
}

func policyBlocksReleaseBundleDistribution(rules []xrayPolicyRuleRecord) bool {
	for _, rule := range rules {
		if boolValue(rule.Actions.BlockReleaseBundleDistribution) {
			return true
		}
	}
	return false
}

func (p *mqlArtifactoryXrayPolicy) id() (string, error) {
	return "artifactory.xray.policy/" + p.Name.Data, p.Name.Error
}

func (p *mqlArtifactoryXrayPolicy) rules() ([]any, error) {
	res := make([]any, 0, len(p.ruleRecords))
	for i := range p.ruleRecords {
		rec := p.ruleRecords[i]

		cvssFrom := llx.NilData
		cvssTo := llx.NilData
		if rec.Criteria.CvssRange != nil {
			if rec.Criteria.CvssRange.From != nil {
				cvssFrom = llx.FloatData(*rec.Criteria.CvssRange.From)
			}
			if rec.Criteria.CvssRange.To != nil {
				cvssTo = llx.FloatData(*rec.Criteria.CvssRange.To)
			}
		}

		blockDownload := false
		blockUnscanned := false
		if rec.Actions.BlockDownload != nil {
			blockDownload = boolValue(rec.Actions.BlockDownload.Active)
			blockUnscanned = boolValue(rec.Actions.BlockDownload.Unscanned)
		}

		created, err := CreateResource(p.MqlRuntime, "artifactory.xray.policy.rule", map[string]*llx.RawData{
			"name":                           llx.StringData(rec.Name),
			"priority":                       optionalInt(rec.Priority),
			"minSeverity":                    optionalString(rec.Criteria.MinSeverity),
			"cvssRangeFrom":                  cvssFrom,
			"cvssRangeTo":                    cvssTo,
			"fixVersionDependant":            llx.BoolData(boolValue(rec.Criteria.FixVersionDependant)),
			"applicableCvesOnly":             llx.BoolData(boolValue(rec.Criteria.ApplicableCvesOnly)),
			"maliciousPackage":               llx.BoolData(boolValue(rec.Criteria.MaliciousPackage)),
			"bannedLicenses":                 llx.ArrayData(strSliceToAny(rec.Criteria.BannedLicenses), types.String),
			"allowedLicenses":                llx.ArrayData(strSliceToAny(rec.Criteria.AllowedLicenses), types.String),
			"allowUnknownLicenses":           llx.BoolData(boolValue(rec.Criteria.AllowUnknown)),
			"blockDownload":                  llx.BoolData(blockDownload),
			"blockUnscanned":                 llx.BoolData(blockUnscanned),
			"blockReleaseBundleDistribution": llx.BoolData(boolValue(rec.Actions.BlockReleaseBundleDistribution)),
			"blockReleaseBundlePromotion":    llx.BoolData(boolValue(rec.Actions.BlockReleaseBundlePromotion)),
			"failBuild":                      llx.BoolData(boolValue(rec.Actions.FailBuild)),
			"buildFailureGracePeriodInDays":  optionalInt(rec.Actions.BuildFailureGracePeriodInDays),
			"notifyWatchRecipients":          llx.BoolData(boolValue(rec.Actions.NotifyWatchRecipients)),
			"notifyDeployer":                 llx.BoolData(boolValue(rec.Actions.NotifyDeployer)),
			"customSeverity":                 optionalString(rec.Actions.CustomSeverity),
		})
		if err != nil {
			return nil, err
		}

		rule := created.(*mqlArtifactoryXrayPolicyRule)
		rule.policyName = p.Name.Data
		res = append(res, rule)
	}
	return res, nil
}

// watches reports where the policy is enforced. A policy no watch names is not
// enforced anywhere, whatever its rules say.
func (p *mqlArtifactoryXrayPolicy) watches() ([]any, error) {
	watches, err := allXrayWatches(p.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, watch := range watches {
		names := watch.GetPolicyNames()
		if names.Error != nil {
			return nil, names.Error
		}
		for _, it := range names.Data {
			if name, ok := it.(string); ok && name == p.Name.Data {
				res = append(res, watch)
				break
			}
		}
	}
	return res, nil
}

type mqlArtifactoryXrayPolicyRuleInternal struct {
	policyName string
}

func (r *mqlArtifactoryXrayPolicyRule) id() (string, error) {
	return "artifactory.xray.policy/" + r.policyName + "/rule/" + r.Name.Data, r.Name.Error
}

// --- ignore rules ---------------------------------------------------------

type mqlArtifactoryXrayIgnoreRuleInternal struct {
	repositories []string
}

// ignoreRules walks every page of the suppression list.
//
// The list is paged, so reading the first page only would report fewer
// permanent suppressions than exist. That is the dangerous direction: an audit
// looking for suppressions that never expire would pass because the rest were
// never fetched.
func (x *mqlArtifactoryXray) ignoreRules() ([]any, error) {
	records, err := fetchXrayIgnoreRules(context.Background(), artifactoryConn(x.MqlRuntime))
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]

		expiresAt := rec.ExpiresAt.Time()
		created, err := CreateResource(x.MqlRuntime, "artifactory.xray.ignoreRule", map[string]*llx.RawData{
			"id":              llx.StringData(rec.ID),
			"notes":           optionalString(rec.Notes),
			"author":          optionalString(rec.Author),
			"createdAt":       llx.TimeDataPtr(rec.Created.Time()),
			"expiresAt":       llx.TimeDataPtr(expiresAt),
			"expires":         llx.BoolData(expiresAt != nil),
			"isExpired":       llx.BoolData(boolValue(rec.IsExpired)),
			"vulnerabilities": llx.ArrayData(strSliceToAny(rec.Vulnerabilities), types.String),
			"licenses":        llx.ArrayData(strSliceToAny(rec.Licenses), types.String),
			"repositories":    llx.ArrayData(strSliceToAny(rec.IgnoreFilters.Repositories), types.String),
		})
		if err != nil {
			return nil, err
		}

		rule := created.(*mqlArtifactoryXrayIgnoreRule)
		rule.repositories = rec.IgnoreFilters.Repositories
		res = append(res, rule)
	}
	return res, nil
}

// xrayPageSize is the number of suppressions requested per page.
const xrayPageSize = 100

// xrayMaxPages bounds the walk. An endpoint that ignores the page parameter
// answers every request with the first page, which would otherwise loop
// forever. The repeated-identifier guard below catches the common shape of that
// bug and this cap catches the rest.
const xrayMaxPages = 200

// fetchXrayIgnoreRules returns every suppression, walking the pages.
func fetchXrayIgnoreRules(ctx context.Context, conn *connection.ArtifactoryConnection) ([]xrayIgnoreRuleRecord, error) {
	var records []xrayIgnoreRuleRecord
	seen := map[string]bool{}
	previousPage := ""

	for page := 1; page <= xrayMaxPages; page++ {
		query := url.Values{}
		query.Set("page_num", strconv.Itoa(page))
		query.Set("num_of_rows", strconv.Itoa(xrayPageSize))

		var response xrayIgnoreRulesResponse
		if err := conn.GetJSON(ctx, conn.XrayURL("/api/v1/ignore_rules")+"?"+query.Encode(), &response); err != nil {
			return nil, err
		}
		if len(response.Data) == 0 {
			break
		}

		// An endpoint that ignores the page parameter answers every request
		// with the first page. Detect that by the page repeating, and stop
		// rather than appending the same suppressions again.
		//
		// The marker covers the identifiers in order, so it also catches a
		// page of records the platform reports without one. Deduplicating on
		// the identifier alone would not: a record with no identifier can
		// never be recognised as seen, so it would count as new on every page
		// and the walk would run to the page cap.
		marker := pageMarker(response.Data)
		if marker == previousPage {
			break
		}
		previousPage = marker

		for _, rec := range response.Data {
			if rec.ID != "" {
				if seen[rec.ID] {
					continue
				}
				seen[rec.ID] = true
			}
			records = append(records, rec)
		}

		// A short page is the last page.
		if len(response.Data) < xrayPageSize {
			break
		}
		// The platform reports the total, so the walk stops as soon as every
		// suppression has been read.
		if response.TotalCount > 0 && len(records) >= response.TotalCount {
			break
		}
	}

	return records, nil
}

// pageMarker summarises a page by the identifiers it carries, in order. A page
// that repeats it is the same page served again. Both sides are values this
// walk produced from the response, so a plain comparison is what is wanted.
func pageMarker(records []xrayIgnoreRuleRecord) string {
	ids := make([]string, 0, len(records))
	for _, rec := range records {
		ids = append(ids, rec.ID)
	}
	return strconv.Itoa(len(records)) + "|" + strings.Join(ids, ",")
}

func (r *mqlArtifactoryXrayIgnoreRule) id() (string, error) {
	return "artifactory.xray.ignoreRule/" + r.Id.Data, r.Id.Error
}

func (r *mqlArtifactoryXrayIgnoreRule) repositoryRefs() ([]any, error) {
	return resolveRepositories(r.MqlRuntime, r.repositories)
}

// --- shared lookups -------------------------------------------------------

// xrayOf returns the scanning service from the root resource, or nil when the
// platform has no reachable Xray.
func xrayOf(runtime *plugin.Runtime) (*mqlArtifactoryXray, error) {
	root, err := getArtifactory(runtime)
	if err != nil {
		return nil, err
	}
	xray := root.GetXray()
	if xray.Error != nil {
		return nil, xray.Error
	}
	return xray.Data, nil
}

func allXrayWatches(runtime *plugin.Runtime) ([]*mqlArtifactoryXrayWatch, error) {
	xray, err := xrayOf(runtime)
	if err != nil || xray == nil {
		return nil, err
	}

	watches := xray.GetWatches()
	if watches.Error != nil {
		return nil, watches.Error
	}

	res := make([]*mqlArtifactoryXrayWatch, 0, len(watches.Data))
	for _, it := range watches.Data {
		if watch, ok := it.(*mqlArtifactoryXrayWatch); ok {
			res = append(res, watch)
		}
	}
	return res, nil
}

func allXrayPolicies(runtime *plugin.Runtime) ([]*mqlArtifactoryXrayPolicy, error) {
	xray, err := xrayOf(runtime)
	if err != nil || xray == nil {
		return nil, err
	}

	policies := xray.GetPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}

	res := make([]*mqlArtifactoryXrayPolicy, 0, len(policies.Data))
	for _, it := range policies.Data {
		if policy, ok := it.(*mqlArtifactoryXrayPolicy); ok {
			res = append(res, policy)
		}
	}
	return res, nil
}

// --- repository coverage --------------------------------------------------

// xrayWatches reports the active watches that reach the repository, either by
// naming it or through a wildcard. Being indexed is not the same as being
// covered, and this is the difference.
func (r *mqlArtifactoryRepository) xrayWatches() ([]any, error) {
	watches, err := allXrayWatches(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, watch := range watches {
		if !watch.Active.Data {
			continue
		}
		covers, err := watchCoversRepository(watch, r.Key.Data)
		if err != nil {
			return nil, err
		}
		if covers {
			res = append(res, watch)
		}
	}
	return res, nil
}

// watchCoversRepository reports whether an active watch reaches the repository.
// Every resource entry is read before the answer is no, because the entries are
// alternatives.
func watchCoversRepository(watch *mqlArtifactoryXrayWatch, wantedRepository string) (bool, error) {
	if watch.CoversAllRepositories.Data {
		return true, nil
	}

	resources := watch.GetResources()
	if resources.Error != nil {
		return false, resources.Error
	}

	for _, it := range resources.Data {
		resource, ok := it.(*mqlArtifactoryXrayWatchResource)
		if !ok {
			continue
		}
		// Both sides are repository names the administrator chose, so a plain
		// comparison is what is wanted here.
		if named := resource.repositoryKey; named == wantedRepository {
			return true, nil
		}
	}
	return false, nil
}

// xrayPolicies reports the policies enforced on the repository, through every
// active watch that reaches it.
func (r *mqlArtifactoryRepository) xrayPolicies() ([]any, error) {
	watches := r.GetXrayWatches()
	if watches.Error != nil {
		return nil, watches.Error
	}

	seen := map[string]bool{}
	res := []any{}
	for _, it := range watches.Data {
		watch, ok := it.(*mqlArtifactoryXrayWatch)
		if !ok {
			continue
		}
		policies := watch.GetPolicies()
		if policies.Error != nil {
			return nil, policies.Error
		}
		for _, pit := range policies.Data {
			policy, ok := pit.(*mqlArtifactoryXrayPolicy)
			if !ok || seen[policy.Name.Data] {
				continue
			}
			seen[policy.Name.Data] = true
			res = append(res, policy)
		}
	}
	return res, nil
}

// xrayBlocksDownload reports whether a policy enforced on the repository stops
// a download. This is what separates a repository that is scanned from one that
// is protected: without it, a violation is recorded and the artifact stays
// installable.
func (r *mqlArtifactoryRepository) xrayBlocksDownload() (bool, error) {
	policies := r.GetXrayPolicies()
	if policies.Error != nil {
		return false, policies.Error
	}

	// Every policy is read before the answer is no, because one blocking
	// policy is enough to protect the repository.
	for _, it := range policies.Data {
		if policy, ok := it.(*mqlArtifactoryXrayPolicy); ok && policy.BlocksDownload.Data {
			return true, nil
		}
	}
	return false, nil
}
