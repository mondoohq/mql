// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/helm/connection"
	"go.mondoo.com/mql/types"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	"helm.sh/helm/v3/pkg/strvals"
)

func (r *mqlHelm) id() (string, error) {
	return "helm", nil
}

func (r *mqlHelm) charts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.HelmConnection)
	charts := conn.Charts()

	var mqlCharts []any
	for _, lc := range charts {
		mqlChart, err := newMqlHelmChart(r.MqlRuntime, lc.Chart, lc.Path, nil)
		if err != nil {
			return nil, err
		}
		// Provenance only exists for a chart fetched from a remote source
		// that ships a .prov; it stays nil for local charts and subcharts.
		mqlChart.provData = lc.ProvenanceData
		mqlChart.archiveSHA256 = lc.ArchiveSHA256
		mqlCharts = append(mqlCharts, mqlChart)
	}
	return mqlCharts, nil
}

type mqlHelmChartInternal struct {
	chartObj        *chart.Chart
	chartPath       string
	parentChart     *mqlHelmChart
	idKey           string
	renderedOnce    sync.Once
	rendered        map[string]string
	renderValues    map[string]any
	renderedErr     error
	resourcesOnce   sync.Once
	cachedResources []any
	provData        []byte // raw .prov contents; nil unless fetched with provenance
	archiveSHA256   string // hex sha256 of the fetched archive; "" for local charts
}

// newMqlHelmChart materializes a *chart.Chart as a helm.chart resource.
// parent is nil for a top-level chart and points at the vendoring chart
// for a subchart reached through subcharts(). The cache key (__id) is
// parent-qualified so that sibling subcharts sharing name+version under
// different parents don't collapse onto one cached instance.
func newMqlHelmChart(runtime *plugin.Runtime, c *chart.Chart, chartPath string, parent *mqlHelmChart) (*mqlHelmChart, error) {
	// Guard against archives that load with a nil Metadata pointer.
	// loader.LoadDir always populates Metadata for a valid chart, but
	// loader.LoadFile (the .tgz path) can return a chart with nil
	// Metadata on a truncated/malformed archive.
	if c == nil || c.Metadata == nil {
		return nil, errors.New("helm chart has no metadata")
	}
	meta := c.Metadata

	keywords := convert.SliceAnyToInterface(meta.Keywords)
	sources := convert.SliceAnyToInterface(meta.Sources)

	// Include the chart's filesystem path in the cache key so two
	// distinct charts that happen to share name + version (common for
	// feature-branch forks in a multi-chart directory) don't collide
	// on CreateResource's cache.
	chartKey := meta.Name + ":" + meta.Version
	if chartPath != "" {
		chartKey += ":" + chartPath
	}

	// Parent-qualify the cache key for subcharts. Sibling subcharts can
	// share name+version across different parents (and a vendored subchart
	// carries no filesystem path of its own), so without the parent chain
	// in the id distinct subcharts would collapse onto one cached instance.
	idKey := "helm.chart:" + chartKey
	if parent != nil {
		idKey = parent.idKey + "/" + chartKey
	}

	args := map[string]*llx.RawData{
		"__id":        llx.StringData(idKey),
		"isSubchart":  llx.BoolData(parent != nil),
		"name":        llx.StringData(meta.Name),
		"version":     llx.StringData(meta.Version),
		"apiVersion":  llx.StringData(meta.APIVersion),
		"type":        llx.StringData(string(meta.Type)),
		"appVersion":  llx.StringData(meta.AppVersion),
		"description": llx.StringData(meta.Description),
		"keywords":    llx.ArrayData(keywords, types.String),
		"home":        llx.StringData(meta.Home),
		"sources":     llx.ArrayData(sources, types.String),
		"icon":        llx.StringData(meta.Icon),
		"deprecated":  llx.BoolData(meta.Deprecated),
		"kubeVersion": llx.StringData(meta.KubeVersion),
	}
	if meta.Annotations == nil {
		args["annotations"] = llx.NilData
	} else {
		annotations := make(map[string]any, len(meta.Annotations))
		for k, v := range meta.Annotations {
			annotations[k] = v
		}
		args["annotations"] = llx.MapData(annotations, types.String)
	}

	res, err := CreateResource(runtime, "helm.chart", args)
	if err != nil {
		return nil, err
	}
	mqlChart := res.(*mqlHelmChart)
	mqlChart.chartObj = c
	mqlChart.chartPath = chartPath
	mqlChart.parentChart = parent
	mqlChart.idKey = idKey
	return mqlChart, nil
}

func (c *mqlHelmChart) id() (string, error) {
	if c.idKey != "" {
		return c.idKey, nil
	}
	key := c.Name.Data + ":" + c.Version.Data
	if c.chartPath != "" {
		key += ":" + c.chartPath
	}
	return "helm.chart:" + key, nil
}

func (c *mqlHelmChart) fetchRendered() (map[string]string, error) {
	c.renderedOnce.Do(func() {
		ro := c.renderOptions()

		// Merge -f/--set overrides on top of the chart's bundled values,
		// exactly as `helm install` does.
		userVals, err := mergeRenderValues(ro)
		if err != nil {
			c.renderedErr = err
			return
		}

		name := ro.ReleaseName
		if name == "" {
			name = c.chartObj.Name()
		}
		options := chartutil.ReleaseOptions{
			Name:      name,
			Namespace: ro.Namespace,
			IsInstall: !ro.IsUpgrade,
			IsUpgrade: ro.IsUpgrade,
		}

		caps, err := renderCapabilities(ro)
		if err != nil {
			c.renderedErr = err
			return
		}

		vals, err := chartutil.ToRenderValues(c.chartObj, userVals, options, caps)
		if err != nil {
			c.renderedErr = err
			return
		}
		// Stash the coalesced values (defaults + overrides) so
		// renderedValues() can expose exactly what drove the render.
		if cv, ok := vals["Values"].(chartutil.Values); ok {
			c.renderValues = map[string]any(cv)
		}

		e := engine.Engine{Strict: false}
		c.rendered, c.renderedErr = e.Render(c.chartObj, vals)
	})
	return c.rendered, c.renderedErr
}

// renderOptions reads the connection's parsed render configuration. A
// subchart shares its parent connection, so this works at any depth.
func (c *mqlHelmChart) renderOptions() connection.RenderOptions {
	conn, ok := c.MqlRuntime.Connection.(*connection.HelmConnection)
	if !ok {
		return connection.RenderOptions{Namespace: "default"}
	}
	return conn.RenderOptions()
}

// mergeRenderValues applies the -f/--set family of overrides in the same
// order and with the same semantics as `helm install`'s MergeValues,
// using helm's own strvals parser. It is reimplemented here (rather than
// calling pkg/cli/values) to avoid pulling in helm's kube/registry getter
// stack for what static analysis only needs locally.
func mergeRenderValues(ro connection.RenderOptions) (map[string]any, error) {
	base := map[string]any{}

	for _, f := range ro.ValueFiles {
		data, err := readValueFile(f)
		if err != nil {
			return nil, err
		}
		current := map[string]any{}
		if err := yaml.Unmarshal(data, &current); err != nil {
			return nil, fmt.Errorf("failed to parse values file %q: %w", f, err)
		}
		base = mergeMaps(base, current)
	}
	for _, v := range ro.Values {
		if err := strvals.ParseInto(v, base); err != nil {
			return nil, fmt.Errorf("failed to parse --set %q: %w", v, err)
		}
	}
	for _, v := range ro.StringValues {
		if err := strvals.ParseIntoString(v, base); err != nil {
			return nil, fmt.Errorf("failed to parse --set-string %q: %w", v, err)
		}
	}
	for _, v := range ro.FileValues {
		reader := func(rs []rune) (any, error) {
			data, err := readValueFile(string(rs))
			return string(data), err
		}
		if err := strvals.ParseIntoFile(v, base, reader); err != nil {
			return nil, fmt.Errorf("failed to parse --set-file %q: %w", v, err)
		}
	}
	for _, v := range ro.JSONValues {
		if err := strvals.ParseJSON(v, base); err != nil {
			return nil, fmt.Errorf("failed to parse --set-json %q: %w", v, err)
		}
	}
	return base, nil
}

// valueFileHTTPClient bounds remote values-file fetches so a slow server
// can't hang the query indefinitely.
var valueFileHTTPClient = &http.Client{Timeout: 30 * time.Second}

// maxValueFileSize caps a remote values/file override (10 MiB) so an
// oversized response can't exhaust memory.
const maxValueFileSize = 10 << 20

// readValueFile reads a values/file override from a local path or an
// http(s) URL.
func readValueFile(ref string) ([]byte, error) {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		resp, err := valueFileHTTPClient.Get(ref) //nolint:gosec // user-supplied values URL, same trust model as helm -f
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch values file %q: status %d", ref, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxValueFileSize))
	}
	return os.ReadFile(ref)
}

// mergeMaps deep-merges src into a copy of dst, mirroring helm's
// values.mergeMaps: maps recurse, scalars and slices from src win.
func mergeMaps(dst, src map[string]any) map[string]any {
	out := make(map[string]any, len(dst))
	maps.Copy(out, dst)
	for k, v := range src {
		if vMap, ok := v.(map[string]any); ok {
			if existing, ok := out[k].(map[string]any); ok {
				out[k] = mergeMaps(existing, vMap)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// renderCapabilities builds the .Capabilities object from a target kube
// version and any --api-versions, falling back to helm's defaults.
func renderCapabilities(ro connection.RenderOptions) (*chartutil.Capabilities, error) {
	caps := chartutil.DefaultCapabilities.Copy()
	if ro.KubeVersion != "" {
		kv, err := chartutil.ParseKubeVersion(ro.KubeVersion)
		if err != nil {
			return nil, err
		}
		caps.KubeVersion = *kv
	}
	for _, av := range ro.APIVersions {
		caps.APIVersions = append(caps.APIVersions, av)
	}
	return caps, nil
}

func (c *mqlHelmChart) dependencies() ([]any, error) {
	deps := c.chartObj.Metadata.Dependencies
	var mqlDeps []any
	for _, dep := range deps {
		mqlDep, err := newMqlHelmDependency(c, dep, "dep")
		if err != nil {
			return nil, err
		}
		mqlDeps = append(mqlDeps, mqlDep)
	}
	return mqlDeps, nil
}

// subcharts wraps chart.Dependencies() — the subchart bodies actually
// loaded from charts/ — as fully recursive helm.chart resources, reusing
// newMqlHelmChart so every chart field works per-subchart. This is the
// loaded subchart objects, distinct from dependencies() which reads the
// declared dependency entries from Chart.yaml.
func (c *mqlHelmChart) subcharts() ([]any, error) {
	subs := c.chartObj.Dependencies()
	mqlSubs := make([]any, 0, len(subs))
	for _, sub := range subs {
		// A vendored subchart has no filesystem path of its own; the
		// parent-qualified id keeps siblings distinct.
		mqlSub, err := newMqlHelmChart(c.MqlRuntime, sub, "", c)
		if err != nil {
			return nil, err
		}
		mqlSubs = append(mqlSubs, mqlSub)
	}
	return mqlSubs, nil
}

func (c *mqlHelmChart) parent() (*mqlHelmChart, error) {
	if c.parentChart == nil {
		c.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return c.parentChart, nil
}

func (c *mqlHelmChart) maintainers() ([]any, error) {
	maintainers := c.chartObj.Metadata.Maintainers
	var mqlMaintainers []any
	for i, m := range maintainers {
		mqlM, err := newMqlHelmMaintainer(c.MqlRuntime, c.chartObj.Name(), i, m)
		if err != nil {
			return nil, err
		}
		mqlMaintainers = append(mqlMaintainers, mqlM)
	}
	return mqlMaintainers, nil
}

func (c *mqlHelmChart) templates() ([]any, error) {
	rendered, renderErr := c.fetchRendered()
	if renderErr != nil {
		log.Warn().Err(renderErr).Str("chart", c.chartObj.Name()).Msg("failed to render helm chart templates")
	}

	var mqlTemplates []any
	for _, t := range c.chartObj.Templates {
		renderedContent := ""
		if rendered != nil {
			// Helm uses "chartName/templateName" as the key
			renderedContent = rendered[c.chartObj.Name()+"/"+t.Name]
		}
		// Pass renderErr through so the template's rendered() accessor
		// can surface it instead of silently returning "" — that lets
		// policy authors distinguish "rendered to empty output" from
		// "rendering failed."
		mqlT, err := newMqlHelmTemplate(c.MqlRuntime, c.chartObj.Name(), t, renderedContent, renderErr)
		if err != nil {
			return nil, err
		}
		mqlTemplates = append(mqlTemplates, mqlT)
	}
	return mqlTemplates, nil
}

func (c *mqlHelmChart) values() (any, error) {
	dict, err := convert.JsonToDict(c.chartObj.Values)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (c *mqlHelmChart) resources() ([]any, error) {
	return c.fetchResources()
}

// fetchResources parses every rendered template into K8s resources
// and caches the result on the chart's Internal struct so repeated
// reads of helm.chart.resources don't reparse the same YAML on
// every access. helm.template.resources parses its own rendered
// string directly (scoped to a single template), so it doesn't go
// through this cache.
//
// Chart-wide render failures are intentionally swallowed at this
// level — see TestHelmRequiredValuesGraceful. A chart that uses
// `required` with no values returns no resources but does not error
// out the whole audit query. Per-template failures still surface
// through helm.template.rendered() and helm.template.resources().
func (c *mqlHelmChart) fetchResources() ([]any, error) {
	c.resourcesOnce.Do(func() {
		// Initialize to an empty (non-nil) slice so the success-with-
		// zero-resources path and the render-error path return the
		// same shape — callers can rely on a non-nil result either way.
		c.cachedResources = []any{}
		rendered, err := c.fetchRendered()
		if err != nil {
			log.Warn().Err(err).Str("chart", c.chartObj.Name()).Msg("failed to render helm chart templates, returning empty resources")
			return
		}
		for templateKey, content := range rendered {
			resources, err := parseK8sResources(c.MqlRuntime, templateKey, content, false)
			if err != nil {
				continue
			}
			// Wire each resource back to this chart so helm.resource.template
			// resolves to the real, materialized helm.template (never a husk).
			for _, r := range resources {
				if res, ok := r.(*mqlHelmResource); ok {
					res.ownerChart = c
				}
			}
			c.cachedResources = append(c.cachedResources, resources...)
		}
	})
	return c.cachedResources, nil
}

func (c *mqlHelmChart) files() ([]any, error) {
	var mqlFiles []any
	for _, f := range c.chartObj.Files {
		mqlF, err := newMqlHelmFile(c.MqlRuntime, c.chartObj.Name(), f)
		if err != nil {
			return nil, err
		}
		mqlFiles = append(mqlFiles, mqlF)
	}
	return mqlFiles, nil
}

type mqlHelmDependencyInternal struct {
	parentChart *mqlHelmChart
}

// renderedValues exposes the coalesced values (chart defaults merged
// with -f/--set overrides) that drove the render, distinct from values()
// which is always the bundled values.yaml.
func (c *mqlHelmChart) renderedValues() (any, error) {
	// fetchRendered populates renderValues during ToRenderValues, before
	// engine.Render runs, so the coalesced values are available even when
	// rendering later fails (e.g. a missing `required` value).
	_, _ = c.fetchRendered()
	vals := c.renderValues
	if vals == nil {
		vals = map[string]any{}
	}
	return convert.JsonToDict(vals)
}

// notes returns the chart's rendered templates/NOTES.txt, or empty when
// the chart ships none or rendering failed.
func (c *mqlHelmChart) notes() (string, error) {
	rendered, _ := c.fetchRendered()
	if rendered == nil {
		return "", nil
	}
	return rendered[c.chartObj.Name()+"/templates/NOTES.txt"], nil
}

// crds parses the CustomResourceDefinition YAML under the chart's crds/
// directory. Helm never templates these, so they're parsed verbatim and
// flagged isCRD.
func (c *mqlHelmChart) crds() ([]any, error) {
	out := []any{}
	for _, crd := range c.chartObj.CRDObjects() {
		if crd.File == nil {
			continue
		}
		resources, err := parseK8sResources(c.MqlRuntime, c.chartObj.Name()+"/"+crd.Name, string(crd.File.Data), true)
		if err != nil {
			continue
		}
		out = append(out, resources...)
	}
	return out, nil
}

// valuesSchema returns the parsed values.schema.json, or null when the
// chart ships no schema.
func (c *mqlHelmChart) valuesSchema() (any, error) {
	if len(c.chartObj.Schema) == 0 {
		return nil, nil
	}
	var parsed any
	if err := json.Unmarshal(c.chartObj.Schema, &parsed); err != nil {
		return nil, err
	}
	return convert.JsonToDict(parsed)
}

// hooks returns the rendered resources carrying a helm.sh/hook annotation.
func (c *mqlHelmChart) hooks() ([]any, error) {
	resources, err := c.fetchResources()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range resources {
		if res, ok := r.(*mqlHelmResource); ok && res.IsHook.Data {
			out = append(out, res)
		}
	}
	return out, nil
}

type mqlHelmChartDependencyLockInternal struct {
	parentChart *mqlHelmChart
	lockObj     *chart.Lock
}

// lock exposes the chart's Chart.lock, or null when the chart has none.
func (c *mqlHelmChart) lock() (*mqlHelmChartDependencyLock, error) {
	lock := c.chartObj.Lock
	if lock == nil {
		c.Lock.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(c.MqlRuntime, "helm.chart.dependencyLock", map[string]*llx.RawData{
		"__id":      llx.StringData(c.idKey + "/lock"),
		"digest":    llx.StringData(lock.Digest),
		"generated": llx.TimeData(lock.Generated),
	})
	if err != nil {
		return nil, err
	}
	mqlLock := res.(*mqlHelmChartDependencyLock)
	mqlLock.parentChart = c
	mqlLock.lockObj = lock
	return mqlLock, nil
}

func (l *mqlHelmChartDependencyLock) dependencies() ([]any, error) {
	out := []any{}
	if l.lockObj == nil || l.parentChart == nil {
		return out, nil
	}
	for _, dep := range l.lockObj.Dependencies {
		mqlDep, err := newMqlHelmDependency(l.parentChart, dep, "lock")
		if err != nil {
			return nil, err
		}
		out = append(out, mqlDep)
	}
	return out, nil
}

// newMqlHelmDependency materializes a chart.Dependency. parent is the
// chart that declared (or locked) it, used by resolvedVersion() and
// chart() to reach the parent's lock file and vendored subcharts.
// idScope ("dep" for declared dependencies, "lock" for Chart.lock
// entries) keeps a declared dependency and its locked counterpart from
// colliding on the resource cache.
func newMqlHelmDependency(parent *mqlHelmChart, dep *chart.Dependency, idScope string) (*mqlHelmDependency, error) {
	tags := convert.SliceAnyToInterface(dep.Tags)

	importValues := make([]any, 0, len(dep.ImportValues))
	for _, iv := range dep.ImportValues {
		d, err := convert.JsonToDict(iv)
		if err != nil {
			continue
		}
		importValues = append(importValues, d)
	}

	res, err := CreateResource(parent.MqlRuntime, "helm.dependency", map[string]*llx.RawData{
		"__id":         llx.StringData("helm.dependency:" + idScope + ":" + parent.chartObj.Name() + ":" + dep.Name),
		"name":         llx.StringData(dep.Name),
		"version":      llx.StringData(dep.Version),
		"repository":   llx.StringData(dep.Repository),
		"condition":    llx.StringData(dep.Condition),
		"tags":         llx.ArrayData(tags, types.String),
		"enabled":      llx.BoolData(dep.Enabled),
		"alias":        llx.StringData(dep.Alias),
		"sourceType":   llx.StringData(classifyHelmSource(dep.Repository, dep.Alias)),
		"importValues": llx.ArrayData(importValues, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	mqlDep := res.(*mqlHelmDependency)
	mqlDep.parentChart = parent
	return mqlDep, nil
}

// resolvedVersion returns the concrete version Helm locked for this
// dependency, read from the parent chart's Chart.lock. Empty when there
// is no lock file or the dependency isn't locked.
func (d *mqlHelmDependency) resolvedVersion() (string, error) {
	if d.parentChart == nil || d.parentChart.chartObj.Lock == nil {
		return "", nil
	}
	for _, locked := range d.parentChart.chartObj.Lock.Dependencies {
		if locked.Name == d.Name.Data {
			return locked.Version, nil
		}
	}
	return "", nil
}

// chart links to the vendored subchart that satisfies this dependency,
// matched by name or alias against the parent's loaded subcharts. Null
// when the dependency isn't vendored on disk.
func (d *mqlHelmDependency) chart() (*mqlHelmChart, error) {
	if d.parentChart != nil {
		for _, sub := range d.parentChart.chartObj.Dependencies() {
			if sub.Name() == d.Name.Data || (d.Alias.Data != "" && sub.Name() == d.Alias.Data) {
				return newMqlHelmChart(d.MqlRuntime, sub, "", d.parentChart)
			}
		}
	}
	d.Chart.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// classifyHelmSource categorizes a dependency's source from its
// repository value (offline, no network). An empty repository with an
// alias is a sibling-chart reference; an empty repository with neither
// is unknown.
func classifyHelmSource(repository, alias string) string {
	repo := strings.TrimSpace(repository)
	switch {
	case repo == "":
		if alias != "" {
			return "alias"
		}
		return "unknown"
	case strings.HasPrefix(repo, "oci://"):
		return "oci"
	case strings.HasPrefix(repo, "https://"):
		return "https"
	case strings.HasPrefix(repo, "http://"):
		return "http"
	case strings.HasPrefix(repo, "file://"), strings.HasPrefix(repo, "./"), strings.HasPrefix(repo, "../"), strings.HasPrefix(repo, "/"):
		return "file"
	default:
		return "unknown"
	}
}

func (d *mqlHelmDependency) registryRef() (*mqlHelmOciRef, error) {
	if d.SourceType.Data != "oci" {
		d.RegistryRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	parsed := parseOciRef(d.Repository.Data, d.Version.Data)

	res, err := CreateResource(d.MqlRuntime, "helm.ociRef", map[string]*llx.RawData{
		"__id":       llx.StringData("helm.dependency:" + d.Name.Data + "/ociRef"),
		"reference":  llx.StringData(parsed.reference),
		"registry":   llx.StringData(parsed.registry),
		"repository": llx.StringData(parsed.repository),
		"tag":        llx.StringData(parsed.tag),
		"digest":     llx.StringData(parsed.digest),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHelmOciRef), nil
}

type ociRef struct {
	reference  string
	registry   string
	repository string
	tag        string
	digest     string
}

// parseOciRef decomposes an oci:// reference (and the dependency's
// version constraint) into registry / repository / tag / digest. It is
// defensive: an unparseable reference yields whatever parts could be
// recovered with empty strings for the rest, and never panics.
//
//	oci://ghcr.io/acme/charts/redis        -> registry=ghcr.io repository=acme/charts/redis
//	oci://ghcr.io/acme/redis:1.2.3         -> ... tag=1.2.3
//	oci://ghcr.io/acme/redis@sha256:abc... -> ... digest=sha256:abc...
//
// The tag falls back to the dependency version when it's a concrete
// version (no range operators); the digest falls back to the version
// when the version itself pins a sha256 digest.
func parseOciRef(repository, version string) ociRef {
	ref := ociRef{reference: repository}

	rest := strings.TrimPrefix(strings.TrimSpace(repository), "oci://")

	// A digest pin (@sha256:...) takes precedence over a :tag suffix.
	if before, after, ok := strings.CutLast(rest, "@"); ok {
		ref.digest = after
		rest = before
	}

	// Split host from path. Everything before the first "/" is the
	// registry host; the remainder is the repository path.
	if slash := strings.Index(rest, "/"); slash != -1 {
		ref.registry = rest[:slash]
		repoPath := rest[slash+1:]

		// A :tag suffix on the final path segment (only when no digest
		// was found, and only if the colon isn't part of a host:port —
		// which lives in the registry segment, already split off).
		if ref.digest == "" {
			if before, after, ok := strings.CutLast(repoPath, ":"); ok {
				ref.tag = after
				repoPath = before
			}
		}
		ref.repository = repoPath
	} else {
		// No path component — treat the whole thing as the registry.
		ref.registry = rest
	}

	// Fall back to the version constraint for tag/digest when the
	// reference itself didn't carry one.
	v := strings.TrimSpace(version)
	if ref.digest == "" && strings.HasPrefix(v, "sha256:") {
		ref.digest = v
	} else if ref.tag == "" && v != "" && isConcreteVersion(v) {
		ref.tag = v
	}

	return ref
}

// isConcreteVersion reports whether a version string is a single
// concrete version rather than a SemVer range/constraint. OCI tags are
// concrete, so only a concrete version maps onto a tag.
func isConcreteVersion(v string) bool {
	return !strings.ContainsAny(v, "^~*><= |,x")
}

func newMqlHelmMaintainer(runtime *plugin.Runtime, chartName string, idx int, m *chart.Maintainer) (*mqlHelmMaintainer, error) {
	// Include the loop index so a chart that declares two maintainers
	// with the same name doesn't silently dedupe through the resource
	// cache. (The Helm spec permits duplicate maintainer names.)
	id := "helm.maintainer:" + chartName + ":" + strconv.Itoa(idx) + ":" + m.Name
	res, err := CreateResource(runtime, "helm.maintainer", map[string]*llx.RawData{
		"__id":  llx.StringData(id),
		"name":  llx.StringData(m.Name),
		"email": llx.StringData(m.Email),
		"url":   llx.StringData(m.URL),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHelmMaintainer), nil
}

func newMqlHelmFile(runtime *plugin.Runtime, chartName string, f *chart.File) (*mqlHelmFile, error) {
	res, err := CreateResource(runtime, "helm.file", map[string]*llx.RawData{
		"__id":     llx.StringData("helm.file:" + chartName + ":" + f.Name),
		"path":     llx.StringData(f.Name),
		"size":     llx.IntData(int64(len(f.Data))),
		"isBinary": llx.BoolData(!utf8.Valid(f.Data)),
	})
	if err != nil {
		return nil, err
	}
	mqlFile := res.(*mqlHelmFile)
	mqlFile.cacheData = f.Data
	return mqlFile, nil
}

type mqlHelmFileInternal struct {
	cacheData []byte
}

func (f *mqlHelmFile) content() (string, error) {
	return string(f.cacheData), nil
}
