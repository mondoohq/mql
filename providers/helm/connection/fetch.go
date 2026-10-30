// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/registry"
)

// fetchedChart is the result of resolving a (possibly remote) chart
// reference to something loadCharts can read. For remote refs it also
// carries the chart's provenance (.prov) bytes when the source ships one,
// plus the sha256 of the fetched archive, so the resource layer can report
// helm.chart.provenance without re-fetching or contacting the registry.
type fetchedChart struct {
	localPath     string
	cleanup       func() // nil for local paths
	provData      []byte // raw .prov contents; nil when no provenance was found
	archiveSHA256 string // hex sha256 of the fetched archive; "" for local paths
}

// resolveChartRef turns a possibly-remote chart reference into a local
// filesystem path that loadCharts can read:
//
//   - oci://registry/repo[:tag]   — pulled from the OCI registry
//   - http(s)://host/chart.tgz    — downloaded directly
//   - chartName with --repo URL   — resolved against the repo index, then pulled
//   - anything else               — treated as a local path (cleaned)
//
// For remote refs it downloads the chart archive into a temp directory and
// returns a cleanup func that removes it; loadCharts reads the archive fully
// into memory, so the caller can clean up immediately afterward. cleanup is
// nil for local paths. Remote refs also surface the chart's provenance (when
// the source ships a .prov) and the archive's sha256 on the returned struct.
//
// Fetching deliberately avoids helm's pkg/getter and pkg/repo, which pull in
// the kube/kubectl stack (incompatible with our pinned k8s.io/api and useless
// for static analysis). OCI uses pkg/registry directly; HTTP repositories and
// index resolution use net/http.
func resolveChartRef(rawPath string, opts map[string]string) (*fetchedChart, error) {
	version := opts[OptionVersion]
	username := opts[OptionUsername]
	password := opts[OptionPassword]
	repoURL := opts[OptionRepo]

	isOCI := strings.HasPrefix(rawPath, registry.OCIScheme+"://")
	isHTTP := strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://")

	// Purely local chart: no fetching, no provenance.
	if !isOCI && !isHTTP && repoURL == "" {
		return &fetchedChart{localPath: filepath.Clean(rawPath)}, nil
	}

	data, prov, err := fetchChartArchive(rawPath, repoURL, version, username, password, isOCI)
	if err != nil {
		return nil, err
	}

	dest, err := os.MkdirTemp("", "mql-helm-chart-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		if rmErr := os.RemoveAll(dest); rmErr != nil {
			log.Warn().Err(rmErr).Str("dir", dest).Msg("failed to clean up helm chart download dir")
		}
	}

	archive := filepath.Join(dest, "chart.tgz")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		cleanup()
		return nil, err
	}

	sum := sha256.Sum256(data)
	return &fetchedChart{
		localPath:     archive,
		cleanup:       cleanup,
		provData:      prov,
		archiveSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// fetchChartArchive downloads the raw .tgz bytes of a remote chart, along
// with its provenance (.prov) bytes when the source provides one. A missing
// provenance is not an error — prov is simply nil.
func fetchChartArchive(rawPath, repoURL, version, username, password string, isOCI bool) (archive, prov []byte, err error) {
	if isOCI {
		client, err := registry.NewClient()
		if err != nil {
			return nil, nil, err
		}
		ref := strings.TrimPrefix(rawPath, registry.OCIScheme+"://")
		// Append the requested version as a tag when the ref isn't already
		// pinned by tag or digest.
		if version != "" && !strings.ContainsAny(lastPathSegment(ref), ":@") {
			ref += ":" + version
		}
		result, err := client.Pull(ref,
			registry.PullOptWithChart(true),
			registry.PullOptWithProv(true),
			registry.PullOptIgnoreMissingProv(true),
		)
		if err != nil {
			return nil, nil, err
		}
		if result.Prov != nil {
			prov = result.Prov.Data
		}
		return result.Chart.Data, prov, nil
	}

	chartURL := rawPath
	if repoURL != "" {
		// Resolve "chartName" against the repository's index.yaml.
		resolved, err := resolveChartInRepo(repoURL, rawPath, version, username, password)
		if err != nil {
			return nil, nil, err
		}
		chartURL = resolved
	}

	archive, err = httpGetBytes(chartURL, username, password)
	if err != nil {
		return nil, nil, err
	}
	// Provenance lives next to the archive at "<url>.prov" by Helm
	// convention. Its absence is expected for unsigned charts, so a failed
	// fetch is swallowed rather than failing the whole connection.
	prov = fetchProvenanceHTTP(chartURL, username, password)
	return archive, prov, nil
}

// fetchProvenanceHTTP best-effort downloads the provenance file that sits
// next to a chart archive at "<chartURL>.prov". It returns nil for any
// failure (missing file, network error, oversized response) because an
// unsigned chart simply has no provenance.
func fetchProvenanceHTTP(chartURL, username, password string) []byte {
	prov, err := httpGetBytes(chartURL+".prov", username, password)
	if err != nil {
		log.Debug().Err(err).Str("url", chartURL+".prov").Msg("no helm chart provenance found")
		return nil
	}
	return prov
}

// repoChartVersion is one published version of a chart in a repository
// index.yaml: its version string and the archive URL(s) that serve it.
type repoChartVersion struct {
	Version string   `yaml:"version"`
	URLs    []string `yaml:"urls"`
}

// repoIndex is the subset of a Helm repository index.yaml we need to map a
// chart name + version to a downloadable archive URL.
type repoIndex struct {
	Entries map[string][]repoChartVersion `yaml:"entries"`
}

// latestChartVersion returns the highest-semver entry for a chart. `helm repo
// index` writes entries newest-first, but not every index producer sorts, so
// we pick by semver rather than trusting file order. Entries whose version
// isn't valid semver are ignored for ranking; if none parse, the first listed
// entry is returned so a non-semver repository still resolves to something.
func latestChartVersion(versions []repoChartVersion) repoChartVersion {
	if len(versions) == 0 {
		return repoChartVersion{}
	}
	best := versions[0]
	var bestVer *semver.Version
	if v, err := semver.NewVersion(best.Version); err == nil {
		bestVer = v
	}
	for _, cur := range versions[1:] {
		cv, err := semver.NewVersion(cur.Version)
		if err != nil {
			continue
		}
		if bestVer == nil || cv.GreaterThan(bestVer) {
			best = cur
			bestVer = cv
		}
	}
	return best
}

// resolveChartInRepo downloads <repoURL>/index.yaml and resolves a chart
// name (and optional version) to a concrete archive URL. With no version it
// picks the highest-semver entry.
func resolveChartInRepo(repoURL, chartName, version, username, password string) (string, error) {
	indexURL := strings.TrimSuffix(repoURL, "/") + "/index.yaml"
	data, err := httpGetBytes(indexURL, username, password)
	if err != nil {
		return "", fmt.Errorf("failed to fetch repository index %q: %w", indexURL, err)
	}

	var index repoIndex
	if err := yaml.Unmarshal(data, &index); err != nil {
		return "", fmt.Errorf("failed to parse repository index %q: %w", indexURL, err)
	}

	versions, ok := index.Entries[chartName]
	if !ok || len(versions) == 0 {
		return "", fmt.Errorf("chart %q not found in repository %q", chartName, repoURL)
	}

	chosen := latestChartVersion(versions)
	if version != "" {
		found := false
		for _, v := range versions {
			if v.Version == version {
				chosen = v
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("chart %q version %q not found in repository %q", chartName, version, repoURL)
		}
	}
	if len(chosen.URLs) == 0 {
		return "", fmt.Errorf("chart %q has no download URL in repository %q", chartName, repoURL)
	}

	// Chart URLs may be relative to the repository URL.
	chartURL := chosen.URLs[0]
	if !strings.Contains(chartURL, "://") {
		base, err := url.Parse(strings.TrimSuffix(repoURL, "/") + "/")
		if err != nil {
			return "", err
		}
		ref, err := url.Parse(chartURL)
		if err != nil {
			return "", err
		}
		chartURL = base.ResolveReference(ref).String()
	}
	return chartURL, nil
}

// chartHTTPClient bounds remote chart/index fetches so a slow or stalled
// repository can't hang the connection indefinitely.
var chartHTTPClient = &http.Client{Timeout: 60 * time.Second}

// maxChartDownloadSize caps a downloaded chart archive or repository index
// (128 MiB) so a misbehaving repo can't exhaust memory. It is a var (not a
// const) only so tests can lower it without downloading 128 MiB.
var maxChartDownloadSize int64 = 128 << 20

// httpGetBytes fetches a URL with optional basic auth, a request timeout,
// and a bounded read.
func httpGetBytes(rawURL, username, password string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	resp, err := chartHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %q: status %d", rawURL, resp.StatusCode)
	}
	// Read up to one byte past the cap so we can tell "exactly at the limit"
	// from "exceeds the limit". io.LimitReader alone returns EOF at the cap
	// with no error, silently truncating an oversized archive/index.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxChartDownloadSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxChartDownloadSize {
		return nil, fmt.Errorf("response from %q exceeds the maximum allowed size of %d bytes", rawURL, maxChartDownloadSize)
	}
	return data, nil
}

// lastPathSegment returns the final path segment of a registry reference,
// where a tag (":") or digest ("@") would appear.
func lastPathSegment(ref string) string {
	if _, after, ok := strings.CutLast(ref, "/"); ok {
		return after
	}
	return ref
}
