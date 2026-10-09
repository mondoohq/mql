// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Command kubelet-defaults-drift checks whether upstream Kubernetes changed the
// kubelet defaults that providers/os/resources/kubelet_defaults.go copies.
//
// It reads every release-1.N branch of kubernetes/kubernetes from the oldest
// minor version in the baseline on, normalizes each tracked source (see
// extract), and compares its hash with baseline.json. A new release branch,
// or a tracked source whose code changed, is reported with a unified diff.
//
// Usage, from the repository root:
//
//	go run ./scripts/kubelet-defaults-drift -report report.md
//	go run ./scripts/kubelet-defaults-drift -update
//
// It exits 0 when nothing changed, 2 when something did, and 1 on error.
// -update rewrites the baseline from the current release branches. Run it in
// the pull request that brings kubelet_defaults.go up to date.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pmezard/go-difflib/difflib"
)

const (
	refsURL = "https://api.github.com/repos/kubernetes/kubernetes/git/matching-refs/heads/release-1."
	rawURL  = "https://raw.githubusercontent.com/kubernetes/kubernetes/%s/%s"
)

var errNotFound = errors.New("not found")

func main() {
	baselinePath := flag.String("baseline", "scripts/kubelet-defaults-drift/baseline.json", "baseline file")
	defaultsPath := flag.String("defaults", "providers/os/resources/kubelet_defaults.go", "kubelet_defaults.go, for the feature gates it reads")
	reportPath := flag.String("report", "", "write a markdown report here")
	update := flag.Bool("update", false, "rewrite the baseline from the current release branches")
	oldestFlag := flag.Int("oldest", 34, "oldest minor version, when the baseline records none")
	flag.Parse()

	code, err := run(*baselinePath, *defaultsPath, *reportPath, *update, *oldestFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

type upstream struct {
	client *http.Client
	token  string
	files  map[string]string
}

func run(baselinePath, defaultsPath, reportPath string, update bool, oldest int) (int, error) {
	defaults, err := os.ReadFile(defaultsPath)
	if err != nil {
		return 0, err
	}
	gates := gatesFrom(string(defaults))
	if len(gates) == 0 {
		return 0, fmt.Errorf("no featureGateEnabled calls in %s", defaultsPath)
	}
	items := trackedItems(gates)

	var b Baseline
	if raw, err := os.ReadFile(baselinePath); err == nil {
		if err := json.Unmarshal(raw, &b); err != nil {
			return 0, fmt.Errorf("cannot parse %s: %w", baselinePath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if o := b.oldest(); o != 0 {
		oldest = o
	}

	up := &upstream{
		client: &http.Client{Timeout: time.Minute},
		token:  os.Getenv("GITHUB_TOKEN"),
		files:  map[string]string{},
	}
	refs, err := up.releaseRefs()
	if err != nil {
		return 0, err
	}
	minors := releaseMinors(refs, oldest)
	if len(minors) == 0 {
		return 0, fmt.Errorf("no release branches from 1.%d on", oldest)
	}

	current := map[int]map[string]string{}
	for minor, sha := range minors {
		current[minor] = map[string]string{}
		for _, it := range items {
			content, found, err := up.extract(sha, it)
			if err != nil {
				return 0, fmt.Errorf("release-1.%d: %w", minor, err)
			}
			current[minor][it.id()] = hashOf(content, found)
		}
	}

	if update {
		next := Baseline{Minors: map[string]MinorBaseline{}}
		for minor, hashes := range current {
			next.Minors[minorKey(minor)] = MinorBaseline{Commit: minors[minor], Items: hashes}
		}
		raw, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return 0, err
		}
		return 0, os.WriteFile(baselinePath, append(raw, '\n'), 0o644)
	}

	findings := drift(b, current)
	if reportPath != "" {
		report, err := up.report(b, minors, items, findings)
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil {
			return 0, err
		}
	}
	for _, f := range findings {
		fmt.Printf("release-1.%d: %s %s\n", f.Minor, f.Kind, f.Item)
	}
	if len(findings) > 0 {
		return 2, nil
	}
	fmt.Println("no changes upstream")
	return 0, nil
}

// get fetches a URL, retrying server errors and rate limits. GitHub answers a
// rate limit with 429, or with 403 and Retry-After.
func (u *upstream) get(url string) ([]byte, error) {
	var lastErr error
	wait := time.Duration(0)
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(wait)
		}
		wait = time.Duration(attempt+1) * 10 * time.Second
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "mql-kubelet-defaults-drift")
		if u.token != "" {
			req.Header.Set("Authorization", "Bearer "+u.token)
		}
		resp, err := u.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		retryAfter := resp.Header.Get("Retry-After")
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusNotFound:
			return nil, errNotFound
		case resp.StatusCode == http.StatusTooManyRequests,
			resp.StatusCode == http.StatusForbidden && retryAfter != "",
			resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s: %s", url, resp.Status)
			wait = retryDelay(retryAfter, wait)
		default:
			return nil, fmt.Errorf("%s: %s", url, resp.Status)
		}
	}
	return nil, lastErr
}

// maxRetryDelay caps how long a Retry-After header can make a run wait.
const maxRetryDelay = 2 * time.Minute

// retryDelay returns the delay a Retry-After header in seconds asks for, at
// least fallback and at most maxRetryDelay.
func retryDelay(retryAfter string, fallback time.Duration) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(retryAfter))
	if err != nil || secs < 0 {
		return fallback
	}
	d := time.Duration(secs) * time.Second
	if d < fallback {
		d = fallback
	}
	return min(d, maxRetryDelay)
}

// releaseRefs returns the release-1.N branches and their commits.
func (u *upstream) releaseRefs() (map[string]string, error) {
	raw, err := u.get(refsURL)
	if err != nil {
		return nil, err
	}
	var refs []struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(raw, &refs); err != nil {
		return nil, fmt.Errorf("cannot parse release branches: %w", err)
	}
	res := map[string]string{}
	for _, r := range refs {
		res[r.Ref] = r.Object.SHA
	}
	return res, nil
}

// file returns a file at a commit. A file the commit does not have is empty
// and not found.
func (u *upstream) file(sha, path string) (string, bool, error) {
	key := sha + "/" + path
	if content, ok := u.files[key]; ok {
		return content, content != "", nil
	}
	raw, err := u.get(fmt.Sprintf(rawURL, sha, path))
	if errors.Is(err, errNotFound) {
		u.files[key] = ""
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	u.files[key] = string(raw)
	return string(raw), true, nil
}

func (u *upstream) extract(sha string, it item) (string, bool, error) {
	src, found, err := u.file(sha, it.Path)
	if err != nil || !found {
		return "", false, err
	}
	return extract(src, it)
}

// report describes the findings, with a diff of every changed item against
// the baseline's commit, and of every item of a new minor against the
// previous minor.
func (u *upstream) report(b Baseline, minors map[int]string, items []item, findings []finding) (string, error) {
	var sb strings.Builder
	sb.WriteString("# Upstream Kubernetes changed the kubelet defaults mql copies\n\n")
	if len(findings) == 0 {
		sb.WriteString("No changes: every release branch matches the baseline.\n")
		return sb.String(), nil
	}
	sb.WriteString("`providers/os/resources/kubelet_defaults.go` copies the kubelet's defaults from upstream Kubernetes. " +
		"These upstream sources differ from the baseline it was last checked against. " +
		"Update `kubelet_defaults.go` and the `TestSetDefaults_ByVersion` cases, add a `/configz` fixture for a new minor version, " +
		"and run `go run ./scripts/kubelet-defaults-drift -update` in the same pull request.\n")

	byID := map[string]item{}
	for _, it := range items {
		byID[it.id()] = it
	}
	for _, f := range findings {
		sha := minors[f.Minor]
		switch f.Kind {
		case newMinor:
			prev, prevSHA := previousMinor(minors, f.Minor)
			fmt.Fprintf(&sb, "\n## release-1.%d: new minor version\n\n", f.Minor)
			if prevSHA == "" {
				sb.WriteString("No earlier release branch to compare with.\n")
				continue
			}
			fmt.Fprintf(&sb, "Compared with release-1.%d.\n", prev)
			for _, it := range items {
				d, err := u.diff(it, prevSHA, fmt.Sprintf("release-1.%d", prev), sha, fmt.Sprintf("release-1.%d", f.Minor))
				if err != nil {
					return "", err
				}
				if d != "" {
					fmt.Fprintf(&sb, "\n### `%s`\n\n```diff\n%s```\n", it.id(), d)
				}
			}
		case changed:
			base := b.Minors[minorKey(f.Minor)].Commit
			fmt.Fprintf(&sb, "\n## release-1.%d: `%s` changed\n\n", f.Minor, f.Item)
			d, err := u.diff(byID[f.Item], base, "baseline "+short(base), sha, fmt.Sprintf("release-1.%d %s", f.Minor, short(sha)))
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&sb, "```diff\n%s```\n", d)
		case newItem:
			fmt.Fprintf(&sb, "\n## release-1.%d: `%s` is newly tracked\n\n", f.Minor, f.Item)
			content, found, err := u.extract(sha, byID[f.Item])
			if err != nil {
				return "", err
			}
			if !found {
				sb.WriteString("Not in this release.\n")
				continue
			}
			fmt.Fprintf(&sb, "```go\n%s```\n", content)
		}
	}
	return sb.String(), nil
}

func (u *upstream) diff(it item, fromSHA, fromName, toSHA, toName string) (string, error) {
	from, _, err := u.extract(fromSHA, it)
	if err != nil {
		return "", err
	}
	to, _, err := u.extract(toSHA, it)
	if err != nil {
		return "", err
	}
	if from == to {
		return "", nil
	}
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(from),
		B:        difflib.SplitLines(to),
		FromFile: fromName,
		ToFile:   toName,
		Context:  3,
	})
}

// previousMinor returns the newest release branch older than minor.
func previousMinor(minors map[int]string, minor int) (int, string) {
	keys := make([]int, 0, len(minors))
	for m := range minors {
		if m < minor {
			keys = append(keys, m)
		}
	}
	if len(keys) == 0 {
		return 0, ""
	}
	sort.Ints(keys)
	prev := keys[len(keys)-1]
	return prev, minors[prev]
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
