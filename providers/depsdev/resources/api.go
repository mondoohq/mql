// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const depsDevBaseURL = "https://api.deps.dev/v3"
const githubAPIBaseURL = "https://api.github.com"

// API response structs for deps.dev v3

type depsDevPackageResponse struct {
	PackageKey struct {
		System string `json:"system"`
		Name   string `json:"name"`
	} `json:"packageKey"`
	Versions []depsDevVersionSummary `json:"versions"`
}

type depsDevVersionSummary struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	IsDefault   bool      `json:"isDefault"`
	PublishedAt time.Time `json:"publishedAt"`
}

type depsDevVersionResponse struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	IsDefault       bool      `json:"isDefault"`
	PublishedAt     time.Time `json:"publishedAt"`
	Licenses        []string  `json:"licenses"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType       string `json:"relationType"`
		RelationProvenance string `json:"relationProvenance"`
	} `json:"relatedProjects"`
}

type depsDevProjectResponse struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	OpenIssuesCount int                       `json:"openIssuesCount"`
	StarsCount      int                       `json:"starsCount"`
	ForksCount      int                       `json:"forksCount"`
	License         string                    `json:"license"`
	Description     string                    `json:"description"`
	Homepage        string                    `json:"homepage"`
	Scorecard       *depsDevScorecardResponse `json:"scorecard"`
}

type depsDevScorecardResponse struct {
	Date         time.Time               `json:"date"`
	OverallScore float64                 `json:"overallScore"`
	Checks       []depsDevScorecardCheck `json:"checks"`
}

type depsDevScorecardCheck struct {
	Name          string `json:"name"`
	Score         int    `json:"score"`
	Reason        string `json:"reason"`
	Documentation struct {
		ShortDescription string `json:"shortDescription"`
		URL              string `json:"url"`
	} `json:"documentation"`
}

// fetchPackage retrieves package info (all versions) from deps.dev.
// GET /v3/systems/go/packages/{package}
func fetchPackage(client *http.Client, modulePath string) (*depsDevPackageResponse, error) {
	u := fmt.Sprintf("%s/systems/go/packages/%s", depsDevBaseURL, url.PathEscape(modulePath))

	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("deps.dev API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("deps.dev API returned %d for package %s: %s", resp.StatusCode, modulePath, string(body))
	}

	var result depsDevPackageResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode deps.dev response: %w", err)
	}

	return &result, nil
}

// fetchVersion retrieves a specific version's details (licenses, related projects).
// GET /v3/systems/go/packages/{package}/versions/{version}
func fetchVersion(client *http.Client, modulePath, version string) (*depsDevVersionResponse, error) {
	u := fmt.Sprintf("%s/systems/go/packages/%s/versions/%s",
		depsDevBaseURL, url.PathEscape(modulePath), url.PathEscape(version))

	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("deps.dev API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("deps.dev API returned %d for version %s@%s: %s", resp.StatusCode, modulePath, version, string(body))
	}

	var result depsDevVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode deps.dev response: %w", err)
	}

	return &result, nil
}

// fetchProject retrieves project info (stars, forks, scorecard) from deps.dev.
// GET /v3/projects/{project}
func fetchProject(client *http.Client, projectID string) (*depsDevProjectResponse, error) {
	u := fmt.Sprintf("%s/projects/%s", depsDevBaseURL, url.PathEscape(projectID))

	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("deps.dev API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("deps.dev API returned %d for project %s: %s", resp.StatusCode, projectID, string(body))
	}

	var result depsDevProjectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode deps.dev response: %w", err)
	}

	return &result, nil
}

type githubRepoResponse struct {
	Archived bool `json:"archived"`
}

// fetchGitHubRepo retrieves repository info from the GitHub API.
// The projectID is expected to be in the format "github.com/owner/repo" or
// "github.com/owner/repo/subpath" (only owner/repo is used).
func fetchGitHubRepo(client *http.Client, projectID string) (*githubRepoResponse, error) {
	// Extract owner/repo from "github.com/owner/repo[/...]"
	parts := strings.Split(projectID, "/")
	if len(parts) < 3 || parts[0] != "github.com" {
		return nil, fmt.Errorf("project %q is not a GitHub repository", projectID)
	}
	ownerRepo := parts[1] + "/" + parts[2]

	u := fmt.Sprintf("%s/repos/%s", githubAPIBaseURL, ownerRepo)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub API request: %w", err)
	}

	// Use GITHUB_TOKEN for authentication if available to avoid rate limiting
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned %d for %s: %s", resp.StatusCode, ownerRepo, string(body))
	}

	var result githubRepoResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub API response: %w", err)
	}

	return &result, nil
}
