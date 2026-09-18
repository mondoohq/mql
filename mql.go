// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
)

// Version is set via ldflags. Note: Can be empty! Use GetVersion() for semver fallbacks
var Version string

// Build version is set via ldflags
var Build string

// Date is set via ldflags
var Date string

// DisableMaxLimit disables the max limit for data that is being collected and sent upstream.
// There are use cases when data is not collected via RPC (when using builtin providers) and it is not being
// sent upstream (when running incognito). In those cases, it is not required to impose this limit.
// It is designed as a compile flag to ensure that it is not accidentally enabled in builds that use RPC/communicate with the server.
var DisableMaxLimit string

/*
 versioning follows semver guidelines: https://semver.org/

<valid semver> ::= <version core>
                 | <version core> "-" <pre-release>
                 | <version core> "+" <build>
                 | <version core> "-" <pre-release> "+" <build>

<version core> ::= <major> "." <minor> "." <patch>

<major> ::= <numeric identifier>

<minor> ::= <numeric identifier>

<patch> ::= <numeric identifier>
*/

// The version an unstamped build reports: the current line, plus `rolling` as
// build metadata. Keep the line current - it is the version every floor check
// sees for a build the release flow did not stamp.
//
// The marker belongs after `+`, not after `-`. Rolling means the continuously
// updated latest of a line, so a rolling build is part of its line and never
// something that precedes it. Build metadata is ignored when versions are
// ordered, which is that reading; the `-` slot instead sorted every source
// build behind the release it was built from, so a locally built core failed
// the `core >= 13.0.0` floor its own tree declares.
const (
	// major.minor.patch on its own, which is what GetCoreVersion answers with.
	devCoreVersion = "14.0.0"
	devVersion     = "v" + devCoreVersion + "+rolling"
)

// GetVersion returns the version of the build
// valid semver version including build version (e.g. 4.10.0+4900), where 4900 is a forward rolling int
func GetVersion() string {
	if Version == "" {
		return devVersion
	}
	return Version
}

// Release represents a release
type Release struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mqlLatestReleaseUrl is the manifest the version check reads. It is the install
// service's route, the same one the self-update reads, so the version reported
// here is the version that would be installed.
//
// It cannot be built with selfupdate.ReleaseURL: cli/selfupdate imports this
// package, so reaching the other way would be a cycle. The bucket's
// "?ignoreCache=1" is dropped -- the install service does not know that
// parameter, and carrying it implies a freshness guarantee it never gave.
var mqlLatestReleaseUrl = "https://install.mondoo.com/package/mql/latest.json"

// GetLatestReleaseName fetches the name of the latest release from releaseUrl
func GetLatestReleaseName(releaseUrl string, client *http.Client) (string, error) {
	return GetLatestReleaseNameContext(context.Background(), releaseUrl, client)
}

// GetLatestReleaseNameContext behaves like GetLatestReleaseName but honors the
// provided context, so callers can bound the request with a deadline or cancel it.
func GetLatestReleaseNameContext(ctx context.Context, releaseUrl string, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseUrl, nil)
	if err != nil {
		return "", fmt.Errorf("error building latest release request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error fetching latest release: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-OK response status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("error unmarshalling response: %v", err)
	}

	return release.Version, nil
}

// GetLatestVersion returns the latest version the install service publishes
func GetLatestVersion(client *http.Client) (string, error) {
	releaseName, err := GetLatestReleaseName(mqlLatestReleaseUrl, client)
	if err != nil {
		return "", err
	}
	return releaseName, nil
}

// The `v` is optional because both spellings reach here: the release flow stamps
// what `git describe` returns (`v13.53.4`), while a plain semver string has no
// prefix. The core is the capture group, so the prefix is dropped rather than
// returned as part of the answer.
var coreSemverRegex = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)

// GetCoreVersion returns the semver core (i.e. major.minor.patch)
func GetCoreVersion() string {
	if m := coreSemverRegex.FindStringSubmatch(Version); m != nil {
		return m[1]
	}
	return devCoreVersion
}

// GetBuild returns the git sha of the build
func GetBuild() string {
	b := Build
	if len(b) == 0 {
		b = "development"
	}
	return b
}

// GetDate returns the date of this build
func GetDate() string {
	d := Date
	if len(d) == 0 {
		d = "unknown"
	}
	return d
}

var majorVersionRegex = regexp.MustCompile(`^(\d+)`)

// APIVersion is the major version of the version string (e.g. 4)
func APIVersion() string {
	v := Version

	if v != "" {
		v = majorVersionRegex.FindString(v)
	}

	if v == "" {
		return "unstable"
	}
	return v
}

// Info on this application with version and build
func Info() string {
	return "mql " + GetVersion() + " (" + GetBuild() + ", " + GetDate() + ")"
}

// LatestMQLVersion returns the current version of MQL
func LatestMQLVersion() string {
	return "v2"
}

func GetDisableMaxLimit() bool {
	return DisableMaxLimit == "true"
}
