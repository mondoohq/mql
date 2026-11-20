// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// appleCareCacheDir is where macOS caches the coverage the AppleCare &
// Warranty pane shows, one JSON file per device serial number, relative to a
// user's home.
const appleCareCacheDir = "Library/Application Support/com.apple.NewDeviceOutreach/caches/coverageDetails"

// appleCareCoverage is the part of a cached coverage file this resource reads.
type appleCareCoverage struct {
	SerialNumber            string `json:"serialNumber"`
	CoverageLabel           string `json:"coverageLabel"`
	HasTheftAndLossBenefit  *bool  `json:"hasTheftAndLossBenefit"`
	SettingsCoverageSection struct {
		CoverageExpirationLabel string `json:"coverageExpirationLabel"`
	} `json:"settingsCoverageSection"`
}

func parseAppleCareCoverage(data []byte) (*appleCareCoverage, error) {
	var c appleCareCoverage
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// appleCareDateRe finds an English date ("October 26, 2028") in the
// expiration label, whatever words surround it.
var appleCareDateRe = regexp.MustCompile(`(January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4}`)

// parseAppleCareExpiration reads the end of coverage from macOS's wording,
// such as "Expires October 26, 2028". The text follows the user's language;
// it returns nil for any it cannot read.
func parseAppleCareExpiration(label string) *time.Time {
	m := appleCareDateRe.FindString(label)
	if m == "" {
		return nil
	}
	t, err := time.Parse("January 2, 2006", m)
	if err != nil {
		return nil
	}
	return &t
}

// findAppleCareCoverage returns the cached coverage for serial from the user
// homes under /Users, and when it was cached. With several users, the most
// recently written copy wins. It returns a nil coverage when no user has one.
func findAppleCareCoverage(fs afero.Fs, serial string) (*appleCareCoverage, *time.Time, error) {
	if serial == "" {
		return nil, nil, nil
	}
	homes, err := afero.ReadDir(fs, "/Users")
	if err != nil {
		return nil, nil, nil
	}
	var best *appleCareCoverage
	var bestTime time.Time
	for _, home := range homes {
		if !home.IsDir() {
			continue
		}
		p := path.Join("/Users", home.Name(), appleCareCacheDir, serial+".json")
		info, err := fs.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		if best != nil && !info.ModTime().After(bestTime) {
			continue
		}
		data, err := afero.ReadFile(fs, p)
		if err != nil {
			continue
		}
		c, err := parseAppleCareCoverage(data)
		if err != nil {
			continue
		}
		best, bestTime = c, info.ModTime()
	}
	if best == nil {
		return nil, nil, nil
	}
	return best, &bestTime, nil
}

func initMacosAppleCare(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)
	if !conn.Asset().Platform.IsFamily("darwin") {
		return nil, nil, errors.New("macos.appleCare is only available on macOS")
	}
	if args == nil {
		args = map[string]*llx.RawData{}
	}

	hw, err := CreateResource(runtime, "macos.hardware", nil)
	if err != nil {
		return nil, nil, err
	}
	serial := hw.(*mqlMacosHardware).SerialNumber.Data

	coverage, updated, err := findAppleCareCoverage(conn.FileSystem(), serial)
	if err != nil {
		return nil, nil, err
	}
	if coverage == nil {
		for _, f := range []string{"appleCare", "label", "expires", "expirationLabel", "theftAndLoss", "updated"} {
			args[f] = llx.NilData
		}
		return args, nil, nil
	}

	label := strings.TrimSpace(coverage.CoverageLabel)
	expiration := strings.TrimSpace(coverage.SettingsCoverageSection.CoverageExpirationLabel)
	args["appleCare"] = llx.BoolData(strings.Contains(label, "AppleCare"))
	args["label"] = llx.StringData(label)
	args["expires"] = llx.TimeDataPtr(parseAppleCareExpiration(expiration))
	args["expirationLabel"] = llx.StringData(expiration)
	args["theftAndLoss"] = llx.BoolDataPtr(coverage.HasTheftAndLossBenefit)
	args["updated"] = llx.TimeDataPtr(updated)
	return args, nil, nil
}

func (m *mqlMacosAppleCare) id() (string, error) {
	return "macos.appleCare", nil
}
