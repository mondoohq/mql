// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"io"
	"os"
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

// appleCareMaxFileSize caps a coverage file read; real ones are under 1 KB.
const appleCareMaxFileSize = 1 << 20

// lstat stats p without following a symlink, where the filesystem can.
func lstat(fs afero.Fs, p string) (os.FileInfo, error) {
	if l, ok := fs.(afero.Lstater); ok {
		info, _, err := l.LstatIfPossible(p)
		return info, err
	}
	return fs.Stat(p)
}

// readAtMost reads p, failing when it holds more than limit bytes or when the
// file opened is not want, the regular file lstat saw: a user who swaps the
// file for a symlink between the two calls cannot redirect the read. afero
// has no O_NOFOLLOW, so the open follows links; this rejects what it lands on.
func readAtMost(fs afero.Fs, p string, want os.FileInfo, limit int64) ([]byte, error) {
	f, err := fs.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !got.Mode().IsRegular() || !sameFile(want, got) {
		return nil, errors.New("file changed while it was read")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file too large")
	}
	return data, nil
}

// sameFile reports whether two stats are of one file: by device and inode
// when both come from the os package, else by size and modification time.
// os.SameFile answers false for any other stat type, which is what the sudo,
// SSH, container and mock filesystems return.
func sameFile(a, b os.FileInfo) bool {
	if isOSFileStat(a) && isOSFileStat(b) {
		return os.SameFile(a, b)
	}
	return a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

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
		// The scan usually runs as root and the file sits in a user's home:
		// read only a regular file, never a symlink, FIFO or device a user
		// put there, and never more than a coverage file can hold.
		info, err := lstat(fs, p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > appleCareMaxFileSize {
			continue
		}
		if best != nil && !info.ModTime().After(bestTime) {
			continue
		}
		data, err := readAtMost(fs, p, info, appleCareMaxFileSize)
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

func initMacosCoverage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(shared.Connection)
	if !conn.Asset().Platform.IsFamily("darwin") {
		return nil, nil, errors.New("macos.coverage is only available on macOS")
	}
	if args == nil {
		args = map[string]*llx.RawData{}
	}

	hw, err := NewResource(runtime, "macos.hardware", nil)
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
	args["appleCare"] = llx.BoolData(strings.Contains(strings.ToLower(label), "applecare"))
	args["label"] = llx.StringData(label)
	args["expires"] = llx.TimeDataPtr(parseAppleCareExpiration(expiration))
	args["expirationLabel"] = llx.StringData(expiration)
	args["theftAndLoss"] = llx.BoolDataPtr(coverage.HasTheftAndLossBenefit)
	args["updated"] = llx.TimeDataPtr(updated)
	return args, nil, nil
}

func (m *mqlMacosCoverage) id() (string, error) {
	return "macos.coverage", nil
}
