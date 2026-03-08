// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/cli/config"
	"go.mondoo.com/mql/v13/logger/zerologadapter"
	"go.mondoo.com/mql/v13/providers/core/resources/versions/semver"
)

const (
	// DefaultRefreshInterval is the minimum time between update checks in seconds (1 hour)
	DefaultRefreshInterval = 3600
	// EnvAutoUpdate can be set to "false" or "0" to disable auto-update.
	EnvAutoUpdate = "MONDOO_AUTO_UPDATE"
	// envBinarySelfUpdateSkip is an internal env var set after a binary self-update
	// to prevent infinite update loops. Unlike EnvAutoUpdate, this only affects
	// binary self-update and not provider auto-update.
	envBinarySelfUpdateSkip = "MONDOO_BINARY_SELF_UPDATE_SKIP"
	// DefaultReleaseURL is the URL to fetch the latest release information
	DefaultReleaseURL = "https://releases.mondoo.com/mql/latest.json"
	// markerFilePrefix is the prefix for per-binary marker files that track when the last update check occurred.
	// Each binary gets its own marker (e.g., ".last-update-check-mql", ".last-update-check-cnspec").
	markerFilePrefix = ".last-update-check-"

	defaultHttpTimeout         = 30 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
)

// Config holds the configuration for self-update checks
type Config struct {
	Enabled         bool
	RefreshInterval int64
	ReleaseURL      string
	// BinaryName is the name of the binary to update (e.g., "mql", "cnspec").
	// Used to match archive entries and construct platform-specific filenames.
	BinaryName string
	// CurrentVersion is the current version of the running binary.
	// If "x.y.z-rolling", self-update is skipped.
	CurrentVersion string
}

// Release represents the release information from latest.json
type Release struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Files   []ReleaseFile `json:"files"`
}

// ReleaseFile represents a downloadable release file
type ReleaseFile struct {
	Filename string `json:"filename"`
	Platform string `json:"platform"` // e.g., "linux_amd64", "darwin_arm64"
	Hash     string `json:"hash"`     // SHA256 hash
}

// CheckAndUpdate checks for updates and installs them if available.
// Returns true if an update was installed and the process was replaced.
func CheckAndUpdate(cfg Config) (bool, error) {
	if !cfg.Enabled {
		return false, nil
	}

	// Skip if this is a re-exec'd process after a binary self-update (prevents infinite loops)
	if os.Getenv(envBinarySelfUpdateSkip) == "1" {
		log.Debug().Msg("self-update: skipping, already updated in this session")
		return false, nil
	}

	// Skip if auto-update is disabled via environment
	if val := os.Getenv(EnvAutoUpdate); val == "false" || val == "0" {
		log.Debug().Msg("self-update: skipping, disabled via environment")
		return false, nil
	}

	// Skip if version is "rolling" (dev build)
	currentVersion := cfg.CurrentVersion
	if strings.HasSuffix(currentVersion, "-rolling") {
		log.Debug().Msg("self-update: skipping, running unstable/dev build")
		return false, nil
	}

	// Get the bin path for storing updated binaries
	binPath, err := getBinPath()
	if err != nil {
		return false, errors.Wrap(err, "failed to get bin path")
	}

	binName := platformBinaryName(cfg.BinaryName)

	// First, check if there's already a newer binary installed locally.
	// This allows us to immediately use an already-downloaded update without
	// needing to check the network.
	if execed, err := execLocalIfNewer(binPath, binName, currentVersion); err != nil {
		log.Debug().Err(err).Msg("self-update: failed to check local binary")
	} else if execed {
		return true, nil
	}

	// Check if we should perform a network update check based on refresh interval
	if !shouldCheckUpdate(binPath, cfg.BinaryName, cfg.RefreshInterval) {
		log.Debug().Msg("self-update: skipping network check, within refresh interval")
		return false, nil
	}

	// Fetch the latest release information
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	release, err := getLatestRelease(ctx, cfg.ReleaseURL)
	if err != nil {
		// We don't update the marker, which may lead to more checks against the URL
		// but this is helpful when e.g. a network configuration wasn't set right.
		// If users fix it and re-run commands it won't check which sucks. The
		// request is fast so we opt to do it to avoid these temporary failures.
		return false, errors.Wrap(err, "failed to fetch latest release")
	}

	// Compare versions
	cmp, err := semver.Parser{}.Compare(release.Version, currentVersion)
	if err != nil {
		// We should only get here if something went really wrong with the version
		// string that is being published. If that's the case, we don't set the
		// marker and force the algo to try updating in case the error was fixed.
		return false, errors.Wrap(err, "failed to compare versions")
	}

	if cmp <= 0 {
		log.Debug().
			Str("current", currentVersion).
			Str("latest", release.Version).
			Msg("self-update: already up to date")
		updateMarkerFile(binPath, cfg.BinaryName)
		return false, nil
	}

	log.Info().
		Str("current", currentVersion).
		Str("latest", release.Version).
		Msgf("new version of %s available, updating", cfg.BinaryName)

	// Check if the bin directory is writable
	if err := checkWritable(binPath); err != nil {
		log.Warn().Str("path", binPath).Msg("self-update: cannot write to install directory, skipping")
		// Since no download has occurred yet we opt to re-run the auto-update
		// in case the error was fixed in the meantime.
		return false, nil
	}

	// Download and install the update
	binaryPath, err := downloadAndInstall(ctx, release, binPath, cfg.BinaryName)
	if err != nil {
		// If the download failed, we still set the marker because this is
		// a larger step that can be annoying if it is re-run a lot.
		updateMarkerFile(binPath, cfg.BinaryName)
		return false, errors.Wrap(err, "failed to download and install update")
	}

	// Update marker file after successful installation
	updateMarkerFile(binPath, cfg.BinaryName)

	log.Debug().
		Str("version", release.Version).
		Str("path", binaryPath).
		Msg("self-update: successfully installed new version, re-executing")

	// On Windows, swap the binary in-place so the firewall rule for the
	// original path keeps working (no second firewall prompt).
	if inPlaceUpdateEnabled {
		if err := verifyBinary(binaryPath); err != nil {
			return false, errors.Wrap(err, "new binary verification failed")
		}
		originalPath, err := swapBinaryInPlace(binaryPath)
		if err != nil {
			return false, errors.Wrap(err, "in-place swap failed")
		}
		binaryPath = originalPath
	}

	// Re-execute with the new binary
	if err := ExecUpdatedBinary(binaryPath, os.Args); err != nil {
		return false, errors.Wrap(err, "failed to re-execute with updated binary")
	}

	// If ExecUpdatedBinary returns (Windows case), we've spawned a new process
	return true, nil
}

// getBinPath returns the path where updated binaries should be stored
func getBinPath() (string, error) {
	return config.HomePath("bin")
}

// platformBinaryName returns the binary name with platform-specific extension
func platformBinaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// execLocalIfNewer checks if there's a newer binary already installed
// in the bin path. If so, it execs to that binary. Returns true if exec happened.
func execLocalIfNewer(binPath, binName, currentVersion string) (bool, error) {
	localBinary := filepath.Join(binPath, binName)

	// Check if local binary exists
	if _, err := os.Stat(localBinary); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	// Get the version of the local binary by running it with "version" command
	// and parsing the output
	localVersion, err := getLocalBinaryVersion(localBinary)
	if err != nil {
		return false, errors.Wrap(err, "failed to get local binary version")
	}

	// Compare versions
	cmp, err := semver.Parser{}.Compare(localVersion, currentVersion)
	if err != nil {
		return false, errors.Wrap(err, "failed to compare versions")
	}

	if cmp <= 0 {
		// Local binary is not newer
		return false, nil
	}

	log.Info().
		Str("installed", localVersion).
		Msg("auto-update: using the latest installed version")
	log.Debug().
		Str("current", currentVersion).
		Str("path", localBinary).
		Msg("self-update: switching to local binary")

	// On Windows, swap the binary in-place so the firewall rule stays valid.
	// No extra verification needed: getLocalBinaryVersion already ran the binary.
	if inPlaceUpdateEnabled {
		originalPath, err := swapBinaryInPlace(localBinary)
		if err != nil {
			return false, errors.Wrap(err, "in-place swap failed")
		}
		localBinary = originalPath
	}

	// Exec to the newer local binary
	if err := ExecUpdatedBinary(localBinary, os.Args); err != nil {
		return false, errors.Wrap(err, "failed to exec local binary")
	}

	return true, nil
}

// getLocalBinaryVersion runs the local binary with "version" and parses the version
func getLocalBinaryVersion(binaryPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "version")
	// Prevent the child from trying to update (avoid recursion)
	cmd.Env = append(os.Environ(), EnvAutoUpdate+"=false")

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse version from output like "mql 13.0.0 (376a12d7049b, 2026-01-28T00:55:02Z)"
	// We want to extract "12.20.1"
	version := strings.TrimSpace(string(output))
	parts := strings.Fields(version)
	if len(parts) >= 2 {
		version = parts[1]
	}

	return version, nil
}

// shouldCheckUpdate returns true if enough time has passed since the last check
// for this specific binary name.
func shouldCheckUpdate(binPath string, binName string, interval int64) bool {
	markerPath := filepath.Join(binPath, markerFilePrefix+binName)
	info, err := os.Stat(markerPath)
	if err != nil {
		// Marker doesn't exist or can't be read, should check
		return true
	}

	lastCheck := info.ModTime().Unix()
	return time.Now().Unix()-lastCheck >= interval
}

// updateMarkerFile touches the marker file to record when the last check occurred
// for this specific binary name.
func updateMarkerFile(binPath string, binName string) {
	markerPath := filepath.Join(binPath, markerFilePrefix+binName)

	// Ensure the directory exists
	if err := os.MkdirAll(binPath, 0o755); err != nil {
		log.Debug().Err(err).Msg("self-update: failed to create bin directory for marker")
		return
	}

	// Create or update the marker file
	f, err := os.Create(markerPath)
	if err != nil {
		log.Debug().Err(err).Msg("self-update: failed to update marker file")
		return
	}
	f.Close()
}

// getLatestRelease fetches and parses the latest release information
func getLatestRelease(ctx context.Context, releaseURL string) (*Release, error) {
	if !strings.HasPrefix(releaseURL, "https://") && !strings.HasPrefix(releaseURL, "http://") {
		if idx := strings.Index(releaseURL, "://"); idx != -1 {
			return nil, errors.Newf("unsupported URL scheme %q, only http and https are supported", releaseURL[:idx])
		}
		releaseURL = "https://" + releaseURL
		if u, err := url.Parse(releaseURL); err != nil || u.Host == "" {
			return nil, errors.Newf("invalid release URL %q", releaseURL)
		}
	}

	client, err := httpClientWithRetry()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch latest release")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Newf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, errors.Wrap(err, "failed to parse release JSON")
	}

	return &release, nil
}

// getPlatformFile finds the appropriate release file for the current platform
func getPlatformFile(release *Release, binaryName string) *ReleaseFile {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// Determine file extension
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}

	// Build the expected filename suffix
	// Format: <binary>_<version>_<os>_<arch>.<ext>
	// Note: The Filename field in latest.json contains full URLs
	suffix := fmt.Sprintf("%s_%s_%s_%s.%s", binaryName, release.Version, goos, goarch, ext)

	for i := range release.Files {
		// Match by suffix since Filename is a full URL
		if strings.HasSuffix(release.Files[i].Filename, suffix) {
			return &release.Files[i]
		}
	}

	return nil
}

// downloadAndInstall downloads and installs the release, returning the path to the new binary
func downloadAndInstall(ctx context.Context, release *Release, destPath string, binaryName string) (string, error) {
	file := getPlatformFile(release, binaryName)
	if file == nil {
		return "", errors.Newf("no release file found for platform %s_%s", runtime.GOOS, runtime.GOARCH)
	}

	// The Filename field contains the full download URL
	downloadURL := file.Filename

	log.Debug().Str("url", downloadURL).Msg("self-update: downloading")

	// Download the file
	client, err := httpClientWithRetry()
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to create download request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "failed to download release")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.Newf("download failed with status: %d", resp.StatusCode)
	}

	// Create a temporary file to store the download
	tmpFile, err := os.CreateTemp("", binaryName+"-update-*")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp file")
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Copy the download and compute hash simultaneously
	hash := sha256.New()
	writer := io.MultiWriter(tmpFile, hash)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		tmpFile.Close()
		return "", errors.Wrap(err, "failed to download file")
	}
	tmpFile.Close()

	// Verify checksum
	computedHash := hex.EncodeToString(hash.Sum(nil))
	if file.Hash != "" && computedHash != file.Hash {
		return "", errors.Newf("checksum mismatch: expected %s, got %s", file.Hash, computedHash)
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(destPath, 0o755); err != nil {
		return "", errors.Wrap(err, "failed to create destination directory")
	}

	// Extract the archive
	tmpArchive, err := os.Open(tmpPath)
	if err != nil {
		return "", errors.Wrap(err, "failed to open temp archive")
	}
	defer tmpArchive.Close()

	var extractedName string
	if runtime.GOOS == "windows" {
		extractedName, err = extractZip(tmpArchive, destPath, tmpPath, binaryName)
	} else {
		extractedName, err = extractTarGz(tmpArchive, destPath, binaryName)
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to extract archive")
	}

	binaryPath := filepath.Join(destPath, extractedName)

	// Set executable permissions on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0o755); err != nil {
			return "", errors.Wrap(err, "failed to set executable permissions")
		}
	}

	return binaryPath, nil
}

// checkWritable checks if the given path is writable
func checkWritable(path string) error {
	// Try to create the directory if it doesn't exist
	if err := os.MkdirAll(path, 0o755); err != nil {
		return errors.Wrap(err, "cannot create directory")
	}

	// Try to create a test file
	testPath := filepath.Join(path, ".write-test")
	f, err := os.Create(testPath)
	if err != nil {
		return errors.Wrap(err, "cannot write to directory")
	}
	f.Close()
	os.Remove(testPath)

	return nil
}

// httpClientWithRetry creates an HTTP client with retry capabilities
func httpClientWithRetry() (*http.Client, error) {
	var proxyFn func(*http.Request) (*url.URL, error)

	proxy, err := config.GetAPIProxy()
	if err != nil {
		log.Warn().Err(err).Msg("self-update: could not parse proxy URL")
	}

	if proxy != nil {
		proxyFn = http.ProxyURL(proxy)
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = zerologadapter.New(log.Logger)
	retryClient.HTTPClient = &http.Client{
		Transport: &http.Transport{
			Proxy: proxyFn,
			DialContext: (&net.Dialer{
				Timeout:   defaultHttpTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       defaultIdleConnTimeout,
			TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: defaultHttpTimeout,
	}

	return retryClient.StandardClient(), nil
}
