// Copyright Mondoo, Inc. 2024, 2026
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
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/logger/zerologadapter"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/utils/httpx"
	"go.mondoo.com/mql/utils/sysproxy"
)

const (
	// DefaultRefreshInterval is the minimum time between update checks in seconds (1 hour)
	DefaultRefreshInterval = 3600
	// EnvAutoUpdate can be set to "false" or "0" to disable all auto-updates
	// (both engine binary and providers). When off, EnvAutoUpdateEngine is also off.
	EnvAutoUpdate = "MONDOO_AUTO_UPDATE"
	// EnvAutoUpdateEngine can be set to "false" or "0" to disable engine binary
	// auto-update specifically. It is also set to "false" after a binary self-update
	// to prevent infinite update loops. Provider auto-update (which reads
	// MONDOO_AUTO_UPDATE via viper) is not affected by this variable.
	EnvAutoUpdateEngine = "MONDOO_AUTO_UPDATE_ENGINE"
	// DefaultUpdatesURL is the install service binary updates resolve through
	// when updates_url is not configured. It is the same service cnspec defaults
	// to, so one updates_url means the same thing to both binaries.
	DefaultUpdatesURL = "https://install.mondoo.com"
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
	// ReleaseURL is the manifest to read. It is the layout the caller asked for
	// and the one any error is reported against.
	ReleaseURL string
	// FallbackReleaseURLs are tried, in order, when ReleaseURL yields no usable
	// manifest -- the other layout the same host might publish. Leave it empty to
	// check exactly one URL.
	FallbackReleaseURLs []string
	// BinaryName is the name of the binary to update (e.g., "mql", "cnspec").
	// Used to match archive entries and construct platform-specific filenames.
	BinaryName string
	// CurrentVersion is the current version of the running binary.
	// If "x.y.z-rolling", self-update is skipped.
	CurrentVersion string
}

// releaseURLs is the ordered list of manifests to try: the configured one
// first, then any fallbacks.
func (c Config) releaseURLs() []string {
	urls := make([]string, 0, 1+len(c.FallbackReleaseURLs))
	if c.ReleaseURL != "" {
		urls = append(urls, c.ReleaseURL)
	}
	for _, u := range c.FallbackReleaseURLs {
		if u != "" && u != c.ReleaseURL {
			urls = append(urls, u)
		}
	}
	return urls
}

// Release represents the release information from latest.json
type Release struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Files   []ReleaseFile `json:"files"`
}

// ReleaseURL returns the release manifest a binary's self-update reads, from the
// install service at updatesURL (or the default one when it is empty).
//
// A channel changes which pointer is read, never where the artifacts live, so a
// pinned version resolves the same on every channel. It travels as a query
// parameter rather than a different document name because the service's routes
// are named after the package, not after the manifest: there is no
// /package/mql/preview.json, and a path-shaped channel would ask for a route
// that does not exist.
//
// The bucket spells the same thing as a sibling document (/mql/preview.json),
// which is why one updates_url cannot address both: the layouts disagree on the
// path and on the channel. This builds the install-service spelling, which is
// what cnspec already uses, so a single configured host serves both binaries.
// ReleaseURLs returns the manifests to try for a binary, in order: the install
// service's layout first, then the release bucket's.
//
// The two are the same document published under different paths, and a host
// answers one of them with a 404. Trying both is what lets updates_url name
// either kind of host -- an operator mirroring the bucket has "/<binary>/", the
// install service has "/package/<binary>/", and neither has to know which the
// client prefers.
//
// The channel is spelled differently in each: a query parameter on the service,
// a sibling document in the bucket. Both spellings are produced here, so a
// fallback does not quietly drop the caller back onto stable.
//
// The bucket layout is the deprecated half of this. It is here so an existing
// mirror keeps working without being re-laid-out, not because it is a second
// supported way to publish: the install service is what updates_url should name
// going forward, and it is the only layout that serves a channel without a
// second document per channel. When mirrors have moved, the fallback is the part
// to delete -- ReleaseURL already returns the layout to keep.
func ReleaseURLs(updatesURL string, binary string, channel string) []string {
	if updatesURL == "" {
		updatesURL = DefaultUpdatesURL
	}
	base := strings.TrimSuffix(updatesURL, "/")

	bucket := base + "/" + binary + "/latest.json"
	if channel == config.ChannelPreview {
		bucket = base + "/" + binary + "/preview.json"
	}

	return []string{ReleaseURL(updatesURL, binary, channel), bucket}
}

func ReleaseURL(updatesURL string, binary string, channel string) string {
	if updatesURL == "" {
		updatesURL = DefaultUpdatesURL
	}

	manifest := strings.TrimSuffix(updatesURL, "/") + "/package/" + binary + "/latest.json"
	if channel == "" || channel == config.ChannelStable {
		return manifest
	}

	// Encoded rather than concatenated, so a caller passing something other than
	// the two normalized constants gets a valid URL with one odd parameter
	// instead of a second "?" or an injected one.
	query := url.Values{}
	query.Set("channel", channel)
	return manifest + "?" + query.Encode()
}

// ReleaseFile represents a downloadable release file
type ReleaseFile struct {
	// Filename is the artifact name. It is the plain name in some documents and
	// the fully qualified download URL in others, so it is not a reliable
	// download target on its own; see downloadTarget.
	Filename string `json:"filename"`
	// Url is the fully qualified download URL. It is absent only on manifests
	// published before the field existed.
	Url      string `json:"url"`
	Platform string `json:"platform"` // e.g., "linux_amd64", "darwin_arm64"
	Hash     string `json:"hash"`     // SHA256 hash
}

// downloadTarget is the URL to fetch this artifact from.
//
// Url is the field that means the same thing in every document and is preferred.
// It is empty only for a manifest published before the field existed, in which
// case Filename carries the fully qualified URL instead - that is what
// latest.json has always held, and what this code read before Url existed. A
// document where Filename is the plain name and Url is absent has no download
// target at all; downloadAndInstall rejects that rather than fetching a bare
// name.
func (f *ReleaseFile) downloadTarget() string {
	if f.Url != "" {
		return f.Url
	}
	return f.Filename
}

// updatePreflight runs the guards shared by every self-update entry point and
// resolves the bin path, platform binary name, and current version. ok is false
// when self-update must be skipped entirely (disabled via config or environment,
// or running a dev build); in that case the caller returns (false, err).
func updatePreflight(cfg Config) (binPath, binName, currentVersion string, ok bool, err error) {
	if !cfg.Enabled {
		return "", "", "", false, nil
	}

	// Skip if auto-update is disabled via environment (disables both engine and providers)
	if val := os.Getenv(EnvAutoUpdate); val == "false" || val == "0" {
		log.Debug().Msg("self-update: skipping, disabled via " + EnvAutoUpdate)
		return "", "", "", false, nil
	}

	// Skip if engine auto-update is specifically disabled (e.g., after a binary self-update
	// to prevent infinite loops, or when the user only wants provider auto-updates)
	if val := os.Getenv(EnvAutoUpdateEngine); val == "false" || val == "0" {
		log.Debug().Msg("self-update: skipping, disabled via " + EnvAutoUpdateEngine)
		return "", "", "", false, nil
	}

	// Skip if version is "rolling" (dev build)
	currentVersion = cfg.CurrentVersion
	if strings.HasSuffix(currentVersion, "-rolling") {
		log.Debug().Msg("self-update: skipping, running unstable/dev build")
		return "", "", "", false, nil
	}

	// Get the bin path for storing updated binaries
	binPath, err = getBinPath()
	if err != nil {
		return "", "", "", false, errors.Wrap(err, "failed to get bin path")
	}

	binName = platformBinaryName(cfg.BinaryName)
	return binPath, binName, currentVersion, true, nil
}

// CheckLocalAndUpdate runs only the local portion of the self-update flow: if a
// newer binary has already been staged in the bin path, it execs into it. It
// performs no network access, so it is fast enough to run on quick commands like
// "version" that still need to report the effective version after an update has
// been staged (otherwise they report the stale compiled-in version while every
// other command transparently execs into the newer binary).
// Returns true if the process was (or is about to be) replaced by the new binary.
func CheckLocalAndUpdate(cfg Config) (bool, error) {
	binPath, binName, currentVersion, ok, err := updatePreflight(cfg)
	if err != nil || !ok {
		return false, err
	}

	return execLocalIfNewer(binPath, binName, currentVersion)
}

// CheckAndUpdate checks for updates and installs them if available.
// Returns true if an update was installed and the process was replaced.
func CheckAndUpdate(cfg Config) (bool, error) {
	binPath, binName, currentVersion, ok, err := updatePreflight(cfg)
	if err != nil || !ok {
		return false, err
	}

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

	// Reconcile what the OS reports with what is actually running, whether or
	// not an update follows. Three cases need this and none of them involve an
	// update landing right now:
	//
	//   - a pre-release installs under its semver core, because Windows
	//     Installer accepts numeric fields only, so 14.0.0-rc.5 registers as
	//     14.0.0 and is wrong from the first boot;
	//   - `msiexec /f` rewrites the registration from the MSI's own
	//     ProductVersion, undoing an earlier correction;
	//   - the binary is already current, so the update path below returns
	//     early and would never reach a correction.
	//
	// Gated behind the refresh interval rather than run per invocation, and it
	// reads before it writes, so the steady state is one registry read.
	registerVersion(currentVersion)

	// Fetch the latest release information
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	release, err := getLatestReleaseFrom(ctx, cfg.releaseURLs())
	if err != nil {
		// We don't update the marker, which may lead to more checks against the URL
		// but this is helpful when e.g. a network configuration wasn't set right.
		// If users fix it and re-run commands it won't check which sucks. The
		// request is fast so we opt to do it to avoid these temporary failures.
		return false, errors.Wrap(err, "failed to fetch latest release")
	}

	// The stable channel never installs a pre-release, whatever the manifest
	// says. Channel membership is decided upstream and this binary trusts it,
	// so one mistake in the index generator reaches every stable install with
	// nothing in between -- which is how a stable client came to install
	// provider notion 14.0.0-rc.1 on 2026-09-14.
	//
	// The marker is written, unlike the error paths above. Those leave it alone
	// because the fault is usually local and transient -- a proxy or a DNS entry
	// the operator corrects and retries within the minute. A pre-release sitting
	// on a stable pointer is neither: it is upstream state that no amount of
	// re-running fixes, so re-fetching the manifest on every single invocation
	// buys nothing and puts a warning in front of every command until someone
	// else acts. With the marker written the check resumes after the refresh
	// interval, so the correction is picked up within the hour and the reason is
	// still stated once per interval rather than never.
	//
	// An explicit `update` passes RefreshInterval 0, so this never suppresses an
	// update the operator asked for by name.
	if channel := config.GetUpdateChannel(); channel != config.ChannelPreview &&
		config.IsPrereleaseVersion(release.Version) {
		log.Warn().
			Str("current", currentVersion).
			Str("offered", release.Version).
			Str("channel", channel).
			Msg("self-update: refusing a pre-release offered on a stable channel")
		updateMarkerFile(binPath, cfg.BinaryName)
		return false, nil
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
		registerVersion(release.Version)
	}

	// Re-execute with the new binary
	if err := ExecUpdatedBinary(binaryPath, os.Args); err != nil {
		return false, errors.Wrap(err, "failed to re-execute with updated binary")
	}

	// If ExecUpdatedBinary returns (Windows case), we've spawned a new process
	return true, nil
}

// registerVersion points the OS package manager's record at the version now on
// disk, where the platform has such a record.
//
// Deliberately not fatal. The binary has already been replaced and verified at
// this point, so the update succeeded; only the bookkeeping did not. Writing
// the Add/Remove entry needs HKLM, which an interactive non-elevated `update`
// will not have even though the swap into a user-writable location did. A
// warning is the honest outcome: the machine is running the new version and
// Windows will keep reporting the old one until something with the rights
// corrects it.
func registerVersion(version string) {
	if err := updateRegisteredVersion(version); err != nil {
		log.Warn().Err(err).
			Str("version", version).
			Msg("self-update: updated the binary but could not update the version the OS reports")
	}
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
		registerVersion(localVersion)
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
		// Name the URL: two layouts are tried, and an operator debugging a mirror
		// needs to know which one answered this.
		return nil, errors.Newf("unexpected status code %d from %s", resp.StatusCode, releaseURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, errors.Wrap(err, "failed to parse release JSON")
	}

	// Unmarshalling into Release succeeds for any JSON object, so a document that
	// is merely well-formed would otherwise pass as a manifest with an empty
	// version -- read downstream as "no newer release", which is a silent no-op
	// rather than an error. A manifest names a version.
	if release.Version == "" {
		return nil, errors.Newf("no version in the release document at %s", releaseURL)
	}

	return &release, nil
}

// LatestVersion returns the version named by the first manifest that answers,
// trying each layout in turn. It is what a status command should report: the
// version resolved the same way the updater resolves it, so the two cannot
// disagree about whether an update is available.
func LatestVersion(ctx context.Context, releaseURLs []string) (string, error) {
	release, err := getLatestReleaseFrom(ctx, releaseURLs)
	if err != nil {
		return "", err
	}
	return release.Version, nil
}

// getLatestReleaseFrom tries each URL in order and returns the first usable
// manifest.
//
// The candidates are the same manifest in two layouts; see ReleaseURLs. A host
// serves one of them and answers the other with a 404, so trying the second is
// the normal path rather than an error case, and only the first error is
// reported: it belongs to the layout the caller asked for, and reporting the
// last would describe a URL the operator never configured -- and would hide a
// real outage on the primary behind a 404 from the fallback.
func getLatestReleaseFrom(ctx context.Context, releaseURLs []string) (*Release, error) {
	var firstErr error
	for _, releaseURL := range releaseURLs {
		release, err := getLatestRelease(ctx, releaseURL)
		if err == nil {
			return release, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		log.Debug().Str("url", releaseURL).Err(err).Msg("no release manifest here, trying the next layout")
	}
	if firstErr == nil {
		firstErr = errors.New("no release URL to check")
	}
	return nil, firstErr
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
		// Match on Filename, which names the artifact in both document shapes:
		// the plain name in one, the fully qualified URL in the other, and both
		// end in it.
		//
		// Not on the download target. Which artifact this is and where to fetch
		// it are separate questions, and answering the first with the second
		// requires the URL to end in the artifact name. That is true of the
		// release bucket's layout but need not be true of whoever serves the
		// manifest, and it is not the client's place to constrain that.
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

	downloadURL := file.downloadTarget()
	// A manifest that carries no url and only a plain filename has no download
	// target. Left alone this reaches http.NewRequestWithContext as a bare name
	// and fails as a URL parse error, which points at the request rather than at
	// the manifest that is actually wrong.
	if !strings.HasPrefix(downloadURL, "http://") && !strings.HasPrefix(downloadURL, "https://") {
		return "", errors.Newf("release manifest has no download url for %s_%s: %q is not a url",
			runtime.GOOS, runtime.GOARCH, downloadURL)
	}

	log.Debug().Str("url", downloadURL).Msg("self-update: downloading")

	// Download the file using a client without total-request timeout,
	// so large downloads on slow connections are not killed prematurely.
	client, err := httpx.ClientForDownload()
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

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return "", errors.Newf("download failed with status: %d", resp.StatusCode)
	}

	// Wrap body with idle timeout so stalled downloads are detected,
	// while slow-but-active transfers are allowed to complete.
	// The idle reader owns resp.Body from this point.
	idleReader := httpx.NewIdleTimeoutReader(resp.Body, httpx.DownloadTimeout())
	defer idleReader.Close()

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

	if _, err := io.Copy(writer, idleReader); err != nil {
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
	// api_proxy, the environment or the operating system's settings, in that
	// order; see cli/config/proxy.go. A broken api_proxy is reported and the
	// download proceeds as it would without one.
	proxyFn, err := config.ProxyFunc()
	if err != nil {
		log.Warn().Err(err).Msg("self-update: could not parse proxy URL")
		proxyFn = sysproxy.EnvironmentProxyFunc()
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
