// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/utils/verify"
)

// binarySignaturePolicy controls signature enforcement for engine-binary
// self-updates. Defaults to 'auto': verify a signature when one is published,
// otherwise fall back to the checksum. Strict fleets can raise it to
// verify.SignatureRequire.
var binarySignaturePolicy = verify.SignatureAuto

// SetBinarySignaturePolicy overrides the signature-enforcement policy for
// binary self-updates.
func SetBinarySignaturePolicy(p verify.SignaturePolicy) {
	binarySignaturePolicy = p
}

// archiveFileName builds the release archive's base name for the current
// platform, matching goreleaser's "<name>_<version>_<os>_<arch>.<ext>" layout.
func archiveFileName(binaryName, version string) string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("%s_%s_%s_%s.%s", binaryName, version, runtime.GOOS, runtime.GOARCH, ext)
}

// checksumManifestName builds the SHA256SUMS manifest name for a binary
// release, matching goreleaser's checksum name_template
// "<name>_v<version>_SHA256SUMS".
func checksumManifestName(binaryName, version string) string {
	return fmt.Sprintf("%s_v%s_SHA256SUMS", binaryName, version)
}

// verifyDownloadManifest verifies a downloaded archive (identified by its
// already-computed SHA256) against the published SHA256SUMS manifest and its
// optional detached minisign signature.
//
// The manifest and signature live in the same release directory as the archive;
// their URLs are derived from downloadURL. A 404 on the manifest is tolerated
// under the 'auto' policy (the caller already checked the latest.json hash) but
// is fatal under 'require'.
func verifyDownloadManifest(ctx context.Context, downloadURL, archiveName, computedHash string) error {
	// Derive the binary name and version from the archive name so we can build
	// the manifest name. archiveName is "<name>_<version>_<os>_<arch>.<ext>".
	binaryName, version, ok := splitArchiveName(archiveName)
	if !ok {
		// If we cannot parse the name we cannot locate the manifest. Under
		// 'require' this must fail; otherwise fall back to the caller's hash.
		if binarySignaturePolicy == verify.SignatureRequire {
			return errors.Newf("cannot derive checksum manifest name from %q", archiveName)
		}
		log.Debug().Str("archive", archiveName).Msg("self-update: cannot locate checksum manifest, relying on latest.json hash")
		return nil
	}

	baseURL := downloadURL[:strings.LastIndex(downloadURL, "/")+1]
	manifestURL := baseURL + checksumManifestName(binaryName, version)
	sigURL := manifestURL + ".sig"

	manifest, notFound, err := fetchBytes(ctx, manifestURL)
	if err != nil {
		return err
	}
	if notFound {
		if binarySignaturePolicy == verify.SignatureRequire {
			return errors.New("no SHA256SUMS manifest published, but verify_signature is 'require'")
		}
		log.Debug().Msg("self-update: no SHA256SUMS manifest published, relying on latest.json hash")
		return nil
	}

	signature, _, err := fetchBytes(ctx, sigURL)
	if err != nil {
		return err
	}

	v, err := verify.NewVerifier(verify.PinnedPublicKey, binarySignaturePolicy)
	if err != nil {
		return err
	}

	res, err := v.VerifyPrehashed(archiveName, computedHash, manifest, signature)
	if err != nil {
		return err
	}

	log.Debug().
		Str("archive", archiveName).
		Str("sha256", res.SHA256).
		Bool("signature_verified", res.SignatureChecked).
		Msg("self-update: verified download")
	return nil
}

// splitArchiveName parses "<name>_<version>_<os>_<arch>.<ext>" into its name
// and version. It splits from the right so a binary name containing an
// underscore would still work, since os/arch/ext are fixed-shape.
func splitArchiveName(archiveName string) (name, version string, ok bool) {
	base := archiveName
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i] // drop ".tar.gz" / ".zip"
	}
	parts := strings.Split(base, "_")
	if len(parts) < 4 {
		return "", "", false
	}
	// Last two are os and arch; the one before them is the version.
	version = parts[len(parts)-3]
	name = strings.Join(parts[:len(parts)-3], "_")
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// fetchBytes GETs a small sidecar file, returning notFound=true on a 404 so the
// caller can distinguish "not published" from a transport error.
func fetchBytes(ctx context.Context, url string) (data []byte, notFound bool, err error) {
	client, err := httpClientWithRetry()
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, errors.Newf("unexpected status code %d for %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return body, false, nil
}
