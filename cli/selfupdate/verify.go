// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/utils/verify"
)

// binarySignaturePolicy controls signature enforcement for engine-binary
// self-updates. The zero value is verify.SignatureAuto: verify a signature when
// one is published, otherwise fall back to the checksum. Strict fleets can raise
// it to verify.SignatureRequire. Atomic so configuring it at startup cannot race
// an update check on another goroutine.
var binarySignaturePolicyValue atomic.Int32

func binarySignaturePolicy() verify.SignaturePolicy {
	return verify.SignaturePolicy(binarySignaturePolicyValue.Load())
}

// SetBinarySignaturePolicy overrides the signature-enforcement policy for
// binary self-updates.
func SetBinarySignaturePolicy(p verify.SignaturePolicy) {
	binarySignaturePolicyValue.Store(int32(p))
}

// checksumManifestName builds the SHA256SUMS manifest name for a binary
// release, matching goreleaser's checksum name_template
// "<name>_v<version>_SHA256SUMS".
func checksumManifestName(binaryName, version string) string {
	return fmt.Sprintf("%s_v%s_SHA256SUMS", binaryName, version)
}

// archiveNameFromURL returns the file name the archive is published under,
// which is the name the SHA256SUMS manifest lists it by. It is taken from the
// download URL rather than rebuilt from the platform, because goreleaser's
// archive names carry suffixes (armv7, amd64 levels) that GOARCH does not.
func archiveNameFromURL(downloadURL string) (string, error) {
	u, err := url.Parse(downloadURL)
	if err != nil {
		return "", err
	}
	name := path.Base(u.Path)
	if name == "" || name == "." || name == "/" {
		return "", errors.Newf("cannot derive an archive name from %q", downloadURL)
	}
	return name, nil
}

// verifyDownloadManifest verifies a downloaded archive (identified by its
// already-computed SHA256) against the published SHA256SUMS manifest and its
// optional detached minisign signature.
//
// The manifest and signature live in the same release directory as the archive;
// their URLs are derived from downloadURL. A manifest that is not published, or
// cannot be fetched, is tolerated under the 'auto' policy (the caller already
// checked the release manifest's hash) but is fatal under 'require'. The same
// goes for the signature.
func verifyDownloadManifest(ctx context.Context, downloadURL, binaryName, version, computedHash string) error {
	policy := binarySignaturePolicy()
	strict := policy == verify.SignatureRequire

	archiveName, err := archiveNameFromURL(downloadURL)
	if err != nil {
		if strict {
			return err
		}
		log.Debug().Err(err).Msg("self-update: cannot locate checksum manifest, relying on the release manifest hash")
		return nil
	}

	baseURL := downloadURL[:strings.LastIndex(downloadURL, "/")+1]
	manifestURL := baseURL + checksumManifestName(binaryName, version)
	sigURL := manifestURL + ".sig"

	manifest, notFound, err := fetchBytes(ctx, manifestURL)
	if err != nil {
		if strict {
			return err
		}
		log.Warn().Err(err).Msg("self-update: could not fetch SHA256SUMS manifest, relying on the release manifest hash")
		return nil
	}
	if notFound {
		if strict {
			return errors.New("no SHA256SUMS manifest published, but verify_signature is 'require'")
		}
		log.Debug().Msg("self-update: no SHA256SUMS manifest published, relying on the release manifest hash")
		return nil
	}

	var signature []byte
	if policy != verify.SignatureOff {
		sig, _, err := fetchBytes(ctx, sigURL)
		if err != nil {
			// The signature is optional under 'auto', so failing to fetch one
			// is treated like it not being published.
			if strict {
				return err
			}
			log.Debug().Err(err).Msg("self-update: could not fetch manifest signature, verifying by checksum only")
		}
		signature = sig
	}

	v, err := verify.NewVerifier(verify.PinnedPublicKey, policy)
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
