// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"fmt"
	"runtime"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/utils/verify"
)

// Provider download verification
//
// Downloaded provider archives are verified against the published SHA256SUMS
// manifest and, when available, a detached minisign signature over that
// manifest. The public key is pinned into the binary at release build time via
// -ldflags so authenticity does not depend on any network service.

// providerSignaturePolicy controls signature enforcement for provider
// downloads. It can be tightened to verify.SignatureRequire in strict fleets
// once signatures are published everywhere.
var providerSignaturePolicy = verify.SignatureAuto

// SetProviderSignaturePolicy overrides the signature-enforcement policy for
// provider downloads (auto | require | off). Callers map their config value
// through verify.ParseSignaturePolicy.
func SetProviderSignaturePolicy(p verify.SignaturePolicy) {
	providerSignaturePolicy = p
}

// providerVerifier builds the verifier for provider downloads from the pinned
// key and current policy. A nil verifier (returned on an unparsable pinned key)
// means "cannot verify"; callers treat that as a hard error rather than
// silently skipping verification.
func providerVerifier() (*verify.Verifier, error) {
	return verify.NewVerifier(verify.PinnedPublicKey, providerSignaturePolicy)
}

// verifyProviderDownload checks the downloaded archive bytes against the
// published SHA256SUMS manifest and, when available, its detached signature.
//
// Verification requires the registry to be able to supply the sidecars
// (VerifiedRegistry). A registry that cannot (e.g. a test double, or a custom
// registry) skips verification unless the signature policy is 'require', in
// which case the absence of verifiable sidecars is a hard failure.
func verifyProviderDownload(ctx context.Context, name, version string, archive []byte) error {
	vr, ok := registry.(VerifiedRegistry)
	if !ok {
		if providerSignaturePolicy == verify.SignatureRequire {
			return errors.New("this registry cannot supply checksums, but verify_signature is 'require'")
		}
		log.Debug().Str("provider", name).Msg("registry does not supply checksums; skipping download verification")
		return nil
	}

	manifest, err := vr.DownloadChecksums(ctx, name, version)
	if err != nil {
		return err
	}

	signature, _, err := vr.DownloadSignature(ctx, name, version)
	if err != nil {
		return err
	}

	v, err := providerVerifier()
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s_%s_%s_%s.tar.xz", name, version, runtime.GOOS, runtime.GOARCH)
	res, err := v.Verify(verify.Inputs{
		Filename:  filename,
		Artifact:  archive,
		Manifest:  manifest,
		Signature: signature,
	})
	if err != nil {
		return err
	}

	log.Debug().
		Str("provider", name).
		Str("version", version).
		Str("sha256", res.SHA256).
		Bool("signature_verified", res.SignatureChecked).
		Msg("verified provider download")
	return nil
}
