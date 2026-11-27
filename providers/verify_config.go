// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"context"
	"sort"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/utils/verify"
)

// Provider download verification
//
// Downloaded provider archives are verified against the published SHA256SUMS
// manifest and, when available, a detached minisign signature over that
// manifest. The public key is pinned into the binary at release build time via
// -ldflags so authenticity does not depend on any network service.

// providerSignaturePolicy controls signature enforcement for provider
// downloads. The zero value is verify.SignatureAuto. It can be tightened to
// verify.SignatureRequire in strict fleets once signatures are published
// everywhere. It is atomic so configuring it at startup cannot race an install
// already running on another goroutine.
var providerSignaturePolicyValue atomic.Int32

func providerSignaturePolicy() verify.SignaturePolicy {
	return verify.SignaturePolicy(providerSignaturePolicyValue.Load())
}

// SetProviderSignaturePolicy overrides the signature-enforcement policy for
// provider downloads (auto | require | off). Callers map their config value
// through verify.ParseSignaturePolicy.
func SetProviderSignaturePolicy(p verify.SignaturePolicy) {
	providerSignaturePolicyValue.Store(int32(p))
}

// providerVerifier builds the verifier for provider downloads from the pinned
// key and current policy. A nil verifier (returned on an unparsable pinned key)
// means "cannot verify"; callers treat that as a hard error rather than
// silently skipping verification.
func providerVerifier(policy verify.SignaturePolicy) (*verify.Verifier, error) {
	return verify.NewVerifier(verify.PinnedPublicKey, policy)
}

// verifyProviderDownload checks downloaded provider files against the
// published SHA256SUMS manifest and, when available, its detached signature.
// files maps each file's name as it appears in the manifest to its bytes.
//
// What happens when something cannot be verified depends on the policy:
//
//   - A file that does not match the manifest, a file the manifest does not
//     list, or a signature that is present but invalid always fails.
//   - A manifest that is not published (a mirror that never copied it, a
//     registry that cannot supply it) or cannot be fetched fails only under
//     'require'. Under 'auto' the install goes ahead as it did before
//     verification existed, so an air-gapped mirror keeps working.
//   - Under 'off' the manifest's signature is not checked, but the files are
//     still checked against a manifest that was published.
func verifyProviderDownload(ctx context.Context, name, version string, files map[string][]byte) error {
	policy := providerSignaturePolicy()
	strict := policy == verify.SignatureRequire
	logCtx := log.With().Str("provider", name).Str("version", version).Logger()

	vr, ok := registry.(VerifiedRegistry)
	if !ok {
		if strict {
			return errors.New("this registry cannot supply checksums, but verify_signature is 'require'")
		}
		logCtx.Debug().Msg("registry does not supply checksums; skipping download verification")
		return nil
	}

	manifest, ok, err := vr.DownloadChecksums(ctx, name, version)
	if err != nil {
		if strict {
			return err
		}
		logCtx.Warn().Err(err).Msg("could not fetch the checksum manifest; installing without verification")
		return nil
	}
	if !ok {
		if strict {
			return errors.New("no checksum manifest is published for " + name + "-" + version + ", but verify_signature is 'require'")
		}
		logCtx.Debug().Msg("no checksum manifest published; installing without verification")
		return nil
	}

	var signature []byte
	if policy != verify.SignatureOff {
		sig, _, err := vr.DownloadSignature(ctx, name, version)
		if err != nil {
			// The signature is optional under 'auto', so failing to fetch one
			// is treated like it not being published.
			if strict {
				return err
			}
			logCtx.Debug().Err(err).Msg("could not fetch the manifest signature; verifying by checksum only")
		}
		signature = sig
	}

	v, err := providerVerifier(policy)
	if err != nil {
		return err
	}

	// Verify in a fixed order so a failure names the same file every time.
	names := make([]string, 0, len(files))
	for filename := range files {
		names = append(names, filename)
	}
	sort.Strings(names)

	for _, filename := range names {
		res, err := v.Verify(verify.Inputs{
			Filename:  filename,
			Artifact:  files[filename],
			Manifest:  manifest,
			Signature: signature,
		})
		if err != nil {
			return err
		}
		logCtx.Debug().
			Str("file", filename).
			Str("sha256", res.SHA256).
			Bool("signature_verified", res.SignatureChecked).
			Msg("verified provider download")
	}
	return nil
}
