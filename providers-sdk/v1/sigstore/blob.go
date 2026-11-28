// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"go.mondoo.com/mql/llx"
)

// maxBundleBytes bounds a Sigstore bundle that is parsed.
const maxBundleBytes = 16 << 20

// VerifyBlob verifies a detached Sigstore bundle over the artifact whose
// digest is digest ("sha256:<hex>"). A bundle that does not parse is
// MalformedData; a trust root that cannot be loaded is an error of its kind.
func VerifyBlob(ctx context.Context, digest string, bundleJSON []byte, p Policy, opts ...Option) (Result, error) {
	c, err := newConfig(p, opts)
	if err != nil {
		return Result{}, err
	}
	if !strings.HasPrefix(digest, "sha256:") {
		return Result{}, llx.MalformedData(fmt.Errorf("digest %q: want sha256:<hex>", digest))
	}
	e, err := parseBundle(bundleJSON, EnvelopeSigstoreBundle)
	if err != nil {
		return Result{}, llx.MalformedData(err)
	}
	r, err := c.verifyEntity(ctx, e, subject{digest: digest})
	if err != nil {
		return Result{}, err
	}
	p.apply(&r)
	return r, nil
}

// parseBundle reads a Sigstore bundle (JSON, v0.1 to v0.3) into an entity.
func parseBundle(b []byte, env Envelope) (entity, error) {
	if len(b) > maxBundleBytes {
		return entity{}, fmt.Errorf("the bundle is %d bytes, above the %d-byte bound", len(b), maxBundleBytes)
	}
	var bun bundle.Bundle
	if err := bun.UnmarshalJSON(b); err != nil {
		return entity{}, fmt.Errorf("reading the Sigstore bundle: %w", err)
	}
	return bundleEntity(&bun, b, env)
}

func bundleEntity(bun *bundle.Bundle, raw []byte, env Envelope) (entity, error) {
	e := entity{signed: bun, envelope: env, raw: raw}
	if dsse := bun.GetDsseEnvelope(); dsse != nil {
		e.payload = dsse.GetPayload()
	}
	if vc, err := bun.VerificationContent(); err == nil {
		if pk := vc.PublicKey(); pk != nil {
			e.keyHint = pk.Hint()
		}
	}
	if entries, err := bun.TlogEntries(); err == nil {
		e.tlogEntries = len(entries)
	}
	return e, nil
}

// decodeB64 is standard base64 or an error naming what it was.
func decodeB64(what, s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", what, err)
	}
	return b, nil
}
