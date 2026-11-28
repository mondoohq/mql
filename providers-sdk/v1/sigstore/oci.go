// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"go.mondoo.com/mql/llx"
)

// The layouts read on a registry.
const (
	cosignSignatureAnnotation = "dev.cosignproject.cosign/signature"
	cosignCertAnnotation      = "dev.sigstore.cosign/certificate"
	cosignChainAnnotation     = "dev.sigstore.cosign/chain"
	cosignBundleAnnotation    = "dev.sigstore.cosign/bundle"

	buildkitRefType      = "vnd.docker.reference.type"
	buildkitRefDigest    = "vnd.docker.reference.digest"
	buildkitManifestType = "attestation-manifest"
	buildkitPredicate    = "in-toto.io/predicate-type"

	sigstoreBundleArtifactPrefix = "application/vnd.dev.sigstore.bundle"

	bundleV01MediaType = "application/vnd.dev.sigstore.bundle+json;version=0.1"
)

// maxSignatures bounds the signatures and attestations read for one subject.
const maxSignatures = 64

// VerifyOCI verifies every signature and attestation stored for one platform
// manifest: cosign .sig and .att tags, Sigstore bundles attached as OCI 1.1
// referrers, and, given WithIndex, the BuildKit attestation manifests the
// index lists for it. ref must be a platform manifest digest; an image index
// digest is refused with ErrIndexSubject, since an index is never a subject.
//
// No signature is an empty list and no error. A registry refusal is
// Forbidden or Unauthenticated, an unreachable registry is Unavailable, and a
// trust root that cannot be loaded is an error: never results that read
// unverified.
func VerifyOCI(ctx context.Context, ref name.Digest, p Policy, opts ...Option) ([]Result, error) {
	c, err := newConfig(p, opts)
	if err != nil {
		return nil, err
	}
	ropts := append([]remote.Option{remote.WithContext(ctx)}, c.remote...)
	desc, err := remote.Head(ref, ropts...)
	if err != nil {
		if isNotFound(err) {
			return nil, llx.NotFound(fmt.Errorf("reading %s: %w", ref.Name(), err))
		}
		return nil, classifyRegistry(fmt.Errorf("reading %s: %w", ref.Name(), err))
	}
	if desc.MediaType.IsIndex() {
		return nil, llx.MalformedData(fmt.Errorf("%s: %w", ref.Name(), ErrIndexSubject))
	}
	digest := ref.DigestStr()
	repo := ref.Context()

	var found []entity
	add := func(es []entity, err error) error {
		if err != nil {
			return err
		}
		found = append(found, es...)
		if len(found) > maxSignatures {
			found = found[:maxSignatures]
		}
		return nil
	}
	tagPrefix := strings.Replace(digest, ":", "-", 1)
	if err := add(c.cosignTag(repo, tagPrefix+".sig", EnvelopeCosignSignature, ropts)); err != nil {
		return nil, err
	}
	if err := add(c.cosignTag(repo, tagPrefix+".att", EnvelopeCosignAttestation, ropts)); err != nil {
		return nil, err
	}
	if err := add(c.referrers(ref, ropts)); err != nil {
		return nil, err
	}

	var results []Result
	for _, e := range found {
		var subj subject
		if e.envelope == EnvelopeCosignSignature {
			// The signature signs the simple-signing document; the document
			// names the image digest, checked below.
			subj = subject{digest: digest, artifact: e.payload}
		} else {
			subj = subject{digest: digest}
		}
		r, err := c.verifyEntityTryKeys(ctx, e, subj)
		if err != nil {
			return nil, err
		}
		if r.SignatureValid && !r.CoversDigest(digest) {
			r.SignatureValid, r.SubjectMismatch = false, true
			r.Reason = "the signature covers another subject than " + digest
			r.clearIdentity()
		}
		p.apply(&r)
		results = append(results, r)
	}

	if c.index != nil {
		bk, err := c.buildkit(*c.index, digest, ropts)
		if err != nil {
			return nil, err
		}
		results = append(results, bk...)
	}
	return results, nil
}

// verifyEntityTryKeys verifies e; a legacy key signature with no log entry
// names no key, so each configured key is tried.
func (c *config) verifyEntityTryKeys(ctx context.Context, e entity, subj subject) (Result, error) {
	if e.keyHint != "" || e.legacy == nil || !e.legacy.keyOnly {
		return c.verifyEntity(ctx, e, subj)
	}
	var last Result
	for fp := range c.keys {
		ke, err := e.legacy.build(fp)
		if err != nil {
			return Result{}, err
		}
		r, err := c.verifyEntity(ctx, ke, subj)
		if err != nil {
			return Result{}, err
		}
		if r.SignatureValid || r.SubjectMismatch {
			return r, nil
		}
		last = r
	}
	if last.Reason == "" {
		last = Result{Envelope: e.envelope, Payload: e.payload, Reason: "signed with a key that is not a configured key"}
		describePayload(&last)
	}
	return last, nil
}

// cosignTag reads a cosign signature or attestation image.
func (c *config) cosignTag(repo name.Repository, tag string, env Envelope, ropts []remote.Option) ([]entity, error) {
	t, err := name.NewTag(repo.Name()+":"+tag, name.WeakValidation)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(t, ropts...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, classifyRegistry(fmt.Errorf("reading %s: %w", t.Name(), err))
	}
	m, err := img.Manifest()
	if err != nil {
		return nil, classifyRegistry(err)
	}
	var out []entity
	for _, l := range m.Layers {
		if len(out) >= maxSignatures {
			break
		}
		b, err := c.readLayer(img, l)
		if err != nil {
			return nil, err
		}
		lg := legacyLayer{env: env, blob: b, ann: l.Annotations}
		e, err := lg.build("")
		if err != nil {
			// One layer that does not parse is reported as an invalid
			// signature, not as an error of the whole subject.
			out = append(out, entity{envelope: env, payload: lg.payloadOrNil(), malformed: err.Error()})
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// referrers reads Sigstore bundles attached to the subject as OCI 1.1
// referrers (or the referrers tag schema, which the registry client falls
// back to).
func (c *config) referrers(ref name.Digest, ropts []remote.Option) ([]entity, error) {
	idx, err := remote.Referrers(ref, ropts...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, classifyRegistry(fmt.Errorf("reading the referrers of %s: %w", ref.Name(), err))
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, classifyRegistry(err)
	}
	var out []entity
	for _, d := range im.Manifests {
		if len(out) >= maxSignatures {
			break
		}
		if !strings.HasPrefix(d.ArtifactType, sigstoreBundleArtifactPrefix) {
			continue
		}
		img, err := remote.Image(ref.Context().Digest(d.Digest.String()), ropts...)
		if err != nil {
			return nil, classifyRegistry(err)
		}
		m, err := img.Manifest()
		if err != nil {
			return nil, classifyRegistry(err)
		}
		for _, l := range m.Layers {
			if !strings.HasPrefix(string(l.MediaType), sigstoreBundleArtifactPrefix) {
				continue
			}
			b, err := c.readLayer(img, l)
			if err != nil {
				return nil, err
			}
			e, err := parseBundle(b, EnvelopeOCIReferrer)
			if err != nil {
				out = append(out, entity{envelope: EnvelopeOCIReferrer, malformed: err.Error()})
				continue
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// buildkit reads the BuildKit attestation manifests an index lists for the
// platform digest. BuildKit does not sign them: each is reported with
// SignatureValid false.
func (c *config) buildkit(index name.Digest, digest string, ropts []remote.Option) ([]Result, error) {
	ii, err := remote.Index(index, ropts...)
	if err != nil {
		return nil, classifyRegistry(fmt.Errorf("reading %s: %w", index.Name(), err))
	}
	im, err := ii.IndexManifest()
	if err != nil {
		return nil, classifyRegistry(err)
	}
	var out []Result
	for _, m := range im.Manifests {
		if m.Annotations[buildkitRefType] != buildkitManifestType || m.Annotations[buildkitRefDigest] != digest {
			continue
		}
		img, err := remote.Image(index.Context().Digest(m.Digest.String()), ropts...)
		if err != nil {
			return nil, classifyRegistry(err)
		}
		man, err := img.Manifest()
		if err != nil {
			return nil, classifyRegistry(err)
		}
		for _, l := range man.Layers {
			if l.Annotations[buildkitPredicate] == "" || len(out) >= maxSignatures {
				continue
			}
			b, err := c.readLayer(img, l)
			if err != nil {
				return nil, err
			}
			r := Result{Envelope: EnvelopeBuildKitIndex, Payload: b, Reason: "BuildKit attestations carry no signature"}
			describePayload(&r)
			out = append(out, r)
		}
	}
	return out, nil
}

// readLayer reads one layer blob, bounded compressed and uncompressed.
func (c *config) readLayer(img v1.Image, l v1.Descriptor) ([]byte, error) {
	if l.Size > c.maxBlob {
		return nil, llx.MalformedData(fmt.Errorf("a signature layer is %d bytes, above the %d-byte bound", l.Size, c.maxBlob))
	}
	layer, err := img.LayerByDigest(l.Digest)
	if err != nil {
		return nil, classifyRegistry(err)
	}
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, classifyRegistry(err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, c.maxBlob+1))
	if err != nil {
		return nil, classifyRegistry(err)
	}
	if int64(len(b)) > c.maxBlob {
		return nil, llx.MalformedData(fmt.Errorf("a signature layer unpacks to more than the %d-byte bound", c.maxBlob))
	}
	return b, nil
}

// legacyLayer is one layer of a cosign .sig or .att image, converted to a
// Sigstore bundle v0.1 so it is verified by the same code as any bundle.
type legacyLayer struct {
	env  Envelope
	blob []byte
	ann  map[string]string
	// keyOnly is set when the layer names no certificate and its log entry
	// (if any) names no key.
	keyOnly bool
}

func (l legacyLayer) payloadOrNil() []byte {
	if l.env == EnvelopeCosignSignature {
		return l.blob
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(l.blob, &env) == nil {
		if b, err := b64(env.Payload); err == nil {
			return b
		}
	}
	return nil
}

// rekorAnnotation is cosign's bundle annotation.
type rekorAnnotation struct {
	SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logID"`
	} `json:"Payload"`
}

// build converts the layer. keyFP, for a key-only layer, is the configured
// key to try.
func (l *legacyLayer) build(keyFP string) (entity, error) {
	vm := &protobundle.VerificationMaterial{}
	e := entity{envelope: l.env, raw: append(append([]byte{}, l.blob...), []byte(fmt.Sprint(l.ann))...)}

	// The log entry, when there is one.
	var loggedKeyHint string
	if text := l.ann[cosignBundleAnnotation]; text != "" {
		var ra rekorAnnotation
		if err := json.Unmarshal([]byte(text), &ra); err != nil {
			return entity{}, fmt.Errorf("reading the transparency-log annotation: %w", err)
		}
		body, err := decodeB64("the log entry", ra.Payload.Body)
		if err != nil {
			return entity{}, err
		}
		set, err := decodeB64("the signed entry timestamp", ra.SignedEntryTimestamp)
		if err != nil {
			return entity{}, err
		}
		logID, err := hex.DecodeString(ra.Payload.LogID)
		if err != nil {
			return entity{}, fmt.Errorf("reading the log id: %w", err)
		}
		var kv struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
		}
		if err := json.Unmarshal(body, &kv); err != nil {
			return entity{}, fmt.Errorf("reading the log entry: %w", err)
		}
		vm.TlogEntries = []*protorekor.TransparencyLogEntry{{
			LogIndex:          ra.Payload.LogIndex,
			LogId:             &protocommon.LogId{KeyId: logID},
			KindVersion:       &protorekor.KindVersion{Kind: kv.Kind, Version: kv.APIVersion},
			IntegratedTime:    ra.Payload.IntegratedTime,
			InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
			CanonicalizedBody: body,
		}}
		e.tlogEntries = 1
		loggedKeyHint = loggedKey(body)
	}

	if certPEM := l.ann[cosignCertAnnotation]; certPEM != "" {
		certs := []*protocommon.X509Certificate{}
		for _, block := range pemCertificates([]byte(certPEM + "\n" + l.ann[cosignChainAnnotation])) {
			certs = append(certs, &protocommon.X509Certificate{RawBytes: block})
		}
		if len(certs) == 0 {
			return entity{}, errors.New("the certificate annotation holds no PEM certificate")
		}
		vm.Content = &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{Certificates: certs},
		}
	} else {
		hint := loggedKeyHint
		if hint == "" {
			hint = keyFP
			l.keyOnly = true
		}
		vm.Content = &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{Hint: hint}}
		e.keyHint = hint
	}

	pb := &protobundle.Bundle{MediaType: bundleV01MediaType, VerificationMaterial: vm}
	switch l.env {
	case EnvelopeCosignSignature:
		sig, err := decodeB64("the signature", l.ann[cosignSignatureAnnotation])
		if err != nil {
			return entity{}, err
		}
		if len(sig) == 0 {
			return entity{}, errors.New("the layer carries no signature")
		}
		sum := sha256.Sum256(l.blob)
		pb.Content = &protobundle.Bundle_MessageSignature{MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{Algorithm: protocommon.HashAlgorithm_SHA2_256, Digest: sum[:]},
			Signature:     sig,
		}}
		e.payload = l.blob
	case EnvelopeCosignAttestation:
		var env struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(l.blob, &env); err != nil {
			return entity{}, fmt.Errorf("reading the DSSE envelope: %w", err)
		}
		payload, err := b64(env.Payload)
		if err != nil {
			return entity{}, fmt.Errorf("reading the DSSE payload: %w", err)
		}
		de := &protodsse.Envelope{Payload: payload, PayloadType: env.PayloadType}
		for _, s := range env.Signatures {
			sig, err := b64(s.Sig)
			if err != nil {
				return entity{}, fmt.Errorf("reading a DSSE signature: %w", err)
			}
			de.Signatures = append(de.Signatures, &protodsse.Signature{Sig: sig, Keyid: s.KeyID})
		}
		if len(de.Signatures) != 1 {
			return entity{}, fmt.Errorf("the DSSE envelope has %d signatures; exactly one is read", len(de.Signatures))
		}
		pb.Content = &protobundle.Bundle_DsseEnvelope{DsseEnvelope: de}
		e.payload = payload
	default:
		return entity{}, fmt.Errorf("unknown layout %s", l.env)
	}
	bun, err := bundle.NewBundle(pb)
	if err != nil {
		return entity{}, fmt.Errorf("reading the signature as a bundle: %w", err)
	}
	e.signed = bun
	ll := *l
	e.legacy = &ll
	return e, nil
}

// loggedKey is the fingerprint of the public key a Rekor v1 entry records,
// or "" when it records a certificate or nothing readable.
func loggedKey(body []byte) string {
	var entry struct {
		Spec struct {
			Signature struct {
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
			Signatures []struct {
				Verifier string `json:"verifier"`
			} `json:"signatures"`
		} `json:"spec"`
	}
	if json.Unmarshal(body, &entry) != nil {
		return ""
	}
	candidates := []string{entry.Spec.Signature.PublicKey.Content}
	for _, s := range entry.Spec.Signatures {
		candidates = append(candidates, s.Verifier)
	}
	for _, cand := range candidates {
		raw, err := b64(cand)
		if err != nil || len(raw) == 0 {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PUBLIC KEY" {
			continue
		}
		return Fingerprint(block.Bytes)
	}
	return ""
}

// pemCertificates returns the DER of each PEM certificate.
func pemCertificates(b []byte) [][]byte {
	var out [][]byte
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
}
