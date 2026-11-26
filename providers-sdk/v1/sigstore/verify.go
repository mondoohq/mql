// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Option configures a verification.
type Option func(*config) error

type config struct {
	trust     *TrustRoot
	trustOpts *TrustOptions
	keys      map[string]crypto.PublicKey
	remote    []remote.Option
	index     *name.Digest
	cache     *Cache
	maxBlob   int64

	modelRoot    string
	modelBound   int64
	modelSigFile string
}

// WithTrustRoot verifies against a trust root loaded with LoadTrustRoot.
func WithTrustRoot(tr *TrustRoot) Option {
	return func(c *config) error {
		if tr == nil {
			return errors.New("nil trust root")
		}
		c.trust = tr
		return nil
	}
}

// WithTrustOptions loads the trust root with these options instead of the
// defaults (the public-good TUF repository, cached under the user's cache
// directory).
func WithTrustOptions(o TrustOptions) Option {
	return func(c *config) error {
		c.trustOpts = &o
		return nil
	}
}

// WithKeys adds public keys (concatenated PEM blocks) a key signature may be
// verified with. The keys of a policy's key signers are always added.
func WithKeys(pemKeys []byte) Option {
	return func(c *config) error {
		keys, err := LoadPublicKeys(pemKeys)
		if err != nil {
			return err
		}
		for fp, k := range keys {
			c.keys[fp] = k
		}
		return nil
	}
}

// WithRemoteOptions passes registry options (credentials, transport) to
// every registry call.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(c *config) error {
		c.remote = append(c.remote, opts...)
		return nil
	}
}

// WithIndex names the image index the platform manifest was resolved from,
// so the BuildKit attestation manifests it lists are read too. The index
// digest is never a subject.
func WithIndex(index name.Digest) Option {
	return func(c *config) error {
		c.index = &index
		return nil
	}
}

// WithCache reuses verifications across calls. Only validity and identity
// are cached; acceptance is evaluated on every call against that call's
// policy.
func WithCache(cache *Cache) Option {
	return func(c *config) error {
		c.cache = cache
		return nil
	}
}

func newConfig(p Policy, opts []Option) (*config, error) {
	c := &config{keys: map[string]crypto.PublicKey{}, maxBlob: 64 << 20}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	for fp, k := range p.keys() {
		c.keys[fp] = k
	}
	return c, nil
}

var (
	defaultRootMu sync.Mutex
	defaultRoot   *TrustRoot
)

// trustRoot returns the configured trust root, loading the default one once
// per process. A failed load is not remembered, so the next call retries.
func (c *config) trustRoot(ctx context.Context) (*TrustRoot, error) {
	if c.trust != nil {
		return c.trust, nil
	}
	if c.trustOpts != nil {
		tr, err := LoadTrustRoot(ctx, *c.trustOpts)
		if err != nil {
			return nil, err
		}
		c.trust = tr
		return tr, nil
	}
	defaultRootMu.Lock()
	defer defaultRootMu.Unlock()
	if defaultRoot != nil && !defaultRoot.expired(time.Now()) {
		c.trust = defaultRoot
		return defaultRoot, nil
	}
	tr, err := LoadTrustRoot(ctx, DefaultTrustOptions())
	if err != nil {
		return nil, err
	}
	defaultRoot, c.trust = tr, tr
	return tr, nil
}

// keyMaterial is the configured keys as trusted material, looked up by a
// bundle's public key hint in any of the fingerprint forms.
func (c *config) keyMaterial() root.TrustedMaterial {
	return root.NewTrustedPublicKeyMaterial(func(hint string) (root.TimeConstrainedVerifier, error) {
		fp := normalizeFingerprint(hint)
		pub, ok := c.keys[fp]
		if !ok {
			return nil, fmt.Errorf("the key %q is not a configured key", hint)
		}
		v, err := signature.LoadVerifier(pub, hashFor(pub))
		if err != nil {
			return nil, err
		}
		return root.NewExpiringKey(v, time.Time{}, time.Time{}), nil
	})
}

// keySetID names the configured key set, for cache keys.
func (c *config) keySetID() string {
	fps := make([]string, 0, len(c.keys))
	for fp := range c.keys {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	return strings.Join(fps, ",")
}

// hashFor is the hash a key signs with, as cosign signs.
func hashFor(pub crypto.PublicKey) crypto.Hash {
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		switch k.Curve {
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		}
	}
	return crypto.SHA256
}

// subject is what a signature must be bound to.
type subject struct {
	// digest is "sha256:<hex>" for a DSSE subject or a message digest.
	digest string
	// artifact, when set, is the signed bytes of a message signature.
	artifact []byte
}

func (s subject) policy() (verify.ArtifactPolicyOption, error) {
	if s.artifact != nil {
		return verify.WithArtifact(strings.NewReader(string(s.artifact))), nil
	}
	alg, hexDigest, ok := strings.Cut(s.digest, ":")
	if !ok {
		return nil, fmt.Errorf("digest %q has no algorithm", s.digest)
	}
	b, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("digest %q: %w", s.digest, err)
	}
	return verify.WithArtifactDigest(alg, b), nil
}

// entity is a signed entity with what is needed to report on it.
type entity struct {
	signed   verify.SignedEntity
	envelope Envelope
	// payload is the DSSE payload or simple-signing document.
	payload []byte
	// raw identifies the entity for the cache.
	raw []byte
	// keyHint is the public key hint, for a key signature.
	keyHint string
	// tlogEntries is the number of transparency-log entries it carries.
	tlogEntries int
	// malformed, when set, is why the entity could not be read; it is
	// reported as an invalid signature.
	malformed string
	// legacy is the cosign layer it was converted from.
	legacy *legacyLayer
}

// verifyEntity checks one signed entity against the trust root, bound to
// subj, and reports validity and identity. Acceptance is left to the caller.
// A verification that cannot run returns an error.
func (c *config) verifyEntity(ctx context.Context, e entity, subj subject) (Result, error) {
	tr, err := c.trustRoot(ctx)
	if err != nil {
		return Result{}, err
	}
	cacheKey := ""
	if c.cache != nil {
		h := sha256.New()
		for _, part := range [][]byte{[]byte(tr.ID), []byte(c.keySetID()), []byte(subj.digest), subj.artifact, []byte(e.envelope), e.raw} {
			h.Write([]byte(strconv.Itoa(len(part))))
			h.Write([]byte{0})
			h.Write(part)
		}
		cacheKey = hex.EncodeToString(h.Sum(nil))
		if r, ok := c.cache.get(cacheKey); ok {
			return r, nil
		}
	}

	r := Result{Envelope: e.envelope, Payload: e.payload}
	describePayload(&r)
	if e.malformed != "" || e.signed == nil {
		r.Reason = "the signature does not parse: " + e.malformed
		return r, nil
	}

	tm := root.TrustedMaterialCollection{tr.Material, c.keyMaterial()}
	strictOpts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if len(tr.Material.CTLogs()) > 0 {
		strictOpts = append(strictOpts, verify.WithSignedCertificateTimestamps(1))
	}
	strict, err := verify.NewVerifier(tm, strictOpts...)
	if err != nil {
		return Result{}, err
	}
	artifactPolicy, err := subj.policy()
	if err != nil {
		return Result{}, err
	}
	// Identities are matched by Policy.Accepts after verification, with
	// anchored patterns, so validity is reported under any policy.
	res, verr := strict.Verify(e.signed, verify.NewPolicy(artifactPolicy, verify.WithoutIdentitiesUnsafe()))
	logged := verr == nil

	if verr != nil && e.keyHint != "" && e.tlogEntries == 0 {
		// A key signature with no log entry: valid when the key is a
		// configured one; acceptance then requires the signer to opt out of
		// the log requirement.
		relaxed, err := verify.NewVerifier(tm, verify.WithNoObserverTimestamps())
		if err != nil {
			return Result{}, err
		}
		if res2, err2 := relaxed.Verify(e.signed, verify.NewPolicy(artifactPolicy, verify.WithoutIdentitiesUnsafe())); err2 == nil {
			res, verr = res2, nil
		}
	}

	if verr != nil {
		r.Reason = verr.Error()
		if subj.digest != "" || subj.artifact != nil {
			// Does the signature verify over its own payload? Then it is a
			// valid signature over another subject.
			opts := strictOpts
			if e.keyHint != "" && e.tlogEntries == 0 {
				opts = []verify.VerifierOption{verify.WithNoObserverTimestamps()}
			}
			own := verify.WithoutArtifactUnsafe()
			if sc, err := e.signed.SignatureContent(); err == nil && sc.MessageSignatureContent() != nil {
				// A message signature verifies only over a digest: its own.
				msg := sc.MessageSignatureContent()
				own = verify.WithArtifactDigest(msg.DigestAlgorithm(), msg.Digest())
			}
			if v, err := verify.NewVerifier(tm, opts...); err == nil {
				if _, err := v.Verify(e.signed, verify.NewPolicy(own, verify.WithoutIdentitiesUnsafe())); err == nil {
					r.SubjectMismatch = true
					r.Reason = "the signature covers another subject than " + subj.digest
				}
			}
		}
		r.clearIdentity()
		c.cache.put(cacheKey, r)
		return r, nil
	}

	r.SignatureValid = true
	r.TransparencyLogged = logged && e.tlogEntries > 0
	if res.Signature != nil && res.Signature.Certificate != nil {
		cert := res.Signature.Certificate
		r.SignerKind = SignerKeyless
		r.Issuer = cert.Issuer
		r.SAN = cert.SubjectAlternativeName
		r.SignerRepository = cert.SourceRepositoryURI
		r.SignerWorkflowRef = cert.BuildSignerURI
	} else {
		r.SignerKind = SignerKey
		r.KeyFingerprint = normalizeFingerprint(e.keyHint)
	}
	for _, ts := range res.VerifiedTimestamps {
		if r.SignedAt.IsZero() || ts.Timestamp.Before(r.SignedAt) {
			r.SignedAt = ts.Timestamp
		}
	}
	c.cache.put(cacheKey, r)
	return r, nil
}

// statement is the part of an in-toto statement this reads.
type statement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []statementSubj `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type statementSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// describePayload fills the payload-derived fields of r: subjects, predicate
// type and, for SLSA provenance, builder, source and materials.
func describePayload(r *Result) {
	if len(r.Payload) == 0 {
		return
	}
	var st statement
	if json.Unmarshal(r.Payload, &st) == nil && st.PredicateType != "" {
		r.PredicateType = st.PredicateType
		for _, s := range st.Subject {
			r.SubjectDigests = append(r.SubjectDigests, digestStrings(s.Digest)...)
		}
		describeProvenance(r, st.PredicateType, st.Predicate)
		return
	}
	// A cosign simple-signing document names the image digest it signs.
	var ss simpleSigning
	if json.Unmarshal(r.Payload, &ss) == nil && ss.Critical.Image.DockerManifestDigest != "" {
		r.SubjectDigests = []string{ss.Critical.Image.DockerManifestDigest}
	}
}

func digestStrings(m map[string]string) []string {
	var out []string
	for alg, v := range m {
		out = append(out, alg+":"+strings.ToLower(v))
	}
	sort.Strings(out)
	return out
}

// simpleSigning is cosign's signature payload.
type simpleSigning struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// describeProvenance reads SLSA provenance v0.2 and v1 and verification
// summary attestations.
func describeProvenance(r *Result, predicateType string, raw json.RawMessage) {
	switch predicateType {
	case "https://slsa.dev/provenance/v0.2":
		var p struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			BuildType  string `json:"buildType"`
			Invocation struct {
				ConfigSource struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"configSource"`
			} `json:"invocation"`
			Materials []Material `json:"materials"`
		}
		if json.Unmarshal(raw, &p) != nil {
			return
		}
		r.BuilderID, r.BuildType, r.Materials = p.Builder.ID, p.BuildType, p.Materials
		r.SourceRepository = p.Invocation.ConfigSource.URI
		r.SourceRevision = commitOf(p.Invocation.ConfigSource.Digest)
	case "https://slsa.dev/provenance/v1":
		var p struct {
			BuildDefinition struct {
				BuildType          string `json:"buildType"`
				ExternalParameters struct {
					Workflow struct {
						Repository string `json:"repository"`
					} `json:"workflow"`
				} `json:"externalParameters"`
				ResolvedDependencies []Material `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		}
		if json.Unmarshal(raw, &p) != nil {
			return
		}
		r.BuilderID, r.BuildType = p.RunDetails.Builder.ID, p.BuildDefinition.BuildType
		r.Materials = p.BuildDefinition.ResolvedDependencies
		r.SourceRepository = p.BuildDefinition.ExternalParameters.Workflow.Repository
		for _, m := range r.Materials {
			uri := strings.TrimPrefix(m.URI, "git+")
			if r.SourceRepository != "" && strings.HasPrefix(uri, r.SourceRepository) {
				r.SourceRevision = commitOf(m.Digest)
				break
			}
		}
	case "https://slsa.dev/verification_summary/v1":
		var p struct {
			VerificationResult string   `json:"verificationResult"`
			VerifiedLevels     []string `json:"verifiedLevels"`
		}
		if json.Unmarshal(raw, &p) != nil || p.VerificationResult != "PASSED" {
			return
		}
		for _, l := range p.VerifiedLevels {
			if n, ok := strings.CutPrefix(l, "SLSA_BUILD_LEVEL_"); ok {
				if v, err := strconv.Atoi(n); err == nil && v > r.SLSABuildLevel {
					r.SLSABuildLevel = v
				}
			}
		}
	}
}

func commitOf(d map[string]string) string {
	for _, k := range []string{"gitCommit", "sha1", "sha256"} {
		if v := d[k]; v != "" {
			return v
		}
	}
	return ""
}

// Cache holds verification outcomes (validity and identity, never
// acceptance) keyed by trust root, key set, subject and the signed bytes. It
// is safe for concurrent use. Errors are never cached.
type Cache struct {
	mu sync.Mutex
	m  map[string]Result
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{m: map[string]Result{}} }

func (c *Cache) get(key string) (Result, bool) {
	if c == nil || key == "" {
		return Result{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[key]
	if ok {
		r.SubjectDigests = slices.Clone(r.SubjectDigests)
		r.Materials = slices.Clone(r.Materials)
	}
	return r, ok
}

func (c *Cache) put(key string, r Result) {
	if c == nil || key == "" {
		return
	}
	// Acceptance is per call, never cached.
	r.Accepted, r.Verified = false, false
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = r
}

// b64 decodes standard base64, tolerating missing padding.
func b64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
