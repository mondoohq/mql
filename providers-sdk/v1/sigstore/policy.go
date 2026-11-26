// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"crypto"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// GitHubActionsIssuer is the OIDC issuer of GitHub Actions workload tokens.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// Signer is one signer a Policy accepts: a keyless identity (an issuer and a
// subject alternative name, optionally narrowed to a source repository and a
// workflow) or a public key.
//
// Every pattern is anchored: SANRegexp, IssuerRegexp, Repository and
// WorkflowRef must match the whole value, never a part of it. To match one
// value exactly, use ExactKeyless, which quotes it.
type Signer struct {
	// Issuer is the OIDC issuer, compared exactly. Either Issuer or
	// IssuerRegexp is set for a keyless signer.
	Issuer string
	// IssuerRegexp is an anchored regular expression over the issuer.
	IssuerRegexp string
	// SANRegexp is an anchored regular expression over the certificate's
	// subject alternative name.
	SANRegexp string
	// Repository is an anchored regular expression over the source repository
	// URI the signing workflow ran in. Empty matches any.
	Repository string
	// WorkflowRef is an anchored regular expression over the workflow identity
	// that signed (Fulcio's build signer URI). Empty matches any.
	WorkflowRef string

	// PublicKey is a PEM public key: a key signer. Fingerprint is filled from
	// it, or set alone when the key is supplied to the verifier separately.
	PublicKey   string
	Fingerprint string
	// RequireTlog, for a key signer, requires a verified transparency-log
	// entry. Nil means true.
	RequireTlog *bool

	// Name is how the signer was written, for messages.
	Name string

	san, issuer, repo, workflow *regexp.Regexp
	key                         crypto.PublicKey
	compiled                    bool
}

// Policy is the list of signers a verification accepts. The zero Policy
// accepts no signer.
type Policy struct {
	Accept []Signer
	// NotBefore, when set, refuses a signature whose verified timestamp is
	// older, or that has none: an older signature replayed in place of a
	// newer one (a downgrade) is not accepted.
	NotBefore time.Time
	// Digests, when set, are the only subject digests accepted ("sha256:<hex>"):
	// a pin against a downgrade to another, older, validly signed artifact.
	Digests []string
}

// ExactKeyless is a keyless signer that matches one issuer and one identity
// exactly, with regular-expression metacharacters in either quoted.
func ExactKeyless(issuer, identity string) Signer {
	return Signer{
		Name:      identity + " (issuer " + issuer + ")",
		Issuer:    issuer,
		SANRegexp: regexp.QuoteMeta(identity),
	}
}

// KeySigner is a signer that accepts signatures by one public key.
func KeySigner(pemKey string) (Signer, error) {
	s := Signer{PublicKey: pemKey}
	if err := s.compile(); err != nil {
		return Signer{}, err
	}
	s.Name = "key " + s.Fingerprint
	return s, nil
}

// NewPolicy checks and compiles every signer.
func NewPolicy(signers ...Signer) (Policy, error) {
	p := Policy{}
	for _, s := range signers {
		if err := s.compile(); err != nil {
			return Policy{}, err
		}
		p.Accept = append(p.Accept, s)
	}
	return p, nil
}

// anchored compiles a pattern that must match a whole value.
func anchored(field, pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(`^(?:` + pattern + `)$`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return re, nil
}

// matchesAnything reports whether a pattern accepts arbitrary values, which
// as a signer pattern would accept any identity.
func matchesAnything(re *regexp.Regexp) bool {
	for _, probe := range []string{"x", "Z9", "https://attacker.invalid/a/b//c@refs/heads/x", "attacker@invalid.example"} {
		if !re.MatchString(probe) {
			return false
		}
	}
	return true
}

func (s *Signer) compile() error {
	if s.compiled {
		return nil
	}
	var err error
	if s.PublicKey != "" || s.Fingerprint != "" {
		if s.Issuer != "" || s.IssuerRegexp != "" || s.SANRegexp != "" || s.Repository != "" || s.WorkflowRef != "" {
			return fmt.Errorf("signer %q: a signer is either a key or a keyless identity, not both", s.Name)
		}
		if s.PublicKey != "" {
			var fp string
			if s.key, fp, err = LoadPublicKey([]byte(s.PublicKey)); err != nil {
				return fmt.Errorf("signer %q: %w", s.Name, err)
			}
			if s.Fingerprint != "" && normalizeFingerprint(s.Fingerprint) != fp {
				return fmt.Errorf("signer %q: the fingerprint does not match the public key", s.Name)
			}
			s.Fingerprint = fp
		} else if s.Fingerprint = normalizeFingerprint(s.Fingerprint); s.Fingerprint == "" {
			return fmt.Errorf("signer %q: not a sha256 key fingerprint", s.Name)
		}
		s.compiled = true
		return nil
	}
	if (s.Issuer == "") == (s.IssuerRegexp == "") {
		return fmt.Errorf("signer %q: a keyless signer needs exactly one of issuer and issuer pattern", s.Name)
	}
	if s.SANRegexp == "" {
		return fmt.Errorf("signer %q: a keyless signer needs a subject pattern", s.Name)
	}
	if s.RequireTlog != nil {
		return fmt.Errorf("signer %q: the transparency-log requirement applies to key signers only", s.Name)
	}
	if s.IssuerRegexp != "" {
		if s.issuer, err = anchored("issuer pattern", s.IssuerRegexp); err != nil {
			return err
		}
		if matchesAnything(s.issuer) {
			return fmt.Errorf("signer %q: the issuer pattern accepts any issuer", s.Name)
		}
	}
	if s.san, err = anchored("subject pattern", s.SANRegexp); err != nil {
		return err
	}
	if matchesAnything(s.san) {
		return fmt.Errorf("signer %q: the subject pattern accepts any identity", s.Name)
	}
	if s.Repository != "" {
		if s.repo, err = anchored("repository pattern", s.Repository); err != nil {
			return err
		}
	}
	if s.WorkflowRef != "" {
		if s.workflow, err = anchored("workflow pattern", s.WorkflowRef); err != nil {
			return err
		}
	}
	s.compiled = true
	return nil
}

// requireTlog is whether a key signer needs a transparency-log entry.
func (s Signer) requireTlog() bool {
	return s.RequireTlog == nil || *s.RequireTlog
}

// matches reports whether the signer is the one that produced r. r must be
// valid; the caller checks.
func (s Signer) matches(r Result) bool {
	if !s.compiled {
		if err := s.compile(); err != nil {
			return false
		}
	}
	if s.Fingerprint != "" {
		if r.SignerKind != SignerKey || r.KeyFingerprint != s.Fingerprint {
			return false
		}
		return r.TransparencyLogged || !s.requireTlog()
	}
	if r.SignerKind != SignerKeyless {
		return false
	}
	if s.Issuer != "" && r.Issuer != s.Issuer {
		return false
	}
	if s.issuer != nil && !s.issuer.MatchString(r.Issuer) {
		return false
	}
	if !s.san.MatchString(r.SAN) {
		return false
	}
	if s.repo != nil && !s.repo.MatchString(r.SignerRepository) {
		return false
	}
	if s.workflow != nil && !s.workflow.MatchString(r.SignerWorkflowRef) {
		return false
	}
	return true
}

// Accepts reports whether the policy accepts the signer of r. It is a pure
// function of r's validity and identity fields, so a caller that holds a
// policy elsewhere reaches the same answer. An invalid result, and any result
// under an empty policy, is never accepted.
func (p Policy) Accepts(r Result) bool {
	if !r.SignatureValid || len(p.Accept) == 0 {
		return false
	}
	if !p.NotBefore.IsZero() && (r.SignedAt.IsZero() || r.SignedAt.Before(p.NotBefore)) {
		return false
	}
	if len(p.Digests) > 0 {
		pinned := false
		for _, d := range p.Digests {
			if r.CoversDigest(d) {
				pinned = true
				break
			}
		}
		if !pinned {
			return false
		}
	}
	for _, s := range p.Accept {
		if s.matches(r) {
			return true
		}
	}
	return false
}

// apply sets Accepted and Verified on r from the policy.
func (p Policy) apply(r *Result) {
	r.Accepted = p.Accepts(*r)
	r.Verified = r.SignatureValid && r.Accepted
}

// keys returns the public keys of the policy's key signers that carry a PEM.
func (p Policy) keys() map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for _, s := range p.Accept {
		if !s.compiled {
			if s.compile() != nil {
				continue
			}
		}
		if s.key != nil {
			out[s.Fingerprint] = s.key
		}
	}
	return out
}

// ParseSigners reads a comma-separated list of signers:
//
//   - github-actions:<owner>/<repo-glob>[@<workflow-glob>]: keyless, issued
//     to a GitHub Actions workflow of a repository of owner. The workflow
//     glob matches the workflow path and ref, as in
//     "github-actions:acme/*@.github/workflows/release.yml@refs/tags/*".
//   - gitlab-ci:[<host>/]<group>/<project-glob>: keyless, issued to a GitLab
//     CI job of those projects; the host defaults to gitlab.com.
//   - oidc:<issuer>|<subject-regexp>: keyless, an exact issuer and an
//     anchored subject pattern.
//   - key:<sha256-fingerprint>: a public key, found in keys (concatenated PEM
//     blocks) or supplied to the verifier.
//
// A glob's "*" matches within one path segment. The owner, group and host
// are literal: a signer list cannot accept every owner.
func ParseSigners(s string, keys ...[]byte) (Policy, error) {
	var pems map[string]string
	if len(keys) > 0 {
		pems = map[string]string{}
		for _, k := range keys {
			parsed, err := splitPEMKeys(k)
			if err != nil {
				return Policy{}, err
			}
			for fp, pemKey := range parsed {
				pems[fp] = pemKey
			}
		}
	}
	var signers []Signer
	for _, item := range splitSigners(s) {
		signer, err := parseSigner(item, pems)
		if err != nil {
			return Policy{}, err
		}
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		return Policy{}, errors.New("no signer given")
	}
	return NewPolicy(signers...)
}

var signerPrefixes = []string{"github-actions:", "gitlab-ci:", "oidc:", "key:"}

// splitSigners splits on commas that start a new signer, so a subject
// pattern may itself hold a comma.
func splitSigners(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != ',' {
			continue
		}
		rest := strings.TrimLeft(s[i+1:], " ")
		for _, p := range signerPrefixes {
			if strings.HasPrefix(rest, p) {
				out = append(out, s[start:i])
				start = i + 1
				break
			}
		}
	}
	out = append(out, s[start:])
	var trimmed []string
	for _, item := range out {
		if item = strings.TrimSpace(item); item != "" {
			trimmed = append(trimmed, item)
		}
	}
	return trimmed
}

func parseSigner(item string, pems map[string]string) (Signer, error) {
	kind, rest, ok := strings.Cut(item, ":")
	if !ok {
		return Signer{}, fmt.Errorf("signer %q: want <kind>:<value>", item)
	}
	switch kind {
	case "github-actions":
		return githubSigner(item, rest)
	case "gitlab-ci":
		return gitlabSigner(item, rest)
	case "oidc":
		issuer, san, ok := strings.Cut(rest, "|")
		if !ok || issuer == "" || san == "" {
			return Signer{}, fmt.Errorf("signer %q: want oidc:<issuer>|<subject-regexp>", item)
		}
		return Signer{Name: item, Issuer: issuer, SANRegexp: san}, nil
	case "key":
		fp := normalizeFingerprint(rest)
		if fp == "" {
			return Signer{}, fmt.Errorf("signer %q: not a sha256 key fingerprint", item)
		}
		return Signer{Name: item, Fingerprint: fp, PublicKey: pems[fp]}, nil
	}
	return Signer{}, fmt.Errorf("signer %q: unknown kind %q", item, kind)
}

// splitPEMKeys reads concatenated PEM keys into their fingerprints.
func splitPEMKeys(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, block := range pemBlocks(b) {
		_, fp, err := LoadPublicKey([]byte(block))
		if err != nil {
			return nil, err
		}
		out[fp] = block
	}
	return out, nil
}

// segmentGlob turns a glob of one path segment into a regular expression:
// "*" matches any run of characters other than "/".
func segmentGlob(field, glob string) (string, error) {
	if glob == "" {
		return "", fmt.Errorf("%s is empty", field)
	}
	if strings.ContainsAny(glob, "/") {
		return "", fmt.Errorf("%s %q spans more than one path segment", field, glob)
	}
	if strings.ContainsAny(glob, `^$+?()[]{}|\`) {
		return "", fmt.Errorf("%s %q is a regular expression, not a glob", field, glob)
	}
	// "*" alone is every repository of the owner, which owner/* says
	// explicitly. A glob of nothing but dots and stars (".*", "**") is a
	// regular expression written as a glob and is refused.
	if glob != "*" && strings.Trim(glob, "*.") == "" {
		return "", fmt.Errorf("%s %q is not a glob", field, glob)
	}
	parts := strings.Split(glob, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return strings.Join(parts, `[^/]*`), nil
}

// pathGlob is segmentGlob over a path: each segment is a glob.
func pathGlob(field, glob string) (string, error) {
	segs := strings.Split(glob, "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		re, err := segmentGlob(field, seg)
		if err != nil {
			return "", err
		}
		segs[i] = re
	}
	return strings.Join(segs, "/"), nil
}

// literalSegment checks a segment that must be written out.
func literalSegment(field, seg string) error {
	if seg == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if strings.ContainsAny(seg, "*?[]{}()|\\^$+ ") {
		return fmt.Errorf("%s %q must be literal", field, seg)
	}
	return nil
}

func githubSigner(item, rest string) (Signer, error) {
	repoPart, workflowPart, hasWorkflow := strings.Cut(rest, "@")
	owner, repoGlob, ok := strings.Cut(repoPart, "/")
	if !ok {
		return Signer{}, fmt.Errorf("signer %q: want github-actions:<owner>/<repo-glob>", item)
	}
	if err := literalSegment("owner", owner); err != nil {
		return Signer{}, fmt.Errorf("signer %q: %w", item, err)
	}
	repoRE, err := segmentGlob("repository glob", repoGlob)
	if err != nil {
		return Signer{}, fmt.Errorf("signer %q: %w", item, err)
	}
	prefix := `https://github\.com/` + regexp.QuoteMeta(owner) + `/` + repoRE
	s := Signer{
		Name:       item,
		Issuer:     GitHubActionsIssuer,
		SANRegexp:  prefix + `/\.github/workflows/[^@]+@refs/.+`,
		Repository: prefix,
	}
	if hasWorkflow {
		wf, ref, ok := strings.Cut(workflowPart, "@")
		if !ok || wf == "" || ref == "" {
			return Signer{}, fmt.Errorf("signer %q: want @<workflow-path>@<ref-glob>", item)
		}
		wfRE, err := pathGlob("workflow glob", wf)
		if err != nil {
			return Signer{}, fmt.Errorf("signer %q: %w", item, err)
		}
		refRE, err := pathGlob("ref glob", ref)
		if err != nil {
			return Signer{}, fmt.Errorf("signer %q: %w", item, err)
		}
		// The workflow that signed may be a reusable workflow in another
		// repository of the owner; the pin is on its path and ref.
		s.WorkflowRef = `https://github\.com/` + regexp.QuoteMeta(owner) + `/[^/]+/` + wfRE + `@` + refRE
		s.SANRegexp = s.WorkflowRef
	}
	return s, nil
}

// gitlabSigner expands gitlab-ci:[<host>/]<group>/<project-glob> to GitLab's
// ID-token identity: issuer https://<host>, and a subject that is the CI
// config ref URI, https://<host>/<group>/<project>//<config path>@refs/...
func gitlabSigner(item, rest string) (Signer, error) {
	segs := strings.Split(rest, "/")
	host := "gitlab.com"
	if len(segs) > 0 && strings.Contains(segs[0], ".") {
		host, segs = segs[0], segs[1:]
	}
	if len(segs) < 2 {
		return Signer{}, fmt.Errorf("signer %q: want gitlab-ci:[<host>/]<group>/<project-glob>", item)
	}
	if err := literalSegment("host", host); err != nil {
		return Signer{}, fmt.Errorf("signer %q: %w", item, err)
	}
	group := segs[:len(segs)-1]
	for _, g := range group {
		if err := literalSegment("group", g); err != nil {
			return Signer{}, fmt.Errorf("signer %q: %w", item, err)
		}
	}
	projectRE, err := segmentGlob("project glob", segs[len(segs)-1])
	if err != nil {
		return Signer{}, fmt.Errorf("signer %q: %w", item, err)
	}
	base := `https://` + regexp.QuoteMeta(host) + `/` + regexp.QuoteMeta(strings.Join(group, "/")) + `/` + projectRE
	return Signer{
		Name:      item,
		Issuer:    "https://" + host,
		SANRegexp: base + `//.+@refs/.+`,
	}, nil
}
