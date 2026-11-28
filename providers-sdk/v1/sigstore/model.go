// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sigstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"golang.org/x/crypto/blake2b"
)

// The OpenSSF model signing predicate types.
const (
	ModelSigningV1Predicate  = "https://model_signing/signature/v1.0"
	ModelSigningV01Predicate = "https://model_signing/Digests/v0.1"

	// ModelSignatureFile is the default name of a model's signature bundle.
	ModelSignatureFile = "model.sig"
)

// ModelStatus is the outcome of a model signature verification.
type ModelStatus string

const (
	// ModelVerified: the signature is valid and every signed file matches. It
	// never means the signer is accepted; that is Policy.Accepts.
	ModelVerified ModelStatus = "verified"
	// ModelInvalid: the signature does not verify, a signed file differs, a
	// signed path is unsafe, or an unsigned file is a weight or code file.
	ModelInvalid ModelStatus = "invalid"
	// ModelUnverifiable: the signer's key or certificate is not trusted here,
	// or the signature format or predicate is not one this reads.
	ModelUnverifiable ModelStatus = "unverifiable"
	// ModelIncomplete: signed files are missing, or the byte bound was
	// reached.
	ModelIncomplete ModelStatus = "incomplete"
)

// DefaultModelByteBound is how much of one model is hashed at most.
const DefaultModelByteBound int64 = 16 << 30

// ModelResult is the outcome of VerifyModel. The embedded Result carries the
// signature's validity and, when valid, the signer identity, so a caller with
// a policy calls Policy.Accepts on it.
type ModelResult struct {
	Result
	Status ModelStatus
	// ManifestDigest is the statement's subject digest, "sha256:<hex>": what
	// a policy pins to refuse a downgrade to an older signed release.
	ManifestDigest  string
	MissingFiles    []string
	MismatchedFiles []string
	// ExtraFiles are files in the directory the signature does not cover and
	// does not ignore. A weight or code file among them makes the status
	// invalid; others are listed only.
	ExtraFiles  []string
	BytesHashed int64
}

// WithModelRoot is the directory a model's symlinks may resolve into, such
// as a Hugging Face cache root whose snapshots link into its blob store. The
// default is the model directory itself.
func WithModelRoot(root string) Option {
	return func(c *config) error {
		c.modelRoot = root
		return nil
	}
}

// WithModelByteBound bounds the bytes hashed for one model.
func WithModelByteBound(n int64) Option {
	return func(c *config) error {
		if n <= 0 {
			return errors.New("the byte bound must be positive")
		}
		c.modelBound = n
		return nil
	}
}

// WithModelSignatureFile names the bundle file inside the directory, so it is
// not reported as an extra file. The default is model.sig.
func WithModelSignatureFile(name string) Option {
	return func(c *config) error {
		c.modelSigFile = name
		return nil
	}
}

// modelResource is one signed file.
type modelResource struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// defaultModelIgnores are the paths the reference signer ignores by default.
var defaultModelIgnores = []string{ModelSignatureFile, ".git", ".gitattributes", ".github", ".gitignore"}

// VerifyModel verifies an OpenSSF model signature (a Sigstore bundle holding
// a DSSE envelope around the model signing in-toto statement) over the model
// directory dir of fsys, and hashes every signed file. It takes no policy: a
// caller with one calls Policy.Accepts on the result.
//
// A bundle that does not parse is MalformedData; a signed file the scan may
// not read is Forbidden; a trust root that cannot be loaded is an error. None
// of them is a status.
func VerifyModel(ctx context.Context, fsys afero.Fs, dir string, bundleJSON []byte, opts ...Option) (ModelResult, error) {
	c, err := newConfig(Policy{}, opts)
	if err != nil {
		return ModelResult{}, err
	}
	if c.modelBound == 0 {
		c.modelBound = DefaultModelByteBound
	}
	if c.modelRoot == "" {
		c.modelRoot = dir
	}
	if c.modelSigFile == "" {
		c.modelSigFile = ModelSignatureFile
	}
	e, err := parseBundle(bundleJSON, EnvelopeSigstoreBundle)
	if err != nil {
		return ModelResult{}, llx.MalformedData(err)
	}
	out := ModelResult{}
	if len(e.payload) == 0 {
		out.Status, out.Reason = ModelUnverifiable, "the bundle holds no DSSE envelope, so it is not a model signature"
		return out, nil
	}
	var st statement
	if err := json.Unmarshal(e.payload, &st); err != nil {
		return ModelResult{}, llx.MalformedData(fmt.Errorf("reading the model signature statement: %w", err))
	}
	out.PredicateType = st.PredicateType
	var resources []modelResource
	ignores := append([]string{}, defaultModelIgnores...)
	switch st.PredicateType {
	case ModelSigningV1Predicate:
		var p struct {
			Resources     []modelResource `json:"resources"`
			Serialization struct {
				Method      string   `json:"method"`
				IgnorePaths []string `json:"ignore_paths"`
			} `json:"serialization"`
		}
		if err := json.Unmarshal(st.Predicate, &p); err != nil {
			return ModelResult{}, llx.MalformedData(fmt.Errorf("reading the model signing predicate: %w", err))
		}
		if p.Serialization.Method != "" && p.Serialization.Method != "files" {
			out.Status, out.Reason = ModelUnverifiable, fmt.Sprintf("serialization method %q is not read; only files is", p.Serialization.Method)
			return out, nil
		}
		resources = p.Resources
		ignores = append(ignores, p.Serialization.IgnorePaths...)
	case ModelSigningV01Predicate:
		for _, s := range st.Subject {
			resources = append(resources, modelResource{Name: s.Name, Algorithm: "sha256", Digest: s.Digest["sha256"]})
		}
	default:
		out.Status, out.Reason = ModelUnverifiable, fmt.Sprintf("predicate type %q is not a model signature this reads", st.PredicateType)
		return out, nil
	}
	if len(resources) == 0 || len(st.Subject) == 0 {
		out.Status, out.Reason = ModelUnverifiable, "the statement lists no signed file"
		return out, nil
	}
	subjectDigest := st.Subject[0].Digest["sha256"]
	if subjectDigest == "" {
		out.Status, out.Reason = ModelUnverifiable, "the statement's subject has no sha256 digest"
		return out, nil
	}
	out.ManifestDigest = "sha256:" + strings.ToLower(subjectDigest)

	if st.PredicateType == ModelSigningV1Predicate {
		// The subject digest is the sha256 over the resource digests in name
		// order. One that does not match is not a statement this can judge.
		if got := manifestDigest(resources); got != out.ManifestDigest {
			out.Status, out.Reason = ModelUnverifiable, "the statement's subject digest does not match its resource list"
			return out, nil
		}
	}

	sig, err := c.verifyEntity(ctx, e, subject{digest: out.ManifestDigest})
	if err != nil {
		return ModelResult{}, err
	}
	out.Result = sig
	out.Envelope = EnvelopeSigstoreBundle
	if !sig.SignatureValid {
		if c.untrustedSigner(ctx, e) {
			out.Status = ModelUnverifiable
			out.Reason = "the signer's key or certificate is not trusted here: " + sig.Reason
		} else {
			out.Status = ModelInvalid
		}
		return out, nil
	}

	// The files.
	covered := map[string]bool{}
	var unsafePaths []string
	for _, res := range resources {
		if ctx.Err() != nil {
			return ModelResult{}, ctx.Err()
		}
		name, ok := safeModelPath(res.Name)
		if !ok {
			unsafePaths = append(unsafePaths, res.Name)
			continue
		}
		covered[name] = true
		h, err := newModelHash(res.Algorithm)
		if err != nil {
			out.Status, out.Reason = ModelUnverifiable, fmt.Sprintf("%s: %v", res.Name, err)
			return out, nil
		}
		if out.BytesHashed >= c.modelBound {
			out.MissingFiles = append(out.MissingFiles, name)
			out.Reason = fmt.Sprintf("the %d-byte bound was reached", c.modelBound)
			continue
		}
		n, err := c.hashModelFile(fsys, dir, name, h, c.modelBound-out.BytesHashed)
		out.BytesHashed += n
		switch {
		case errors.Is(err, errBoundReached):
			out.MissingFiles = append(out.MissingFiles, name)
			out.Reason = fmt.Sprintf("the %d-byte bound was reached", c.modelBound)
			continue
		case errors.Is(err, errUnsafeLink):
			unsafePaths = append(unsafePaths, res.Name)
			continue
		case errors.Is(err, fs.ErrNotExist):
			out.MissingFiles = append(out.MissingFiles, name)
			continue
		case errors.Is(err, fs.ErrPermission):
			return ModelResult{}, llx.Forbidden(fmt.Errorf("reading the signed model file %s: %w", path.Join(dir, name), err))
		case err != nil:
			return ModelResult{}, fmt.Errorf("reading the signed model file %s: %w", path.Join(dir, name), err)
		}
		if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(res.Digest) {
			out.MismatchedFiles = append(out.MismatchedFiles, name)
		}
	}

	extra, err := c.extraModelFiles(fsys, dir, covered, ignores)
	if err != nil {
		return ModelResult{}, err
	}
	out.ExtraFiles = extra
	var extraCode []string
	for _, f := range extra {
		if isModelCodeOrWeight(f) {
			extraCode = append(extraCode, f)
		}
	}

	switch {
	case len(unsafePaths) > 0:
		out.Status, out.Reason = ModelInvalid, "the signature names unsafe paths: "+strings.Join(unsafePaths, ", ")
	case len(out.MismatchedFiles) > 0:
		out.Status, out.Reason = ModelInvalid, "signed files differ: "+strings.Join(out.MismatchedFiles, ", ")
	case len(extraCode) > 0:
		out.Status, out.Reason = ModelInvalid, "weight or code files the signature does not cover: "+strings.Join(extraCode, ", ")
	case len(out.MissingFiles) > 0:
		out.Status = ModelIncomplete
		if out.Reason == "" {
			out.Reason = "signed files are missing: " + strings.Join(out.MissingFiles, ", ")
		}
	default:
		out.Status, out.Reason = ModelVerified, ""
	}
	return out, nil
}

// manifestDigest is the model signing subject digest: sha256 over the raw
// resource digests, in name order.
func manifestDigest(resources []modelResource) string {
	sorted := append([]modelResource{}, resources...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	h := sha256.New()
	for _, r := range sorted {
		b, err := hex.DecodeString(r.Digest)
		if err != nil {
			return ""
		}
		h.Write(b)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// untrustedSigner reports whether a signature failed because its key or
// certificate is not trusted here, or carries nothing to verify a
// certificate's time with, as opposed to failing to verify.
func (c *config) untrustedSigner(ctx context.Context, e entity) bool {
	vc, err := e.signed.VerificationContent()
	if err != nil {
		return false
	}
	if pk := vc.PublicKey(); pk != nil {
		_, ok := c.keys[normalizeFingerprint(pk.Hint())]
		return !ok
	}
	leaf := vc.Certificate()
	if leaf == nil {
		return false
	}
	if ts, _ := e.signed.Timestamps(); e.tlogEntries == 0 && len(ts) == 0 {
		// A short-lived certificate with no log entry or timestamp cannot be
		// checked at all; that is not evidence of tampering.
		return true
	}
	tr, err := c.trustRoot(ctx)
	if err != nil {
		return false
	}
	_, err = verify.VerifyLeafCertificate(leaf.NotBefore.Add(time.Second), leaf, tr.Material)
	return err != nil
}

func newModelHash(alg string) (hash.Hash, error) {
	switch strings.ToLower(alg) {
	case "sha256", "":
		return sha256.New(), nil
	case "blake2b":
		return blake2b.New512(nil)
	}
	return nil, fmt.Errorf("hash algorithm %q is not read", alg)
}

// safeModelPath checks a signed name: relative, slash-separated, no "..".
func safeModelPath(name string) (string, bool) {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", false
	}
	clean := path.Clean(name)
	if clean != name || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

var (
	errBoundReached = errors.New("byte bound reached")
	errUnsafeLink   = errors.New("a symlink resolves outside the model root")
)

// resolveModelPath resolves name under dir component by component, following
// symlinks only while they stay inside the model root.
func (c *config) resolveModelPath(fsys afero.Fs, dir, name string) (string, error) {
	root := filepath.Clean(c.modelRoot)
	cur := filepath.Clean(dir)
	parts := strings.Split(name, "/")
	hops := 0
	for len(parts) > 0 {
		next := filepath.Join(cur, parts[0])
		parts = parts[1:]
		fi, err := lstat(fsys, next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > 40 {
			return "", errUnsafeLink
		}
		lr, ok := fsys.(afero.LinkReader)
		if !ok {
			return "", errUnsafeLink
		}
		target, err := lr.ReadlinkIfPossible(next)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(next), target)
		}
		target = filepath.Clean(target)
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return "", errUnsafeLink
		}
		// Resolve the target's own components again from the root.
		rel, err := filepath.Rel(root, target)
		if err != nil {
			return "", errUnsafeLink
		}
		cur = root
		if rel != "." {
			parts = append(strings.Split(filepath.ToSlash(rel), "/"), parts...)
		}
	}
	return cur, nil
}

func lstat(fsys afero.Fs, p string) (os.FileInfo, error) {
	if l, ok := fsys.(afero.Lstater); ok {
		fi, _, err := l.LstatIfPossible(p)
		return fi, err
	}
	return fsys.Stat(p)
}

// hashModelFile streams one signed file into h, at most bound bytes.
func (c *config) hashModelFile(fsys afero.Fs, dir, name string, h hash.Hash, bound int64) (int64, error) {
	p, err := c.resolveModelPath(fsys, dir, name)
	if err != nil {
		return 0, err
	}
	fi, err := fsys.Stat(p)
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, errUnsafeLink
	}
	if fi.Size() > bound {
		return 0, errBoundReached
	}
	f, err := fsys.Open(p)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 1<<20)
	n, err := io.CopyBuffer(h, io.LimitReader(f, bound+1), buf)
	if err != nil {
		return n, err
	}
	if n > bound {
		return n, errBoundReached
	}
	return n, nil
}

// extraModelFiles lists regular files under dir that the signature neither
// covers nor ignores.
func (c *config) extraModelFiles(fsys afero.Fs, dir string, covered map[string]bool, ignores []string) ([]string, error) {
	var out []string
	err := afero.Walk(fsys, dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return llx.Forbidden(fmt.Errorf("listing the model directory %s: %w", p, err))
			}
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil || rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if ignored(rel, ignores) || rel == c.modelSigFile {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		if !covered[rel] {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

func ignored(rel string, ignores []string) bool {
	for _, ig := range ignores {
		ig = strings.Trim(filepath.ToSlash(ig), "/")
		if ig != "" && (rel == ig || strings.HasPrefix(rel, ig+"/")) {
			return true
		}
	}
	return false
}

// modelCodeOrWeight are file kinds that change what a model computes or run
// code when loaded.
var modelCodeOrWeight = []string{
	".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill",
	".npy", ".npz", ".h5", ".hdf5", ".keras", ".onnx", ".gguf", ".ggml", ".msgpack",
	".tflite", ".pb", ".mlmodel", ".py", ".pyc",
}

func isModelCodeOrWeight(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if base == "config.json" || base == "keras_metadata.pb" {
		return true
	}
	for _, ext := range modelCodeOrWeight {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}
