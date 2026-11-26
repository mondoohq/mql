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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"go.mondoo.com/mql/llx"
)

// TrustSource is where a trust root came from.
type TrustSource string

const (
	// TrustPrivate is a configured private trust root (a private Fulcio and
	// Rekor, or an air-gapped mirror's trusted_root.json).
	TrustPrivate TrustSource = "private"
	// TrustTUF is the TUF repository's root, refreshed now.
	TrustTUF TrustSource = "tuf"
	// TrustTUFCache is the TUF root cached on disk, within its expiry, used
	// because the repository could not be reached.
	TrustTUFCache TrustSource = "tuf-cache"
	// TrustEmbedded is the root embedded in the caller's binary, used only
	// when no TUF root was ever fetched on this machine.
	TrustEmbedded TrustSource = "embedded"
)

// trustedRootTarget is the TUF target that holds the Sigstore trust root.
const trustedRootTarget = "trusted_root.json"

// TrustOptions selects the trust root. The order is fixed:
//
//  1. PrivateRoot, when set, is the only root; nothing else is consulted.
//  2. The TUF repository's root, refreshed, and cached under CacheDir.
//  3. When the repository cannot be reached, the cached root, only within
//     the expiry of its TUF metadata. Past it, verification fails.
//  4. Embedded, only when no TUF root was ever fetched into CacheDir.
//
// A root is never older than one already used from CacheDir, nor older than
// EmbeddedVersion: TUF metadata whose targets version is lower is refused,
// so blocking the repository cannot roll the root back to revoked keys.
type TrustOptions struct {
	// PrivateRoot is a trusted_root.json for a private Sigstore instance.
	PrivateRoot []byte
	// CacheDir holds the TUF cache and the highest version used. Empty is
	// the user's cache directory.
	CacheDir string
	// TUFRoot is the TUF bootstrap root.json. Empty is the public-good root.
	TUFRoot []byte
	// RepositoryURL is the TUF repository. Empty is the public-good mirror.
	RepositoryURL string
	// Fetcher fetches TUF metadata and targets. Empty is an HTTP fetcher.
	Fetcher fetcher.Fetcher
	// Embedded is a trusted_root.json the caller ships, and EmbeddedVersion
	// the TUF targets version it was copied from.
	Embedded        []byte
	EmbeddedVersion int64
	// Offline skips the refresh: only the cache or the embedded root is used.
	Offline bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// DefaultTrustOptions is the public-good instance, cached under the user's
// cache directory.
func DefaultTrustOptions() TrustOptions {
	return TrustOptions{}
}

// TrustRoot is a loaded trust root.
type TrustRoot struct {
	Material root.TrustedMaterial
	Source   TrustSource
	// Version is the TUF targets version the root came from; 0 for a
	// private root.
	Version int64
	// ID is the sha256 of the trusted_root.json.
	ID string
	// Expires is the earliest expiry of the TUF metadata the root was read
	// under; zero for a private or embedded root.
	Expires time.Time
}

// String names the root as an outcome records it, "tuf@14".
func (t *TrustRoot) String() string {
	if t.Version == 0 {
		return string(t.Source)
	}
	return string(t.Source) + "@" + strconv.FormatInt(t.Version, 10)
}

func (t *TrustRoot) expired(now time.Time) bool {
	return !t.Expires.IsZero() && now.After(t.Expires)
}

// NewTrustRoot wraps already-trusted material, for a caller that builds its
// own (tests, a private instance held in memory).
func NewTrustRoot(material root.TrustedMaterial, source TrustSource, id string) *TrustRoot {
	return &TrustRoot{Material: material, Source: source, ID: id}
}

// trustState is the highest TUF targets version used per repository.
type trustState struct {
	Highest map[string]int64 `json:"highest"`
}

var trustStateMu sync.Mutex

// LoadTrustRoot selects and loads the trust root in the order TrustOptions
// documents.
func LoadTrustRoot(ctx context.Context, o TrustOptions) (*TrustRoot, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if len(o.PrivateRoot) > 0 {
		tr, err := root.NewTrustedRootFromJSON(o.PrivateRoot)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("reading the private trust root: %w", err))
		}
		return &TrustRoot{Material: tr, Source: TrustPrivate, ID: sha(o.PrivateRoot)}, nil
	}

	if o.CacheDir == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			dir = os.TempDir()
		}
		o.CacheDir = filepath.Join(dir, "mondoo", "sigstore")
	}
	if len(o.TUFRoot) == 0 {
		o.TUFRoot = tuf.DefaultRoot()
	}
	if o.RepositoryURL == "" {
		o.RepositoryURL = tuf.DefaultMirror
	}
	metaDir := filepath.Join(o.CacheDir, tuf.URLToPath(o.RepositoryURL))

	trustStateMu.Lock()
	defer trustStateMu.Unlock()
	state := readTrustState(o.CacheDir)
	highest := state.Highest[o.RepositoryURL]
	_, statErr := os.Stat(filepath.Join(metaDir, "targets.json"))
	everFetched := highest > 0 || statErr == nil
	floor := max(highest, o.EmbeddedVersion)

	var refreshErr error
	if !o.Offline {
		opts := tufOptions(ctx, o, false)
		client, err := tuf.New(opts)
		if err == nil {
			tr, err := fromTUF(client, metaDir, TrustTUF, floor, now())
			if err != nil {
				return nil, err
			}
			state.Highest[o.RepositoryURL] = tr.Version
			writeTrustState(o.CacheDir, state)
			return tr, nil
		}
		refreshErr = err
	} else {
		refreshErr = errors.New("offline")
	}

	if everFetched {
		opts := tufOptions(ctx, o, true)
		client, err := tuf.New(opts)
		if err != nil {
			return nil, llx.Unavailable(fmt.Errorf("%w: the cached TUF metadata cannot be used (%v) and the refresh failed: %v", ErrTrustRootExpired, err, refreshErr))
		}
		tr, err := fromTUF(client, metaDir, TrustTUFCache, floor, now())
		if err != nil {
			if errors.Is(err, ErrTrustRootExpired) {
				return nil, llx.Unavailable(fmt.Errorf("%w; the refresh failed: %v", err, refreshErr))
			}
			return nil, err
		}
		if tr.Version > highest {
			state.Highest[o.RepositoryURL] = tr.Version
			writeTrustState(o.CacheDir, state)
		}
		return tr, nil
	}

	if len(o.Embedded) > 0 {
		tr, err := root.NewTrustedRootFromJSON(o.Embedded)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("reading the embedded trust root: %w", err))
		}
		return &TrustRoot{Material: tr, Source: TrustEmbedded, Version: o.EmbeddedVersion, ID: sha(o.Embedded)}, nil
	}
	return nil, llx.Unavailable(fmt.Errorf("%w: %v", ErrNoTrustRoot, refreshErr))
}

// tufOptions are the TUF client options; cacheOnly reads the cache without
// any network call.
func tufOptions(ctx context.Context, o TrustOptions, cacheOnly bool) *tuf.Options {
	opts := &tuf.Options{
		Root:              o.TUFRoot,
		CachePath:         o.CacheDir,
		RepositoryBaseURL: o.RepositoryURL,
		Fetcher:           o.Fetcher,
		Context:           ctx,
	}
	if cacheOnly {
		opts.ForceCache = true
		// Should the cache fail to load, the client would refresh: make that
		// refresh fail instead of reaching the network.
		opts.Fetcher = offlineFetcher{}
	}
	if opts.Fetcher == nil {
		opts.Fetcher = tuf.DefaultOptions().Fetcher
	}
	return opts
}

type offlineFetcher struct{}

func (offlineFetcher) DownloadFile(string, int64, time.Duration) ([]byte, error) {
	return nil, errors.New("offline: the TUF repository is not contacted")
}

// fromTUF reads the trust root target through a TUF client, after checking
// the metadata's version against floor and its expiry against now.
func fromTUF(client *tuf.Client, metaDir string, source TrustSource, floor int64, now time.Time) (*TrustRoot, error) {
	version, expires, err := readTUFMetadata(metaDir)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("reading the cached TUF metadata: %w", err))
	}
	if version < floor {
		return nil, fmt.Errorf("%w: targets version %d, at least %d was already trusted", ErrTrustRootRollback, version, floor)
	}
	if now.After(expires) {
		return nil, fmt.Errorf("%w: its TUF metadata expired at %s", ErrTrustRootExpired, expires.UTC().Format(time.RFC3339))
	}
	b, err := client.GetTarget(trustedRootTarget)
	if err != nil {
		return nil, llx.Unavailable(fmt.Errorf("reading %s from TUF: %w", trustedRootTarget, err))
	}
	tr, err := root.NewTrustedRootFromJSON(b)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("reading %s: %w", trustedRootTarget, err))
	}
	return &TrustRoot{Material: tr, Source: source, Version: version, ID: sha(b), Expires: expires}, nil
}

// readTUFMetadata returns the targets version of the cached metadata and the
// earliest expiry among root, timestamp, snapshot and targets.
func readTUFMetadata(dir string) (int64, time.Time, error) {
	var version int64
	var earliest time.Time
	for _, role := range []string{"root", "timestamp", "snapshot", "targets"} {
		b, err := os.ReadFile(filepath.Join(dir, role+".json"))
		if err != nil {
			return 0, time.Time{}, err
		}
		var md struct {
			Signed struct {
				Version int64     `json:"version"`
				Expires time.Time `json:"expires"`
			} `json:"signed"`
		}
		if err := json.Unmarshal(b, &md); err != nil {
			return 0, time.Time{}, fmt.Errorf("%s.json: %w", role, err)
		}
		if role == "targets" {
			version = md.Signed.Version
		}
		if earliest.IsZero() || md.Signed.Expires.Before(earliest) {
			earliest = md.Signed.Expires
		}
	}
	return version, earliest, nil
}

func trustStatePath(cacheDir string) string {
	return filepath.Join(cacheDir, "trust-state.json")
}

func readTrustState(cacheDir string) trustState {
	s := trustState{Highest: map[string]int64{}}
	if b, err := os.ReadFile(trustStatePath(cacheDir)); err == nil {
		_ = json.Unmarshal(b, &s)
		if s.Highest == nil {
			s.Highest = map[string]int64{}
		}
	}
	return s
}

// writeTrustState records the highest version used. A write failure leaves
// the TUF metadata on disk as the record, which everFetched also reads.
func writeTrustState(cacheDir string, s trustState) {
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return
	}
	tmp := trustStatePath(cacheDir) + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, trustStatePath(cacheDir))
	}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
