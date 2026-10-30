// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"maps"
	"sync"

	"go.mondoo.com/mql/providers/k8s/connection/shared"
)

// loaded is a manifest as read and parsed: everything about a connection that
// depends on the manifest alone and not on the namespace it is scoped to.
// Nothing in it is written once it is built, which is what lets connections
// share it.
type loaded struct {
	// The manifest files as read, retained for source context. Content passed
	// in directly is one entry without a path.
	sources []shared.ManifestFile
	// parser holds the parsed objects and is scoped to no namespace. Each
	// connection takes a copy scoped to its own.
	parser shared.ManifestParser

	posOnce   sync.Once
	contents  map[string]string
	positions map[string]shared.SourcePosition
}

// source returns the text of each manifest file keyed by its path, and the
// per-resource source-position index. Both are built on first use.
func (l *loaded) source() (map[string]string, map[string]shared.SourcePosition) {
	l.posOnce.Do(func() {
		l.contents = make(map[string]string, len(l.sources))
		l.positions = map[string]shared.SourcePosition{}
		for _, src := range l.sources {
			l.contents[src.Path] = string(src.Content)
			maps.Copy(l.positions, shared.BuildManifestPositionIndex(src.Content, src.Path, l.parser.EffectiveNamespace))
		}
	})
	return l.contents, l.positions
}

// cacheKey names a manifest. A file manifest is its absolute path; a git
// clone adds the repository URL, since file paths are then reported relative
// to the clone. Content passed in directly is its digest.
type cacheKey struct {
	path   string
	gitUrl string
	digest string
}

type cacheEntry struct {
	refs int
	done chan struct{}
	val  *loaded
	err  error
}

// Cache lets the connections to one manifest share a single read and parse
// of it. Discovery turns one manifest into many assets: the manifest itself,
// each namespace in it and each workload, every one connected on its own.
// Without the cache each of those connections reads and parses every file
// again, so a manifest with N namespaces and W workloads is held in memory up
// to 1+N+W times over and parsed as often.
//
// Entries are reference counted: a connection holds its entry until it is
// closed, and the entry is dropped when the last one closes. A manifest
// connected again after that is read from disk again, so a later scan of the
// same path sees the files as they are then.
//
// A nil *Cache is valid and caches nothing.
type Cache struct {
	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
}

func NewCache() *Cache {
	return &Cache{entries: map[cacheKey]*cacheEntry{}}
}

// acquire returns the manifest for key, calling load if no connection holds
// it yet. Concurrent callers for one key wait for a single load. The returned
// release gives the reference back; it is safe to call more than once.
//
// A failed load is not kept past its waiters: every caller that finds the
// entry before the last of them has returned gets the same error, and the
// first caller after that loads again. Handing a late caller the error rather
// than retrying is deliberate: it arrives within the same moment, for the same
// files, and a retry would only fail the same way.
func (c *Cache) acquire(key cacheKey, load func() (*loaded, error)) (*loaded, func(), error) {
	if c == nil {
		l, err := load()
		return l, func() {}, err
	}

	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		e = &cacheEntry{done: make(chan struct{})}
		c.entries[key] = e
	}
	e.refs++
	c.mu.Unlock()

	if ok {
		<-e.done
	} else {
		e.val, e.err = load()
		close(e.done)
	}

	if e.err != nil {
		c.release(key, e)
		return nil, nil, e.err
	}
	var once sync.Once
	return e.val, func() { once.Do(func() { c.release(key, e) }) }, nil
}

func (c *Cache) release(key cacheKey, e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.refs--
	if e.refs == 0 && c.entries[key] == e {
		delete(c.entries, key)
	}
}
