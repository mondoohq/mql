// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"io"
	"sync"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// hotfixQueryCache memoizes Get-HotFix's parsed result per connection, keyed
// by conn.ID(), so that packages.list (WinPkgManager.List, below) and
// windows.hotfixes (providers/os/resources/windows.go, which calls
// GetHotfixes too) run the COM enumeration once per scan instead of twice.
// Both resolve independently and Get-HotFix is not cheap: it is a fresh
// PowerShell process that walks the CBS package store.
//
// Modeled on smbios.managerCache: the cache lives for the process lifetime.
// Entries are not evicted on disconnect because the os provider has no
// Disconnect lifecycle hook. In practice this is fine: connections are
// short-lived (one per scan) and the process exits after.
var hotfixQueryCache sync.Map // map[uint32]*cachingHotfixQuery

// GetHotfixes returns the host's installed hotfixes (Get-HotFix), running the
// query at most once per connection no matter how many callers ask.
func GetHotfixes(conn shared.Connection) ([]PowershellWinHotFix, error) {
	connID := conn.ID()

	c, _ := hotfixQueryCache.LoadOrStore(connID, &cachingHotfixQuery{conn: conn})
	return c.(*cachingHotfixQuery).get()
}

// cachingHotfixQuery memoizes a single connection's Get-HotFix result.
//
// The lock is held across the underlying command on purpose, mirroring
// smbios.cachingManager: releasing it first would let packages.list and
// windows.hotfixes, which can both be resolved in the same scan, each miss
// the empty cache and run Get-HotFix on their own, which is exactly the
// duplicate work this cache exists to remove.
//
// Only a successful result is memoized, so a transient failure (the agent
// busy, a momentary WMI hiccup) is retried by the next caller instead of
// turning one bad moment into an empty hotfix list for the rest of the scan.
type cachingHotfixQuery struct {
	conn shared.Connection

	lock     sync.Mutex
	fetched  bool
	hotfixes []PowershellWinHotFix
}

func (c *cachingHotfixQuery) get() ([]PowershellWinHotFix, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.fetched {
		return c.hotfixes, nil
	}

	// Encode (rather than Wrap) so the script travels as a base64-encoded
	// -EncodedCommand: the same transport windows.hotfixes used before this
	// cache existed, and the one every other Windows PowerShell query in this
	// provider uses.
	cmd, err := c.conn.RunCommand(powershell.Encode(WINDOWS_QUERY_HOTFIXES))
	if err != nil {
		return nil, errors.Wrap(err, "could not fetch hotfixes")
	}
	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve hotfixes: " + string(stderr))
	}

	hotfixes, err := ParseWindowsHotfixes(cmd.Stdout)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse hotfix results")
	}

	c.hotfixes = hotfixes
	c.fetched = true
	return c.hotfixes, nil
}
