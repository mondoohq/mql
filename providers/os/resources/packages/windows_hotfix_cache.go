// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"io"
	"sync"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// hotfixQueryCache memoizes Get-HotFix's raw outcome per connection, keyed by
// conn.ID(), so that packages.list (WinPkgManager.List, below) and
// windows.hotfixes (providers/os/resources/windows.go, which calls
// GetHotfixQueryResult too) run the COM enumeration once per scan instead of
// twice. Both resolve independently and Get-HotFix is not cheap: it is a
// fresh PowerShell process that walks the CBS package store.
//
// Modeled on smbios.managerCache: the cache lives for the process lifetime.
// Entries are not evicted on disconnect because the os provider has no
// Disconnect lifecycle hook. In practice this is fine: connections are
// short-lived (one per scan) and the process exits after.
var hotfixQueryCache sync.Map // map[uint32]*cachingHotfixQuery

// HotfixQueryResult is the raw outcome of one Get-HotFix run: the exit
// status and captured stderr, and the parsed stdout (best-effort — parsing
// does not require a zero exit status, and ParseErr carries a JSON failure
// instead of being folded into the returned error).
//
// The two existing callers read a non-zero exit differently.
// WinPkgManager.List (below) has always parsed stdout regardless of exit
// status: a single broken QFE entry that makes PowerShell exit non-zero
// while still printing valid JSON must not fail the whole package
// inventory, since an empty or failed package list closes vulnerability
// findings upstream. windows.hotfixes (providers/os/resources/windows.go)
// has always treated a non-zero exit as an error outright. Sharing one
// underlying command means the cache cannot pick one interpretation for
// both, so it hands back the raw outcome and leaves that choice to each
// caller, exactly as it was before this cache existed.
type HotfixQueryResult struct {
	Hotfixes   []PowershellWinHotFix
	ParseErr   error
	ExitStatus int
	Stderr     string
}

// GetHotfixQueryResult returns the host's Get-HotFix outcome, running the
// query at most once per connection no matter how many callers ask. See
// HotfixQueryResult for how to interpret ExitStatus/ParseErr.
func GetHotfixQueryResult(conn shared.Connection) (HotfixQueryResult, error) {
	connID := conn.ID()

	c, _ := hotfixQueryCache.LoadOrStore(connID, &cachingHotfixQuery{conn: conn})
	return c.(*cachingHotfixQuery).get()
}

// cachingHotfixQuery memoizes a single connection's Get-HotFix outcome.
//
// The lock is held across the underlying command on purpose, mirroring
// smbios.cachingManager: releasing it first would let packages.list and
// windows.hotfixes, which can both be resolved in the same scan, each miss
// the empty cache and run Get-HotFix on their own, which is exactly the
// duplicate work this cache exists to remove.
//
// A result is memoized only once RunCommand itself succeeds (a transport
// error is not cached), so a transient failure to even run the command (the
// agent busy, a momentary WMI hiccup) is retried by the next caller instead
// of turning one bad moment into an empty hotfix list for the rest of the
// scan. A non-zero exit status or a JSON parse failure, on the other hand,
// IS memoized: the command did run, its outcome is deterministic within a
// scan, and each caller's own ExitStatus/ParseErr handling decides what
// that outcome means for them.
type cachingHotfixQuery struct {
	conn shared.Connection

	lock    sync.Mutex
	fetched bool
	result  HotfixQueryResult
}

func (c *cachingHotfixQuery) get() (HotfixQueryResult, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.fetched {
		return c.result, nil
	}

	// Encode (rather than Wrap) so the script travels as a base64-encoded
	// -EncodedCommand: the same transport windows.hotfixes used before this
	// cache existed, and the one every other Windows PowerShell query in this
	// provider uses.
	cmd, err := c.conn.RunCommand(powershell.Encode(WINDOWS_QUERY_HOTFIXES))
	if err != nil {
		// RunCommand itself failed: nothing to memoize, so the next caller
		// gets a fresh attempt instead of being stuck on this failure.
		return HotfixQueryResult{}, err
	}

	stderr, err := io.ReadAll(cmd.Stderr)
	if err != nil {
		// Same reasoning: we never captured a usable outcome, so don't cache one.
		return HotfixQueryResult{}, err
	}

	// Parsed regardless of exit status: WinPkgManager.List has always done
	// this, and a caller that wants to be strict about ExitStatus can still
	// check it below without this cache making that decision for them.
	hotfixes, parseErr := ParseWindowsHotfixes(cmd.Stdout)

	c.result = HotfixQueryResult{
		Hotfixes:   hotfixes,
		ParseErr:   parseErr,
		ExitStatus: cmd.ExitStatus,
		Stderr:     string(stderr),
	}
	c.fetched = true
	return c.result, nil
}
