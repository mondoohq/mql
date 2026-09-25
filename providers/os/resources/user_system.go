// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path"
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	// defaultUIDMin and defaultUIDMax are the shadow-utils compiled-in
	// defaults for UID_MIN and UID_MAX, used when login.defs is absent or does
	// not set a usable value.
	defaultUIDMin int64 = 1000
	defaultUIDMax int64 = 60000
	// maxUID16 is the top of the 16-bit uid space. Above UID_MAX and up to
	// here sit Debian's static allocations (60000 to 64999), systemd's
	// DynamicUser range (61184 to 65519) and nobody (65534). Uids past it are
	// container and directory-service ranges, which hold ordinary users.
	maxUID16 int64 = 65535
	// homedUIDMin and homedUIDMax bound the systemd-homed range, which holds
	// regular users even though it lies above the default UID_MAX.
	homedUIDMin int64 = 60001
	homedUIDMax int64 = 60513
	// darwinUIDMin is the first uid macOS assigns to a user created through
	// System Settings or sysadminctl. Accounts below it are hidden from the
	// login window and reserved for the system.
	darwinUIDMin int64 = 500
)

// uidRange holds UID_MIN and UID_MAX from login.defs: the uids useradd
// hands to regular users.
type uidRange struct {
	min int64
	max int64
}

type systemAccountRule int

const (
	systemAccountRuleUnknown systemAccountRule = iota
	systemAccountRuleLinux
	systemAccountRuleDarwin
)

// systemAccountRuleFor picks how system accounts are told apart on a platform.
// Only Linux (shadow-utils login.defs) and macOS have a rule; everything else,
// including Windows, BSD and Solaris, reports null rather than a guess.
func systemAccountRuleFor(pf *inventory.Platform) systemAccountRule {
	switch {
	case pf.IsFamily("darwin"):
		return systemAccountRuleDarwin
	case pf.IsFamily("linux"):
		return systemAccountRuleLinux
	default:
		return systemAccountRuleUnknown
	}
}

// parseUIDRange reads UID_MIN and UID_MAX from parsed login.defs parameters.
func parseUIDRange(params map[string]string) uidRange {
	return uidRange{
		min: parseLoginDefsUID(params, "UID_MIN", defaultUIDMin),
		max: parseLoginDefsUID(params, "UID_MAX", defaultUIDMax),
	}
}

// parseLoginDefsUID reads one numeric login.defs key. shadow-utils parses
// numbers with strtoul base 0, so decimal, 0x-prefixed hex and 0-prefixed
// octal are all accepted. A missing, unparsable or negative value falls back
// to the shadow-utils default.
func parseLoginDefsUID(params map[string]string, key string, def int64) int64 {
	raw, ok := params[key]
	if !ok {
		return def
	}
	v, err := strconv.ParseInt(raw, 0, 64)
	if err != nil || v < 0 {
		return def
	}
	return v
}

// isLinuxSystemUID reports whether uid belongs to a system account: below
// UID_MIN (root included), or above UID_MAX within the 16-bit uid space
// except for the systemd-homed range.
func isLinuxSystemUID(uid int64, r uidRange) bool {
	if uid < r.min {
		return true
	}
	if uid <= r.max || uid > maxUID16 {
		return false
	}
	return uid < homedUIDMin || uid > homedUIDMax
}

// isDarwinSystemUID reports whether uid belongs to a macOS system account.
// This covers root (0), the `_`-prefixed service accounts, and nobody (-2).
func isDarwinSystemUID(uid int64) bool {
	return uid < darwinUIDMin
}

// nonLoginShellDirs are the directories a nologin or false binary is accepted
// from. Both the split and the merged-/usr locations are listed, so
// /sbin/nologin and /usr/sbin/nologin are recognized whether or not /sbin is a
// symlink. A binary of the same name anywhere else (a home directory, /tmp)
// is treated as an ordinary shell.
var nonLoginShellDirs = map[string]struct{}{
	"/bin":      {},
	"/sbin":     {},
	"/usr/bin":  {},
	"/usr/sbin": {},
}

// nonLoginShellNames are the programs that end a login without starting an
// interactive session: nologin prints a refusal, false and true exit at once.
var nonLoginShellNames = map[string]struct{}{
	"nologin": {},
	"false":   {},
	"true":    {},
}

// isLoginShell reports whether a passwd shell field starts an interactive
// session. An empty field means /bin/sh (passwd(5)), so it is a login shell.
// /etc/shells is deliberately not consulted: login and sshd do not read it,
// and distributions list non-interactive entries there (openSUSE ships
// /bin/false and /bin/true in it), so membership says nothing either way.
func isLoginShell(shell string) bool {
	if shell == "" {
		return true
	}
	p := path.Clean(shell)
	if _, ok := nonLoginShellNames[path.Base(p)]; !ok {
		return true
	}
	_, ok := nonLoginShellDirs[path.Dir(p)]
	return !ok
}

// userUIDRange returns UID_MIN and UID_MAX from login.defs, read once per scan
// and shared by every user.
func (x *mqlUsers) userUIDRange() (uidRange, error) {
	x.uidRangeOnce.Do(func() {
		x.uidRange, x.uidRangeErr = readUIDRange(x.MqlRuntime)
	})
	return x.uidRange, x.uidRangeErr
}

func readUIDRange(runtime *plugin.Runtime) (uidRange, error) {
	defaults := parseUIDRange(nil)
	raw, err := CreateResource(runtime, "logindefs", nil)
	if err != nil {
		return uidRange{}, err
	}
	ld := raw.(*mqlLogindefs)
	file := ld.GetFile()
	if file.Error != nil {
		return uidRange{}, file.Error
	}
	if file.Data == nil {
		return defaults, nil
	}
	exists := file.Data.GetExists()
	if exists.Error != nil {
		return uidRange{}, exists.Error
	}
	if !exists.Data {
		return defaults, nil
	}
	params := ld.GetParams()
	if params.Error != nil {
		return uidRange{}, params.Error
	}
	parsed := make(map[string]string, len(params.Data))
	for k, v := range params.Data {
		if s, ok := v.(string); ok {
			parsed[k] = s
		}
	}
	return parseUIDRange(parsed), nil
}

func (u *mqlUser) assetPlatform() *inventory.Platform {
	conn, ok := u.MqlRuntime.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil {
		return nil
	}
	return conn.Asset().Platform
}

func (u *mqlUser) system() (bool, error) {
	if u.Uid.Error != nil {
		return false, u.Uid.Error
	}
	switch systemAccountRuleFor(u.assetPlatform()) {
	case systemAccountRuleDarwin:
		return isDarwinSystemUID(u.Uid.Data), nil
	case systemAccountRuleLinux:
		raw, err := CreateResource(u.MqlRuntime, "users", nil)
		if err != nil {
			return false, err
		}
		users, ok := raw.(*mqlUsers)
		if !ok {
			return false, errors.New("cannot resolve users resource")
		}
		r, err := users.userUIDRange()
		if err != nil {
			return false, err
		}
		return isLinuxSystemUID(u.Uid.Data, r), nil
	default:
		u.System.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
}

// loginShellApplies reports whether the passwd shell field decides login on
// this platform. Windows accounts have no shell, so hasLoginShell is null there.
func loginShellApplies(pf *inventory.Platform) bool {
	return pf.IsFamily("unix")
}

func (u *mqlUser) hasLoginShell() (bool, error) {
	if u.Shell.Error != nil {
		return false, u.Shell.Error
	}
	if !loginShellApplies(u.assetPlatform()) {
		u.HasLoginShell.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return isLoginShell(u.Shell.Data), nil
}
