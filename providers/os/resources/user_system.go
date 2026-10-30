// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"math"
	"path"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
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
	// freebsdUIDMin and freebsdUIDMax are the pw(8) compiled-in defaults for
	// minuid and maxuid. pw.conf(5): "The default values for both user and
	// group ids are 1000 and 32000 as minimum and maximum respectively."
	freebsdUIDMin int64 = 1000
	freebsdUIDMax int64 = 32000
	pwConfPath          = "/etc/pw.conf"
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
	systemAccountRuleFreeBSD
	systemAccountRuleWindows
)

// systemAccountRuleFor picks how system accounts are told apart on a platform.
// Linux (shadow-utils login.defs), FreeBSD (pw.conf), macOS and Windows (SID
// shape) have a rule; everything else, including the other BSDs and Solaris,
// reports null rather than a guess.
func systemAccountRuleFor(pf *inventory.Platform) systemAccountRule {
	switch {
	case pf == nil:
		return systemAccountRuleUnknown
	case pf.IsFamily("darwin"):
		return systemAccountRuleDarwin
	case pf.Name == "freebsd":
		return systemAccountRuleFreeBSD
	case pf.IsFamily("linux"):
		return systemAccountRuleLinux
	case pf.IsFamily("windows"):
		return systemAccountRuleWindows
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

// parsePwConfUIDRange reads minuid and maxuid from /etc/pw.conf the way pw(8)
// does (usr.sbin/pw/pw_conf.c): a line's first token, split on whitespace and
// '=', is the keyword unless it starts with '#'; the next token, also split on
// ',', is the value, with a surrounding quote pair stripped. Values are
// decimal only and a later line overrides an earlier one. pw warns "Invalid
// min_uid ...; ignoring" for a value it cannot parse, so such a value leaves
// the current one in place. When minuid is not below maxuid, pw falls back to
// 1000 and 32000 (pw_user.c, pw_uidpolicy).
func parsePwConfUIDRange(content string) uidRange {
	r := uidRange{min: freebsdUIDMin, max: freebsdUIDMax}
	isKeySep := func(c rune) bool { return c == ' ' || c == '\t' || c == '\r' || c == '=' }
	isValSep := func(c rune) bool { return isKeySep(c) || c == ',' }
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimLeftFunc(line, isKeySep)
		end := strings.IndexFunc(line, isKeySep)
		if end <= 0 || line[0] == '#' {
			continue
		}
		key, value := line[:end], strings.TrimLeftFunc(line[end:], isValSep)
		if i := strings.IndexFunc(value, isValSep); i >= 0 {
			value = value[:i]
		}
		v, ok := parsePwConfUID(value)
		if !ok {
			continue
		}
		switch key {
		case "minuid":
			r.min = v
		case "maxuid":
			r.max = v
		}
	}
	if r.min >= r.max {
		return uidRange{min: freebsdUIDMin, max: freebsdUIDMax}
	}
	return r
}

// parsePwConfUID parses one pw.conf uid value: an optional quote pair around
// an unsigned decimal number (pw's strtounum parses base 10).
func parsePwConfUID(raw string) (int64, bool) {
	if raw != "" && (raw[0] == '"' || raw[0] == '\'') {
		q := raw[0]
		raw = raw[1:]
		if i := strings.IndexByte(raw, q); i >= 0 {
			raw = raw[:i]
		}
	}
	if raw == "" || raw[0] < '0' || raw[0] > '9' {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v > math.MaxUint32 {
		return 0, false
	}
	return v, true
}

// isFreeBSDSystemUID reports whether uid belongs to a FreeBSD system account:
// below minuid (root, daemon, the ports-assigned service accounts), or above
// maxuid within the 16-bit uid space (nobody is 65534). pw(8) and adduser(8)
// only hand out uids inside [minuid, maxuid]; uids past 65535 come from
// directory services and hold ordinary users, as on Linux.
func isFreeBSDSystemUID(uid int64, r uidRange) bool {
	if uid < r.min {
		return true
	}
	return uid > r.max && uid <= maxUID16
}

// windowsSystemRIDs are the built-in accounts in a machine or domain SID
// space that Windows runs itself rather than a person signing in: krbtgt (502,
// the domain's Kerberos service account), DefaultAccount (503) and
// WDAGUtilityAccount (504). Administrator (500) and Guest (501) are accounts
// people sign in with and count as users.
var windowsSystemRIDs = map[uint64]struct{}{
	502: {},
	503: {},
	504: {},
}

// isWindowsSystemSID reports whether a user SID belongs to a system account.
// Accounts people sign in with have one of two shapes: S-1-5-21-a-b-c-RID, a
// local or Active Directory account (three sub-authorities identify the
// machine or domain, the RID the account), and S-1-12-1-a-b-c-d, an Entra ID
// account (the object GUID split into four 32-bit values). Every other SID is a
// built-in or service identity, such as LocalSystem (S-1-5-18), LocalService
// (S-1-5-19), NetworkService (S-1-5-20), service SIDs (S-1-5-80-...) and IIS
// app pool identities (S-1-5-82-...). ok is false when sid is not a SID.
func isWindowsSystemSID(sid string) (system bool, ok bool) {
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "S") || parts[1] != "1" {
		return false, false
	}
	nums := make([]uint64, 0, len(parts)-2)
	for _, p := range parts[2:] {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return false, false
		}
		nums = append(nums, v)
	}
	switch {
	case len(nums) == 6 && nums[0] == 5 && nums[1] == 21:
		_, builtin := windowsSystemRIDs[nums[5]]
		return builtin, true
	case len(nums) == 6 && nums[0] == 12 && nums[1] == 1:
		return false, true
	default:
		return true, true
	}
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

// userUIDRange returns the uid range handed to regular users (login.defs on
// Linux, pw.conf on FreeBSD), read once per scan and shared by every user.
// The rule is fixed per connection, so the cached range always matches it.
func (x *mqlUsers) userUIDRange(rule systemAccountRule) (uidRange, error) {
	x.uidRangeOnce.Do(func() {
		if rule == systemAccountRuleFreeBSD {
			x.uidRange, x.uidRangeErr = readPwConfUIDRange(x.MqlRuntime)
			return
		}
		x.uidRange, x.uidRangeErr = readUIDRange(x.MqlRuntime)
	})
	return x.uidRange, x.uidRangeErr
}

func readPwConfUIDRange(runtime *plugin.Runtime) (uidRange, error) {
	raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(pwConfPath),
	})
	if err != nil {
		return uidRange{}, err
	}
	f := raw.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return uidRange{}, exists.Error
	}
	if !exists.Data {
		return parsePwConfUIDRange(""), nil
	}
	content := f.GetContent()
	if content.Error != nil {
		return uidRange{}, content.Error
	}
	return parsePwConfUIDRange(content.Data), nil
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
	rule := systemAccountRuleFor(u.assetPlatform())
	switch rule {
	case systemAccountRuleWindows:
		if u.Sid.Error != nil {
			return false, u.Sid.Error
		}
		system, ok := isWindowsSystemSID(u.Sid.Data)
		if !ok {
			u.System.State = plugin.StateIsSet | plugin.StateIsNull
			return false, nil
		}
		return system, nil
	case systemAccountRuleDarwin:
		return isDarwinSystemUID(u.Uid.Data), nil
	case systemAccountRuleLinux, systemAccountRuleFreeBSD:
		raw, err := CreateResource(u.MqlRuntime, "users", nil)
		if err != nil {
			return false, err
		}
		users, ok := raw.(*mqlUsers)
		if !ok {
			return false, errors.New("cannot resolve users resource")
		}
		r, err := users.userUIDRange(rule)
		if err != nil {
			return false, err
		}
		if rule == systemAccountRuleFreeBSD {
			return isFreeBSDSystemUID(u.Uid.Data, r), nil
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
