// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package snmpd

import "strings"

// Access values reported for a VACM user directive.
const (
	AccessReadOnly  = "ro"
	AccessReadWrite = "rw"
	AccessNone      = "none"
)

// Security levels, normalized to the short spellings snmpd.conf(5) documents.
const (
	LevelNoAuth = "noauth"
	LevelAuth   = "auth"
	LevelPriv   = "priv"
)

// DefaultSecurityModel is the model snmpd assigns when a user directive has
// no -s option.
const DefaultSecurityModel = "usm"

// User is a VACM user directive (rouser, rwuser, or authuser) in the form
// snmpd applies it.
type User struct {
	// Directive is the lowercased keyword: rouser, rwuser, or authuser.
	Directive string
	// Name is the security name the directive grants access to.
	Name string
	// Access is "rw" when the directive grants write access, "ro" when it
	// grants read access without write, and "none" otherwise.
	Access string
	// AccessTypes are the VACM access types the directive declares, in the
	// order written: read, write, notify, log, execute, or net.
	AccessTypes []string
	// SecurityLevel is the minimum level snmpd requires: noauth, auth, or
	// priv. snmpd uses auth when the directive omits it.
	SecurityLevel string
	// SecurityModel is the -s value, lowercased, or usm when absent.
	SecurityModel string
	// OID is the subtree the access is restricted to, empty when the
	// directive names none (snmpd then grants the whole tree) or uses -V.
	OID string
	// View is the -V view name, empty when none is given.
	View string
	// ContextName is the SNMP context restriction, empty when none is given.
	// A trailing * makes it a prefix match.
	ContextName string
	// Line is the 1-based line number of the directive within its file.
	Line int
}

// accessTypeNames are the VACM access types snmpd recognizes in authuser.
// snmpd matches them case-sensitively and ignores any other name.
var accessTypeNames = map[string]struct{}{
	"read":    {},
	"write":   {},
	"notify":  {},
	"log":     {},
	"execute": {},
	"net":     {},
}

// securityLevels maps every spelling snmpd accepts (case-insensitively) to
// its short form.
var securityLevels = map[string]string{
	"noauth":       LevelNoAuth,
	"noauthnopriv": LevelNoAuth,
	"auth":         LevelAuth,
	"authnopriv":   LevelAuth,
	"priv":         LevelPriv,
	"authpriv":     LevelPriv,
}

// Users returns the VACM user directives in content, in file order. Lines
// that snmpd rejects when loading the configuration are skipped, since they
// grant no access.
func Users(content string) []User {
	res := []User{}
	for _, d := range Parse(content) {
		if u, ok := ParseUser(d); ok {
			res = append(res, u)
		}
	}
	return res
}

// ParseUser interprets a directive as a VACM user directive. It follows
// Net-SNMP's vacm_create_simple:
//
//	rouser   [-s MODEL] USER [LEVEL [OID | -V VIEW [CONTEXT]]]
//	rwuser   [-s MODEL] USER [LEVEL [OID | -V VIEW [CONTEXT]]]
//	authuser TYPES [-s MODEL] USER [LEVEL [OID | -V VIEW [CONTEXT]]]
//
// It returns false for any other keyword and for lines snmpd rejects: a
// missing user, a -s without both model and user, an unknown security level,
// a -V without a view, or an authuser whose types name no known access type.
func ParseUser(d Directive) (User, bool) {
	u := User{
		Directive: strings.ToLower(d.Keyword),
		Line:      d.Line,
	}
	args := d.Args

	switch u.Directive {
	case "rouser":
		u.AccessTypes = []string{"read"}
	case "rwuser":
		u.AccessTypes = []string{"read", "write"}
	case "authuser":
		if len(args) < 2 {
			return User{}, false
		}
		u.AccessTypes = parseAccessTypes(args[0])
		if len(u.AccessTypes) == 0 {
			return User{}, false
		}
		args = args[1:]
	default:
		return User{}, false
	}

	if len(args) == 0 {
		return User{}, false
	}

	// snmpd matches -s case-sensitively and needs both the model and the
	// user after it.
	u.SecurityModel = DefaultSecurityModel
	if args[0] == "-s" {
		if len(args) < 3 {
			return User{}, false
		}
		u.SecurityModel = strings.ToLower(args[1])
		args = args[2:]
	}

	u.Name = args[0]
	args = args[1:]

	u.SecurityLevel = LevelAuth
	if len(args) > 0 {
		level, ok := securityLevels[strings.ToLower(args[0])]
		if !ok {
			return User{}, false
		}
		u.SecurityLevel = level
		args = args[1:]
	}

	if len(args) > 0 {
		if args[0] == "-V" {
			if len(args) < 2 {
				return User{}, false
			}
			u.View = args[1]
			args = args[2:]
		} else {
			u.OID = args[0]
			args = args[1:]
		}
	}

	if len(args) > 0 {
		u.ContextName = args[0]
	}

	u.Access = accessFromTypes(u.AccessTypes)
	return u, true
}

// parseAccessTypes splits an authuser type list on the separators snmpd
// accepts (comma, pipe, colon) and keeps the names it recognizes.
func parseAccessTypes(spec string) []string {
	res := []string{}
	for _, t := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == '|' || r == ':'
	}) {
		if _, ok := accessTypeNames[t]; ok {
			res = append(res, t)
		}
	}
	return res
}

func accessFromTypes(types []string) string {
	read := false
	for _, t := range types {
		switch t {
		case "write":
			return AccessReadWrite
		case "read":
			read = true
		}
	}
	if read {
		return AccessReadOnly
	}
	return AccessNone
}
