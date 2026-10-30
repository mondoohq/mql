// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// Snowflake reports no "key set at" time on a user, so the only record of when
// a key-pair credential was installed is the statement that installed it, in
// ACCOUNT_USAGE.QUERY_HISTORY.
//
// The statement text contains the public key. It is a public key rather than a
// secret, but there is no reason to carry it, so the projection redacts every
// long base64 run before the text leaves Snowflake. Redacting only those runs
// keeps the statement's structure, which is what the parser reads.
//
// The `<` bound is deliberate: QUERY_HISTORY is retained for a year, so a key
// installed longer ago than that has no row and reports null, which is not the
// same as "not set".
const keySetStatementsQuery = `
SELECT END_TIME AS SET_TIME,
       REGEXP_REPLACE(QUERY_TEXT, '[A-Za-z0-9+/=]{40,}', '<redacted>') AS STATEMENT
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE EXECUTION_STATUS = 'SUCCESS'
  AND QUERY_TYPE IN ('ALTER_USER', 'CREATE_USER')
  AND QUERY_TEXT ILIKE '%RSA_PUBLIC_KEY%'
ORDER BY END_TIME`

// userNamePattern reads the user a CREATE/ALTER USER statement names, allowing
// the optional IF [NOT] EXISTS between the keyword and the name, and a quoted
// identifier. A statement with no name targets the current user and is skipped.
var userNamePattern = regexp.MustCompile(`(?i)\bUSER\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?"?([A-Za-z0-9_$]+)"?`)

// keySlotPattern reads which key slot the statement assigns.
//
// The trailing boundary is the whole point: RSA_PUBLIC_KEY_2 contains
// RSA_PUBLIC_KEY as a prefix, so a plain substring test records a second-slot
// rotation as a first-slot one and reports the first key as newer than it is.
var keySlotPattern = regexp.MustCompile(`(?i)\bRSA_PUBLIC_KEY(_2)?\b`)

// keySet is one observed key installation.
type keySet struct {
	user string
	slot int // 1 or 2
}

// parseKeySetStatement reads the user and key slot out of a CREATE/ALTER USER
// statement. ok is false when the statement names no user, assigns no key slot,
// or removes a key rather than setting one.
func parseKeySetStatement(statement string) (keySet, bool) {
	slot := keySlotPattern.FindStringSubmatch(statement)
	if slot == nil {
		return keySet{}, false
	}
	// UNSET clears a key; treating it as an installation would report a
	// removed credential as freshly rotated.
	if unsetPattern.MatchString(statement) {
		return keySet{}, false
	}
	name := userNamePattern.FindStringSubmatch(statement)
	if name == nil || name[1] == "" {
		return keySet{}, false
	}
	// A statement may omit the user entirely and act on the current one, as in
	// `ALTER USER SET WORKSHEETS_MIGRATED = true`, which really does appear in
	// account history. The name pattern then captures the clause keyword, so a
	// key set that way would be filed under a user called "SET". The session
	// user is not recoverable from the text, so skip it rather than guess.
	if userClauseKeywords[strings.ToUpper(name[1])] {
		return keySet{}, false
	}
	n := 1
	if slot[1] != "" {
		n = 2
	}
	return keySet{user: strings.ToUpper(name[1]), slot: n}, true
}

var unsetPattern = regexp.MustCompile(`(?i)\bUNSET\b`)

// userClauseKeywords are the words that may directly follow USER in place of a
// user name.
var userClauseKeywords = map[string]bool{
	"SET": true, "UNSET": true, "ADD": true, "DROP": true,
	"RENAME": true, "RESET": true, "MODIFY": true,
}

// keySetTimes maps an upper-cased user name to the most recent time each key
// slot was installed.
type keySetTimes map[string][2]*time.Time

// foldKeySetRows reduces statement rows to the latest installation per user and
// slot. Rows arrive oldest first, so a later row legitimately overwrites an
// earlier one and the result is the most recent rotation.
func foldKeySetRows(rows []keySetRow) keySetTimes {
	out := keySetTimes{}
	for _, row := range rows {
		parsed, ok := parseKeySetStatement(row.statement)
		if !ok {
			continue
		}
		entry := out[parsed.user]
		t := row.setTime
		entry[parsed.slot-1] = &t
		out[parsed.user] = entry
	}
	return out
}

// unsafeTimeValue reads a QueryUnsafe timestamp cell as a time.Time. The driver
// hands back a time.Time for a real timestamp column; a string form goes through
// the same layouts the SHOW responses use.
func unsafeTimeValue(v *any) (time.Time, bool) {
	if v == nil || *v == nil {
		return time.Time{}, false
	}
	if t, ok := (*v).(time.Time); ok {
		return t, true
	}
	raw := parseSnowflakeTime(unsafeString(v))
	if raw == nil {
		return time.Time{}, false
	}
	if t, ok := raw.Value.(time.Time); ok {
		return t, true
	}
	if t, ok := raw.Value.(*time.Time); ok && t != nil {
		return *t, true
	}
	return time.Time{}, false
}

type keySetRow struct {
	setTime   time.Time
	statement string
}

type keySetIndex struct {
	once  sync.Once
	times keySetTimes
	err   error
}

// keySetTimes runs the history correlation once for the whole account. Resolving
// it per user would run the same scan once per user.
func (r *mqlSnowflakeAccount) keySetTimes() (keySetTimes, error) {
	r.keySetIndex.once.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		rows, err := conn.Client().QueryUnsafe(context.Background(), keySetStatementsQuery)
		if err != nil {
			r.keySetIndex.err = err
			return
		}
		parsed := make([]keySetRow, 0, len(rows))
		for _, row := range rows {
			t, ok := unsafeTimeValue(row["SET_TIME"])
			if !ok {
				continue
			}
			parsed = append(parsed, keySetRow{setTime: t, statement: unsafeString(row["STATEMENT"])})
		}
		r.keySetIndex.times = foldKeySetRows(parsed)
	})
	return r.keySetIndex.times, r.keySetIndex.err
}

// keySetAt resolves one key slot's installation time for a user.
//
// Reaching ACCOUNT_USAGE needs both a warehouse and the privilege to read the
// SNOWFLAKE database, and a connection has neither guaranteed. When the history
// cannot be read the field reports null: a zero time would date every key to
// year one and read as long overdue for rotation, and reporting "never set"
// would read as rotation being unnecessary. Both are answers we have not
// earned.
func userKeySetAt(r *mqlSnowflakeUser, slot int, field *plugin.TValue[*time.Time]) (*time.Time, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	times, err := account.keySetTimes()
	if err != nil {
		log.Debug().Err(err).
			Msg("snowflake: cannot read ACCOUNT_USAGE.QUERY_HISTORY, key-pair set times unavailable")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	entry, ok := times[strings.ToUpper(r.Name.Data)]
	if !ok || entry[slot-1] == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return entry[slot-1], nil
}

func (r *mqlSnowflakeUser) rsaPublicKeySetAt() (*time.Time, error) {
	return userKeySetAt(r, 1, &r.RsaPublicKeySetAt)
}

func (r *mqlSnowflakeUser) rsaPublicKey2SetAt() (*time.Time, error) {
	return userKeySetAt(r, 2, &r.RsaPublicKey2SetAt)
}
