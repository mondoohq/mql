// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/go-sqlite"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTccServiceName(t *testing.T) {
	tests := []struct {
		service  string
		expected string
	}{
		{"kTCCServiceSystemPolicyAllFiles", "Full Disk Access"},
		{"kTCCServiceScreenCapture", "Screen Recording"},
		{"kTCCServiceAccessibility", "Accessibility"},
		{"kTCCServiceListenEvent", "Input Monitoring"},
		{"kTCCServiceEndpointSecurityClient", "Endpoint Security Client"},
		// An identifier this release does not know passes through unchanged
		// rather than being labeled with a guess.
		{"kTCCServiceSomethingAppleAddedLater", "kTCCServiceSomethingAppleAddedLater"},
		{"", ""},
	}
	for _, test := range tests {
		t.Run(test.service, func(t *testing.T) {
			assert.Equal(t, test.expected, tccServiceName(test.service))
		})
	}
}

func TestTccAuthorization(t *testing.T) {
	tests := []struct {
		name      string
		authValue int64
		expected  string
		granted   bool
	}{
		{"denied", 0, "denied", false},
		{"unknown", 1, "unknown", false},
		{"allowed", 2, "allowed", true},
		{"limited", 3, "limited", true},
		// Regression: a live macOS host carries auth_value 5 on
		// kTCCServiceSystemPolicyAppData. An undecoded code must report
		// "unknown" rather than being silently folded into denied.
		{"undecoded 5", 5, "unknown", false},
		{"undecoded 4", 4, "unknown", false},
		{"negative", -1, "unknown", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, tccAuthorization(test.authValue))
			assert.Equal(t, test.granted, tccGranted(test.authValue))
		})
	}
}

func TestTccAuthReason(t *testing.T) {
	// The audit-relevant distinction: a grant an administrator pushed against
	// one a user consented to.
	assert.Equal(t, "mdmPolicy", tccAuthReason(6))
	assert.Equal(t, "userConsent", tccAuthReason(2))
	assert.Equal(t, "userSet", tccAuthReason(3))
	assert.Equal(t, "systemSet", tccAuthReason(4))
	assert.Equal(t, "servicePolicy", tccAuthReason(5))
	assert.Equal(t, "unknown", tccAuthReason(99))
	assert.Equal(t, "unknown", tccAuthReason(0))
}

func TestTccClientType(t *testing.T) {
	assert.Equal(t, "bundleId", tccClientType(0))
	assert.Equal(t, "path", tccClientType(1))
	assert.Equal(t, "unknown", tccClientType(7))
}

func TestTccIndirectObject(t *testing.T) {
	// TCC stores the literal UNUSED for services that take no target; that is
	// an absence, not a value.
	assert.Equal(t, "", tccIndirectObject("UNUSED"))
	assert.Equal(t, "com.example.target", tccIndirectObject("com.example.target"))
	assert.Equal(t, "", tccIndirectObject(""))
	// Only the exact literal counts.
	assert.Equal(t, "unused", tccIndirectObject("unused"))
}

func TestTccEntryID(t *testing.T) {
	row := tccRow{
		service:                  "kTCCServiceCamera",
		client:                   "com.example.agent",
		clientType:               0,
		indirectObjectIdentifier: "UNUSED",
	}

	// The same grant in two users' stores must not collapse onto one entry.
	alice := tccEntryID(tccScopeUser, "alice", row)
	bob := tccEntryID(tccScopeUser, "bob", row)
	assert.NotEqual(t, alice, bob)

	// Nor must a user-scope grant collide with a system-scope one.
	system := tccEntryID(tccScopeSystem, "", row)
	assert.NotEqual(t, alice, system)

	// Every dimension of the access table's own primary key separates entries.
	otherService := row
	otherService.service = "kTCCServiceMicrophone"
	assert.NotEqual(t, alice, tccEntryID(tccScopeUser, "alice", otherService))

	otherClient := row
	otherClient.client = "com.example.other"
	assert.NotEqual(t, alice, tccEntryID(tccScopeUser, "alice", otherClient))

	otherType := row
	otherType.clientType = 1
	assert.NotEqual(t, alice, tccEntryID(tccScopeUser, "alice", otherType))

	otherTarget := row
	otherTarget.indirectObjectIdentifier = "com.example.target"
	assert.NotEqual(t, alice, tccEntryID(tccScopeUser, "alice", otherTarget))

	// Identical input is stable.
	assert.Equal(t, alice, tccEntryID(tccScopeUser, "alice", row))
}

func TestTccAccessQuery(t *testing.T) {
	columns := func(names ...string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, n := range names {
			out[n] = struct{}{}
		}
		return out
	}

	t.Run("current schema", func(t *testing.T) {
		q, legacy, err := tccAccessQuery(columns("service", "client", "client_type",
			"auth_value", "auth_reason", "indirect_object_identifier", "last_modified"))
		require.NoError(t, err)
		assert.False(t, legacy)
		assert.Equal(t, "SELECT service, client, client_type, auth_value, auth_reason, "+
			"indirect_object_identifier, last_modified FROM access", q)
	})

	t.Run("legacy allowed column", func(t *testing.T) {
		// Mojave and Catalina: `allowed` instead of auth_value, no auth_reason.
		q, legacy, err := tccAccessQuery(columns("service", "client", "client_type",
			"allowed", "indirect_object_identifier", "last_modified"))
		require.NoError(t, err)
		assert.True(t, legacy)
		assert.Equal(t, "SELECT service, client, client_type, allowed, 0, "+
			"indirect_object_identifier, last_modified FROM access", q)
	})

	t.Run("missing optional columns become literals", func(t *testing.T) {
		q, _, err := tccAccessQuery(columns("service", "client", "client_type", "auth_value"))
		require.NoError(t, err)
		assert.Equal(t, "SELECT service, client, client_type, auth_value, 0, '', 0 FROM access", q)
	})

	t.Run("no authorization column is an error", func(t *testing.T) {
		_, _, err := tccAccessQuery(columns("service", "client", "client_type"))
		require.Error(t, err)
	})

	t.Run("missing identity column is an error", func(t *testing.T) {
		_, _, err := tccAccessQuery(columns("service", "auth_value"))
		require.Error(t, err)
	})
}

func TestTccNormalizeAuthValue(t *testing.T) {
	// Current schema values pass through untouched, including undecoded ones.
	assert.Equal(t, int64(0), tccNormalizeAuthValue(0, false))
	assert.Equal(t, int64(2), tccNormalizeAuthValue(2, false))
	assert.Equal(t, int64(5), tccNormalizeAuthValue(5, false))

	// Legacy `allowed` is a plain boolean mapped onto the auth_value scale.
	assert.Equal(t, int64(2), tccNormalizeAuthValue(1, true))
	assert.Equal(t, int64(0), tccNormalizeAuthValue(0, true))
}

// writeTccFixture builds a TCC store with the current (Big Sur and later)
// access-table schema and returns its path.
func writeTccFixture(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "TCC.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE access (
		service TEXT NOT NULL,
		client TEXT NOT NULL,
		client_type INTEGER NOT NULL,
		auth_value INTEGER NOT NULL,
		auth_reason INTEGER NOT NULL,
		auth_version INTEGER NOT NULL,
		csreq BLOB,
		policy_id INTEGER,
		indirect_object_identifier_type INTEGER,
		indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED',
		indirect_object_code_identity BLOB,
		flags INTEGER,
		last_modified INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (service, client, client_type, indirect_object_identifier))`)
	require.NoError(t, err)

	_, err = db.Exec(`INSERT INTO access
		(service, client, client_type, auth_value, auth_reason, auth_version, indirect_object_identifier, last_modified)
		VALUES
		('kTCCServiceSystemPolicyAllFiles', 'com.example.agent', 0, 2, 6, 1, 'UNUSED', 1700000000),
		('kTCCServiceScreenCapture', '/usr/local/bin/example', 1, 0, 4, 1, 'UNUSED', 1700000001),
		('kTCCServiceAppleEvents', 'com.example.driver', 0, 2, 2, 1, 'com.apple.finder', 1700000002),
		('kTCCServiceSystemPolicyAppData', 'com.example.odd', 0, 5, 4, 1, 'UNUSED', 0)`)
	require.NoError(t, err)

	return dbPath
}

func TestReadTccStore(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	dbPath := writeTccFixture(t, t.TempDir())

	rows, err := readTccStore(afs, dbPath)
	require.NoError(t, err)
	require.Len(t, rows, 4)

	byService := map[string]tccRow{}
	for _, r := range rows {
		byService[r.service] = r
	}

	fda := byService["kTCCServiceSystemPolicyAllFiles"]
	assert.Equal(t, "com.example.agent", fda.client)
	assert.Equal(t, int64(0), fda.clientType)
	assert.Equal(t, int64(2), fda.authValue)
	assert.True(t, tccGranted(fda.authValue))
	// An MDM-pushed grant is distinguishable from a user-consented one.
	assert.Equal(t, "mdmPolicy", tccAuthReason(fda.authReason))

	screen := byService["kTCCServiceScreenCapture"]
	assert.Equal(t, int64(1), screen.clientType)
	assert.Equal(t, "path", tccClientType(screen.clientType))
	assert.False(t, tccGranted(screen.authValue))

	events := byService["kTCCServiceAppleEvents"]
	assert.Equal(t, "com.apple.finder", events.indirectObjectIdentifier)

	// The undecoded code survives the round trip as its raw value.
	odd := byService["kTCCServiceSystemPolicyAppData"]
	assert.Equal(t, int64(5), odd.authValue)
	assert.Equal(t, "unknown", tccAuthorization(odd.authValue))
	// A zero last_modified stays zero so the resource can report it as null
	// rather than as 1 January 1970.
	assert.Equal(t, int64(0), odd.lastModified)
}

func TestReadTccStoreLegacySchema(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "TCC.db")

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE access (
		service TEXT NOT NULL,
		client TEXT NOT NULL,
		client_type INTEGER NOT NULL,
		allowed INTEGER NOT NULL,
		prompt_count INTEGER NOT NULL,
		indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED',
		last_modified INTEGER NOT NULL DEFAULT 0)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO access
		(service, client, client_type, allowed, prompt_count, indirect_object_identifier, last_modified)
		VALUES
		('kTCCServiceAccessibility', 'com.example.legacy', 0, 1, 1, 'UNUSED', 1500000000),
		('kTCCServiceCamera', 'com.example.denied', 0, 0, 1, 'UNUSED', 1500000001)`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	afs := &afero.Afero{Fs: afero.NewOsFs()}
	rows, err := readTccStore(afs, dbPath)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	byService := map[string]tccRow{}
	for _, r := range rows {
		byService[r.service] = r
	}

	// allowed=1 normalizes onto the auth_value scale so both schema
	// generations produce the same authorization string.
	access := byService["kTCCServiceAccessibility"]
	assert.Equal(t, int64(2), access.authValue)
	assert.Equal(t, "allowed", tccAuthorization(access.authValue))
	assert.True(t, tccGranted(access.authValue))

	cam := byService["kTCCServiceCamera"]
	assert.Equal(t, int64(0), cam.authValue)
	assert.Equal(t, "denied", tccAuthorization(cam.authValue))
}

func TestReadTccStoreAbsentIsNotAnError(t *testing.T) {
	// A user who has never granted anything has no store. That is an absence,
	// not a failure.
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	rows, err := readTccStore(afs, filepath.Join(t.TempDir(), "does-not-exist", "TCC.db"))
	require.NoError(t, err)
	assert.Nil(t, rows)
}

func TestReadTccStoreUnreadableIsAnError(t *testing.T) {
	// A store that exists but cannot be parsed must surface. Reporting an empty
	// list would let a check for an unwanted grant pass because nothing could
	// be read.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "TCC.db")
	afs := &afero.Afero{Fs: afero.NewOsFs()}
	require.NoError(t, afs.WriteFile(dbPath, []byte("this is not a sqlite database"), 0o600))

	_, err := readTccStore(afs, dbPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), dbPath)
}
