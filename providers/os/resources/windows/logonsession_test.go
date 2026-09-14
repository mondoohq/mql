// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logonSessionsJSON is the shape ConvertTo-Json produces for
// LogonSessionsScript. Written by hand from the Win32_LogonSession and
// Win32_LoggedOnUser field sets rather than captured from a run, so that it
// cannot agree with the decoder by construction.
//
// The four records cover what decodes differently: the SYSTEM session the
// machine creates at boot with no start time, an interactive local logon, an
// incoming Remote Desktop logon by a domain account whose SID translated, and
// a network logon whose SID did not.
const logonSessionsJSON = `[
 {"LogonId":"999","LogonType":0,"AuthenticationPackage":"Negotiate","StartTime":null,
  "AccountName":"WIN-SRV01$","AccountDomain":"WORKGROUP","Sid":"S-1-5-18"},
 {"LogonId":"107587","LogonType":2,"AuthenticationPackage":"Negotiate","StartTime":"2026-09-11T14:23:11.1234567Z",
  "AccountName":"Administrator","AccountDomain":"WIN-SRV01","Sid":"S-1-5-21-1004336348-1177238915-682003330-500"},
 {"LogonId":"312790","LogonType":10,"AuthenticationPackage":"Kerberos","StartTime":"2026-09-11T15:02:44.0000000Z",
  "AccountName":"jdoe","AccountDomain":"CONTOSO","Sid":"S-1-5-21-99-88-77-1105"},
 {"LogonId":"518393","LogonType":3,"AuthenticationPackage":"NTLM","StartTime":"2026-09-11T15:10:02.5000000Z",
  "AccountName":"svc_backup","AccountDomain":"CONTOSO","Sid":null}
]`

func TestParseLogonSessions(t *testing.T) {
	sessions, err := ParseLogonSessions(strings.NewReader(logonSessionsJSON))
	require.NoError(t, err)
	require.Len(t, sessions, 4)

	// Every field read by value: a mistyped struct tag yields the zero value
	// rather than an error, so only comparing the value catches it.
	s := sessions[1]
	assert.Equal(t, "107587", s.LogonId)
	assert.Equal(t, int64(2), s.LogonType)
	assert.Equal(t, "Negotiate", s.AuthenticationPackage)
	assert.Equal(t, "Administrator", s.AccountName)
	assert.Equal(t, "WIN-SRV01", s.AccountDomain)
	assert.Equal(t, "S-1-5-21-1004336348-1177238915-682003330-500", s.Sid)

	// A session the LSA reports with no start time must stay null. The zero
	// time.Time would report it as having started in year 1, which reads as a
	// real value and would satisfy any age comparison written against it.
	assert.Nil(t, sessions[0].StartTime, "an absent start time must be null, not the zero time")

	require.NotNil(t, s.StartTime)
	assert.Equal(t, time.Date(2026, 9, 11, 14, 23, 11, 123456700, time.UTC), s.StartTime.UTC())

	// An untranslatable SID is absent rather than an error on the collection.
	assert.Empty(t, sessions[3].Sid)
	assert.Equal(t, "NTLM", sessions[3].AuthenticationPackage)
}

func TestParseLogonSessionsEmpty(t *testing.T) {
	// A target that reported no sessions is a normal state, not an error.
	for _, in := range []string{"", "   ", "null", "[]"} {
		sessions, err := ParseLogonSessions(strings.NewReader(in))
		require.NoError(t, err, "input %q", in)
		assert.Empty(t, sessions, "input %q", in)
	}
}

func TestParseLogonSessionsMalformed(t *testing.T) {
	_, err := ParseLogonSessions(strings.NewReader(`{"LogonId":`))
	assert.Error(t, err)
}

func TestParseLogonSessionsBadTimestamp(t *testing.T) {
	// A timestamp that does not parse leaves the field null rather than
	// failing the whole collection or inventing the zero time.
	sessions, err := ParseLogonSessions(strings.NewReader(
		`[{"LogonId":"1","LogonType":2,"StartTime":"not-a-timestamp"}]`))
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Nil(t, sessions[0].StartTime)
	assert.Equal(t, "1", sessions[0].LogonId)
}

func TestLogonTypeName(t *testing.T) {
	// The documented SECURITY_LOGON_TYPE values. These are the names policies
	// are written against, so a wrong one silently retargets a check.
	assert.Equal(t, "Interactive", LogonTypeName(2))
	assert.Equal(t, "Network", LogonTypeName(3))
	assert.Equal(t, "Batch", LogonTypeName(4))
	assert.Equal(t, "Service", LogonTypeName(5))
	assert.Equal(t, "Unlock", LogonTypeName(7))
	assert.Equal(t, "NetworkCleartext", LogonTypeName(8))
	assert.Equal(t, "NewCredentials", LogonTypeName(9))
	assert.Equal(t, "RemoteInteractive", LogonTypeName(10))
	assert.Equal(t, "CachedInteractive", LogonTypeName(11))

	// Outside the documented set the name is empty rather than guessed, so a
	// caller can tell an unknown type from a known one. 0 and 1 are reported
	// by the system for sessions that predate a real logon.
	assert.Empty(t, LogonTypeName(0))
	assert.Empty(t, LogonTypeName(1))
	assert.Empty(t, LogonTypeName(6))
	assert.Empty(t, LogonTypeName(12))
	assert.Empty(t, LogonTypeName(-1))
}
