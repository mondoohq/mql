// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// This provider has shipped six fields that decoded a key the Zoom API does
// not return, each reporting a confident safe-looking value on every account.
// The tests below pin the struct tags of the security, recording, lock, and
// domain records against payloads shaped like the documented responses, so a
// mistyped tag fails here rather than passing an audit.

// securitySettingsPayload is shaped like the `security` section of the
// documented un-optioned GET /accounts/{accountId}/settings response.
const securitySettingsPayload = `{
  "schedule_meeting": {"enforce_login": true, "join_before_host": true},
  "recording": {
    "cloud_recording": true,
    "local_recording": false,
    "cloud_recording_download": true,
    "account_user_access_recording": true,
    "auto_delete_cmr": true,
    "auto_delete_cmr_days": 90,
    "required_password_for_existing_cloud_recordings": true,
    "recording_disclaimer": true,
    "auto_recording": "cloud",
    "ip_address_access_control": {
      "enable": true,
      "ip_addresses_or_ranges": "10.0.0.0/8, 192.0.2.1"
    }
  },
  "security": {
    "sign_again_period_for_inactivity_on_client": 30,
    "sign_again_period_for_inactivity_on_web": 15,
    "sign_in_with_two_factor_auth": "group",
    "sign_in_with_two_factor_auth_groups": ["g1", "g2"],
    "sign_in_with_two_factor_auth_roles": ["r1"],
    "password_requirement": {
      "minimum_password_length": 12,
      "have_special_character": true,
      "consecutive_characters_length": 4,
      "weak_enhance_detection": true,
      "expired_rule": 90,
      "former_rule": 5,
      "first_login_rule": true
    },
    "signin_with_sso": {
      "enable": true,
      "require_sso_for_domains": true,
      "domains": ["example.com"],
      "sso_bypass_users": [{"id": "u1", "email": "one@example.com"}]
    }
  }
}`

func TestAccountSettingsDecodeSecurityPosture(t *testing.T) {
	s := decodeAccountSettings(t, securitySettingsPayload)

	if s.Security.SignInWithTwoFactorAuth == nil || *s.Security.SignInWithTwoFactorAuth != "group" {
		t.Errorf("twoFactorAuthMode: got %v, want \"group\"", s.Security.SignInWithTwoFactorAuth)
	}
	if !reflect.DeepEqual(s.Security.SignInWithTwoFactorAuthGroups, []string{"g1", "g2"}) {
		t.Errorf("twoFactorAuthGroups: got %v, want [g1 g2]", s.Security.SignInWithTwoFactorAuthGroups)
	}
	if !reflect.DeepEqual(s.Security.SignInWithTwoFactorAuthRoles, []string{"r1"}) {
		t.Errorf("twoFactorAuthRoles: got %v, want [r1]", s.Security.SignInWithTwoFactorAuthRoles)
	}

	pw := s.Security.PasswordRequirement
	assertInt64Ptr(t, "passwordMinimumLength", pw.MinimumPasswordLength, 12)
	assertBoolPtr(t, "passwordSpecialCharacterRequired", pw.HaveSpecialCharacter, true)
	assertInt64Ptr(t, "passwordMaxConsecutiveCharacters", pw.ConsecutiveCharactersLength, 4)
	assertBoolPtr(t, "passwordWeakDetectionEnabled", pw.WeakEnhanceDetection, true)
	assertInt64Ptr(t, "passwordExpiryDays", pw.ExpiredRule, 90)
	assertInt64Ptr(t, "passwordHistoryCount", pw.FormerRule, 5)
	assertBoolPtr(t, "passwordChangeRequiredOnFirstSignIn", pw.FirstLoginRule, true)

	sso := s.Security.SignInWithSso
	assertBoolPtr(t, "ssoSignInEnabled", sso.Enable, true)
	assertBoolPtr(t, "ssoRequiredForDomains", sso.RequireSsoForDomains, true)
	if !reflect.DeepEqual(sso.Domains, []string{"example.com"}) {
		t.Errorf("ssoRequiredDomains: got %v, want [example.com]", sso.Domains)
	}
	if len(sso.SsoBypassUsers) != 1 || sso.SsoBypassUsers[0].ID != "u1" || sso.SsoBypassUsers[0].Email != "one@example.com" {
		t.Errorf("ssoBypassUsers: got %v, want one entry for u1", sso.SsoBypassUsers)
	}
}

func TestAccountSettingsDecodeRecordingGovernance(t *testing.T) {
	s := decodeAccountSettings(t, securitySettingsPayload)

	r := s.Recording
	if !r.CloudRecording {
		t.Error("cloudRecordingEnabled: got false, want true")
	}
	assertBoolPtr(t, "localRecordingEnabled", r.LocalRecording, false)
	assertBoolPtr(t, "recordingDownloadEnabled", r.CloudRecordingDownload, true)
	assertBoolPtr(t, "recordingAccountMembersOnly", r.AccountUserAccessRecording, true)
	assertBoolPtr(t, "recordingAutoDeleteEnabled", r.AutoDeleteCmr, true)
	assertInt64Ptr(t, "recordingAutoDeleteDays", r.AutoDeleteCmrDays, 90)
	assertBoolPtr(t, "recordingExistingPasscodeRequired", r.RequiredPasswordForExistingCloudRecordings, true)
	assertBoolPtr(t, "recordingDisclaimerEnabled", r.RecordingDisclaimer, true)
	if r.AutoRecording == nil || *r.AutoRecording != "cloud" {
		t.Errorf("autoRecordingMode: got %v, want \"cloud\"", r.AutoRecording)
	}
	assertBoolPtr(t, "recordingIpAccessControlEnabled", r.IPAddressAccessControl.Enable, true)
	if r.IPAddressAccessControl.IPAddressesOrRanges == nil {
		t.Fatal("recordingIpAccessRanges: got nil, want the comma-separated list")
	}
	assertBoolPtr(t, "joinBeforeHostEnabled", s.ScheduleMeeting.JoinBeforeHost, true)
}

// An account whose plan does not report a setting must leave it null, not
// false. `null && null` evaluates to true in MQL, so a fabricated false on
// two-factor enforcement or an account lock would let an assertion pass on an
// account where nothing was read at all.
func TestAccountSettingsAbsentKeysStayNil(t *testing.T) {
	s := decodeAccountSettings(t, `{"security": {}, "recording": {}, "schedule_meeting": {}}`)

	if s.Security.SignInWithTwoFactorAuth != nil {
		t.Errorf("twoFactorAuthMode: got %v, want nil", *s.Security.SignInWithTwoFactorAuth)
	}
	if s.Security.PasswordRequirement.MinimumPasswordLength != nil {
		t.Errorf("passwordMinimumLength: got %v, want nil", *s.Security.PasswordRequirement.MinimumPasswordLength)
	}
	if s.Security.PasswordRequirement.FirstLoginRule != nil {
		t.Errorf("passwordChangeRequiredOnFirstSignIn: got %v, want nil", *s.Security.PasswordRequirement.FirstLoginRule)
	}
	if s.Security.SignInWithSso.Enable != nil {
		t.Errorf("ssoSignInEnabled: got %v, want nil", *s.Security.SignInWithSso.Enable)
	}
	if s.Recording.AutoDeleteCmr != nil {
		t.Errorf("recordingAutoDeleteEnabled: got %v, want nil", *s.Recording.AutoDeleteCmr)
	}
	if s.Recording.IPAddressAccessControl.Enable != nil {
		t.Errorf("recordingIpAccessControlEnabled: got %v, want nil", *s.Recording.IPAddressAccessControl.Enable)
	}
	if s.ScheduleMeeting.JoinBeforeHost != nil {
		t.Errorf("joinBeforeHostEnabled: got %v, want nil", *s.ScheduleMeeting.JoinBeforeHost)
	}
}

// ---- lock settings ----

func TestGetAccountLockSettingsDecodesLocks(t *testing.T) {
	const payload = `{
	  "schedule_meeting": {"enforce_login": true, "meeting_authentication": false, "join_before_host": true},
	  "recording": {"cloud_recording": true, "local_recording": false, "auto_delete_cmr": true},
	  "in_meeting": {"chat": true}
	}`

	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		fmt.Fprint(w, payload)
	}))
	defer srv.Close()

	locks, err := newTestClient(srv).GetAccountLockSettings(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAccountLockSettings: %v", err)
	}
	// The un-optioned view is the one carrying the schedule-meeting and
	// recording locks; asking for an option would return a different object.
	if got := gotQuery.Get("option"); got != "" {
		t.Errorf("option: got %q, want no option", got)
	}
	assertBoolPtr(t, "meetingSignedInUsersOnlyLocked", locks.ScheduleMeeting.EnforceLogin, true)
	assertBoolPtr(t, "meetingAuthenticationRequiredLocked", locks.ScheduleMeeting.MeetingAuthentication, false)
	assertBoolPtr(t, "joinBeforeHostLocked", locks.ScheduleMeeting.JoinBeforeHost, true)
	assertBoolPtr(t, "cloudRecordingLocked", locks.Recording.CloudRecording, true)
	assertBoolPtr(t, "localRecordingLocked", locks.Recording.LocalRecording, false)
	assertBoolPtr(t, "recordingAutoDeleteLocked", locks.Recording.AutoDeleteCmr, true)
}

func TestGetAccountMeetingSecurityLockRequestsTheOption(t *testing.T) {
	const payload = `{
	  "meeting_security": {
	    "waiting_room": true,
	    "meeting_password": true,
	    "pmi_password": false,
	    "end_to_end_encrypted_meetings": true,
	    "encryption_type": "e2ee"
	  }
	}`

	var gotOption string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOption = r.URL.Query().Get("option")
		fmt.Fprint(w, payload)
	}))
	defer srv.Close()

	locks, err := newTestClient(srv).GetAccountMeetingSecurityLock(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAccountMeetingSecurityLock: %v", err)
	}
	// The meeting_security object is returned only for this option, exactly as
	// on the settings endpoint.
	if gotOption != "meeting_security" {
		t.Errorf("option: got %q, want %q", gotOption, "meeting_security")
	}
	assertBoolPtr(t, "waitingRoomLocked", locks.WaitingRoom, true)
	assertBoolPtr(t, "meetingPasscodeLocked", locks.MeetingPassword, true)
	assertBoolPtr(t, "pmiPasscodeLocked", locks.PmiPassword, false)
	assertBoolPtr(t, "meetingE2eeAvailableLocked", locks.E2eeAvailable, true)
}

// Zoom's two published specs disagree on whether the meeting_security
// encryption_type lock is a string or a boolean. It is deliberately left
// unmapped, because a mismatched type fails the decode of the whole response
// and would take every other lock down with it.
func TestMeetingSecurityLockToleratesAStringEncryptionType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"meeting_security": {"waiting_room": true, "encryption_type": "e2ee"}}`)
	}))
	defer srv.Close()

	locks, err := newTestClient(srv).GetAccountMeetingSecurityLock(context.Background(), "acct")
	if err != nil {
		t.Fatalf("a string encryption_type must not fail the decode: %v", err)
	}
	assertBoolPtr(t, "waitingRoomLocked", locks.WaitingRoom, true)
}

// ---- domains ----

func TestGetManagedDomainsDecodesDomainAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"total_records": 2, "domains": [
		  {"domain": "example.com", "status": "verified"},
		  {"domain": "example.net", "status": "pending"}
		]}`)
	}))
	defer srv.Close()

	res, err := newTestClient(srv).GetManagedDomains(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetManagedDomains: %v", err)
	}
	if len(res.Domains) != 2 {
		t.Fatalf("domains: got %d, want 2", len(res.Domains))
	}
	if res.Domains[0].Domain != "example.com" || res.Domains[0].Status != "verified" {
		t.Errorf("first domain: got %+v", res.Domains[0])
	}
	if res.Domains[1].Status != "pending" {
		t.Errorf("second domain status: got %q, want %q", res.Domains[1].Status, "pending")
	}
}

func TestGetTrustedDomainsDecodesList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"trusted_domains": ["example.com", "example.org"]}`)
	}))
	defer srv.Close()

	res, err := newTestClient(srv).GetTrustedDomains(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetTrustedDomains: %v", err)
	}
	if !reflect.DeepEqual(res.TrustedDomains, []string{"example.com", "example.org"}) {
		t.Errorf("trustedDomains: got %v", res.TrustedDomains)
	}
}

// ---- error classification ----

// A network blip must not be mistaken for an answer the API gave. If a
// transport error matched a classifier, the caller would report the posture as
// unread-but-fine, or as an empty list, and an audit would pass on data that
// was never read.
func TestErrorClassifiersRejectTransportErrors(t *testing.T) {
	transport := errors.New("dial tcp: connection refused")
	if IsPlanRestricted(transport) {
		t.Error("IsPlanRestricted matched a transport error")
	}
	if IsNotFound(transport) {
		t.Error("IsNotFound matched a transport error")
	}
	if IsForbidden(transport) {
		t.Error("IsForbidden matched a transport error")
	}
}

func TestErrorClassifiers(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		body           string
		planRestricted bool
		notFound       bool
		forbidden      bool
	}{
		{
			name:           "plan restricted",
			status:         http.StatusBadRequest,
			body:           `{"code": 200, "message": "Only available for paid account."}`,
			planRestricted: true,
		},
		{
			name:     "not found",
			status:   http.StatusNotFound,
			body:     `{"code": 1001, "message": "Account does not exist."}`,
			notFound: true,
		},
		{
			// A missing OAuth scope is a configuration problem the user has to
			// fix. Degrading it to an empty list would make "not allowed to
			// read the domains" indistinguishable from "the account claims
			// none".
			name:      "forbidden",
			status:    http.StatusForbidden,
			body:      `{"code": 4711, "message": "Invalid access token, does not contain scopes."}`,
			forbidden: true,
		},
		{
			name:   "server error carries no classification",
			status: http.StatusInternalServerError,
			body:   `<html>gateway error</html>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()

			_, err := newTestClient(srv).GetTrustedDomains(context.Background(), "acct")
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := IsPlanRestricted(err); got != tc.planRestricted {
				t.Errorf("IsPlanRestricted: got %v, want %v", got, tc.planRestricted)
			}
			if got := IsNotFound(err); got != tc.notFound {
				t.Errorf("IsNotFound: got %v, want %v", got, tc.notFound)
			}
			if got := IsForbidden(err); got != tc.forbidden {
				t.Errorf("IsForbidden: got %v, want %v", got, tc.forbidden)
			}
			// A body Zoom did not encode as a code/message pair is preserved
			// rather than discarded, so the message still says what happened.
			if tc.body != "" && !strings.Contains(err.Error(), "acct") && !strings.Contains(err.Error(), "trusted_domains") {
				t.Errorf("error message lost the request path: %v", err)
			}
		})
	}
}

// ---- pagination ----

func TestListAllUsersWalksEveryStatus(t *testing.T) {
	var gotStatuses []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		gotStatuses = append(gotStatuses, status)
		fmt.Fprintf(w, `{"users": [{"id": "%s-1", "status": "%s"}]}`, status, status)
	}))
	defer srv.Close()

	users, err := newTestClient(srv).ListAllUsers(context.Background(), 300)
	if err != nil {
		t.Fatalf("ListAllUsers: %v", err)
	}
	if !reflect.DeepEqual(gotStatuses, []string{"active", "inactive", "pending"}) {
		t.Errorf("statuses requested: got %v, want [active inactive pending]", gotStatuses)
	}
	if len(users) != 3 {
		t.Fatalf("users: got %d, want 3", len(users))
	}
}

func TestListAllUsersPaginates(t *testing.T) {
	pages := map[string]string{
		"": `{"users": [{"id": "u1"}], "next_page_token": "p2"}`,
	}
	pages["p2"] = `{"users": [{"id": "u2"}], "next_page_token": ""}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("status") != "active" {
			fmt.Fprint(w, `{"users": []}`)
			return
		}
		fmt.Fprint(w, pages[r.URL.Query().Get("next_page_token")])
	}))
	defer srv.Close()

	users, err := newTestClient(srv).ListAllUsers(context.Background(), 300)
	if err != nil {
		t.Fatalf("ListAllUsers: %v", err)
	}
	if len(users) != 2 || users[0].ID != "u1" || users[1].ID != "u2" {
		t.Errorf("users: got %v, want [u1 u2]", users)
	}
}

// An endpoint that echoes back the token it was given instead of advancing
// would otherwise re-read the same page up to the cap, multiplying every
// record. The walk stops on a repeated token the same way it stops on an
// empty one.
func TestPaginationStopsOnAStuckCursor(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("status") != "active" {
			fmt.Fprint(w, `{"users": []}`)
			return
		}
		// Always hands back the same token, whichever page was asked for.
		fmt.Fprint(w, `{"users": [{"id": "u1"}], "next_page_token": "stuck"}`)
	}))
	defer srv.Close()

	users, err := newTestClient(srv).ListAllUsers(context.Background(), 300)
	if err != nil {
		t.Fatalf("ListAllUsers: %v", err)
	}
	// One page for the first token, one for the repeat that proves the cursor
	// is stuck, and one for each of the two remaining statuses.
	if len(users) != 2 {
		t.Errorf("users: got %d, want 2 (the walk must stop on a repeated token)", len(users))
	}
	if calls > 6 {
		t.Errorf("requests: got %d, want a handful (the walk did not stop)", calls)
	}
}

func TestListAllGroupMembersPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("next_page_token") {
		case "":
			fmt.Fprint(w, `{"members": [{"id": "m1"}], "next_page_token": "p2"}`)
		default:
			fmt.Fprint(w, `{"members": [{"id": "m2"}]}`)
		}
	}))
	defer srv.Close()

	ids, err := newTestClient(srv).ListAllGroupMembers(context.Background(), "g1", 300)
	if err != nil {
		t.Fatalf("ListAllGroupMembers: %v", err)
	}
	if !reflect.DeepEqual(ids, []string{"m1", "m2"}) {
		t.Errorf("members: got %v, want [m1 m2]", ids)
	}
}

// ---- helpers ----

func TestSplitIPRanges(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"10.0.0.0/8", []string{"10.0.0.0/8"}},
		{"10.0.0.0/8, 192.0.2.1", []string{"10.0.0.0/8", "192.0.2.1"}},
		{"10.0.0.0/8 - 10.0.0.255", []string{"10.0.0.0/8 - 10.0.0.255"}},
		// A trailing comma or an all-whitespace value must yield no entries
		// rather than an empty-string entry, which would read as a configured
		// range and make an unrestricted allow list look populated.
		{"10.0.0.0/8,", []string{"10.0.0.0/8"}},
		{"", []string{}},
		{"  ", []string{}},
		{",,", []string{}},
	}

	for _, tc := range tests {
		if got := SplitIPRanges(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SplitIPRanges(%q): got %v, want %v", tc.in, got, tc.want)
		}
	}
}

func decodeAccountSettings(t *testing.T, payload string) *AccountSettings {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payload)
	}))
	defer srv.Close()

	s, err := newTestClient(srv).GetAccountSettings(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAccountSettings: %v", err)
	}
	return s
}

func assertBoolPtr(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: got nil, want %v", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s: got %v, want %v", name, *got, want)
	}
}

func assertInt64Ptr(t *testing.T, name string, got *int64, want int64) {
	t.Helper()
	if got == nil {
		t.Errorf("%s: got nil, want %d", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s: got %d, want %d", name, *got, want)
	}
}
