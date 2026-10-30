// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Zoom returns the meeting_security object ONLY for the
// `?option=meeting_security` view of the account and group settings
// endpoints. The un-optioned response documents a different set of sections
// entirely, so an un-optioned request decodes every meeting-security field to
// its zero value: waiting room off, no passcode, no E2EE. These tests pin both
// halves of that contract, the query the client sends and the value it decodes,
// against payloads shaped like the documented responses.

// newTestClient points a Client at a test server standing in for api.zoom.us.
func newTestClient(srv *httptest.Server) *Client {
	return &Client{httpClient: srv.Client(), baseURL: srv.URL}
}

// accountMeetingSecurityPayload is shaped like the documented
// GET /accounts/{accountId}/settings?option=meeting_security response.
const accountMeetingSecurityPayload = `{
  "meeting_security": {
    "auto_security": true,
    "waiting_room": true,
    "meeting_password": true,
    "pmi_password": true,
    "phone_password": true,
    "webinar_password": true,
    "encryption_type": "e2ee",
    "end_to_end_encrypted_meetings": true,
    "embed_password_in_join_link": false,
    "only_authenticated_can_join_from_webclient": true,
    "block_user_domain": false
  }
}`

// unoptionedAccountSettingsPayload is shaped like the documented un-optioned
// GET /accounts/{accountId}/settings response. Note that it has no
// meeting_security key at all.
const unoptionedAccountSettingsPayload = `{
  "schedule_meeting": {"enforce_login": true, "join_before_host": false, "host_video": false},
  "in_meeting": {"e2e_encryption": true, "chat": true},
  "recording": {"cloud_recording": true, "local_recording": true},
  "security": {
    "admin_change_name_pic": false,
    "sign_again_period_for_inactivity_on_client": 30,
    "sign_again_period_for_inactivity_on_web": 15
  }
}`

func TestGetAccountMeetingSecurityRequestsTheMeetingSecurityOption(t *testing.T) {
	var gotPath, gotOption string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotOption = r.URL.Query().Get("option")
		// Stand in for Zoom: only the meeting_security option returns the
		// meeting_security object.
		if gotOption != "meeting_security" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(unoptionedAccountSettingsPayload))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accountMeetingSecurityPayload))
	}))
	defer srv.Close()

	ms, err := newTestClient(srv).GetAccountMeetingSecurity(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("GetAccountMeetingSecurity: %v", err)
	}

	if want := "/accounts/acct-1/settings"; gotPath != want {
		t.Errorf("path: got %q, want %q", gotPath, want)
	}
	if want := "meeting_security"; gotOption != want {
		t.Errorf("option query parameter: got %q, want %q", gotOption, want)
	}
	if !ms.WaitingRoom {
		t.Error("waitingRoom: got false, want true")
	}
	if !ms.MeetingPasswordRequirement {
		t.Error("meetingPasscodeRequired: got false, want true")
	}
	if !ms.PmiPasswordRequirement {
		t.Error("meetingPmiPasscodeRequired: got false, want true")
	}
	if !ms.E2eeAvailable {
		t.Error("meetingE2eeAvailable: got false, want true")
	}
	if want := "e2ee"; ms.EncryptionType != want {
		t.Errorf("meetingEncryptionType: got %q, want %q", ms.EncryptionType, want)
	}
}

func TestGetGroupMeetingSecurityRequestsTheMeetingSecurityOption(t *testing.T) {
	var gotPath, gotOption string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotOption = r.URL.Query().Get("option")
		if gotOption != "meeting_security" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"schedule_meeting": {"host_video": false}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meeting_security": {
			"waiting_room": true,
			"meeting_password": true,
			"end_to_end_encrypted_meetings": true,
			"encryption_type": "enhanced_encryption"
		}}`))
	}))
	defer srv.Close()

	ms, err := newTestClient(srv).GetGroupMeetingSecurity(context.Background(), "grp-1")
	if err != nil {
		t.Fatalf("GetGroupMeetingSecurity: %v", err)
	}

	if want := "/groups/grp-1/settings"; gotPath != want {
		t.Errorf("path: got %q, want %q", gotPath, want)
	}
	if want := "meeting_security"; gotOption != want {
		t.Errorf("option query parameter: got %q, want %q", gotOption, want)
	}
	if !ms.WaitingRoom {
		t.Error("settingsWaitingRoomEnabled: got false, want true")
	}
	if !ms.MeetingPasswordRequirement {
		t.Error("settingsMeetingPasscodeRequired: got false, want true")
	}
	if !ms.E2eeAvailable {
		t.Error("settingsE2eeAvailable: got false, want true")
	}
}

// The bug this replaces: an un-optioned request against the documented
// un-optioned payload leaves every meeting-security field false, which reads
// as "waiting room off, no passcode, no E2EE" on an account that has all
// three enabled.
func TestUnoptionedAccountSettingsCarryNoMeetingSecurity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("option") != "" {
			t.Errorf("GetAccountSettings must not send an option, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(unoptionedAccountSettingsPayload))
	}))
	defer srv.Close()

	settings, err := newTestClient(srv).GetAccountSettings(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("GetAccountSettings: %v", err)
	}
	if !settings.Recording.CloudRecording {
		t.Error("cloudRecordingEnabled: got false, want true")
	}

	// A meeting-security field read off this response would be false, which is
	// why they are fetched through GetAccountMeetingSecurity instead. Decoding
	// the same payload into the meeting-security wrapper proves the key is
	// absent rather than merely unread.
	var wrapper meetingSecurityResponse
	if err := json.Unmarshal([]byte(unoptionedAccountSettingsPayload), &wrapper); err != nil {
		t.Fatal(err)
	}
	if wrapper.MeetingSecurity.WaitingRoom || wrapper.MeetingSecurity.MeetingPasswordRequirement ||
		wrapper.MeetingSecurity.E2eeAvailable || wrapper.MeetingSecurity.EncryptionType != "" {
		t.Errorf("un-optioned response unexpectedly carried meeting_security: %+v", wrapper.MeetingSecurity)
	}
}

// `meeting_security.only_authenticated_can_join` is not a Zoom field. The two
// controls it was standing in for are `schedule_meeting.enforce_login` in the
// un-optioned response and the top-level `meeting_authentication` boolean of
// the `?option=meeting_authentication` view. These tests pin both.

func TestAccountSettingsDecodeEnforceLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(unoptionedAccountSettingsPayload))
	}))
	defer srv.Close()

	settings, err := newTestClient(srv).GetAccountSettings(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("GetAccountSettings: %v", err)
	}
	if !settings.ScheduleMeeting.EnforceLogin {
		t.Error("meetingSignedInUsersOnly: got false, want true")
	}

	// The documented meeting_security view carries no sign-in requirement at
	// all, which is where the field used to be read from.
	var ms meetingSecurityResponse
	if err := json.Unmarshal([]byte(accountMeetingSecurityPayload), &ms); err != nil {
		t.Fatal(err)
	}
	if !ms.MeetingSecurity.WaitingRoom {
		t.Error("sanity: meeting_security payload should decode waiting_room true")
	}
}

func TestGetAccountMeetingAuthenticationRequestsTheOption(t *testing.T) {
	var gotOption string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOption = r.URL.Query().Get("option")
		w.Header().Set("Content-Type", "application/json")
		if gotOption != "meeting_authentication" {
			_, _ = w.Write([]byte(unoptionedAccountSettingsPayload))
			return
		}
		// Shaped like the documented option=meeting_authentication response:
		// meeting_authentication sits at the top level, not under
		// meeting_security.
		_, _ = w.Write([]byte(`{
			"meeting_authentication": true,
			"allow_authentication_exception": false,
			"authentication_options": [
				{"id": "mtg_enforce_domain_x", "name": "Sign in to Zoom with specified domain",
				 "type": "enforce_login_with_domains", "domains": "example.com", "default_option": true, "visible": true}
			]
		}`))
	}))
	defer srv.Close()

	auth, err := newTestClient(srv).GetAccountMeetingAuthentication(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("GetAccountMeetingAuthentication: %v", err)
	}
	if want := "meeting_authentication"; gotOption != want {
		t.Errorf("option query parameter: got %q, want %q", gotOption, want)
	}
	if !auth.MeetingAuthentication {
		t.Error("meetingAuthenticationRequired: got false, want true")
	}
}

func TestGetGroupMeetingAuthenticationRequestsTheOption(t *testing.T) {
	var gotPath, gotOption string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotOption = r.URL.Query().Get("option")
		w.Header().Set("Content-Type", "application/json")
		if gotOption != "meeting_authentication" {
			_, _ = w.Write([]byte(`{"schedule_meeting": {"host_video": false}}`))
			return
		}
		_, _ = w.Write([]byte(`{"meeting_authentication": true, "allow_authentication_exception": true}`))
	}))
	defer srv.Close()

	auth, err := newTestClient(srv).GetGroupMeetingAuthentication(context.Background(), "grp-1")
	if err != nil {
		t.Fatalf("GetGroupMeetingAuthentication: %v", err)
	}
	if want := "/groups/grp-1/settings"; gotPath != want {
		t.Errorf("path: got %q, want %q", gotPath, want)
	}
	if want := "meeting_authentication"; gotOption != want {
		t.Errorf("option query parameter: got %q, want %q", gotOption, want)
	}
	if !auth.MeetingAuthentication {
		t.Error("settingsOnlyAuthenticatedUsersCanJoin: got false, want true")
	}
}

// `security.session_timeout` is not a Zoom field. The sign-in inactivity
// timeouts are `sign_again_period_for_inactivity_on_client` and
// `sign_again_period_for_inactivity_on_web`, both in minutes, both 0 when the
// setting is switched off.
func TestAccountSettingsDecodeSignInInactivityPeriods(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(unoptionedAccountSettingsPayload))
	}))
	defer srv.Close()

	settings, err := newTestClient(srv).GetAccountSettings(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("GetAccountSettings: %v", err)
	}
	if want := int64(30); settings.Security.SignAgainPeriodForInactivityOnClient != want {
		t.Errorf("signInSessionTimeoutClientMinutes: got %d, want %d",
			settings.Security.SignAgainPeriodForInactivityOnClient, want)
	}
	if want := int64(15); settings.Security.SignAgainPeriodForInactivityOnWeb != want {
		t.Errorf("signInSessionTimeoutWebMinutes: got %d, want %d",
			settings.Security.SignAgainPeriodForInactivityOnWeb, want)
	}
}

// A response carrying the `session_timeout` key the provider used to read must
// leave both periods at 0: Zoom does not send it, and accepting it would hide
// the real keys regressing.
func TestAccountSettingsIgnoreSessionTimeoutKey(t *testing.T) {
	var settings AccountSettings
	if err := json.Unmarshal([]byte(`{"security": {"session_timeout": 15}}`), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Security.SignAgainPeriodForInactivityOnWeb != 0 ||
		settings.Security.SignAgainPeriodForInactivityOnClient != 0 {
		t.Errorf("session_timeout unexpectedly decoded: %+v", settings.Security)
	}
}

// An account with the timeouts switched off reports 0 for both, which is a
// real reading and not an absent key.
func TestAccountSettingsSignInInactivityPeriodsOff(t *testing.T) {
	var settings AccountSettings
	const payload = `{"security": {
		"sign_again_period_for_inactivity_on_client": 0,
		"sign_again_period_for_inactivity_on_web": 0
	}}`
	if err := json.Unmarshal([]byte(payload), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Security.SignAgainPeriodForInactivityOnClient != 0 ||
		settings.Security.SignAgainPeriodForInactivityOnWeb != 0 {
		t.Errorf("expected both periods 0, got %+v", settings.Security)
	}
}
