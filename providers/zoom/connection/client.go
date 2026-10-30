// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
)

// defaultBaseURL is the Zoom REST API v2 base URL.
const defaultBaseURL = "https://api.zoom.us/v2"

// Client is a minimal, hand-written typed HTTP client covering exactly the
// read endpoints the zoom.lr schema needs: account settings, users, roles,
// and groups. It is a pragmatic first implementation; see README.md for the
// production intent of a client generated from Zoom's published OpenAPI
// spec (ADR-033). Field names on the response types below are modeled after
// Zoom's documented account/user/role/group settings and may need
// adjustment once verified against (or regenerated from) that spec.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// newClient wraps an already-authenticated *http.Client (typically produced
// by clientcredentials.Config.Client) for calls against the Zoom API.
func newClient(httpClient *http.Client) *Client {
	return &Client{
		httpClient: httpClient,
		baseURL:    defaultBaseURL,
	}
}

// get issues an authenticated GET request against the Zoom API and decodes
// a JSON response into out. A nil out discards the response body after
// checking the status code.
func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return errors.Wrap(err, "failed to build zoom API request")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "zoom API request to %s failed", path)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "failed to read zoom API response from %s", path)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(path, resp.StatusCode, body)
	}

	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.Wrapf(err, "failed to decode zoom API response from %s", path)
	}
	return nil
}

// APIError is a non-2xx response from the Zoom API. Zoom carries its own
// error code in the response body alongside the HTTP status, and the two do
// not agree: an endpoint the account's plan does not include answers with an
// HTTP 4xx whose body code is 200. Classifying on this type rather than on a
// message match is what keeps a transport failure, which is wrapped as
// something else entirely and never as an *APIError, from being read as an
// answer the API actually gave.
type APIError struct {
	// Path is the API path that produced the error.
	Path string
	// StatusCode is the HTTP status of the response.
	StatusCode int
	// Code is Zoom's own error code from the response body, or 0 when the
	// body carried no code.
	Code int
	// Message is Zoom's error message from the response body.
	Message string
	// Body is the raw response body, kept for errors Zoom did not encode as
	// a code/message pair.
	Body string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("zoom API request to %s failed with status %d (code %d): %s", e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("zoom API request to %s failed with status %d: %s", e.Path, e.StatusCode, e.Body)
}

// newAPIError builds an *APIError from a non-2xx response, decoding Zoom's
// code/message envelope when the body carries one. A body that is not that
// envelope is preserved verbatim rather than discarded.
func newAPIError(path string, statusCode int, body []byte) *APIError {
	e := &APIError{Path: path, StatusCode: statusCode, Body: string(body)}
	var envelope struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		e.Code = envelope.Code
		e.Message = envelope.Message
	}
	return e
}

// planRestrictedCode is the code Zoom returns in the body of an error response
// for an endpoint the account's plan does not include ("Only available for
// paid account"). It collides numerically with HTTP 200, which is harmless
// here: a successful response never produces an *APIError.
const planRestrictedCode = 200

// IsPlanRestricted reports whether err is Zoom refusing an endpoint because
// the account's plan does not include it. Callers use it to report the
// posture as unread (null) rather than as an empty result, which would claim
// the account has none of whatever was being listed.
func IsPlanRestricted(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == planRestrictedCode
}

// IsNotFound reports whether err is a 404 from the Zoom API.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusNotFound
}

// IsForbidden reports whether err is the Zoom API refusing the request for
// want of authorization. A missing OAuth scope is a configuration problem the
// user has to fix, so callers surface it rather than degrading it to a null
// or an empty list.
func IsForbidden(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}

// maxPages caps how many pages a single paginated walk will request. Zoom's
// page size for these endpoints is 300, so the cap sits far above any real
// account while still bounding a cursor that never terminates.
const maxPages = 1000

// walkPages drives a Zoom `next_page_token` cursor. fetch is called with the
// token of the page to read and returns the token of the page after it, or an
// empty string when the walk is done. An endpoint that echoes back the token
// it was given instead of advancing would otherwise re-read the same page up
// to the cap, multiplying every record, so a repeated token ends the walk the
// same way an empty one does.
func walkPages(fetch func(token string) (string, error)) error {
	token := ""
	for range maxPages {
		next, err := fetch(token)
		if err != nil {
			return err
		}
		if next == "" || next == token {
			return nil
		}
		token = next
	}
	return errors.Newf("zoom API pagination did not terminate within %d pages", maxPages)
}

// ---- Users ----

// User is the subset of Zoom's user object this provider reads.
type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	DisplayName string `json:"display_name"`
	Type        int64  `json:"type"`
	Status      string `json:"status"`
	// Verified is 0 or 1 (whether the user's email address is verified).
	Verified int `json:"verified"`
	// LoginTypes is the user's sign-in methods. The Get a user and List users
	// responses return `login_types`, an array of integers; the singular
	// `login_type` the docs once described is a query parameter, not a
	// response field.
	LoginTypes []int64  `json:"login_types"`
	RoleID     string   `json:"role_id"`
	GroupIDs   []string `json:"group_ids"`
	// LastClientVersion is the Zoom client build the user last signed in
	// with, the only per-user signal of an outdated client on the account.
	LastClientVersion string     `json:"last_client_version"`
	LastLoginTime     *time.Time `json:"last_login_time"`
	// CreatedAt is when the user's most recent login type was created, which
	// is not the same instant as when the user was provisioned. Zoom reports
	// the latter separately as user_created_at.
	CreatedAt     *time.Time `json:"created_at"`
	UserCreatedAt *time.Time `json:"user_created_at"`
}

// UsersListResponse is the paginated response of the List Users endpoint.
type UsersListResponse struct {
	PageSize      int    `json:"page_size"`
	TotalRecords  int    `json:"total_records"`
	NextPageToken string `json:"next_page_token"`
	Users         []User `json:"users"`
}

// UserStatuses are the provisioning states a Zoom user can be in. The List
// Users endpoint answers for exactly one of them per call and defaults to
// active, so reading the account's full roster means asking for each in turn:
// a deactivated user still holds their group memberships and a pending user
// still holds a claim on an account email address.
var UserStatuses = []string{"active", "inactive", "pending"}

// ListUsers returns one page of users in the given status. Pass an empty
// nextPageToken to fetch the first page.
func (c *Client) ListUsers(ctx context.Context, status string, pageSize int, nextPageToken string) (*UsersListResponse, error) {
	q := url.Values{}
	q.Set("status", status)
	q.Set("page_size", strconv.Itoa(pageSize))
	if nextPageToken != "" {
		q.Set("next_page_token", nextPageToken)
	}

	var out UsersListResponse
	if err := c.get(ctx, "/users", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAllUsers returns every user provisioned on the account, in every
// status, paginating each status in turn.
func (c *Client) ListAllUsers(ctx context.Context, pageSize int) ([]User, error) {
	var all []User
	for _, status := range UserStatuses {
		err := walkPages(func(token string) (string, error) {
			list, err := c.ListUsers(ctx, status, pageSize, token)
			if err != nil {
				return "", err
			}
			all = append(all, list.Users...)
			return list.NextPageToken, nil
		})
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}

// GetUser fetches a single user by ID or email.
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	var out User
	if err := c.get(ctx, "/users/"+url.PathEscape(userID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMe fetches the user identified by the credentials used to connect,
// the cheapest authenticated read available to verify a connection.
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	return c.GetUser(ctx, "me")
}

// ---- Account ----

// AccountInfo is the account identity returned by Get Account.
type AccountInfo struct {
	ID          string `json:"id"`
	AccountName string `json:"account_name"`
	OwnerEmail  string `json:"owner_email"`
}

// GetAccount fetches the account's identity (name, owner email).
func (c *Client) GetAccount(ctx context.Context, accountID string) (*AccountInfo, error) {
	var out AccountInfo
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// optionMeetingSecurity is the `option` query value that selects the
// meeting-security view of the account and group settings endpoints. The
// meeting_security object is returned ONLY for this option: the un-optioned
// response documents an entirely different set of sections (schedule_meeting,
// in_meeting, recording, security, ...) and carries no meeting_security key,
// so an un-optioned request decodes every meeting-security field to false.
const optionMeetingSecurity = "meeting_security"

// optionMeetingAuthentication is the `option` query value that selects the
// meeting-authentication view of the account and group settings endpoints. The
// `meeting_authentication` boolean is returned only for this option and sits at
// the top level of that response, not inside meeting_security.
const optionMeetingAuthentication = "meeting_authentication"

// AccountSettings is the subset of the un-optioned Get Account Settings
// response this provider reads: the schedule-meeting sign-in requirement,
// cloud recording, and the sign-in security section. The meeting-security
// defaults live behind `?option=meeting_security` and are fetched separately,
// see GetAccountMeetingSecurity.
type AccountSettings struct {
	ScheduleMeeting struct {
		// EnforceLogin is Zoom's "only signed-in users can join meetings"
		// control. It applies to any signed-in Zoom user, not only to users on
		// this account.
		EnforceLogin bool `json:"enforce_login"`
		// JoinBeforeHost lets participants start a meeting without the host
		// present, which bypasses the host's admission of arrivals.
		JoinBeforeHost *bool `json:"join_before_host"`
	} `json:"schedule_meeting"`
	Recording AccountRecordingSettings `json:"recording"`
	Security  AccountSecuritySettings  `json:"security"`
}

// AccountRecordingSettings is the `recording` section of the un-optioned Get
// Account Settings response: what may be recorded, who may reach a recording
// once it exists, and how long it is kept. Every field beyond CloudRecording
// is a pointer so that a key the account's plan does not report stays null
// instead of reporting the permissive reading as fact.
type AccountRecordingSettings struct {
	CloudRecording bool  `json:"cloud_recording"`
	LocalRecording *bool `json:"local_recording"`
	// CloudRecordingDownload allows viewers to download a cloud recording
	// rather than only stream it.
	CloudRecordingDownload *bool `json:"cloud_recording_download"`
	// AccountUserAccessRecording restricts cloud recordings to account
	// members, so a shared link cannot be opened from outside the account.
	AccountUserAccessRecording *bool `json:"account_user_access_recording"`
	// AutoDeleteCmr and AutoDeleteCmrDays are Zoom's cloud-recording
	// retention control: whether recordings are deleted automatically, and
	// after how many days.
	AutoDeleteCmr     *bool  `json:"auto_delete_cmr"`
	AutoDeleteCmrDays *int64 `json:"auto_delete_cmr_days"`
	// RequiredPasswordForExistingCloudRecordings applies a passcode
	// requirement to recordings that were already made, not only to new ones.
	RequiredPasswordForExistingCloudRecordings *bool `json:"required_password_for_existing_cloud_recordings"`
	RecordingDisclaimer                        *bool `json:"recording_disclaimer"`
	// AutoRecording is one of local, cloud, or none.
	AutoRecording          *string `json:"auto_recording"`
	IPAddressAccessControl struct {
		Enable *bool `json:"enable"`
		// IPAddressesOrRanges is a comma-separated list of addresses and
		// ranges, not a JSON array.
		IPAddressesOrRanges *string `json:"ip_addresses_or_ranges"`
	} `json:"ip_address_access_control"`
}

// AccountSecuritySettings is the `security` section of the un-optioned Get
// Account Settings response, which is where workforce identity posture lives:
// two-factor enforcement, the password rules applied to Zoom-managed
// credentials, and the single sign-on requirement. Zoom documents the same
// keys at the top level of the `?option=security` view of the endpoint.
type AccountSecuritySettings struct {
	// SignAgainPeriodForInactivityOnClient and
	// SignAgainPeriodForInactivityOnWeb are the periods of inactivity, in
	// minutes, after which a signed-in user is automatically signed out of
	// the Zoom client and the Zoom web portal respectively. Zoom enforces
	// the two separately, and reports 0 for whichever is switched off.
	SignAgainPeriodForInactivityOnClient int64 `json:"sign_again_period_for_inactivity_on_client"`
	SignAgainPeriodForInactivityOnWeb    int64 `json:"sign_again_period_for_inactivity_on_web"`
	// SignInWithTwoFactorAuth is one of all, group, role, or none. Zoom only
	// returns SignInWithTwoFactorAuthGroups when the mode is group, and
	// SignInWithTwoFactorAuthRoles when the mode is role.
	SignInWithTwoFactorAuth       *string                    `json:"sign_in_with_two_factor_auth"`
	SignInWithTwoFactorAuthGroups []string                   `json:"sign_in_with_two_factor_auth_groups"`
	SignInWithTwoFactorAuthRoles  []string                   `json:"sign_in_with_two_factor_auth_roles"`
	PasswordRequirement           AccountPasswordRequirement `json:"password_requirement"`
	SignInWithSso                 AccountSsoSettings         `json:"signin_with_sso"`
}

// AccountPasswordRequirement is the rule set applied to the passwords of
// users who sign in with a Zoom-managed credential rather than through an
// identity provider.
type AccountPasswordRequirement struct {
	MinimumPasswordLength *int64 `json:"minimum_password_length"`
	HaveSpecialCharacter  *bool  `json:"have_special_character"`
	// ConsecutiveCharactersLength caps runs of consecutive characters
	// (abcde...). Zoom reports 0 when the rule is switched off.
	ConsecutiveCharactersLength *int64 `json:"consecutive_characters_length"`
	WeakEnhanceDetection        *bool  `json:"weak_enhance_detection"`
	// ExpiredRule is the number of days after which a password expires, and
	// FormerRule the number of previous passwords that cannot be reused.
	// Zoom reports 0 for whichever rule is switched off.
	ExpiredRule *int64 `json:"expired_rule"`
	FormerRule  *int64 `json:"former_rule"`
	// FirstLoginRule requires a new user to change their password on first
	// sign-in.
	FirstLoginRule *bool `json:"first_login_rule"`
}

// AccountSsoSettings is the account's single sign-on requirement, including
// the users exempted from it.
type AccountSsoSettings struct {
	Enable *bool `json:"enable"`
	// RequireSsoForDomains forces users whose email address is on one of
	// Domains to sign in through the identity provider.
	RequireSsoForDomains *bool    `json:"require_sso_for_domains"`
	Domains              []string `json:"domains"`
	// SsoBypassUsers are the users allowed to sign in without going through
	// the identity provider even when the requirement is on.
	SsoBypassUsers []SsoBypassUser `json:"sso_bypass_users"`
}

// SsoBypassUser identifies a user exempted from the account's single sign-on
// requirement.
type SsoBypassUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// SplitIPRanges splits Zoom's comma-separated ip_addresses_or_ranges encoding
// into one entry per address or range, discarding empty segments so a
// trailing comma or an all-whitespace value yields no entries rather than an
// empty-string entry that would read as a configured range.
func SplitIPRanges(v string) []string {
	out := []string{}
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

// GetAccountSettings fetches the un-optioned account settings: the recording
// and sign-in security sections.
func (c *Client) GetAccountSettings(ctx context.Context, accountID string) (*AccountSettings, error) {
	var out AccountSettings
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/settings", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MeetingSecuritySettings is the meeting_security object returned by the
// account and group settings endpoints under `?option=meeting_security`. Both
// endpoints document the same object, so one type serves the account defaults
// and the per-group overrides.
type MeetingSecuritySettings struct {
	WaitingRoom                bool   `json:"waiting_room"`
	MeetingPasswordRequirement bool   `json:"meeting_password"`
	PmiPasswordRequirement     bool   `json:"pmi_password"`
	EncryptionType             string `json:"encryption_type"`
	E2eeAvailable              bool   `json:"end_to_end_encrypted_meetings"`
}

// meetingSecurityResponse wraps the meeting_security object both settings
// endpoints nest their meeting-security view under.
type meetingSecurityResponse struct {
	MeetingSecurity MeetingSecuritySettings `json:"meeting_security"`
}

// GetAccountMeetingSecurity fetches the account-wide meeting-security
// defaults, which the settings endpoint only returns for
// `?option=meeting_security`.
func (c *Client) GetAccountMeetingSecurity(ctx context.Context, accountID string) (*MeetingSecuritySettings, error) {
	var out meetingSecurityResponse
	q := url.Values{"option": {optionMeetingSecurity}}
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/settings", q, &out); err != nil {
		return nil, err
	}
	return &out.MeetingSecurity, nil
}

// MeetingAuthenticationSettings is the meeting-authentication view of the
// account and group settings endpoints. Both endpoints document the same
// top-level `meeting_authentication` boolean, so one type serves the account
// default and the per-group override.
type MeetingAuthenticationSettings struct {
	// MeetingAuthentication is Zoom's "only authenticated users can join
	// meetings" control.
	MeetingAuthentication bool `json:"meeting_authentication"`
}

// GetAccountMeetingAuthentication fetches the account-wide
// meeting-authentication requirement, which the settings endpoint only returns
// for `?option=meeting_authentication`.
func (c *Client) GetAccountMeetingAuthentication(ctx context.Context, accountID string) (*MeetingAuthenticationSettings, error) {
	var out MeetingAuthenticationSettings
	q := url.Values{"option": {optionMeetingAuthentication}}
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/settings", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Roles ----

// Role is a Zoom role definition.
type Role struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	TotalMembers int64    `json:"total_members"`
	Privileges   []string `json:"privileges"`
}

// RolesListResponse is the response of the List Roles endpoint. Zoom does
// not paginate roles: an account's role set is small and returned in full.
type RolesListResponse struct {
	TotalRecords int    `json:"total_records"`
	Roles        []Role `json:"roles"`
}

// ListRoles returns every role defined on the account.
func (c *Client) ListRoles(ctx context.Context) (*RolesListResponse, error) {
	var out RolesListResponse
	if err := c.get(ctx, "/roles", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRole fetches a single role by ID.
func (c *Client) GetRole(ctx context.Context, roleID string) (*Role, error) {
	var out Role
	if err := c.get(ctx, "/roles/"+url.PathEscape(roleID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RoleMember is a member entry returned by List Role Members.
type RoleMember struct {
	ID string `json:"id"`
}

// RoleMembersResponse is the paginated response of List Role Members.
type RoleMembersResponse struct {
	PageSize      int          `json:"page_size"`
	TotalRecords  int          `json:"total_records"`
	NextPageToken string       `json:"next_page_token"`
	Members       []RoleMember `json:"members"`
}

// ListRoleMembers returns one page of users assigned the given role.
func (c *Client) ListRoleMembers(ctx context.Context, roleID string, pageSize int, nextPageToken string) (*RoleMembersResponse, error) {
	q := url.Values{}
	q.Set("page_size", strconv.Itoa(pageSize))
	if nextPageToken != "" {
		q.Set("next_page_token", nextPageToken)
	}

	var out RoleMembersResponse
	if err := c.get(ctx, "/roles/"+url.PathEscape(roleID)+"/members", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Groups ----

// Group is a Zoom user group.
type Group struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TotalMembers int64  `json:"total_members"`
}

// GroupsListResponse is the response of the List Groups endpoint.
type GroupsListResponse struct {
	TotalRecords int     `json:"total_records"`
	Groups       []Group `json:"groups"`
}

// ListGroups returns every group defined on the account.
func (c *Client) ListGroups(ctx context.Context) (*GroupsListResponse, error) {
	var out GroupsListResponse
	if err := c.get(ctx, "/groups", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetGroup fetches a single group by ID.
func (c *Client) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	var out Group
	if err := c.get(ctx, "/groups/"+url.PathEscape(groupID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetGroupMeetingSecurity fetches the meeting-security overrides configured on
// a group, which take precedence over the account defaults for the group's
// members. As with the account endpoint, the group settings endpoint only
// returns the meeting_security object for `?option=meeting_security`.
func (c *Client) GetGroupMeetingSecurity(ctx context.Context, groupID string) (*MeetingSecuritySettings, error) {
	var out meetingSecurityResponse
	q := url.Values{"option": {optionMeetingSecurity}}
	if err := c.get(ctx, "/groups/"+url.PathEscape(groupID)+"/settings", q, &out); err != nil {
		return nil, err
	}
	return &out.MeetingSecurity, nil
}

// GetGroupMeetingAuthentication fetches the group's meeting-authentication
// override, which the group settings endpoint only returns for
// `?option=meeting_authentication`.
func (c *Client) GetGroupMeetingAuthentication(ctx context.Context, groupID string) (*MeetingAuthenticationSettings, error) {
	var out MeetingAuthenticationSettings
	q := url.Values{"option": {optionMeetingAuthentication}}
	if err := c.get(ctx, "/groups/"+url.PathEscape(groupID)+"/settings", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GroupMember is a member entry returned by List Group Members.
type GroupMember struct {
	ID string `json:"id"`
}

// GroupMembersResponse is the paginated response of List Group Members.
type GroupMembersResponse struct {
	PageSize      int           `json:"page_size"`
	TotalRecords  int           `json:"total_records"`
	NextPageToken string        `json:"next_page_token"`
	Members       []GroupMember `json:"members"`
}

// ListGroupMembers returns one page of users belonging to the given group.
func (c *Client) ListGroupMembers(ctx context.Context, groupID string, pageSize int, nextPageToken string) (*GroupMembersResponse, error) {
	q := url.Values{}
	q.Set("page_size", strconv.Itoa(pageSize))
	if nextPageToken != "" {
		q.Set("next_page_token", nextPageToken)
	}

	var out GroupMembersResponse
	if err := c.get(ctx, "/groups/"+url.PathEscape(groupID)+"/members", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Account lock settings ----

// AccountLockSettings is the subset of the un-optioned Get Account Lock
// Settings response this provider reads. A locked setting is one an account
// admin has fixed for everyone: users and groups cannot override it. Without
// it every account default is advisory, because an unlocked waiting room can
// be switched off per user. Every field is a pointer so a section the
// response omits stays null rather than reporting "not locked" as fact.
type AccountLockSettings struct {
	ScheduleMeeting struct {
		EnforceLogin          *bool `json:"enforce_login"`
		MeetingAuthentication *bool `json:"meeting_authentication"`
		JoinBeforeHost        *bool `json:"join_before_host"`
	} `json:"schedule_meeting"`
	Recording struct {
		CloudRecording *bool `json:"cloud_recording"`
		LocalRecording *bool `json:"local_recording"`
		AutoDeleteCmr  *bool `json:"auto_delete_cmr"`
	} `json:"recording"`
}

// GetAccountLockSettings fetches the un-optioned lock settings: which
// schedule-meeting and recording defaults users cannot override.
func (c *Client) GetAccountLockSettings(ctx context.Context, accountID string) (*AccountLockSettings, error) {
	var out AccountLockSettings
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/lock_settings", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MeetingSecurityLockSettings is the meeting-security view of the lock
// settings endpoint, which like the settings endpoint returns the
// meeting_security object only for `?option=meeting_security`.
//
// Zoom's published specs disagree on the type of the meeting_security
// encryption_type lock, one documenting a string and the other a boolean, so
// it is deliberately left unmapped: a mismatched type fails the decode of the
// whole response and would take every other lock down with it.
type MeetingSecurityLockSettings struct {
	WaitingRoom     *bool `json:"waiting_room"`
	MeetingPassword *bool `json:"meeting_password"`
	PmiPassword     *bool `json:"pmi_password"`
	E2eeAvailable   *bool `json:"end_to_end_encrypted_meetings"`
}

// meetingSecurityLockResponse wraps the meeting_security object the lock
// settings endpoint nests its meeting-security view under.
type meetingSecurityLockResponse struct {
	MeetingSecurity MeetingSecurityLockSettings `json:"meeting_security"`
}

// GetAccountMeetingSecurityLock fetches which of the account's
// meeting-security defaults are locked against per-user and per-group
// override.
func (c *Client) GetAccountMeetingSecurityLock(ctx context.Context, accountID string) (*MeetingSecurityLockSettings, error) {
	var out meetingSecurityLockResponse
	q := url.Values{"option": {optionMeetingSecurity}}
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/lock_settings", q, &out); err != nil {
		return nil, err
	}
	return &out.MeetingSecurity, nil
}

// ---- Domains ----

// ManagedDomain is a domain the account has claimed. Anyone who signs up with
// an email address on a managed domain is placed on this account, so a stale
// or wrongly verified entry is a standing path onto the account.
type ManagedDomain struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
}

// ManagedDomainsResponse is the response of the Get Account's Managed Domains
// endpoint. Zoom does not paginate it.
type ManagedDomainsResponse struct {
	Domains      []ManagedDomain `json:"domains"`
	TotalRecords int             `json:"total_records"`
}

// GetManagedDomains returns the domains the account has claimed. Zoom offers
// the endpoint only to paid accounts, so callers check IsPlanRestricted.
func (c *Client) GetManagedDomains(ctx context.Context, accountID string) (*ManagedDomainsResponse, error) {
	var out ManagedDomainsResponse
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/managed_domains", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TrustedDomainsResponse is the response of the Get Account's Trusted Domains
// endpoint. Zoom does not paginate it.
type TrustedDomainsResponse struct {
	TrustedDomains []string `json:"trusted_domains"`
}

// GetTrustedDomains returns the domains the account trusts. Zoom offers the
// endpoint only to paid accounts, so callers check IsPlanRestricted.
func (c *Client) GetTrustedDomains(ctx context.Context, accountID string) (*TrustedDomainsResponse, error) {
	var out TrustedDomainsResponse
	if err := c.get(ctx, "/accounts/"+url.PathEscape(accountID)+"/trusted_domains", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Membership walks ----

// ListAllRoleMembers returns the IDs of every user assigned the given role.
func (c *Client) ListAllRoleMembers(ctx context.Context, roleID string, pageSize int) ([]string, error) {
	var ids []string
	err := walkPages(func(token string) (string, error) {
		list, err := c.ListRoleMembers(ctx, roleID, pageSize, token)
		if err != nil {
			return "", err
		}
		for _, m := range list.Members {
			ids = append(ids, m.ID)
		}
		return list.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// ListAllGroupMembers returns the IDs of every user belonging to the given
// group.
func (c *Client) ListAllGroupMembers(ctx context.Context, groupID string, pageSize int) ([]string, error) {
	var ids []string
	err := walkPages(func(token string) (string, error) {
		list, err := c.ListGroupMembers(ctx, groupID, pageSize, token)
		if err != nil {
			return "", err
		}
		for _, m := range list.Members {
			ids = append(ids, m.ID)
		}
		return list.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}
