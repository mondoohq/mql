// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.mondoo.com/mql/providers/circleci/connection"
)

// The CircleCI API records this provider maps are decoded by struct tag
// alone. A mistyped tag compiles, lints, and yields a zero value, which
// surfaces as a confident "false" or "" rather than an error. Go's
// encoding/json also matches field names case-insensitively, so a payload
// written with the wrong casing passes against a wrong tag and proves
// nothing. These tests therefore use the exact key spelling CircleCI
// returns (note the split: the project settings block is snake_case, while
// webhooks and checkout keys are hyphenated), and pair each
// security-relevant field with a negative case that decodes a deliberately
// wrong key and asserts the field stays null.

func wantBool(t *testing.T, label string, got *bool, want bool) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: expected %v, got nil", label, want)
	}
	if *got != want {
		t.Fatalf("%s: expected %v, got %v", label, want, *got)
	}
}

func wantNilBool(t *testing.T, label string, got *bool) {
	t.Helper()
	if got != nil {
		t.Fatalf("%s: expected nil (key absent means never read), got %v", label, *got)
	}
}

// advancedSettingsFields is the complete set of *bool flags on
// connection.AdvancedSettings, keyed by the JSON name CircleCI returns under
// the "advanced" block of GET /project/{project-slug}/settings.
var advancedSettingsFields = []struct {
	key string
	get func(connection.AdvancedSettings) *bool
}{
	{"build_fork_prs", func(s connection.AdvancedSettings) *bool { return s.BuildForkPrs }},
	{"forks_receive_secret_env_vars", func(s connection.AdvancedSettings) *bool { return s.ForksReceiveSecretEnvVars }},
	{"build_prs_only", func(s connection.AdvancedSettings) *bool { return s.BuildPrsOnly }},
	{"write_settings_requires_admin", func(s connection.AdvancedSettings) *bool { return s.WriteSettingsRequiresAdmin }},
	{"disable_ssh", func(s connection.AdvancedSettings) *bool { return s.DisableSsh }},
	{"set_github_status", func(s connection.AdvancedSettings) *bool { return s.SetGithubStatus }},
	{"autocancel_builds", func(s connection.AdvancedSettings) *bool { return s.AutocancelBuilds }},
}

// TestAdvancedSettingsPinsEachBooleanTag decodes a settings payload carrying
// exactly one advanced flag and asserts that only the matching Go field
// receives it. Isolating one key per subtest catches both a wrong tag (the
// field stays nil) and two fields whose tags are swapped (the wrong field
// lights up), which a payload setting every key to the same value cannot.
func TestAdvancedSettingsPinsEachBooleanTag(t *testing.T) {
	for _, tc := range advancedSettingsFields {
		t.Run(tc.key, func(t *testing.T) {
			payload := fmt.Sprintf(`{"advanced":{%q:true}}`, tc.key)

			var rec connection.ProjectSettings
			if err := json.Unmarshal([]byte(payload), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			wantBool(t, tc.key, tc.get(rec.Advanced), true)

			for _, other := range advancedSettingsFields {
				if other.key == tc.key {
					continue
				}
				wantNilBool(t, "sibling "+other.key, other.get(rec.Advanced))
			}
		})
	}
}

// TestAdvancedSettingsDecodesFullPayload pins every tag at once against a
// payload shaped like GET /project/{project-slug}/settings, with mixed
// values so a flag reported as disabled is distinguishable from one that was
// never returned.
func TestAdvancedSettingsDecodesFullPayload(t *testing.T) {
	const payload = `{
		"advanced": {
			"build_fork_prs": true,
			"forks_receive_secret_env_vars": false,
			"build_prs_only": true,
			"write_settings_requires_admin": false,
			"disable_ssh": true,
			"set_github_status": false,
			"autocancel_builds": true,
			"pr_only_branch_overrides": ["main", "release"]
		}
	}`

	var rec connection.ProjectSettings
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	s := rec.Advanced

	wantBool(t, "build_fork_prs", s.BuildForkPrs, true)
	// A false here is the whole point of the pointer: it is the provider's
	// headline audit finding, and it must never be produced by an absent key.
	wantBool(t, "forks_receive_secret_env_vars", s.ForksReceiveSecretEnvVars, false)
	wantBool(t, "build_prs_only", s.BuildPrsOnly, true)
	wantBool(t, "write_settings_requires_admin", s.WriteSettingsRequiresAdmin, false)
	wantBool(t, "disable_ssh", s.DisableSsh, true)
	wantBool(t, "set_github_status", s.SetGithubStatus, false)
	wantBool(t, "autocancel_builds", s.AutocancelBuilds, true)

	want := []string{"main", "release"}
	if !reflect.DeepEqual(s.PrOnlyBranchOverrides, want) {
		t.Fatalf("pr_only_branch_overrides: expected %v, got %v", want, s.PrOnlyBranchOverrides)
	}
}

// TestAdvancedSettingsAbsentKeysStayNull is the case that makes the pointers
// worth having: a settings response that omits the flags must leave every
// field null so the accessors report null rather than a clean bill of health
// on data that was never read.
func TestAdvancedSettingsAbsentKeysStayNull(t *testing.T) {
	cases := map[string]string{
		"empty advanced block": `{"advanced":{}}`,
		"advanced key absent":  `{}`,
		"advanced is null":     `{"advanced":null}`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			var rec connection.ProjectSettings
			if err := json.Unmarshal([]byte(payload), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			for _, f := range advancedSettingsFields {
				wantNilBool(t, f.key, f.get(rec.Advanced))
			}
			if rec.Advanced.PrOnlyBranchOverrides != nil {
				t.Fatalf("pr_only_branch_overrides: expected nil, got %v", rec.Advanced.PrOnlyBranchOverrides)
			}
		})
	}
}

// TestAdvancedSettingsRejectsWrongKeySpelling is the negative half of the
// tag pin. camelCase is the spelling a Go author reaches for by reflex, and
// encoding/json's case-insensitive matching does not bridge the missing
// underscores, so each of these must decode to nothing. If any of them
// populates a field, the production tag is the camelCase one and every real
// response reads as null.
func TestAdvancedSettingsRejectsWrongKeySpelling(t *testing.T) {
	const payload = `{
		"advanced": {
			"buildForkPrs": true,
			"forksReceiveSecretEnvVars": true,
			"buildPrsOnly": true,
			"writeSettingsRequiresAdmin": true,
			"disableSsh": true,
			"setGithubStatus": true,
			"autocancelBuilds": true,
			"prOnlyBranchOverrides": ["main"]
		}
	}`

	var rec connection.ProjectSettings
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, f := range advancedSettingsFields {
		wantNilBool(t, "camelCase "+f.key, f.get(rec.Advanced))
	}
	if rec.Advanced.PrOnlyBranchOverrides != nil {
		t.Fatalf("camelCase pr_only_branch_overrides leaked: %v", rec.Advanced.PrOnlyBranchOverrides)
	}
}

// TestProjectSettingsRequiresAdvancedWrapper pins the wrapper key itself. A
// wrong tag on ProjectSettings.Advanced makes every flag read null on every
// project, which looks identical to a permission problem.
func TestProjectSettingsRequiresAdvancedWrapper(t *testing.T) {
	t.Run("correct wrapper", func(t *testing.T) {
		var rec connection.ProjectSettings
		if err := json.Unmarshal([]byte(`{"advanced":{"disable_ssh":true}}`), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		wantBool(t, "disable_ssh", rec.Advanced.DisableSsh, true)
	})

	t.Run("flags at the top level are not read", func(t *testing.T) {
		var rec connection.ProjectSettings
		if err := json.Unmarshal([]byte(`{"disable_ssh":true}`), &rec); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		wantNilBool(t, "disable_ssh", rec.Advanced.DisableSsh)
	})
}

// TestWebhookDecodesHyphenatedTags pins the webhook record. Its keys are
// hyphenated, unlike the snake_case used for project settings, so a
// snake_case tag here silently makes verifyTls null and signingSecretSet
// false for every webhook, forever.
func TestWebhookDecodesHyphenatedTags(t *testing.T) {
	const payload = `{
		"id": "00000000-0000-0000-0000-000000000001",
		"name": "example-webhook",
		"url": "https://example.com/hook",
		"verify-tls": false,
		"signing-secret": "xxxx",
		"events": ["workflow-completed", "job-completed"],
		"scope": {
			"id": "00000000-0000-0000-0000-000000000002",
			"type": "project"
		}
	}`

	var rec connection.Webhook
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rec.ID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("id: got %q", rec.ID)
	}
	if rec.Name != "example-webhook" {
		t.Errorf("name: got %q", rec.Name)
	}
	if rec.URL != "https://example.com/hook" {
		t.Errorf("url: got %q", rec.URL)
	}
	// A reported false is the finding; it must be distinguishable from nil.
	wantBool(t, "verify-tls", rec.VerifyTLS, false)
	if rec.SigningSecret != "xxxx" {
		t.Errorf("signing-secret: got %q", rec.SigningSecret)
	}
	if !reflect.DeepEqual(rec.Events, []string{"workflow-completed", "job-completed"}) {
		t.Errorf("events: got %v", rec.Events)
	}
	if rec.Scope.ID != "00000000-0000-0000-0000-000000000002" || rec.Scope.Type != "project" {
		t.Errorf("scope: got %+v", rec.Scope)
	}
}

func TestWebhookVerifyTLSAbsentStaysNull(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    *bool
	}{
		{"verify-tls true", `{"verify-tls":true}`, boolRef(true)},
		{"verify-tls false", `{"verify-tls":false}`, boolRef(false)},
		{"verify-tls absent", `{"id":"00000000-0000-0000-0000-000000000001"}`, nil},
		{"verify-tls null", `{"verify-tls":null}`, nil},
		// the snake_case mistake: encoding/json will not bridge the
		// underscore, so a wrong tag shows up as a permanently null field
		{"verify_tls underscore is not the key", `{"verify_tls":true}`, nil},
		{"verifyTls camelCase is not the key", `{"verifyTls":true}`, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec connection.Webhook
			if err := json.Unmarshal([]byte(tc.payload), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if tc.want == nil {
				wantNilBool(t, "verify-tls", rec.VerifyTLS)
				return
			}
			wantBool(t, "verify-tls", rec.VerifyTLS, *tc.want)
		})
	}
}

func TestWebhookSigningSecretRejectsWrongKey(t *testing.T) {
	var rec connection.Webhook
	if err := json.Unmarshal([]byte(`{"signing_secret":"xxxx"}`), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.SigningSecret != "" {
		t.Fatalf("signing_secret (underscore) must not decode into SigningSecret, got %q", rec.SigningSecret)
	}
}

// TestSigningSecretSetPredicate covers the derived predicate that
// project.webhooks() computes for the signingSecretSet field. CircleCI never
// returns the configured secret, so "is a secret configured" is inferred
// from whether the masked placeholder came back non-empty. It is a security
// predicate that is computed rather than reported, so it gets its own table
// including the absent case, which must read as "no secret" only because the
// API says so.
func TestSigningSecretSetPredicate(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    bool
	}{
		{"key absent", `{"id":"00000000-0000-0000-0000-000000000001"}`, false},
		{"explicit null", `{"signing-secret":null}`, false},
		{"empty string means no secret configured", `{"signing-secret":""}`, false},
		{"masked placeholder means a secret is configured", `{"signing-secret":"xxxx"}`, true},
		{"non-empty value means a secret is configured", `{"signing-secret":"redacted"}`, true},
		{"whitespace is still non-empty", `{"signing-secret":" "}`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec connection.Webhook
			if err := json.Unmarshal([]byte(tc.payload), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			// mirrors project.go: "signingSecretSet": llx.BoolData(w.SigningSecret != "")
			got := rec.SigningSecret != ""
			if got != tc.want {
				t.Fatalf("signingSecretSet: expected %v, got %v", tc.want, got)
			}
		})
	}
}

// TestCheckoutKeyDecodesHyphenatedTags pins the checkout-key record. These
// keys are hyphenated too. A wrong tag on fingerprint is the worst of them:
// the fingerprint is half of the resource's cache key, so an empty value
// collapses every key on a project onto the same __id and only one survives.
func TestCheckoutKeyDecodesHyphenatedTags(t *testing.T) {
	const payload = `{
		"public-key": "ssh-rsa xxxx",
		"type": "deploy-key",
		"fingerprint": "aa:bb:cc:dd",
		"preferred": false,
		"created-at": "2026-01-02T03:04:05Z"
	}`

	var rec connection.CheckoutKey
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rec.PublicKey != "ssh-rsa xxxx" {
		t.Errorf("public-key: got %q", rec.PublicKey)
	}
	if rec.Type != "deploy-key" {
		t.Errorf("type: got %q", rec.Type)
	}
	if rec.Fingerprint != "aa:bb:cc:dd" {
		t.Errorf("fingerprint: got %q", rec.Fingerprint)
	}
	wantBool(t, "preferred", rec.Preferred, false)
	if rec.CreatedAt != "2026-01-02T03:04:05Z" {
		t.Errorf("created-at: got %q", rec.CreatedAt)
	}
}

func TestCheckoutKeyRejectsWrongKeySpelling(t *testing.T) {
	// every key here is the snake_case or camelCase spelling, which is what
	// the rest of the API uses and therefore what a wrong tag would be
	const payload = `{
		"public_key": "ssh-rsa xxxx",
		"created_at": "2026-01-02T03:04:05Z",
		"finger_print": "aa:bb:cc:dd",
		"isPreferred": true
	}`

	var rec connection.CheckoutKey
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.PublicKey != "" {
		t.Errorf("public_key (underscore) must not decode, got %q", rec.PublicKey)
	}
	if rec.CreatedAt != "" {
		t.Errorf("created_at (underscore) must not decode, got %q", rec.CreatedAt)
	}
	if rec.Fingerprint != "" {
		t.Errorf("finger_print must not decode, got %q", rec.Fingerprint)
	}
	wantNilBool(t, "isPreferred", rec.Preferred)
}

func TestCheckoutKeyPreferredAbsentStaysNull(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    *bool
	}{
		{"preferred true", `{"preferred":true}`, boolRef(true)},
		{"preferred false", `{"preferred":false}`, boolRef(false)},
		{"preferred absent", `{"fingerprint":"aa:bb:cc:dd"}`, nil},
		{"preferred null", `{"preferred":null}`, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec connection.CheckoutKey
			if err := json.Unmarshal([]byte(tc.payload), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if tc.want == nil {
				wantNilBool(t, "preferred", rec.Preferred)
				return
			}
			wantBool(t, "preferred", rec.Preferred, *tc.want)
		})
	}
}

// TestProjectEnvVarDoesNotDecodeValue pins the deliberate omission. The
// envvar endpoint returns a truncated suffix of the value, which is real
// secret material, so the record decodes the name only. The assertion walks
// every field by reflection rather than naming them, so re-adding a field
// that captures the value fails here instead of shipping the secret into a
// scan report.
func TestProjectEnvVarDoesNotDecodeValue(t *testing.T) {
	const sentinel = "xxxx"
	payload := fmt.Sprintf(`{"name":"EXAMPLE_VAR","value":%q,"truncated_value":%q}`, sentinel, sentinel)

	var rec connection.ProjectEnvVar
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec.Name != "EXAMPLE_VAR" {
		t.Fatalf("name: expected EXAMPLE_VAR, got %q", rec.Name)
	}

	v := reflect.ValueOf(rec)
	typ := v.Type()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if strings.EqualFold(field.Name, "value") {
			t.Fatalf("ProjectEnvVar must not carry a %s field: the API's value suffix is secret material", field.Name)
		}
		if got := fmt.Sprint(v.Field(i).Interface()); strings.Contains(got, sentinel) {
			t.Fatalf("field %s captured the secret value %q", field.Name, got)
		}
	}
}

// TestPageWalkerNext covers the guard around CircleCI's next_page_token walk.
// An endpoint that re-issues a token it already handed out makes a naive loop
// append the same page forever, so the failure mode is an out-of-memory scan
// rather than a wrong answer. Each case drives a fresh zero-value walker,
// which also proves the seen map is created lazily.
func TestPageWalkerNext(t *testing.T) {
	type step struct {
		token    string
		wantNext string
		wantDone bool
		wantErr  bool
	}

	cases := []struct {
		name  string
		steps []step
	}{
		{
			name:  "empty token ends the walk",
			steps: []step{{token: "", wantNext: "", wantDone: true}},
		},
		{
			name: "a fresh token advances",
			steps: []step{
				{token: "page-a", wantNext: "page-a"},
				{token: "page-b", wantNext: "page-b"},
				{token: "", wantNext: "", wantDone: true},
			},
		},
		{
			name: "the same token twice is a fault",
			steps: []step{
				{token: "page-a", wantNext: "page-a"},
				{token: "page-a", wantErr: true},
			},
		},
		{
			name: "an A to B to A cycle errors on the repeat",
			steps: []step{
				{token: "page-a", wantNext: "page-a"},
				{token: "page-b", wantNext: "page-b"},
				{token: "page-a", wantErr: true},
			},
		},
		{
			name: "an empty token after a real page still ends cleanly",
			steps: []step{
				{token: "page-a", wantNext: "page-a"},
				{token: "", wantNext: "", wantDone: true},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// zero value on purpose: the seen map is lazily created
			var w pageWalker
			for i, s := range tc.steps {
				next, done, err := w.next(s.token)
				if s.wantErr {
					if err == nil {
						t.Fatalf("step %d (%q): expected an error, got next=%q done=%v", i, s.token, next, done)
					}
					if done {
						t.Fatalf("step %d (%q): an error must not report done", i, s.token)
					}
					continue
				}
				if err != nil {
					t.Fatalf("step %d (%q): unexpected error: %v", i, s.token, err)
				}
				if next != s.wantNext {
					t.Fatalf("step %d (%q): expected next %q, got %q", i, s.token, s.wantNext, next)
				}
				if done != s.wantDone {
					t.Fatalf("step %d (%q): expected done %v, got %v", i, s.token, s.wantDone, done)
				}
			}
		})
	}
}

// TestPageWalkerZeroValueIsUsable states the lazy-map property on its own,
// since every caller declares the walker with var and never initializes it.
func TestPageWalkerZeroValueIsUsable(t *testing.T) {
	var w pageWalker
	if w.seen != nil {
		t.Fatalf("expected a nil seen map on the zero value, got %v", w.seen)
	}
	next, done, err := w.next("page-a")
	if err != nil || done || next != "page-a" {
		t.Fatalf("zero-value walker: got next=%q done=%v err=%v", next, done, err)
	}
	if w.seen == nil {
		t.Fatal("expected the seen map to be created on first use")
	}
}

// TestParseCircleciTime pins the timestamp parser. The important half is the
// failure path: returning the zero time instead of nil would report 1 January
// year 1 as a real creation date.
func TestParseCircleciTime(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string // RFC3339 the result must equal; "" means nil
	}{
		{"rfc3339 utc", "2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"},
		{"rfc3339 with fractional seconds", "2026-01-02T03:04:05.123Z", "2026-01-02T03:04:05.123Z"},
		{"rfc3339 with a non-zulu offset", "2026-01-02T03:04:05+02:00", "2026-01-02T01:04:05Z"},
		{"rfc3339 with a negative offset", "2026-01-02T03:04:05-05:00", "2026-01-02T08:04:05Z"},
		{"empty means the api reported no timestamp", "", ""},
		{"date only is not rfc3339", "2026-01-02", ""},
		{"garbage", "not-a-timestamp", ""},
		{"whitespace", "   ", ""},
		{"unix seconds are not accepted", "1767322745", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCircleciTime(tc.input)

			if tc.want == "" {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected %s, got nil", tc.want)
			}
			// a zero time would be a silent 1 January year 1
			if got.IsZero() {
				t.Fatalf("expected %s, got the zero time", tc.want)
			}
			want, err := time.Parse(time.RFC3339, tc.want)
			if err != nil {
				t.Fatalf("bad test expectation %q: %v", tc.want, err)
			}
			if !got.Equal(want) {
				t.Fatalf("expected %s, got %s", want, *got)
			}
		})
	}
}

func boolRef(b bool) *bool { return &b }
