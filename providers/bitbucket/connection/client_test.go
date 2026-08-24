// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Every Bitbucket API record in this package is decoded by struct tag alone,
// and Go's encoding/json matches keys case-insensitively. A mistyped tag
// therefore compiles, lints, and yields a zero value, which a resource then
// reports as a confident false / "" / 0 instead of null. These tests pin each
// security-relevant tag against a payload shaped like the documented response,
// and pair every positive case with a negative one (a deliberately wrong key)
// so the tag itself is pinned rather than the field name.

const testTime = "2026-01-01T00:00:00Z"

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

func decode(t *testing.T, payload string, out any) {
	t.Helper()
	if err := json.Unmarshal([]byte(payload), out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// wantBoolPtr asserts a *bool decoded to exactly want.
func wantBoolPtr(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = nil, want %v", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %v, want %v", name, *got, want)
	}
}

// wantNilBoolPtr asserts an absent key left the field null rather than
// collapsing to false, which would report an unread setting as disabled.
func wantNilBoolPtr(t *testing.T, name string, got *bool) {
	t.Helper()
	if got != nil {
		t.Errorf("%s = %v, want nil (absent key must stay null, not read as false)", name, *got)
	}
}

// jsonTagKeys lists the wire keys a struct decodes, so a test can assert a
// secret-bearing key is decoded by no field at all.
func jsonTagKeys(v any) []string {
	rt := reflect.TypeOf(v)
	keys := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" {
			continue
		}
		keys = append(keys, strings.Split(tag, ",")[0])
	}
	return keys
}

// assertValueNotRetained decodes payload into out and then re-marshals it,
// proving the sentinel never reached any field. Re-marshalling (rather than
// naming fields) keeps the assertion valid if a field is added later.
func assertValueNotRetained(t *testing.T, payload, sentinel string, out any) {
	t.Helper()
	decode(t, payload, out)
	round, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(round), sentinel) {
		t.Errorf("%q was decoded into a field; round-trip = %s", sentinel, round)
	}
}

// TestDeployKeyDecodesAddedOn pins the one type in this provider whose
// creation timestamp is NOT created_on. Bitbucket's deploy-key object reports
// it as added_on; decoding created_on left every deploy key's timestamp
// permanently null.
func TestDeployKeyDecodesAddedOn(t *testing.T) {
	t.Run("added_on populates CreatedOn", func(t *testing.T) {
		payload := fmt.Sprintf(`{
			"id": 1,
			"label": "ci-runner",
			"key": "ssh-rsa xxxx",
			"added_on": %q,
			"last_used": %q
		}`, testTime, testTime)

		var k DeployKey
		decode(t, payload, &k)

		if k.ID != 1 || k.Label != "ci-runner" {
			t.Errorf("identity fields: %+v", k)
		}
		if k.CreatedOn == nil {
			t.Fatal("added_on must populate CreatedOn")
		}
		if !k.CreatedOn.Equal(mustTime(t, testTime)) {
			t.Errorf("CreatedOn = %v, want %v", *k.CreatedOn, testTime)
		}
		if k.LastUsed == nil || !k.LastUsed.Equal(mustTime(t, testTime)) {
			t.Errorf("LastUsed = %v", k.LastUsed)
		}
	})

	t.Run("created_on is not the deploy-key spelling", func(t *testing.T) {
		// Negative guard: every other type in this provider uses created_on,
		// so this is the exact payload a copy-pasted tag would satisfy.
		var k DeployKey
		decode(t, fmt.Sprintf(`{"id":1,"label":"ci-runner","created_on":%q}`, testTime), &k)
		if k.CreatedOn != nil {
			t.Errorf("created_on must not populate CreatedOn, got %v", *k.CreatedOn)
		}
	})

	t.Run("absent timestamps stay null", func(t *testing.T) {
		var k DeployKey
		decode(t, `{"id":2,"label":"unused-key"}`, &k)
		if k.CreatedOn != nil {
			t.Errorf("absent added_on should stay nil, got %v", *k.CreatedOn)
		}
		// A key that was never used must not report the zero time as a real
		// last-used date.
		if k.LastUsed != nil {
			t.Errorf("absent last_used should stay nil, got %v", *k.LastUsed)
		}
	})
}

func TestWebhookDecode(t *testing.T) {
	t.Run("all tags populate", func(t *testing.T) {
		payload := fmt.Sprintf(`{
			"uuid": "{00000000-0000-0000-0000-000000000001}",
			"url": "https://hooks.example.com/endpoint",
			"description": "build notifications",
			"active": true,
			"events": ["repo:push", "pullrequest:created"],
			"skip_cert_verification": true,
			"secret_set": true,
			"created_at": %q
		}`, testTime)

		var h Webhook
		decode(t, payload, &h)

		if h.UUID != "{00000000-0000-0000-0000-000000000001}" || h.URL != "https://hooks.example.com/endpoint" {
			t.Errorf("identity fields: %+v", h)
		}
		if h.Description != "build notifications" {
			t.Errorf("description = %q", h.Description)
		}
		wantBoolPtr(t, "Active", h.Active, true)
		wantBoolPtr(t, "SkipCertVerification", h.SkipCertVerification, true)
		wantBoolPtr(t, "SecretSet", h.SecretSet, true)
		if len(h.Events) != 2 || h.Events[0] != "repo:push" {
			t.Errorf("events = %v", h.Events)
		}
		// The webhook subscription really is created_at in Bitbucket's spec,
		// unlike the deploy key's added_on.
		if h.CreatedAt == nil || !h.CreatedAt.Equal(mustTime(t, testTime)) {
			t.Errorf("created_at must populate CreatedAt, got %v", h.CreatedAt)
		}
	})

	t.Run("false values decode as false", func(t *testing.T) {
		var h Webhook
		decode(t, `{"uuid":"{0}","active":false,"skip_cert_verification":false,"secret_set":false}`, &h)
		wantBoolPtr(t, "Active", h.Active, false)
		wantBoolPtr(t, "SkipCertVerification", h.SkipCertVerification, false)
		wantBoolPtr(t, "SecretSet", h.SecretSet, false)
	})

	t.Run("omitted keys stay null", func(t *testing.T) {
		// A false skip_cert_verification reads as "TLS is verified", which is
		// the direction that makes an audit pass on data that was never read.
		var h Webhook
		decode(t, `{"uuid":"{0}","url":"https://hooks.example.com/endpoint"}`, &h)
		wantNilBoolPtr(t, "SkipCertVerification", h.SkipCertVerification)
		wantNilBoolPtr(t, "Active", h.Active)
		wantNilBoolPtr(t, "SecretSet", h.SecretSet)
		if h.CreatedAt != nil {
			t.Errorf("absent created_at should stay nil, got %v", *h.CreatedAt)
		}
	})

	t.Run("wrong key spellings do not populate", func(t *testing.T) {
		// encoding/json is case-insensitive but not separator-insensitive, so
		// these camelCase / created_on variants are what a wrong tag matches.
		var h Webhook
		decode(t, fmt.Sprintf(`{
			"uuid": "{0}",
			"skipCertVerification": true,
			"secretSet": true,
			"created_on": %q
		}`, testTime), &h)
		wantNilBoolPtr(t, "SkipCertVerification", h.SkipCertVerification)
		wantNilBoolPtr(t, "SecretSet", h.SecretSet)
		if h.CreatedAt != nil {
			t.Errorf("created_on must not populate CreatedAt, got %v", *h.CreatedAt)
		}
	})

	t.Run("secret is decoded into no field", func(t *testing.T) {
		for _, key := range jsonTagKeys(Webhook{}) {
			if key == "secret" {
				t.Fatal("Webhook must not decode the secret itself, only secret_set")
			}
		}
		payload := `{"uuid":"{0}","secret":"redacted","secret_set":true}`
		var h Webhook
		assertValueNotRetained(t, payload, "redacted", &h)
		wantBoolPtr(t, "SecretSet", h.SecretSet, true)
	})
}

func TestPipelineVariableDecode(t *testing.T) {
	t.Run("uuid, key and secured populate", func(t *testing.T) {
		var v PipelineVariable
		decode(t, `{"uuid":"{00000000-0000-0000-0000-000000000002}","key":"API_TOKEN","secured":true}`, &v)
		if v.UUID != "{00000000-0000-0000-0000-000000000002}" || v.Key != "API_TOKEN" {
			t.Errorf("identity fields: %+v", v)
		}
		wantBoolPtr(t, "Secured", v.Secured, true)
	})

	t.Run("unsecured variable decodes false", func(t *testing.T) {
		var v PipelineVariable
		decode(t, `{"uuid":"{0}","key":"BUILD_ENV","secured":false}`, &v)
		wantBoolPtr(t, "Secured", v.Secured, false)
	})

	t.Run("omitted secured stays null", func(t *testing.T) {
		var v PipelineVariable
		decode(t, `{"uuid":"{0}","key":"BUILD_ENV"}`, &v)
		wantNilBoolPtr(t, "Secured", v.Secured)
	})

	t.Run("plaintext value is decoded into no field", func(t *testing.T) {
		// Bitbucket returns the value in the clear for an unsecured variable,
		// which is exactly where an accidentally plaintext credential lives.
		for _, key := range jsonTagKeys(PipelineVariable{}) {
			if key == "value" {
				t.Fatal("PipelineVariable must not decode the plaintext value")
			}
		}
		var v PipelineVariable
		assertValueNotRetained(t, `{"uuid":"{0}","key":"API_TOKEN","value":"redacted","secured":false}`, "redacted", &v)
		if v.Key != "API_TOKEN" {
			t.Errorf("key = %q", v.Key)
		}
	})
}

func TestWorkspaceDecode(t *testing.T) {
	t.Run("privacy flags populate", func(t *testing.T) {
		payload := fmt.Sprintf(`{
			"uuid": "{00000000-0000-0000-0000-000000000003}",
			"slug": "example-workspace",
			"name": "Example Workspace",
			"is_private": true,
			"is_privacy_enforced": true,
			"created_on": %q
		}`, testTime)

		var w Workspace
		decode(t, payload, &w)
		if w.Slug != "example-workspace" || w.Name != "Example Workspace" {
			t.Errorf("identity fields: %+v", w)
		}
		wantBoolPtr(t, "IsPrivate", w.IsPrivate, true)
		wantBoolPtr(t, "IsPrivacyEnforced", w.IsPrivacyEnforced, true)
		if w.CreatedOn == nil || !w.CreatedOn.Equal(mustTime(t, testTime)) {
			t.Errorf("created_on must populate CreatedOn, got %v", w.CreatedOn)
		}
	})

	t.Run("absent privacy flags stay null", func(t *testing.T) {
		var w Workspace
		decode(t, `{"uuid":"{0}","slug":"example-workspace"}`, &w)
		wantNilBoolPtr(t, "IsPrivate", w.IsPrivate)
		wantNilBoolPtr(t, "IsPrivacyEnforced", w.IsPrivacyEnforced)
		if w.CreatedOn != nil {
			t.Errorf("absent created_on should stay nil, got %v", *w.CreatedOn)
		}
	})

	t.Run("camelCase keys do not populate", func(t *testing.T) {
		var w Workspace
		decode(t, `{"slug":"example-workspace","isPrivate":true,"isPrivacyEnforced":true,"privacy_enforced":true}`, &w)
		wantNilBoolPtr(t, "IsPrivate", w.IsPrivate)
		wantNilBoolPtr(t, "IsPrivacyEnforced", w.IsPrivacyEnforced)
	})
}

func TestProjectDecode(t *testing.T) {
	t.Run("is_private and workspace ref populate", func(t *testing.T) {
		payload := fmt.Sprintf(`{
			"uuid": "{00000000-0000-0000-0000-000000000004}",
			"key": "API",
			"name": "API services",
			"description": "internal services",
			"is_private": true,
			"created_on": %q,
			"updated_on": %q,
			"workspace": {"uuid":"{0}","slug":"example-workspace","name":"Example Workspace"}
		}`, testTime, testTime)

		var p Project
		decode(t, payload, &p)
		if p.Key != "API" || p.Name != "API services" || p.Description != "internal services" {
			t.Errorf("identity fields: %+v", p)
		}
		wantBoolPtr(t, "IsPrivate", p.IsPrivate, true)
		if p.Workspace == nil || p.Workspace.Slug != "example-workspace" {
			t.Errorf("workspace ref = %+v", p.Workspace)
		}
		if p.CreatedOn == nil || p.UpdatedOn == nil {
			t.Errorf("timestamps: created=%v updated=%v", p.CreatedOn, p.UpdatedOn)
		}
	})

	t.Run("a public project decodes false, not nil", func(t *testing.T) {
		var p Project
		decode(t, `{"key":"API","is_private":false}`, &p)
		wantBoolPtr(t, "IsPrivate", p.IsPrivate, false)
	})

	t.Run("absent keys stay null", func(t *testing.T) {
		var p Project
		decode(t, `{"key":"API","isPrivate":true}`, &p)
		wantNilBoolPtr(t, "IsPrivate", p.IsPrivate)
		if p.Workspace != nil {
			t.Errorf("absent workspace should stay nil, got %+v", p.Workspace)
		}
	})
}

func TestRepositoryDecode(t *testing.T) {
	t.Run("all flags and refs populate", func(t *testing.T) {
		payload := fmt.Sprintf(`{
			"uuid": "{00000000-0000-0000-0000-000000000005}",
			"slug": "api-service",
			"full_name": "acme-corp/api-service",
			"name": "api-service",
			"description": "service repo",
			"is_private": true,
			"fork_policy": "no_public_forks",
			"language": "go",
			"size": 1024,
			"has_issues": true,
			"has_wiki": true,
			"mainbranch": {"name": "main"},
			"project": {"uuid":"{0}","key":"API","name":"API services"},
			"workspace": {"uuid":"{0}","slug":"acme-corp","name":"Acme Corp"},
			"created_on": %q,
			"updated_on": %q
		}`, testTime, testTime)

		var r Repository
		decode(t, payload, &r)

		if r.FullName != "acme-corp/api-service" {
			t.Errorf("full_name = %q, want acme-corp/api-service", r.FullName)
		}
		// fork_policy is the field that says whether the repo may be forked
		// into a public namespace, so a dropped tag silently reads as "".
		if r.ForkPolicy != "no_public_forks" {
			t.Errorf("fork_policy = %q, want no_public_forks", r.ForkPolicy)
		}
		wantBoolPtr(t, "IsPrivate", r.IsPrivate, true)
		wantBoolPtr(t, "HasIssues", r.HasIssues, true)
		wantBoolPtr(t, "HasWiki", r.HasWiki, true)
		if r.MainBranch == nil || r.MainBranch.Name != "main" {
			t.Errorf("mainbranch = %+v", r.MainBranch)
		}
		if r.Project == nil || r.Project.Key != "API" {
			t.Errorf("project ref = %+v", r.Project)
		}
		if r.Workspace == nil || r.Workspace.Slug != "acme-corp" {
			t.Errorf("workspace ref = %+v", r.Workspace)
		}
		if r.Size != 1024 || r.Language != "go" || r.Slug != "api-service" {
			t.Errorf("scalar fields: %+v", r)
		}
	})

	t.Run("false flags decode as false", func(t *testing.T) {
		var r Repository
		decode(t, `{"slug":"api-service","is_private":false,"has_issues":false,"has_wiki":false}`, &r)
		wantBoolPtr(t, "IsPrivate", r.IsPrivate, false)
		wantBoolPtr(t, "HasIssues", r.HasIssues, false)
		wantBoolPtr(t, "HasWiki", r.HasWiki, false)
	})

	t.Run("absent keys stay null", func(t *testing.T) {
		var r Repository
		decode(t, `{"slug":"api-service"}`, &r)
		wantNilBoolPtr(t, "IsPrivate", r.IsPrivate)
		wantNilBoolPtr(t, "HasIssues", r.HasIssues)
		wantNilBoolPtr(t, "HasWiki", r.HasWiki)
		// An empty repository has no default branch; that must read as null
		// rather than as a branch named "".
		if r.MainBranch != nil {
			t.Errorf("absent mainbranch should stay nil, got %+v", r.MainBranch)
		}
	})

	t.Run("wrong key spellings do not populate", func(t *testing.T) {
		// full_name / fork_policy are snake_case, so the camelCase forms below
		// match no tag. Note mainbranch is deliberately probed as main_branch
		// rather than mainBranch: encoding/json ignores case, so "mainBranch"
		// WOULD satisfy the mainbranch tag and prove nothing.
		var r Repository
		decode(t, `{
			"isPrivate": true,
			"hasIssues": true,
			"hasWiki": true,
			"main_branch": {"name": "main"},
			"fullName": "acme-corp/api-service",
			"forkPolicy": "no_public_forks"
		}`, &r)
		wantNilBoolPtr(t, "IsPrivate", r.IsPrivate)
		wantNilBoolPtr(t, "HasIssues", r.HasIssues)
		wantNilBoolPtr(t, "HasWiki", r.HasWiki)
		if r.MainBranch != nil {
			t.Errorf("main_branch must not populate MainBranch, got %+v", r.MainBranch)
		}
		if r.FullName != "" {
			t.Errorf("fullName must not populate FullName, got %q", r.FullName)
		}
		if r.ForkPolicy != "" {
			t.Errorf("forkPolicy must not populate ForkPolicy, got %q", r.ForkPolicy)
		}
	})
}

// TestBranchRestrictionValue pins the pointer semantics of value. The resource
// maps it to minApprovals, which must be null (not 0) for the many restriction
// kinds that carry no approval count, or a denylist check reads "0 approvals
// required" as fact on a rule that never had the setting.
func TestBranchRestrictionValue(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    *int64
	}{
		{"numeric value", `{"id":1,"kind":"require_approvals_to_merge","pattern":"main","value":2}`, ptrInt64(2)},
		{"explicit null", `{"id":2,"kind":"force","pattern":"main","value":null}`, nil},
		{"absent key", `{"id":3,"kind":"delete","pattern":"main"}`, nil},
		{"zero is a real value", `{"id":4,"kind":"require_approvals_to_merge","pattern":"main","value":0}`, ptrInt64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var br BranchRestriction
			decode(t, tc.payload, &br)
			switch {
			case tc.want == nil && br.Value != nil:
				t.Errorf("Value = %d, want nil", *br.Value)
			case tc.want != nil && br.Value == nil:
				t.Errorf("Value = nil, want %d", *tc.want)
			case tc.want != nil && *br.Value != *tc.want:
				t.Errorf("Value = %d, want %d", *br.Value, *tc.want)
			}
		})
	}

	t.Run("kind, pattern and exemptions populate", func(t *testing.T) {
		payload := `{
			"id": 5,
			"kind": "require_approvals_to_merge",
			"pattern": "main",
			"value": 2,
			"users": [{"uuid":"{0}","account_id":"acct-1","nickname":"person","display_name":"Person One","type":"user"}],
			"groups": [{"slug":"developers","name":"Developers"}]
		}`
		var br BranchRestriction
		decode(t, payload, &br)
		if br.ID != 5 || br.Kind != "require_approvals_to_merge" || br.Pattern != "main" {
			t.Errorf("identity fields: %+v", br)
		}
		if len(br.Users) != 1 || br.Users[0].AccountID != "acct-1" || br.Users[0].DisplayName != "Person One" {
			t.Errorf("users = %+v", br.Users)
		}
		if len(br.Groups) != 1 || br.Groups[0].Slug != "developers" {
			t.Errorf("groups = %+v", br.Groups)
		}
	})
}

func ptrInt64(v int64) *int64 { return &v }

type pagedItem struct {
	ID string `json:"id"`
}

// pageURL reconstructs the absolute URL of the request the test server just
// received, so a handler can echo it back as "next" to simulate a stuck
// pagination cursor.
func pageURL(r *http.Request) string {
	return "http://" + r.Host + r.URL.RequestURI()
}

func TestListAllPagesWalk(t *testing.T) {
	t.Run("accumulates every page", func(t *testing.T) {
		var calls int32
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/page1":
				fmt.Fprintf(w, `{"values":[{"id":"a"},{"id":"b"}],"next":%q}`, srv.URL+"/page2")
			case "/page2":
				fmt.Fprintf(w, `{"values":[{"id":"c"}],"next":%q}`, srv.URL+"/page3")
			case "/page3":
				io.WriteString(w, `{"values":[{"id":"d"}],"next":null}`)
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}))
		defer srv.Close()

		got, err := listAllPages[pagedItem](context.Background(), NewClient(srv.Client()), srv.URL+"/page1")
		if err != nil {
			t.Fatalf("listAllPages: %v", err)
		}
		if n := atomic.LoadInt32(&calls); n != 3 {
			t.Fatalf("expected 3 page requests, got %d", n)
		}
		want := []string{"a", "b", "c", "d"}
		if len(got) != len(want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
		for i := range want {
			if got[i].ID != want[i] {
				t.Errorf("index %d: got %q, want %q", i, got[i].ID, want[i])
			}
		}
	})

	t.Run("terminates on absent and null next", func(t *testing.T) {
		for _, body := range []string{
			`{"values":[{"id":"only"}]}`,
			`{"values":[{"id":"only"}],"next":null}`,
			`{"values":[{"id":"only"}],"next":""}`,
		} {
			body := body
			t.Run(body, func(t *testing.T) {
				var calls int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&calls, 1)
					io.WriteString(w, body)
				}))
				defer srv.Close()

				got, err := listAllPages[pagedItem](context.Background(), NewClient(srv.Client()), srv.URL+"/things")
				if err != nil {
					t.Fatalf("listAllPages: %v", err)
				}
				if n := atomic.LoadInt32(&calls); n != 1 {
					t.Fatalf("expected 1 request, got %d", n)
				}
				if len(got) != 1 || got[0].ID != "only" {
					t.Fatalf("expected [only], got %v", got)
				}
			})
		}
	})

	t.Run("stuck cursor terminates", func(t *testing.T) {
		// An endpoint that echoes back the URL just requested would loop
		// forever without the guard. The request counter bounds a regression
		// so it fails the test instead of hanging CI, and the context timeout
		// backstops a walk that ignores the counter.
		const maxCalls = 4
		var calls int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&calls, 1)
			if n > maxCalls {
				// Break the loop so the assertion below, not a hang, reports it.
				io.WriteString(w, `{"values":[],"next":null}`)
				return
			}
			fmt.Fprintf(w, `{"values":[{"id":"a"}],"next":%q}`, pageURL(r))
		}))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		got, err := listAllPages[pagedItem](ctx, NewClient(srv.Client()), srv.URL+"/things")
		if err != nil {
			t.Fatalf("listAllPages: %v", err)
		}
		if n := atomic.LoadInt32(&calls); n != 1 {
			t.Fatalf("a repeated next URL must stop the walk after 1 request, got %d", n)
		}
		if len(got) != 1 {
			t.Fatalf("expected the single page's 1 item, got %d: %v", len(got), got)
		}
	})

	t.Run("an error on a later page fails the walk", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/page1" {
				fmt.Fprintf(w, `{"values":[{"id":"a"}],"next":%q}`, srv.URL+"/page2")
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"error":{"message":"boom"}}`)
		}))
		defer srv.Close()

		got, err := listAllPages[pagedItem](context.Background(), NewClient(srv.Client()), srv.URL+"/page1")
		if err == nil {
			t.Fatalf("expected an error, got %v", got)
		}
		// Partial results must not be returned as if the walk completed.
		if got != nil {
			t.Errorf("expected no values alongside the error, got %v", got)
		}
	})
}

func TestClientGetStatusHandling(t *testing.T) {
	t.Run("404 yields ErrNotFound", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"type":"error","error":{"message":"Resource not found"}}`)
		}))
		defer srv.Close()

		var out map[string]any
		err := NewClient(srv.Client()).get(context.Background(), srv.URL+"/things", &out)
		if !stderrors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("other failures are not ErrNotFound", func(t *testing.T) {
		for _, status := range []int{http.StatusForbidden, http.StatusUnauthorized, http.StatusInternalServerError} {
			status := status
			t.Run(http.StatusText(status), func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(status)
					io.WriteString(w, `{"type":"error","error":{"message":"denied"}}`)
				}))
				defer srv.Close()

				var out map[string]any
				err := NewClient(srv.Client()).get(context.Background(), srv.URL+"/things", &out)
				if err == nil {
					t.Fatalf("expected an error on %d", status)
				}
				// A 403 or 500 must never be mistaken for "absent", or an
				// unread field degrades to null and an audit passes.
				if stderrors.Is(err, ErrNotFound) {
					t.Errorf("status %d must not classify as ErrNotFound", status)
				}
				if !strings.Contains(err.Error(), fmt.Sprintf("status %d", status)) {
					t.Errorf("error should name the status: %v", err)
				}
			})
		}
	})

	t.Run("transport failure is not ErrNotFound", func(t *testing.T) {
		// A closed listener stands in for a network blip; it must surface as
		// an error rather than degrading into a null field.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		client := srv.Client()
		url := srv.URL
		srv.Close()

		var out map[string]any
		err := NewClient(client).get(context.Background(), url+"/things", &out)
		if err == nil {
			t.Fatal("expected a transport error")
		}
		if stderrors.Is(err, ErrNotFound) {
			t.Errorf("a transport failure must not classify as ErrNotFound: %v", err)
		}
	})

	t.Run("200 decodes the body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Accept"); got != "application/json" {
				t.Errorf("Accept header = %q", got)
			}
			io.WriteString(w, `{"slug":"example-workspace","is_private":true}`)
		}))
		defer srv.Close()

		var w Workspace
		if err := NewClient(srv.Client()).get(context.Background(), srv.URL+"/workspaces/example-workspace", &w); err != nil {
			t.Fatalf("get: %v", err)
		}
		if w.Slug != "example-workspace" {
			t.Errorf("slug = %q", w.Slug)
		}
		wantBoolPtr(t, "IsPrivate", w.IsPrivate, true)
	})

	t.Run("malformed body errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `not json`)
		}))
		defer srv.Close()

		var out map[string]any
		err := NewClient(srv.Client()).get(context.Background(), srv.URL+"/things", &out)
		if err == nil {
			t.Fatal("expected a decode error")
		}
		if stderrors.Is(err, ErrNotFound) {
			t.Errorf("a decode failure must not classify as ErrNotFound: %v", err)
		}
	})
}
