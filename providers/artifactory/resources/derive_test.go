// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"go.mondoo.com/mql/providers/artifactory/connection"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// These predicates are what a policy reads. Each one turns several raw API
// values into a single answer, so a wrong branch reports an over-broad grant
// as narrow and nothing fails.

func TestContainsDeployAction(t *testing.T) {
	tests := []struct {
		name    string
		actions []string
		want    bool
	}{
		{name: "read only", actions: []string{"read"}, want: false},
		{name: "annotate only", actions: []string{"read", "annotate"}, want: false},
		{name: "write", actions: []string{"read", "write"}, want: true},
		{name: "deploy", actions: []string{"deploy"}, want: true},
		{name: "delete", actions: []string{"read", "delete"}, want: true},
		{name: "manage", actions: []string{"manage"}, want: true},
		{name: "mixed case", actions: []string{"Write"}, want: true},
		{name: "empty", actions: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsDeployAction(tt.actions); got != tt.want {
				t.Errorf("containsDeployAction(%v) = %v, want %v", tt.actions, got, tt.want)
			}
		})
	}
}

func TestContainsAction(t *testing.T) {
	actions := []string{"read", "Manage"}
	if !containsAction(actions, "manage") {
		t.Error("containsAction ignored case")
	}
	if containsAction(actions, "write") {
		t.Error("containsAction matched an action that is not held")
	}
	if containsAction(nil, "read") {
		t.Error("containsAction matched on an empty list")
	}
}

func TestScopeCoversRepository(t *testing.T) {
	tests := []struct {
		name         string
		repositories []string
		key          string
		repoType     string
		want         bool
	}{
		{name: "named", repositories: []string{"example-docker"}, key: "example-docker", repoType: "local", want: true},
		{name: "not named", repositories: []string{"other"}, key: "example-docker", repoType: "local", want: false},
		{name: "any covers every type", repositories: []string{"ANY"}, key: "example-docker", repoType: "virtual", want: true},
		{name: "any local covers a local repository", repositories: []string{"ANY LOCAL"}, key: "example-docker", repoType: "local", want: true},
		{name: "any local does not cover a remote repository", repositories: []string{"ANY LOCAL"}, key: "example-remote", repoType: "remote", want: false},
		{name: "any remote covers a remote repository", repositories: []string{"ANY REMOTE"}, key: "example-remote", repoType: "remote", want: true},
		{name: "any distribution covers a distribution repository", repositories: []string{"ANY DISTRIBUTION"}, key: "example-dist", repoType: "distribution", want: true},
		{name: "wildcard in lower case", repositories: []string{"any local"}, key: "example-docker", repoType: "local", want: true},
		{name: "empty scope covers nothing", repositories: nil, key: "example-docker", repoType: "local", want: false},
		{name: "a later entry still matches", repositories: []string{"other", "ANY LOCAL"}, key: "example-docker", repoType: "local", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scopeCoversRepository(tt.repositories, tt.key, tt.repoType); got != tt.want {
				t.Errorf("scopeCoversRepository(%v, %q, %q) = %v, want %v", tt.repositories, tt.key, tt.repoType, got, tt.want)
			}
		})
	}
}

func TestHasWildcardRepository(t *testing.T) {
	if hasWildcardRepository([]string{"example-docker", "example-helm"}) {
		t.Error("a named repository list was reported as a wildcard")
	}
	if !hasWildcardRepository([]string{"example-docker", "ANY REMOTE"}) {
		t.Error("a wildcard key was not recognised")
	}
	if hasWildcardRepository(nil) {
		t.Error("an empty list was reported as a wildcard")
	}
}

func TestAppliesToAllPaths(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{name: "no pattern", patterns: nil, want: true},
		{name: "empty pattern", patterns: []string{""}, want: true},
		{name: "match everything", patterns: []string{"**"}, want: true},
		{name: "match everything with a wildcard leaf", patterns: []string{"**/*"}, want: true},
		{name: "narrowed", patterns: []string{"example/**"}, want: false},
		{name: "narrowed after an empty entry", patterns: []string{"", "example/**"}, want: false},
		{name: "a match-everything pattern after a narrow one still wins", patterns: []string{"example/**", "**"}, want: true},
		{name: "several narrow patterns stay narrowed", patterns: []string{"example/**", "other/**"}, want: false},
		{name: "surrounding space is ignored", patterns: []string{" ** "}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := appliesToAllPaths(tt.patterns); got != tt.want {
				t.Errorf("appliesToAllPaths(%v) = %v, want %v", tt.patterns, got, tt.want)
			}
		})
	}
}

func TestSplitScopeAndGrantsAdmin(t *testing.T) {
	if got := splitScope(""); len(got) != 0 {
		t.Errorf("splitScope(\"\") = %v, want an empty list", got)
	}

	scopes := splitScope("applied-permissions/groups:ci member-of-groups:ci")
	if len(scopes) != 2 {
		t.Fatalf("splitScope returned %v", scopes)
	}
	if grantsAdmin(scopes) {
		t.Error("a group-scoped token was reported as an administrator token")
	}
	if !grantsAdmin(splitScope("applied-permissions/admin")) {
		t.Error("an admin-scoped token was not recognised")
	}
	if !grantsAdmin(splitScope("APPLIED-PERMISSIONS/ADMIN")) {
		t.Error("grantsAdmin ignored case")
	}
}

func TestSubjectUserName(t *testing.T) {
	tests := []struct {
		subject string
		want    string
	}{
		{subject: "jfrt@01ab2c3d/users/build-account", want: "build-account"},
		{subject: "jfrt@01ab2c3d/users/example@example.com", want: "example@example.com"},
		{subject: "jfrt@01ab2c3d/groups/ci", want: ""},
		{subject: "", want: ""},
		{subject: "users", want: ""},
	}

	for _, tt := range tests {
		if got := subjectUserName(tt.subject); got != tt.want {
			t.Errorf("subjectUserName(%q) = %q, want %q", tt.subject, got, tt.want)
		}
	}
}

func TestEpochTime(t *testing.T) {
	if epochTime(0) != nil {
		t.Error("an absent timestamp produced a time value")
	}
	if epochTime(-1) != nil {
		t.Error("a negative timestamp produced a time value")
	}
	got := epochTime(1767225600)
	if got == nil {
		t.Fatal("a valid timestamp produced no time value")
	}
	if got.Year() != 2026 {
		t.Errorf("epochTime produced %v", got)
	}
}

func TestMillisTime(t *testing.T) {
	if millisTime(0) != nil {
		t.Error("an absent timestamp produced a time value")
	}
	got := millisTime(1767225600000)
	if got == nil || got.Year() != 2026 {
		t.Errorf("millisTime produced %v", got)
	}
}

func TestIsoTimeShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantNil bool
		wantY   int
	}{
		{name: "rfc 3339", payload: `"2026-01-02T03:04:05Z"`, wantY: 2026},
		{name: "offset without a colon", payload: `"2026-01-02T03:04:05.000+0000"`, wantY: 2026},
		{name: "epoch milliseconds", payload: `1767225600000`, wantY: 2026},
		{name: "null", payload: `null`, wantNil: true},
		{name: "empty string", payload: `""`, wantNil: true},
		{name: "unparseable", payload: `"never"`, wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var value isoTime
			if err := json.Unmarshal([]byte(tt.payload), &value); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := value.Time()
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected null, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected a time value, got null")
			}
			if got.UTC().Year() != tt.wantY {
				t.Errorf("year = %d, want %d", got.UTC().Year(), tt.wantY)
			}
		})
	}
}

func TestSecurityArgsMapsTheDescriptor(t *testing.T) {
	enabled := true
	disabled := false
	attempts := int64(5)
	maxAge := int64(60)

	config := &securityConfig{Security: securitySection{
		AnonAccessEnabled:         &enabled,
		HideUnauthorizedResources: &disabled,
		UserLockPolicy:            userLockPolicy{Enabled: &enabled, LoginAttempts: &attempts},
		PasswordSettings: passwordSettingsRecord{
			EncryptionPolicy: "REQUIRED",
			ExpirationPolicy: expirationPolicyRecord{Enabled: &enabled, MaxAgeDays: &maxAge},
		},
	}}

	args := securityArgs(config)
	if args["anonymousAccessEnabled"].Value != true {
		t.Error("anonymousAccessEnabled was not mapped")
	}
	if args["loginAttempts"].Value != int64(5) {
		t.Errorf("loginAttempts = %v, want 5", args["loginAttempts"].Value)
	}
	if args["passwordExpiryDays"].Value != int64(60) {
		t.Errorf("passwordExpiryDays = %v, want 60", args["passwordExpiryDays"].Value)
	}
}

// A threshold that only applies while its policy is on must stay null when the
// policy is off, so an audit does not read a limit the instance never applies.
func TestSecurityArgsKeepsInactiveThresholdsNull(t *testing.T) {
	disabled := false
	attempts := int64(5)
	maxAge := int64(60)

	config := &securityConfig{Security: securitySection{
		UserLockPolicy: userLockPolicy{Enabled: &disabled, LoginAttempts: &attempts},
		PasswordSettings: passwordSettingsRecord{
			ExpirationPolicy: expirationPolicyRecord{Enabled: &disabled, MaxAgeDays: &maxAge},
		},
	}}

	args := securityArgs(config)
	if args["loginAttempts"].Value != nil {
		t.Errorf("loginAttempts = %v, want null while locking is off", args["loginAttempts"].Value)
	}
	if args["passwordExpiryDays"].Value != nil {
		t.Errorf("passwordExpiryDays = %v, want null while expiry is off", args["passwordExpiryDays"].Value)
	}
	if args["anonymousAccessEnabled"].Value != false {
		t.Error("an absent anonymous access setting was not mapped to false")
	}
}

func TestOptionalInt(t *testing.T) {
	if optionalInt(nil).Value != nil {
		t.Error("an absent value produced a number")
	}
	value := int64(7)
	if optionalInt(&value).Value != int64(7) {
		t.Error("a present value was not mapped")
	}
}

func TestBoolValue(t *testing.T) {
	if boolValue(nil) {
		t.Error("an absent flag read as true")
	}
	yes := true
	no := false
	if !boolValue(&yes) || boolValue(&no) {
		t.Error("boolValue did not follow the flag")
	}
}

func TestStrSliceToAny(t *testing.T) {
	got := strSliceToAny([]string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("strSliceToAny produced %v", got)
	}
	if len(strSliceToAny(nil)) != 0 {
		t.Error("an empty slice produced entries")
	}
}

// The headline check of this provider is an unauthenticated caller that can
// publish. It is derived from the repository scope of a permission target, so
// the derivation is asserted against the payload shape rather than only
// against the helper.
func TestAnonymousGrantsAreDerivedFromTheRepositoryScope(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantRead   bool
		wantDeploy bool
	}{
		{
			name:     "read only",
			payload:  `{"name":"a","repo":{"repositories":["example-docker"],"actions":{"users":{"anonymous":["read"]}}}}`,
			wantRead: true,
		},
		{
			name:       "read and write",
			payload:    `{"name":"b","repo":{"repositories":["ANY"],"actions":{"users":{"anonymous":["read","write"]}}}}`,
			wantRead:   true,
			wantDeploy: true,
		},
		{
			name:    "named user only",
			payload: `{"name":"c","repo":{"repositories":["example-docker"],"actions":{"users":{"build-account":["read","write"]}}}}`,
		},
		{
			name:    "anonymous on the build scope only",
			payload: `{"name":"d","build":{"repositories":["artifactory-build-info"],"actions":{"users":{"anonymous":["read","write"]}}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rec permissionTargetRecord
			if err := json.Unmarshal([]byte(tt.payload), &rec); err != nil {
				t.Fatalf("decode: %v", err)
			}

			var actions []string
			if rec.Repo != nil {
				actions = rec.Repo.Actions.Users[AnonymousUser]
			}

			if got := containsAction(actions, "read"); got != tt.wantRead {
				t.Errorf("anonymous read = %v, want %v", got, tt.wantRead)
			}
			if got := containsDeployAction(actions); got != tt.wantDeploy {
				t.Errorf("anonymous deploy = %v, want %v", got, tt.wantDeploy)
			}
		})
	}
}

// The lazy detail read has a fast path that reads the loaded flag without the
// lock. A plain bool there would be an unsynchronized read against the write
// the lock holder makes, so the flag is atomic. This exercises both paths
// concurrently, and fails under -race if that ever regresses.
func TestDetailLoadedFlagIsRaceFree(t *testing.T) {
	var internal mqlArtifactoryRepositoryInternal

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				if internal.detailLoaded.Load() {
					continue
				}
				internal.lock.Lock()
				if !internal.detailLoaded.Load() {
					internal.detail = &repositoryDetailRecord{Key: "example-docker"}
					internal.detailLoaded.Store(true)
				}
				internal.lock.Unlock()
			}
		})
	}
	wg.Wait()

	if !internal.detailLoaded.Load() || internal.detail == nil {
		t.Fatal("the detail was never recorded")
	}
	if internal.detail.Key != "example-docker" {
		t.Errorf("the detail was overwritten: %+v", internal.detail)
	}
}

// A class wildcard this provider does not recognise would make a grant read as
// covering nothing, which is the dangerous direction. Every class the instance
// can name is covered.
func TestScopeCoversRepositoryHandlesEveryClassWildcard(t *testing.T) {
	tests := []struct {
		wildcard string
		repoType string
	}{
		{wildcard: "ANY LOCAL", repoType: "local"},
		{wildcard: "ANY REMOTE", repoType: "remote"},
		{wildcard: "ANY VIRTUAL", repoType: "virtual"},
		{wildcard: "ANY FEDERATED", repoType: "federated"},
		{wildcard: "ANY DISTRIBUTION", repoType: "distribution"},
	}

	for _, tt := range tests {
		t.Run(tt.wildcard, func(t *testing.T) {
			repositories := []string{tt.wildcard}
			if !scopeCoversRepository(repositories, "example-repo", tt.repoType) {
				t.Errorf("%q did not cover a %s repository", tt.wildcard, tt.repoType)
			}
			if scopeCoversRepository(repositories, "example-repo", "other") {
				t.Errorf("%q covered a repository of another type", tt.wildcard)
			}
			if !hasWildcardRepository(repositories) {
				t.Errorf("%q was not recognised as a wildcard", tt.wildcard)
			}
		})
	}
}

// Surrounding space and case must not change whether a wildcard is recognised.
func TestScopeWildcardsIgnoreCaseAndSpace(t *testing.T) {
	for _, entry := range []string{" any local ", "Any Local", "ANY LOCAL"} {
		if !scopeCoversRepository([]string{entry}, "example-repo", "local") {
			t.Errorf("%q did not cover a local repository", entry)
		}
	}
}

// The list-first path must only be taken when the list is genuinely complete.
// Taking a short entry would report an administrator as ordinary, or an
// account as belonging to no group, which is the answer a review acts on.
func TestUserListIsComplete(t *testing.T) {
	admin := true

	tests := []struct {
		name string
		rec  userRecord
		want bool
	}{
		{name: "short list entry", rec: userRecord{Username: "example", Realm: "internal"}},
		{name: "admin flag only", rec: userRecord{Username: "example", Admin: &admin}},
		{name: "group list only", rec: userRecord{Username: "example", Groups: []string{}}},
		{name: "both markers", rec: userRecord{Username: "example", Admin: &admin, Groups: []string{}}, want: true},
		{name: "both markers with groups", rec: userRecord{Username: "example", Admin: &admin, Groups: []string{"readers"}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := userListIsComplete(&tt.rec); got != tt.want {
				t.Errorf("userListIsComplete(%+v) = %v, want %v", tt.rec, got, tt.want)
			}
		})
	}
}

func TestGroupListIsComplete(t *testing.T) {
	adminPrivileges := true

	tests := []struct {
		name string
		rec  groupRecord
		want bool
	}{
		{name: "short list entry", rec: groupRecord{Name: "readers", Description: "readers"}},
		{name: "admin flag only", rec: groupRecord{Name: "readers", AdminPrivileges: &adminPrivileges}},
		{name: "member list only", rec: groupRecord{Name: "readers", Members: []string{}}},
		{name: "both markers", rec: groupRecord{Name: "readers", AdminPrivileges: &adminPrivileges, Members: []string{}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupListIsComplete(&tt.rec); got != tt.want {
				t.Errorf("groupListIsComplete(%+v) = %v, want %v", tt.rec, got, tt.want)
			}
		})
	}
}

// An absent JSON member list decodes to nil and a present but empty one does
// not. The completeness markers depend on that difference.
func TestAbsentAndEmptyListsDiffer(t *testing.T) {
	var absent groupRecord
	if err := json.Unmarshal([]byte(`{"name":"readers"}`), &absent); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if absent.Members != nil {
		t.Errorf("an absent member list decoded as %v, want nil", absent.Members)
	}

	var empty groupRecord
	if err := json.Unmarshal([]byte(`{"name":"readers","members":[]}`), &empty); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if empty.Members == nil {
		t.Error("an empty member list decoded as nil, want an empty slice")
	}
}

func TestRepositoryProxies(t *testing.T) {
	tests := []struct {
		rclass string
		want   bool
	}{
		{rclass: "remote", want: true},
		{rclass: "REMOTE", want: true},
		{rclass: "local"},
		{rclass: "virtual"},
		{rclass: "federated"},
		{rclass: ""},
	}

	for _, tt := range tests {
		if got := repositoryProxies(&repositoryDetailRecord{RClass: tt.rclass}); got != tt.want {
			t.Errorf("repositoryProxies(%q) = %v, want %v", tt.rclass, got, tt.want)
		}
	}
}

// Several fields promise null when the instance leaves them unset. Returning
// an empty string instead would make "not set" indistinguishable from "set to
// nothing", and a query filtering on null would silently match neither.
func TestOptionalStringReportsAnUnsetValueAsNull(t *testing.T) {
	if optionalString("").Value != nil {
		t.Errorf("an empty value produced %v, want null", optionalString("").Value)
	}
	if got := optionalString("platform images").Value; got != "platform images" {
		t.Errorf("a set value produced %v", got)
	}
}

func TestNullableStringMarksTheFieldNull(t *testing.T) {
	var field plugin.TValue[string]

	got, err := nullableString("", &field)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("an empty value produced %q", got)
	}
	if field.State&plugin.StateIsNull == 0 {
		t.Error("the field was not marked null")
	}

	var set plugin.TValue[string]
	got, err = nullableString("example", &set)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "example" {
		t.Errorf("a set value produced %q", got)
	}
	if set.State&plugin.StateIsNull != 0 {
		t.Error("a set value was marked null")
	}
}

func TestUsesEncryptedLdapTransport(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{url: "ldaps://ldap.example.com:636/dc=example,dc=com", want: true},
		{url: "LDAPS://ldap.example.com/dc=example,dc=com", want: true},
		{url: "  ldaps://ldap.example.com  ", want: true},
		{url: "ldap://ldap.example.com:389/dc=example,dc=com"},
		{url: "ldap://ldaps.example.com/dc=example,dc=com"},
		{url: ""},
	}

	for _, tt := range tests {
		if got := usesEncryptedLdapTransport(tt.url); got != tt.want {
			t.Errorf("usesEncryptedLdapTransport(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

// Every string field whose schema promises null must be built with
// optionalString. Returning an empty string instead makes "not configured"
// indistinguishable from "configured to nothing", so a query filtering on null
// matches neither.
//
// The check is per resource, because the same field name means different
// things on different resources: name is the identifier of a watch and is
// always set, but on a watch resource entry it is null on a wildcard. It walks
// the schema and the code together, so a field added later cannot quietly
// break the promise.
func TestSchemaNullPromisesAreHonoured(t *testing.T) {
	promised := schemaNullPromises(t)
	if len(promised) == 0 {
		t.Fatal("no field promises null; the schema scan is broken")
	}

	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the sources: %v", err)
	}

	create := regexp.MustCompile(`CreateResource\([^,]+,\s*"([a-zA-Z0-9_.]+)"`)
	plain := regexp.MustCompile(`"([a-zA-Z][a-zA-Z0-9_]*)":\s*llx\.StringData\(`)

	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") || strings.HasSuffix(source, ".lr.go") {
			continue
		}
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}

		// Each CreateResource call owns the argument map that follows it, up to
		// the next call, so the fields are attributed to the right resource.
		calls := create.FindAllStringSubmatchIndex(string(body), -1)
		for i, call := range calls {
			resource := string(body)[call[2]:call[3]]
			end := len(body)
			if i+1 < len(calls) {
				end = calls[i+1][0]
			}
			for _, m := range plain.FindAllStringSubmatch(string(body)[call[1]:end], -1) {
				if promised[resource+"."+m[1]] {
					t.Errorf("%s builds %s.%s with llx.StringData, but the schema promises null; use optionalString",
						source, resource, m[1])
				}
			}
		}
	}
}

// schemaNullPromises returns the "<resource>.<field>" keys whose doc comment
// says the field is null when it is not set.
func schemaNullPromises(t *testing.T) map[string]bool {
	t.Helper()

	schema, err := os.ReadFile("artifactory.lr")
	if err != nil {
		t.Fatalf("read the schema: %v", err)
	}

	resourceStart := regexp.MustCompile(`^(?:private\s+)?([a-zA-Z][a-zA-Z0-9_.]*)\s*(?:@[^{]*)?\{`)
	field := regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_]*)\(?\)? +string\b`)

	promised := map[string]bool{}
	resource := ""
	var doc []string
	for line := range strings.SplitSeq(string(schema), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			doc = append(doc, trimmed)
			continue
		}
		if m := resourceStart.FindStringSubmatch(trimmed); m != nil {
			resource = m[1]
			doc = nil
			continue
		}
		if m := field.FindStringSubmatch(trimmed); m != nil && resource != "" {
			blob := strings.ToLower(strings.Join(doc, " "))
			if strings.Contains(blob, "null when") || strings.Contains(blob, "null on") {
				promised[resource+"."+m[1]] = true
			}
		}
		doc = nil
	}
	return promised
}

func TestUsesEncryptedReplicationTransport(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{url: "https://artifactory.example.com/artifactory/example-docker", want: true},
		{url: "HTTPS://artifactory.example.com/artifactory/example-docker", want: true},
		{url: "  https://artifactory.example.com  ", want: true},
		{url: "http://artifactory.example.com/artifactory/example-docker"},
		{url: "http://https.example.com/artifactory/example-docker"},
		{url: ""},
	}

	for _, tt := range tests {
		if got := usesEncryptedReplicationTransport(tt.url); got != tt.want {
			t.Errorf("usesEncryptedReplicationTransport(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

// A policy's rules are alternatives. Stopping at the first rule that does not
// block would report a policy as toothless because of the order its rules
// happen to be in, which is the dangerous direction to be wrong in.
func TestPolicyActionsReadEveryRule(t *testing.T) {
	blocking := xrayPolicyRuleRecord{}
	blocking.Actions.BlockDownload = &struct {
		Unscanned *bool `json:"unscanned"`
		Active    *bool `json:"active"`
	}{Unscanned: new(true), Active: new(true)}
	blocking.Actions.FailBuild = new(true)
	blocking.Actions.BlockReleaseBundleDistribution = new(true)

	notifying := xrayPolicyRuleRecord{}
	notifying.Actions.NotifyWatchRecipients = new(true)

	tests := []struct {
		name  string
		rules []xrayPolicyRuleRecord
		want  bool
	}{
		{name: "no rules", rules: nil},
		{name: "only a notifying rule", rules: []xrayPolicyRuleRecord{notifying}},
		{name: "blocking rule first", rules: []xrayPolicyRuleRecord{blocking, notifying}, want: true},
		{name: "blocking rule last", rules: []xrayPolicyRuleRecord{notifying, blocking}, want: true},
		{name: "blocking rule between two others", rules: []xrayPolicyRuleRecord{notifying, blocking, notifying}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyBlocksDownload(tt.rules); got != tt.want {
				t.Errorf("policyBlocksDownload = %v, want %v", got, tt.want)
			}
			if got := policyBlocksUnscanned(tt.rules); got != tt.want {
				t.Errorf("policyBlocksUnscanned = %v, want %v", got, tt.want)
			}
			if got := policyFailsBuild(tt.rules); got != tt.want {
				t.Errorf("policyFailsBuild = %v, want %v", got, tt.want)
			}
			if got := policyBlocksReleaseBundleDistribution(tt.rules); got != tt.want {
				t.Errorf("policyBlocksReleaseBundleDistribution = %v, want %v", got, tt.want)
			}
		})
	}
}

// A rule that records a violation without stopping anything leaves the artifact
// installable. It must not read as blocking.
func TestPolicyThatOnlyRecordsDoesNotBlock(t *testing.T) {
	rule := xrayPolicyRuleRecord{}
	rule.Criteria.MinSeverity = "Critical"

	rules := []xrayPolicyRuleRecord{rule}
	if policyBlocksDownload(rules) || policyBlocksUnscanned(rules) || policyFailsBuild(rules) {
		t.Errorf("a rule with no actions read as blocking: %+v", rule.Actions)
	}
}

// An action block the platform omits must not read as enabled.
func TestPolicyBlockDownloadHandlesAnAbsentAction(t *testing.T) {
	rule := xrayPolicyRuleRecord{}
	if rule.Actions.BlockDownload != nil {
		t.Fatal("an absent block_download decoded as present")
	}
	if policyBlocksDownload([]xrayPolicyRuleRecord{rule}) || policyBlocksUnscanned([]xrayPolicyRuleRecord{rule}) {
		t.Error("an absent block_download read as blocking")
	}
}

// The watch resource entries are alternatives too, so a wildcard anywhere in
// the list covers every repository.
func TestWatchCoversAllRepositories(t *testing.T) {
	named := xrayWatchResourceRecord{Type: "repository", Name: "example-docker"}
	wildcard := xrayWatchResourceRecord{Type: "all-repos"}
	builds := xrayWatchResourceRecord{Type: "all-builds"}

	tests := []struct {
		name      string
		resources []xrayWatchResourceRecord
		want      bool
	}{
		{name: "no resources", resources: nil},
		{name: "named only", resources: []xrayWatchResourceRecord{named}},
		{name: "another wildcard class", resources: []xrayWatchResourceRecord{builds}},
		{name: "wildcard first", resources: []xrayWatchResourceRecord{wildcard, named}, want: true},
		{name: "wildcard last", resources: []xrayWatchResourceRecord{named, builds, wildcard}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := watchCoversAllRepositories(tt.resources); got != tt.want {
				t.Errorf("watchCoversAllRepositories = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWatchResourceRepositoryKey(t *testing.T) {
	tests := []struct {
		name string
		rec  xrayWatchResourceRecord
		want string
	}{
		{name: "named repository", rec: xrayWatchResourceRecord{Type: "repository", Name: "example-docker"}, want: "example-docker"},
		{name: "wildcard names no repository", rec: xrayWatchResourceRecord{Type: "all-repos", Name: "ignored"}},
		{name: "build entry", rec: xrayWatchResourceRecord{Type: "build", Name: "example-build"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := watchResourceRepositoryKey(&tt.rec); got != tt.want {
				t.Errorf("watchResourceRepositoryKey = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWatchWildcardTypes(t *testing.T) {
	for _, typ := range []string{"all-repos", "all-builds", "all-releaseBundles", "all-releaseBundlesV2", "all-projects"} {
		if !watchWildcardTypes[typ] {
			t.Errorf("%q is not recognised as a wildcard", typ)
		}
	}
	for _, typ := range []string{"repository", "build", "releaseBundle", "project", ""} {
		if watchWildcardTypes[typ] {
			t.Errorf("%q was recognised as a wildcard", typ)
		}
	}
}

//go:fix inline
func boolPtr(v bool) *bool { return new(v) }

// A platform with no Xray and a platform whose Xray the token may not read are
// different answers. Reporting the denial as an absent Xray would say "this
// platform does not scan", and a policy asking whether a repository is
// protected would pass on data that was never read.
func TestXrayAbsentIsNotTheSameAsDenied(t *testing.T) {
	notFound := &connection.APIError{StatusCode: http.StatusNotFound, URL: "/xray/api/v1/system/version"}
	forbidden := &connection.APIError{StatusCode: http.StatusForbidden, URL: "/xray/api/v1/system/version"}
	unauthorized := &connection.APIError{StatusCode: http.StatusUnauthorized, URL: "/xray/api/v1/system/version"}
	broken := errors.New("connection reset")

	if !xrayIsAbsent(notFound) {
		t.Error("a 404 was not treated as an absent Xray")
	}
	for name, err := range map[string]error{"403": forbidden, "401": unauthorized, "transport": broken} {
		if xrayIsAbsent(err) {
			t.Errorf("a %s error was treated as an absent Xray", name)
		}
	}

	// A denial must name the rights it needs, so the failure reads as a
	// permission problem rather than as a broken provider.
	denied := xrayReadError(forbidden)
	if denied == nil || !strings.Contains(denied.Error(), "may not read Xray") {
		t.Errorf("a denied read produced %v", denied)
	}
	if !errors.Is(denied, forbidden) {
		t.Error("the denial dropped the underlying error")
	}

	// Anything else is passed through unchanged, so a transport failure is not
	// dressed up as a permission problem.
	if got := xrayReadError(broken); got != broken {
		t.Errorf("a transport error produced %v", got)
	}
}

// The roles of a member are alternatives, so every role is read before the
// answer is no. Stopping at the first ordinary role would report a project
// administrator as an ordinary member.
func TestRolesAdministerProject(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
		want  bool
	}{
		{name: "no roles", roles: nil},
		{name: "ordinary roles", roles: []string{"Developer", "Contributor"}},
		{name: "admin role first", roles: []string{"Project Admin", "Developer"}, want: true},
		{name: "admin role last", roles: []string{"Developer", "Viewer", "Project Admin"}, want: true},
		{name: "admin role in the middle", roles: []string{"Developer", "Project Admin", "Viewer"}, want: true},
		{name: "underscore spelling", roles: []string{"project_admin"}, want: true},
		{name: "lower case", roles: []string{"project admin"}, want: true},
		{name: "surrounding space", roles: []string{"  Project Admin  "}, want: true},
		{name: "bare admin", roles: []string{"Admin"}, want: true},
		{name: "a role that only contains admin", roles: []string{"Administrator of nothing"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rolesAdministerProject(tt.roles); got != tt.want {
				t.Errorf("rolesAdministerProject(%v) = %v, want %v", tt.roles, got, tt.want)
			}
		})
	}
}
