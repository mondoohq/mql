// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/firebaserules/v1"
)

func TestParseFirebaseReleaseName(t *testing.T) {
	cases := []struct {
		name string
		want firebaseReleaseTarget
	}{
		{
			name: "projects/p/releases/cloud.firestore",
			want: firebaseReleaseTarget{service: "cloud.firestore", database: "(default)"},
		},
		{
			name: "projects/p/releases/cloud.firestore/orders-db",
			want: firebaseReleaseTarget{service: "cloud.firestore", database: "orders-db"},
		},
		{
			name: "projects/p/releases/firebase.storage/p.appspot.com",
			want: firebaseReleaseTarget{service: "firebase.storage", bucket: "p.appspot.com"},
		},
		// A release with a custom name protects nothing this can name.
		{name: "projects/p/releases/prod", want: firebaseReleaseTarget{}},
		// A prefix that is not the whole service segment is not that service.
		{name: "projects/p/releases/cloud.firestore-staging", want: firebaseReleaseTarget{}},
		{name: "projects/p/releases/firebase.storage", want: firebaseReleaseTarget{}},
		{name: "projects/p/releases/firebase.storage/", want: firebaseReleaseTarget{}},
		{name: "projects/p/releases/cloud.firestore/a/b", want: firebaseReleaseTarget{}},
		{name: "not-a-release", want: firebaseReleaseTarget{}},
		{name: "", want: firebaseReleaseTarget{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseFirebaseReleaseName(tc.name))
		})
	}
}

func TestFirebaseRulesetFiles(t *testing.T) {
	rs := &firebaserules.Ruleset{
		Source: &firebaserules.Source{Files: []*firebaserules.File{
			{Name: "firestore.rules", Content: "rules_version = '2';", Fingerprint: "abc"},
			nil,
			{Name: "storage.rules", Content: "service firebase.storage {}"},
		}},
		Metadata: &firebaserules.Metadata{Services: []string{"cloud.firestore"}},
	}
	assert.Equal(t, []any{
		map[string]any{"name": "firestore.rules", "content": "rules_version = '2';", "fingerprint": "abc"},
		map[string]any{"name": "storage.rules", "content": "service firebase.storage {}", "fingerprint": ""},
	}, firebaseRulesetFiles(rs))
	assert.Equal(t, []any{"cloud.firestore"}, firebaseRulesetServices(rs))

	// A ruleset read without its source reports no files, not null.
	assert.Equal(t, []any{}, firebaseRulesetFiles(&firebaserules.Ruleset{}))
	assert.Equal(t, []any{}, firebaseRulesetFiles(nil))
	assert.Equal(t, []any{}, firebaseRulesetServices(&firebaserules.Ruleset{}))
}
