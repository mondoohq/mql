// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	dropboxsdk "github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team_policies"
)

func sharedFolderPolicy(tag string) *team_policies.SharedFolderMemberPolicy {
	return &team_policies.SharedFolderMemberPolicy{Tag: tag}
}

func sharedLinkPolicy(tag string) *team_policies.SharedLinkCreatePolicy {
	return &team_policies.SharedLinkCreatePolicy{Tag: tag}
}

func TestDeriveSharingPolicies(t *testing.T) {
	tests := []struct {
		name         string
		policies     *team_policies.TeamMemberPolicies
		wantExternal bool
		wantPublic   bool
	}{
		{
			name:         "nil policies",
			policies:     nil,
			wantExternal: false,
			wantPublic:   false,
		},
		{
			name:         "nil sharing block",
			policies:     &team_policies.TeamMemberPolicies{},
			wantExternal: false,
			wantPublic:   false,
		},
		{
			name: "empty sharing block leaves both false",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{},
			},
			wantExternal: false,
			wantPublic:   false,
		},
		{
			name: "team-only folder + team_only links",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{
					SharedFolderMemberPolicy: sharedFolderPolicy("team"),
					SharedLinkCreatePolicy:   sharedLinkPolicy("team_only"),
				},
			},
			wantExternal: false,
			wantPublic:   false,
		},
		{
			name: "anyone folder admits external members",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{
					SharedFolderMemberPolicy: sharedFolderPolicy("anyone"),
				},
			},
			wantExternal: true,
			wantPublic:   false,
		},
		{
			name: "team_and_approved folder admits external members",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{
					SharedFolderMemberPolicy: sharedFolderPolicy("team_and_approved"),
				},
			},
			wantExternal: true,
			wantPublic:   false,
		},
		{
			name: "default_public permits public links",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{
					SharedLinkCreatePolicy: sharedLinkPolicy("default_public"),
				},
			},
			wantExternal: false,
			wantPublic:   true,
		},
		{
			name: "default_team_only still permits creating public links",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{
					SharedLinkCreatePolicy: sharedLinkPolicy("default_team_only"),
				},
			},
			wantExternal: false,
			wantPublic:   true,
		},
		{
			name: "default_no_one bars public links",
			policies: &team_policies.TeamMemberPolicies{
				Sharing: &team_policies.TeamSharingPolicies{
					SharedLinkCreatePolicy: sharedLinkPolicy("default_no_one"),
				},
			},
			wantExternal: false,
			wantPublic:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotExternal, gotPublic := deriveSharingPolicies(tt.policies)
			if gotExternal != tt.wantExternal {
				t.Errorf("externalSharingAllowed = %v, want %v", gotExternal, tt.wantExternal)
			}
			if gotPublic != tt.wantPublic {
				t.Errorf("publicSharingAllowed = %v, want %v", gotPublic, tt.wantPublic)
			}
		})
	}
}

func TestDbxTimePtr(t *testing.T) {
	if got := dbxTimePtr(nil); got != nil {
		t.Errorf("dbxTimePtr(nil) = %v, want nil", got)
	}

	want := time.Date(2024, 3, 14, 9, 30, 0, 0, time.UTC)
	dbx := dropboxsdk.DBXTime(want)
	got := dbxTimePtr(&dbx)
	if got == nil {
		t.Fatal("dbxTimePtr(&dbx) = nil, want non-nil")
	}
	if !got.Equal(want) {
		t.Errorf("dbxTimePtr(&dbx) = %v, want %v", got, want)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"linux", "desktop", "linux"},
		{"", "desktop", "desktop"},
		{"", "", ""},
		{"a", "", "a"},
	}
	for _, tt := range tests {
		if got := firstNonEmpty(tt.a, tt.b); got != tt.want {
			t.Errorf("firstNonEmpty(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestPagedFetch(t *testing.T) {
	t.Run("single page", func(t *testing.T) {
		got, err := pagedFetch(
			func() ([]int, string, bool, error) { return []int{1, 2, 3}, "", false, nil },
			func(string) ([]int, string, bool, error) {
				t.Fatal("next should not be called")
				return nil, "", false, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 3 {
			t.Errorf("got %v, want 3 items", got)
		}
	})

	t.Run("multiple pages accumulate in order", func(t *testing.T) {
		calls := 0
		got, err := pagedFetch(
			func() ([]int, string, bool, error) { return []int{1}, "c1", true, nil },
			func(cursor string) ([]int, string, bool, error) {
				calls++
				switch cursor {
				case "c1":
					return []int{2}, "c2", true, nil
				case "c2":
					return []int{3}, "", false, nil
				default:
					t.Fatalf("unexpected cursor %q", cursor)
					return nil, "", false, nil
				}
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls != 2 {
			t.Errorf("next called %d times, want 2", calls)
		}
		want := []int{1, 2, 3}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("got[%d] = %d, want %d", i, got[i], want[i])
			}
		}
	})

	t.Run("first-page error propagates", func(t *testing.T) {
		sentinel := errors.New("boom")
		_, err := pagedFetch(
			func() ([]int, string, bool, error) { return nil, "", false, sentinel },
			func(string) ([]int, string, bool, error) { return nil, "", false, nil },
		)
		if !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want %v", err, sentinel)
		}
	})

	t.Run("continuation error propagates", func(t *testing.T) {
		sentinel := errors.New("boom")
		_, err := pagedFetch(
			func() ([]int, string, bool, error) { return []int{1}, "c1", true, nil },
			func(string) ([]int, string, bool, error) { return nil, "", false, sentinel },
		)
		if !errors.Is(err, sentinel) {
			t.Errorf("err = %v, want %v", err, sentinel)
		}
	})
}
