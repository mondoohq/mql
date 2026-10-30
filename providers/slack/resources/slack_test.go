// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func strVal(s string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: s, State: plugin.StateIsSet}
}

// TestUserGroupOptionalUserRefsNullWhenEmpty is the regression test for the
// userGroups listing failing whenever a lifecycle user ID was empty. deletedBy
// is empty for every group that has not been deleted; the old code eagerly
// resolved it via NewResource -> GetUsersInfo(""), which errored and failed the
// entire userGroups query. The accessors must now return a null reference
// (no lookup) when the cached ID is empty.
func TestUserGroupOptionalUserRefsNullWhenEmpty(t *testing.T) {
	cases := []struct {
		name   string
		call   func(*mqlSlackUserGroup) (*mqlSlackUser, error)
		field  func(*mqlSlackUserGroup) plugin.TValue[*mqlSlackUser]
		setKey func(*mqlSlackUserGroup, string)
	}{
		{"createdBy", (*mqlSlackUserGroup).createdBy, func(g *mqlSlackUserGroup) plugin.TValue[*mqlSlackUser] { return g.CreatedBy }, func(g *mqlSlackUserGroup, v string) { g.cacheCreatedBy = v }},
		{"updatedBy", (*mqlSlackUserGroup).updatedBy, func(g *mqlSlackUserGroup) plugin.TValue[*mqlSlackUser] { return g.UpdatedBy }, func(g *mqlSlackUserGroup, v string) { g.cacheUpdatedBy = v }},
		{"deletedBy", (*mqlSlackUserGroup).deletedBy, func(g *mqlSlackUserGroup) plugin.TValue[*mqlSlackUser] { return g.DeletedBy }, func(g *mqlSlackUserGroup, v string) { g.cacheDeletedBy = v }},
	}

	for _, tc := range cases {
		t.Run(tc.name+" empty -> null ref", func(t *testing.T) {
			g := &mqlSlackUserGroup{}
			tc.setKey(g, "")

			res, err := tc.call(g)
			if err != nil {
				t.Fatalf("expected no error for empty %s, got %v", tc.name, err)
			}
			if res != nil {
				t.Fatalf("expected nil resource for empty %s, got %v", tc.name, res)
			}
			field := tc.field(g)
			if !field.IsSet() || !field.IsNull() {
				t.Fatalf("expected %s to be set+null, got state %v", tc.name, field.State)
			}
		})
	}
}

func TestResourceIDs(t *testing.T) {
	t.Run("slack.user", func(t *testing.T) {
		u := &mqlSlackUser{TeamId: strVal("T123"), Id: strVal("U456")}
		got, _ := u.id()
		if want := "slack.user/T123/U456"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("slack.enterpriseUser", func(t *testing.T) {
		e := &mqlSlackEnterpriseUser{EnterpriseId: strVal("E1"), Id: strVal("U9")}
		got, _ := e.id()
		if want := "slack.enterpriseUser/E1/U9"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("slack.userGroup", func(t *testing.T) {
		g := &mqlSlackUserGroup{Id: strVal("S01")}
		got, _ := g.id()
		if want := "slack.userGroup/S01"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("slack.conversation", func(t *testing.T) {
		c := &mqlSlackConversation{Id: strVal("C77")}
		got, _ := c.id()
		if want := "slack.conversation/C77"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("slack.team", func(t *testing.T) {
		team := &mqlSlackTeam{Id: strVal("T123")}
		got, _ := team.id()
		if want := "slack.team/T123"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("slack.login composite key", func(t *testing.T) {
		l := &mqlSlackLogin{
			UserID:    strVal("U1"),
			Ip:        strVal("1.2.3.4"),
			UserAgent: strVal("Mozilla/5.0"),
		}
		got, _ := l.id()
		if want := "slack.login/user/U1/ip/1.2.3.4/useragent/Mozilla/5.0"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestNewTopicAndPurpose(t *testing.T) {
	ts := slack.JSONTime(1_600_000_000)
	want := time.Unix(1_600_000_000, 0)

	topic := newTopic(slack.Topic{Value: "hello", Creator: "U1", LastSet: ts})
	if topic.Value != "hello" || topic.Creator != "U1" {
		t.Errorf("topic fields mismatch: %+v", topic)
	}
	if topic.LastSet == nil || !topic.LastSet.Equal(want) {
		t.Errorf("topic.LastSet = %v, want %v", topic.LastSet, want)
	}

	purpose := newPurpose(slack.Purpose{Value: "goal", Creator: "U2", LastSet: ts})
	if purpose.Value != "goal" || purpose.Creator != "U2" {
		t.Errorf("purpose fields mismatch: %+v", purpose)
	}
	if purpose.LastSet == nil || !purpose.LastSet.Equal(want) {
		t.Errorf("purpose.LastSet = %v, want %v", purpose.LastSet, want)
	}
}

func TestWalkCursor(t *testing.T) {
	t.Run("follows cursors through empty pages until the cursor is empty", func(t *testing.T) {
		// Synthetic: admin.slackbot.skills.list documents empty pages that
		// still carry a cursor.
		next := map[string]string{"": "c1", "c1": "c2", "c2": ""}
		var got []string
		err := walkCursor(func(cursor string) (string, error) {
			got = append(got, cursor)
			return next[cursor], nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{"", "c1", "c2"}; !slices.Equal(got, want) {
			t.Errorf("cursors = %v, want %v", got, want)
		}
	})

	t.Run("stops on a repeated cursor", func(t *testing.T) {
		// Synthetic: a server that keeps returning the same cursor.
		calls := 0
		err := walkCursor(func(cursor string) (string, error) {
			calls++
			return "stuck", nil
		})
		if err == nil {
			t.Fatal("expected an error for a repeated cursor")
		}
		if calls != 2 {
			t.Errorf("calls = %d, want 2", calls)
		}
	})

	t.Run("returns the page error", func(t *testing.T) {
		// Synthetic: the second page fails.
		pageErr := errors.New("page failed")
		err := walkCursor(func(cursor string) (string, error) {
			if cursor == "c1" {
				return "", pageErr
			}
			return "c1", nil
		})
		if !errors.Is(err, pageErr) {
			t.Errorf("err = %v, want %v", err, pageErr)
		}
	})
}

func TestUnixTimeData(t *testing.T) {
	// Synthetic: 0 is what an absent date_* field decodes to.
	if got := unixTimeData(0); got.Value != nil {
		t.Errorf("unixTimeData(0) = %v, want null", got.Value)
	}
	got := unixTimeData(1700000000)
	ts, ok := got.Value.(*time.Time)
	if !ok || !ts.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("unixTimeData(1700000000) = %v, want %v", got.Value, time.Unix(1700000000, 0))
	}
}
