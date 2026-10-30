// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/azuredevops/internal/fakeado"
)

func TestSubscriptionsAreReadOncePerClient(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))

	for range 3 {
		subs, err := c.Subscriptions(context.Background())
		require.NoError(t, err)
		assert.Len(t, subs, 7)
	}
	reqs := srv.Requests()
	require.Len(t, reqs, 1)
	assert.Contains(t, reqs[0], "/"+fakeado.Org+"/_apis/hooks/subscriptions?")
}

func TestSubscriptionsTheCredentialCannotReadAreForbidden(t *testing.T) {
	c, srv, _ := newFakeClient(t, patAuth(t, fakeado.PAT))
	srv.Deny("/_apis/hooks/subscriptions")

	_, err := c.Subscriptions(context.Background())
	assert.True(t, IsForbidden(err))
}

func TestSubscriptionAppliesToRepository(t *testing.T) {
	const project, repo = "p1", "r1"
	tests := []struct {
		name  string
		event string
		in    map[string]string
		want  bool
	}{
		{"names the repository", "git.push", map[string]string{"projectId": "p1", "repository": "r1"}, true},
		{"names it in another letter case", "git.push", map[string]string{"projectId": "P1", "repository": "R1"}, true},
		{"names another repository", "git.push", map[string]string{"projectId": "p1", "repository": "r2"}, false},
		{"code event of every repository", "git.push", map[string]string{"projectId": "p1", "repository": ""}, true},
		{"pull request comment event of every repository", "ms.vss-code.git-pullrequest-comment-event", map[string]string{"projectId": "p1"}, true},
		{"work item event", "workitem.created", map[string]string{"projectId": "p1"}, false},
		{"another project", "git.push", map[string]string{"projectId": "p2"}, false},
		{"no project", "git.push", map[string]string{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := Subscription{EventType: tc.event, PublisherInputs: tc.in}
			assert.Equal(t, tc.want, s.AppliesToRepository(project, repo))
		})
	}
}

func TestSubscriptionURL(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
	}{
		{"https://ci.example.invalid/hook", "ci.example.invalid"},
		{"  http://ci.example.invalid:8080/hook ", "ci.example.invalid:8080"},
		{"https://user:secret@ci.example.invalid/hook", "ci.example.invalid"},
		{"", ""},
		{"/relative/path", ""},
		{"https://%zz", ""},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			u := Subscription{ConsumerInputs: map[string]string{"url": tc.raw}}.URL()
			if tc.wantHost == "" {
				assert.Nil(t, u)
				return
			}
			require.NotNil(t, u)
			assert.Equal(t, tc.wantHost, u.Host)
		})
	}
}

func TestSubscriptionActive(t *testing.T) {
	for status, want := range map[string]bool{
		"enabled": true, "onProbation": true, "disabledByUser": false, "disabledBySystem": false, "": false,
	} {
		assert.Equal(t, want, Subscription{Status: status}.Active(), status)
	}
}
