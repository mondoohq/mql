// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: a GET /v1/aliases body shaped after the Go client's alias type,
// beside a schema holding one of the two target collections; no live server
// was checked.
func TestAliases(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/aliases":
			_, _ = w.Write([]byte(`{"aliases":[{"alias":"ArticleLive","class":"Article"},{"alias":"Orphan","class":"Hidden"}]}`))
		case "/v1/schema":
			_, _ = w.Write([]byte(`{"classes":[{"class":"Article"}]}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	instance := testInstance(t, serverRuntime(t, srv))

	list, err := instance.aliases()
	require.NoError(t, err)
	require.Len(t, list, 2)

	live := list[0].(*mqlWeaviateAlias)
	assert.Equal(t, "ArticleLive", live.Name.Data)
	assert.Equal(t, "http://weaviate.test:8080/alias/ArticleLive", live.MqlID())
	col, err := live.collection()
	require.NoError(t, err)
	require.NotNil(t, col)
	assert.Equal(t, "Article", col.Name.Data)

	orphan := list[1].(*mqlWeaviateAlias)
	col, err = orphan.collection()
	require.NoError(t, err)
	assert.Nil(t, col)
	assert.True(t, orphan.Collection.IsNull(), "an unresolved target must be marked null")
}

// Synthetic: a server that predates aliases answers 404; no live server was
// checked.
func TestAliasesNotSupported(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	list, err := testInstance(t, serverRuntime(t, srv)).aliases()
	require.NoError(t, err)
	assert.Empty(t, list)
}
