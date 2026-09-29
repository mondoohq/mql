// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

const memberNetworkBody = `{"network":{"id":3,"name":"net","ip_range":"10.0.0.0/16","created":"2026-01-01T00:00:00+00:00",
"subnets":[],"routes":[],"servers":[42],"load_balancers":[42],"protection":{"delete":false},"labels":{}}}`

// Page one carries the server, page two the load balancer, so a lister that
// stops after the first page reports one member instead of two.
const membersPage1 = `{"members":[
{"type":"server","id":42,"ip":"10.0.1.5","status":"error","alias_ips":["10.0.1.6"],"subnet":"10.0.1.0/24"}
],"meta":{"pagination":{"page":1,"per_page":1,"previous_page":null,"next_page":2,"last_page":2,"total_entries":2}}}`

const membersPage2 = `{"members":[
{"type":"load_balancer","id":42,"ip":"10.0.2.2","status":"ok","alias_ips":[],"subnet":"10.0.2.0/24"}
],"meta":{"pagination":{"page":2,"per_page":1,"previous_page":1,"next_page":null,"last_page":2,"total_entries":2}}}`

const memberServersBody = `{"servers":[{"id":42,"name":"web","status":"running","created":"2026-01-01T00:00:00+00:00",
"public_net":{"ipv4":null,"ipv6":null,"floating_ips":[],"firewalls":[]},"private_net":[],"labels":{},"volumes":[],"load_balancers":[],
"protection":{"delete":false,"rebuild":false}}],
"meta":{"pagination":{"page":1,"per_page":50,"previous_page":null,"next_page":null,"last_page":1,"total_entries":1}}}`

func TestNetworkMembers(t *testing.T) {
	runtime := initRuntime(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/networks/3":
			_, _ = w.Write([]byte(memberNetworkBody))
		case "/networks/3/members":
			if r.URL.Query().Get("page") == "2" {
				_, _ = w.Write([]byte(membersPage2))
			} else {
				_, _ = w.Write([]byte(membersPage1))
			}
		case "/servers":
			_, _ = w.Write([]byte(memberServersBody))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"not found"}}`))
		}
	})
	_, res, err := initHetznerNetwork(runtime, map[string]*llx.RawData{"id": llx.IntData(3)})
	require.NoError(t, err)
	network := res.(*mqlHetznerNetwork)

	members, err := network.members()
	require.NoError(t, err)
	require.Len(t, members, 2, "the second page must be read")

	srv := members[0].(*mqlHetznerNetworkMember)
	lb := members[1].(*mqlHetznerNetworkMember)
	assert.NotEqual(t, srv.MqlID(), lb.MqlID(), "a server and a load balancer sharing an id are two members")

	assert.Equal(t, "server", srv.Type.Data)
	assert.Equal(t, "10.0.1.5", srv.Ip.Data)
	assert.Equal(t, []any{"10.0.1.6"}, srv.AliasIps.Data)
	assert.Equal(t, "10.0.1.0/24", srv.Subnet.Data)
	assert.Equal(t, "error", srv.Status.Data)

	s, err := srv.server()
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, int64(42), s.Id.Data)
	assert.Equal(t, "web", s.Name.Data)

	notLB, err := srv.loadBalancer()
	require.NoError(t, err)
	assert.Nil(t, notLB)
	assert.True(t, srv.LoadBalancer.IsNull(), "a server member has a null load balancer")

	notServer, err := lb.server()
	require.NoError(t, err)
	assert.Nil(t, notServer)
	assert.True(t, lb.Server.IsNull())

	parent, err := lb.network()
	require.NoError(t, err)
	assert.Same(t, network, parent)
}

// A server listed as a member but gone from the project list resolves to null
// rather than an error or a blank server.
func TestNetworkMemberServerGone(t *testing.T) {
	runtime := initRuntime(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/networks/3":
			_, _ = w.Write([]byte(memberNetworkBody))
		case "/networks/3/members":
			_, _ = w.Write([]byte(`{"members":[{"type":"server","id":99,"ip":"10.0.1.9","status":"ok","alias_ips":[],"subnet":"10.0.1.0/24"}]}`))
		case "/servers":
			_, _ = w.Write([]byte(memberServersBody))
		}
	})
	_, res, err := initHetznerNetwork(runtime, map[string]*llx.RawData{"id": llx.IntData(3)})
	require.NoError(t, err)
	members, err := res.(*mqlHetznerNetwork).members()
	require.NoError(t, err)
	require.Len(t, members, 1)
	m := members[0].(*mqlHetznerNetworkMember)
	s, err := m.server()
	require.NoError(t, err)
	assert.Nil(t, s)
	assert.True(t, m.Server.IsNull())
}

// A refused member listing is an error, never an empty list: a denial says
// nothing about what is attached.
func TestNetworkMembersPropagateDenial(t *testing.T) {
	runtime := initRuntime(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/networks/3" {
			_, _ = w.Write([]byte(memberNetworkBody))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"forbidden","message":"insufficient permissions"}}`))
	})
	_, res, err := initHetznerNetwork(runtime, map[string]*llx.RawData{"id": llx.IntData(3)})
	require.NoError(t, err)
	_, err = res.(*mqlHetznerNetwork).members()
	require.Error(t, err)
}
