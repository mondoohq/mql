// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// The fixtures in testdata were recorded from yugabytedb/yugabyte:2025.2.8.1-b8
// started with yugabyted, on 2026-11-13: a single node (master-*, tserver-*)
// and a two-node cluster (two-node-*), the "down" files after the second
// node was stopped, which left the masters without a leader).
// tserver-varz.json keeps a subset of the flags.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Measured: single node.
func TestParseTabletServersSingleNode(t *testing.T) {
	list, err := ParseTabletServers(fixture(t, "master-tablet-servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d tablet servers, want 1", len(list))
	}
	ts := list[0]
	if ts.UUID != "f98ec0e91cc04ae08563d0ac605fbf7a" || ts.Address != "fdac6ddb0721:9000" || ts.Status != "ALIVE" {
		t.Errorf("got %+v", ts)
	}
}

// Measured: two nodes, keyed by HTTP address; sorted by address.
func TestParseTabletServersTwoNodes(t *testing.T) {
	list, err := ParseTabletServers(fixture(t, "two-node-tablet-servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Address != "yb1:9000" || list[1].Address != "yb2:9000" {
		t.Fatalf("got %+v", list)
	}
	if list[0].UUID == "" || list[0].UUID == list[1].UUID {
		t.Errorf("tablet server UUIDs %q and %q", list[0].UUID, list[1].UUID)
	}
}

// Synthetic: a malformed answer is an error, not an empty list.
func TestParseTabletServersMalformed(t *testing.T) {
	if _, err := ParseTabletServers([]byte(`<h2>Not found</h2>`)); err == nil {
		t.Error("HTML answer parsed")
	}
}

// Measured: single node, leader master.
func TestMasterEntry(t *testing.T) {
	var res struct {
		Masters []MasterEntry `json:"masters"`
	}
	if err := json.Unmarshal(fixture(t, "master-masters.json"), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Masters) != 1 {
		t.Fatalf("got %d masters", len(res.Masters))
	}
	m := res.Masters[0]
	if m.InstanceID.PermanentUUID != "f2b96a32c92d433d9ba6a09464ee2d52" || m.Role != "LEADER" {
		t.Errorf("got uuid %q role %q", m.InstanceID.PermanentUUID, m.Role)
	}
	if m.HTTPAddress() != "fdac6ddb0721:7000" || m.RPCAddress() != "fdac6ddb0721:7100" || m.Status() != "ALIVE" {
		t.Errorf("got http %q rpc %q status %q", m.HTTPAddress(), m.RPCAddress(), m.Status())
	}
	started := time.UnixMicro(m.InstanceID.StartTimeUs)
	if got, ok := m.Uptime(started.Add(90 * time.Second)); got != 90 || !ok {
		t.Errorf("uptime = %d %v, want 90", got, ok)
	}
	if got, ok := m.Uptime(started.Add(-time.Second)); got != 0 || !ok {
		t.Errorf("uptime before start = %d %v, want 0", got, ok)
	}
}

// Measured: a master that does not answer carries an error; its status is
// the error code.
func TestMasterEntryDown(t *testing.T) {
	var res struct {
		Masters []MasterEntry `json:"masters"`
	}
	if err := json.Unmarshal(fixture(t, "two-node-down-masters.json"), &res); err != nil {
		t.Fatal(err)
	}
	byRPC := map[string]MasterEntry{}
	for _, m := range res.Masters {
		byRPC[m.RPCAddress()] = m
	}
	if s := byRPC["yb1:7100"].Status(); s != "ALIVE" {
		t.Errorf("yb1 status = %q, want ALIVE", s)
	}
	down := byRPC["yb2:7100"]
	if s := down.Status(); s != "TIMED_OUT" {
		t.Errorf("yb2 status = %q, want TIMED_OUT", s)
	}
	// It reports neither an HTTP address nor a start time.
	if down.HTTPAddress() != "" {
		t.Errorf("yb2 HTTP address = %q", down.HTTPAddress())
	}
	if _, ok := down.Uptime(time.Now()); ok {
		t.Error("yb2 uptime known")
	}
}

// Synthetic: an error without a code still is not ALIVE.
func TestMasterStatusWithoutCode(t *testing.T) {
	var m MasterEntry
	if err := json.Unmarshal([]byte(`{"error":{"message":"timed out"}}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Status() != "ERROR" {
		t.Errorf("status = %q, want ERROR", m.Status())
	}
}

// Measured: the health of a single node; Synthetic: a dead node.
func TestHealth(t *testing.T) {
	var h Health
	if err := json.Unmarshal(fixture(t, "master-health-check.json"), &h); err != nil {
		t.Fatal(err)
	}
	if h.DeadNodes == nil || len(h.DeadNodes) != 0 || len(h.UnderReplicatedTablets) != 0 {
		t.Errorf("healthy node: %+v", h)
	}
	if err := json.Unmarshal([]byte(`{"dead_nodes":["d56185d9b93e463e986f9d4031d94112"],"most_recent_uptime":12,"under_replicated_tablets":["t1","t2"]}`), &h); err != nil {
		t.Fatal(err)
	}
	if len(h.DeadNodes) != 1 || len(h.UnderReplicatedTablets) != 2 || h.MostRecentUptime != 12 {
		t.Errorf("dead node: %+v", h)
	}
}

// Synthetic: leaderless tablets as IDs or objects.
func TestTabletIDs(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`"abc"`),
		json.RawMessage(`{"tablet_uuid":"def","table_name":"x"}`),
		json.RawMessage(`{"tablet_id":"ghi"}`),
		json.RawMessage(`{"other":1}`),
	}
	got := tabletIDs(raw)
	want := []string{"abc", "def", "ghi"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

// Measured: varz keeps names, values, and types; a masked flag stays masked.
func TestParseVarz(t *testing.T) {
	flags, err := ParseVarz(fixture(t, "tserver-varz.json"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Flag{}
	for _, f := range flags {
		byName[f.Name] = f
	}
	if f := byName["ysql_enable_auth"]; f.Value != "false" || f.Type != "Default" {
		t.Errorf("ysql_enable_auth = %+v", f)
	}
	if f := byName["ysql_pg_conf_csv"]; f.Value != "yb_enable_cbo=on" || f.Type != "Custom" {
		t.Errorf("ysql_pg_conf_csv = %+v", f)
	}
	if f := byName["ysql_hba_conf_csv"]; f.Value != "***" {
		t.Errorf("ysql_hba_conf_csv = %+v, want masked", f)
	}
	if f := byName["placement_zone"]; f.Type != "NodeInfo" {
		t.Errorf("placement_zone = %+v", f)
	}
}

// Synthetic: an answer without a flags list is an error.
func TestParseVarzNoFlags(t *testing.T) {
	if _, err := ParseVarz([]byte(`{}`)); err == nil {
		t.Error("answer without flags parsed")
	}
}

// Measured: the footer of a tablet server's /tls page.
func TestParseServerUUID(t *testing.T) {
	if got := ParseServerUUID(fixture(t, "tserver-tls.html")); got != "f98ec0e91cc04ae08563d0ac605fbf7a" {
		t.Errorf("uuid = %q", got)
	}
	if got := ParseServerUUID([]byte(`<html>no footer</html>`)); got != "" {
		t.Errorf("uuid without footer = %q", got)
	}
}

// Synthetic: UUIDs compare with or without dashes and case.
func TestSameUUID(t *testing.T) {
	if !SameUUID("F98EC0E9-1CC0-4AE0-8563-D0AC605FBF7A", "f98ec0e91cc04ae08563d0ac605fbf7a") {
		t.Error("dashed upper-case UUID did not match")
	}
	if SameUUID("", "") {
		t.Error("empty UUIDs matched")
	}
	if SameUUID("f98ec0e91cc04ae08563d0ac605fbf7a", "f2b96a32c92d433d9ba6a09464ee2d52") {
		t.Error("different UUIDs matched")
	}
}

// Synthetic: classification of non-200 answers.
func TestHTTPError(t *testing.T) {
	cases := map[int]error{
		http.StatusUnauthorized:       llx.ErrUnauthenticated,
		http.StatusForbidden:          llx.ErrForbidden,
		http.StatusServiceUnavailable: llx.ErrTargetUnavailable,
	}
	for code, kind := range cases {
		if err := httpError("h/x", code, nil); !errors.Is(err, kind) {
			t.Errorf("HTTP %d: %v is not %v", code, err, kind)
		}
	}
	// Measured: with one of two masters stopped there is no leader, and the
	// remaining master answers 404 with an HTML message.
	err := httpError("h/x", http.StatusNotFound, fixture(t, "two-node-down-health-check.html"))
	if llx.KindOf(err) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		t.Errorf("404 classified as %v", llx.KindOf(err))
	}
	if want := "Unable to locate leader master"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not carry %q", err, want)
	}
}

// newServer starts a fake YugabyteDB web server that answers /tls with the
// given server UUID and /api/v1/varz with one flag naming the server.
func newServer(t *testing.T, uuid, label string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tls":
			_, _ = w.Write([]byte(`<html><body>TLS Settings<div>server uuid ` + uuid + ` local time 2026-11-13</div></body></html>`))
		case "/api/v1/varz":
			_, _ = w.Write([]byte(`{"flags":[{"name":"label","value":"` + label + `","type":"Custom"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func testConn(t *testing.T, host string, opts map[string]string) *YugabyteConnection {
	t.Helper()
	if opts == nil {
		opts = map[string]string{}
	}
	conf := &inventory.Config{Type: "yugabyte", Host: host, Options: opts}
	conn, err := NewYugabyteConnection(1, &inventory.Asset{Connections: []*inventory.Config{conf}}, conf)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// Synthetic: the server behind the configured endpoint is read there when
// its UUID matches; any other server at its reported address.
func TestServerAddress(t *testing.T) {
	local := newServer(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "local")
	conn := testConn(t, "127.0.0.1", nil)

	// The master reports an address the scanner cannot reach.
	if got := conn.ServerAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "container:9000", local); got != local {
		t.Errorf("matching server read at %q, want %q", got, local)
	}
	if got := conn.ServerAddress("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "other:9000", local); got != "other:9000" {
		t.Errorf("other server read at %q, want other:9000", got)
	}
	flags, err := conn.Varz(conn.ServerAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "container:9000", local))
	if err != nil || len(flags) != 1 || flags[0].Value != "local" {
		t.Errorf("flags = %v, %v", flags, err)
	}
}

// Synthetic: an unreachable server is an unavailable error.
func TestVarzUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	conn := testConn(t, "127.0.0.1", nil)
	if _, err := conn.Varz(addr); !errors.Is(err, llx.ErrTargetUnavailable) {
		t.Errorf("err = %v, want unavailable", err)
	}
	// The local endpoint being down falls back to the reported address.
	if got := conn.ServerAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "reported:9000", addr); got != "reported:9000" {
		t.Errorf("got %q", got)
	}
}
