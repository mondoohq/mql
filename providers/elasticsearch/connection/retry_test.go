// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// A refused dial must not be retried: each retry dials the same single
// address, which multiplied the time to fail on an unreachable host.
func TestRetryOnErrorSkipsDialFailures(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens here any more: the dial is refused

	// the error as the transport sees it, from a real round trip
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	_, dialErr := tr.RoundTrip(req)
	if dialErr == nil {
		t.Fatal("round trip to a closed port succeeded")
	}
	if retryOnError(req, dialErr) {
		t.Errorf("retryOnError(%v) = true, want no retry for a failed dial", dialErr)
	}
	if !retryOnError(req, &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}) {
		t.Error("an error after the connection was made should still be retried")
	}
}

// A connection dropped after it was made is still retried.
func TestDroppedConnectionIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		_, _ = w.Write([]byte(`{"cluster_name":"prod"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := newTestConn(t, map[string]string{OptionHost: u.Hostname(), OptionPort: u.Port(), OptionScheme: "http"})
	var out struct {
		ClusterName string `json:"cluster_name"`
	}
	if err := c.Get("/", &out); err != nil {
		t.Fatalf("Get after a dropped connection: %v", err)
	}
	if out.ClusterName != "prod" || calls.Load() != 2 {
		t.Errorf("cluster %q after %d calls, want prod after 2", out.ClusterName, calls.Load())
	}
}
