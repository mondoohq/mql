// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package health

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"go.mondoo.com/ranger-rpc"
)

// IngestStatus is the outcome of an unauthenticated reachability probe of the
// scan-upload ingest endpoint. The endpoint is a different host from the API on
// a different static IP, so it is possible — and in locked-down networks
// common — for the API to be reachable while uploads are blackholed. This is
// what makes that visible before a scan discovers it.
type IngestStatus struct {
	// Endpoint is the ingest endpoint that was probed.
	Endpoint string `json:"endpoint,omitempty"`
	// Reachable reports whether the endpoint answered at all. ANY HTTP status
	// counts: the probe is not authenticated and carries no presigned
	// signature, so the ingest proxy answers it with 404 — reaching that 404
	// already proves DNS, TCP, TLS and the proxy are all working, which is
	// exactly what a preflight needs to know.
	Reachable bool `json:"reachable"`
	// StatusCode is the HTTP status the endpoint answered with, 0 when it did
	// not answer. Recorded for diagnostics only; see Reachable for why it is
	// not compared against 200.
	StatusCode int `json:"statusCode,omitempty"`
	// LatencyMs is how long the probe took, on both the success and the failure
	// path (a firewall that blackholes the connection shows up as a latency
	// equal to the probe timeout, a rejecting one as a few milliseconds).
	LatencyMs int64 `json:"latencyMs,omitempty"`
	// Reason is a short stable label for why the probe failed, empty on
	// success. See the IngestFailure* constants.
	Reason string `json:"reason,omitempty"`
	// Error is the underlying transport error, empty on success.
	Error string `json:"error,omitempty"`
}

// Reasons an ingest probe failed. They are a closed set of short labels meant
// to be rendered as-is and to stay stable in the JSON output of `status`.
const (
	// IngestFailureDNS means the host did not resolve.
	IngestFailureDNS = "dns"
	// IngestFailureTimeout means nothing came back before the deadline — the
	// signature of a firewall that drops packets instead of rejecting them.
	IngestFailureTimeout = "timeout"
	// IngestFailureTLS means the TLS handshake failed, which is what an
	// intercepting proxy without a trusted certificate looks like.
	IngestFailureTLS = "tls"
	// IngestFailureConnectionRefused means the connection was actively
	// rejected, so something answered — a firewall that rejects rather than
	// drops, or a proxy with no route.
	IngestFailureConnectionRefused = "connection refused"
	// IngestFailureConnectionReset means an established connection was dropped.
	IngestFailureConnectionReset = "connection reset"
	// IngestFailureRequest means the endpoint could not be turned into a
	// request at all (a malformed URL), so nothing was ever sent.
	IngestFailureRequest = "invalid endpoint"
	// IngestFailureOther is the catch-all; Error carries the detail.
	IngestFailureOther = "unreachable"
)

// ingestProbeTimeout bounds a single ingest probe. A blackholed host answers
// nothing at all, so this is the wall-clock cost of the check in the worst
// case, and the reason callers run it concurrently with their other checks
// rather than in series.
const ingestProbeTimeout = 10 * time.Second

// ingestDrainLimit caps how much of the probe response body is read before the
// connection is returned to the pool. The endpoint answers a short 404 body;
// the limit is only there so a misconfigured host cannot stream at us.
const ingestDrainLimit = 4 << 10

// CheckIngestReachable probes the scan-upload ingest endpoint with a plain,
// unauthenticated GET and reports whether it answered.
//
// It sends no credentials: the ingest proxy strips platform auth headers and
// only honors the storage signature on a real upload, so there is nothing for a
// probe to authenticate with — and nothing to leak by probing. httpClient
// should be the caller's configured client so the probe traverses the same
// proxy (api_proxy / HTTPS_PROXY) real uploads do; nil falls back to the
// default client.
//
// An empty endpoint returns a zero IngestStatus without touching the network:
// callers that could not derive an endpoint skip the check rather than report a
// failure.
func CheckIngestReachable(ctx context.Context, httpClient *http.Client, endpoint string) IngestStatus {
	status := IngestStatus{Endpoint: endpoint}
	if endpoint == "" {
		return status
	}
	if httpClient == nil {
		httpClient = ranger.DefaultHttpClient()
	}

	ctx, cancel := context.WithTimeout(ctx, ingestProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		status.Reason = IngestFailureRequest
		status.Error = err.Error()
		return status
	}

	start := time.Now()
	resp, err := httpClient.Do(req)
	status.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		status.Reason = classifyIngestFailure(err)
		status.Error = err.Error()
		return status
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ingestDrainLimit))

	status.Reachable = true
	status.StatusCode = resp.StatusCode
	return status
}

// classifyIngestFailure maps a transport error to one of the IngestFailure*
// labels. It inspects the error tree with errors.Is/As rather than matching
// message strings, so it survives standard-library wording changes, and it
// checks the specific cases before the generic net.Error timeout: a DNS or TLS
// failure is also a net.Error, and "timeout" is the least useful of the answers
// that fit.
func classifyIngestFailure(err error) string {
	if err == nil {
		return ""
	}

	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return IngestFailureDNS
	}

	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return IngestFailureTLS
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return IngestFailureTLS
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return IngestFailureConnectionRefused
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return IngestFailureConnectionReset
	}

	// Checked after the cases above, and before context.Canceled: the probe's
	// own deadline surfaces as DeadlineExceeded, while a parent context that
	// was canceled (the whole command timed out) is still, from the user's
	// point of view, "nothing came back in time".
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return IngestFailureTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return IngestFailureTimeout
	}

	return IngestFailureOther
}
