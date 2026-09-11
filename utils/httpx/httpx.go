// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package httpx

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/logger/zerologadapter"
)

const (
	// EnvDownloadTimeout configures the idle timeout for provider and binary
	// downloads. The timeout resets every time data is received, so slow but
	// active transfers are not interrupted. Format: Go duration string
	// (e.g. "5m", "120s"). Default: 2 minutes.
	EnvDownloadTimeout     = "MONDOO_DOWNLOAD_TIMEOUT"
	DefaultDownloadTimeout = 2 * time.Minute

	defaultHttpTimeout         = 30 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
)

// DownloadTimeout returns the configured idle timeout for downloads.
// It reads MONDOO_DOWNLOAD_TIMEOUT and falls back to DefaultDownloadTimeout.
func DownloadTimeout() time.Duration {
	v := os.Getenv(EnvDownloadTimeout)
	if v == "" {
		return DefaultDownloadTimeout
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Warn().Str("value", v).Msg("invalid " + EnvDownloadTimeout + " value, using default")
		return DefaultDownloadTimeout
	}
	if d <= 0 {
		log.Warn().Str("value", v).Msg(EnvDownloadTimeout + " must be positive, using default")
		return DefaultDownloadTimeout
	}
	return d
}

// ClientForDownload creates an HTTP client tuned for large file downloads.
// It does NOT set http.Client.Timeout, which would cap the entire request
// lifecycle including body reads. Callers should wrap the response body with
// NewIdleTimeoutReader to detect stalled transfers.
func ClientForDownload() (*http.Client, error) {
	// api_proxy, the environment or the operating system's settings, in that
	// order; see cli/config/proxy.go.
	proxyFn, err := config.ProxyFunc()
	if err != nil {
		log.Fatal().Err(err).Msg("could not parse proxy URL")
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = zerologadapter.New(log.Logger)
	retryClient.HTTPClient = &http.Client{
		Transport: &http.Transport{
			Proxy: proxyFn,
			DialContext: (&net.Dialer{
				Timeout:   defaultHttpTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       defaultIdleConnTimeout,
			TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	return retryClient.StandardClient(), nil
}

// IdleTimeoutReader wraps an io.ReadCloser and enforces an idle timeout.
// If no data is received for the configured duration, the underlying reader
// is closed, causing any blocked Read to return an error.
type IdleTimeoutReader struct {
	body     io.ReadCloser
	timeout  time.Duration
	timer    *time.Timer
	timedOut atomic.Bool
}

// NewIdleTimeoutReader wraps body with an idle timeout. The timer starts
// immediately; each successful Read that returns data resets it.
func NewIdleTimeoutReader(body io.ReadCloser, timeout time.Duration) *IdleTimeoutReader {
	itr := &IdleTimeoutReader{
		body:    body,
		timeout: timeout,
	}
	itr.timer = time.AfterFunc(timeout, func() {
		itr.timedOut.Store(true)
		body.Close()
	})
	return itr
}

func (itr *IdleTimeoutReader) Read(p []byte) (int, error) {
	n, err := itr.body.Read(p)
	if n > 0 {
		itr.timer.Reset(itr.timeout)
	}
	if err != nil && itr.timedOut.Load() {
		return n, fmt.Errorf("download stalled: no data received for %s (configure with %s)", itr.timeout, EnvDownloadTimeout)
	}
	return n, err
}

func (itr *IdleTimeoutReader) Close() error {
	itr.timer.Stop()
	if itr.timedOut.Load() {
		return nil // body already closed by timer callback
	}
	return itr.body.Close()
}
