// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tokenauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/logger/zerologadapter"
)

const (
	// githubAttemptTimeout bounds a single request to the GitHub Actions OIDC
	// endpoint. It is generous because the endpoint can be slow under load.
	githubAttemptTimeout = 10 * time.Second
	// githubMaxAttempts is the total number of tries, including the first.
	githubMaxAttempts = 3
	// githubBaseBackoff is the base delay before the second attempt; it
	// doubles for each following attempt.
	githubBaseBackoff = 1 * time.Second
	// githubMaxBackoff caps the wait between attempts, including a
	// server-provided Retry-After.
	githubMaxBackoff = 30 * time.Second
)

// GitHubTokenProvider fetches an identity token from GitHub Actions.
//
// The zero value is ready to use. The unexported fields override the defaults
// and exist for tests.
type GitHubTokenProvider struct {
	attemptTimeout time.Duration
	maxAttempts    int
	baseBackoff    time.Duration
}

// cappedBackoff is retryablehttp.DefaultBackoff, but never waits longer than
// waitMax. DefaultBackoff returns a Retry-After header uncapped.
func cappedBackoff(waitMin, waitMax time.Duration, attemptNum int, resp *http.Response) time.Duration {
	return min(retryablehttp.DefaultBackoff(waitMin, waitMax, attemptNum, resp), waitMax)
}

// githubRetryExhausted turns the end of the retries into an error that names
// the last status or error, wrapped so callers can still match a context
// error. It contains neither the bearer token nor the URL.
func githubRetryExhausted(resp *http.Response, err error, numTries int) (*http.Response, error) {
	if resp != nil {
		// drain so the connection can be reused
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("github Actions token request failed after %d attempt(s): status %d", numTries, resp.StatusCode)
	}
	if uerr, ok := errors.AsType[*url.Error](err); ok {
		err = uerr.Err
	}
	return nil, fmt.Errorf("github Actions token request failed after %d attempt(s): %w", numTries, err)
}

func (p *GitHubTokenProvider) GetToken(ctx context.Context, audience string) (string, error) {
	tokenRequestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	tokenRequestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")

	if tokenRequestToken == "" || tokenRequestURL == "" {
		return "", fmt.Errorf("github Actions environment variables not set")
	}

	timeout := p.attemptTimeout
	if timeout <= 0 {
		timeout = githubAttemptTimeout
	}
	maxAttempts := p.maxAttempts
	if maxAttempts <= 0 {
		maxAttempts = githubMaxAttempts
	}
	backoff := p.baseBackoff
	if backoff <= 0 {
		backoff = githubBaseBackoff
	}

	client := retryablehttp.NewClient()
	client.Logger = zerologadapter.New(log.Logger)
	client.HTTPClient = &http.Client{Timeout: timeout}
	client.RetryMax = maxAttempts - 1
	client.RetryWaitMin = backoff
	client.RetryWaitMax = githubMaxBackoff
	client.Backoff = cappedBackoff
	client.ErrorHandler = githubRetryExhausted

	tokenURL := fmt.Sprintf("%s&audience=%s", tokenRequestURL, url.QueryEscape(audience))
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "bearer "+tokenRequestToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github Actions token service returned non-OK status: %d", resp.StatusCode)
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("could not decode github Actions token response: %w", err)
	}
	if result.Value == "" {
		return "", fmt.Errorf("github Actions token service returned an empty token")
	}
	return result.Value, nil
}
