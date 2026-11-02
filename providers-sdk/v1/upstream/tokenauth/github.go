// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tokenauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
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
	// githubMaxRetryAfter caps how long a Retry-After header can make us wait.
	githubMaxRetryAfter = 30 * time.Second
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

// githubTransientError marks a failure that is worth retrying.
type githubTransientError struct {
	err        error
	retryAfter time.Duration
}

func (e *githubTransientError) Error() string { return e.err.Error() }
func (e *githubTransientError) Unwrap() error { return e.err }

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

	tokenURL := fmt.Sprintf("%s&audience=%s", tokenRequestURL, url.QueryEscape(audience))
	client := &http.Client{Timeout: timeout}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		token, err := fetchGitHubToken(ctx, client, tokenURL, tokenRequestToken)
		if err == nil {
			return token, nil
		}
		lastErr = err

		transient, ok := errors.AsType[*githubTransientError](err)
		if !ok {
			return "", err
		}
		if attempt == maxAttempts {
			break
		}

		// exponential backoff with jitter in [delay/2, delay]
		delay := backoff << (attempt - 1)
		delay = delay/2 + rand.N(delay/2+1)
		if transient.retryAfter > 0 {
			delay = min(transient.retryAfter, githubMaxRetryAfter)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", fmt.Errorf("github Actions token request failed after %d attempts: %w", maxAttempts, lastErr)
}

// fetchGitHubToken performs a single token request. Transient failures are
// wrapped in a *githubTransientError.
func fetchGitHubToken(ctx context.Context, client *http.Client, tokenURL, bearer string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "bearer "+bearer)

	resp, err := client.Do(req)
	if err != nil {
		// the parent context ending is final, anything else (timeout,
		// connection reset, ...) may succeed on retry
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if uerr, ok := errors.AsType[*url.Error](err); ok {
			// do not leak the request URL into the error
			err = uerr.Err
		}
		return "", &githubTransientError{err: err}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		terr := &githubTransientError{err: fmt.Errorf("github Actions token service returned status: %d", resp.StatusCode)}
		if secs, convErr := strconv.Atoi(resp.Header.Get("Retry-After")); convErr == nil && secs > 0 {
			terr.retryAfter = time.Duration(secs) * time.Second
		}
		return "", terr
	default:
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
