// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package oauthlogin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Revoke asks the login server to end a login (RFC 7009). The client is
// public and has no secret: holding the token is what allows revoking it.
// issuer is the login server the token came from.
func Revoke(ctx context.Context, client *http.Client, issuer, token string, insecure bool) error {
	if token == "" {
		return errors.New("no login token to revoke")
	}
	if client == nil {
		client = http.DefaultClient
	}
	md, err := DiscoverIssuer(ctx, client, issuer, insecure)
	if err != nil {
		return err
	}
	if md.RevocationEndpoint == "" {
		return errors.New("the server does not support revocation")
	}

	form := url.Values{
		"token":           {token},
		"token_type_hint": {"access_token"},
		"client_id":       {ClientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if snippet := bodySnippet(body); snippet != "" {
		return fmt.Errorf("revocation failed: %s: %s", resp.Status, snippet)
	}
	return fmt.Errorf("revocation failed: %s", resp.Status)
}

// bodySnippet returns a short, single-line excerpt of an error response body.
func bodySnippet(body []byte) string {
	return truncateUTF8(DisplayText(string(body)), 200)
}
