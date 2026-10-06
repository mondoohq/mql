// Copyright Mondoo, Inc. 2026
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
	"time"

	"go.mondoo.com/ranger-rpc/plugins/rangerguard/crypto"
)

// Revoke asks the server to revoke a session credential (RFC 7009). The
// request is proven with the credential's private key and bound to the token.
func Revoke(ctx context.Context, client *http.Client, issuer, accessToken, privateKeyPEM string, insecure bool) error {
	if accessToken == "" {
		return errors.New("no session token to revoke")
	}
	if client == nil {
		client = http.DefaultClient
	}
	md, err := Discover(ctx, client, issuer, insecure)
	if err != nil {
		return err
	}
	if md.RevocationEndpoint == "" {
		return errors.New("the server does not support revocation")
	}
	key, err := crypto.PrivateKeyFromBytes([]byte(privateKeyPEM))
	if err != nil {
		return fmt.Errorf("could not load the session key: %w", err)
	}
	proof, err := NewKeyProof(key, md.RevocationEndpoint, accessToken, time.Now(), 5*time.Minute)
	if err != nil {
		return err
	}

	form := url.Values{
		"token":            {accessToken},
		"client_id":        {ClientID},
		"mondoo_key_proof": {proof},
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation failed: %s", resp.Status)
	}
	return nil
}
