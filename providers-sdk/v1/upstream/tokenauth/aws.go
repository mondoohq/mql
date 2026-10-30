// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tokenauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	signerv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"go.mondoo.com/mql/utils/sortx"
)

const (
	// we use global STS endpoint and it maps to us-east-1
	awsStsURL     = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
	awsStsRegion  = "us-east-1"
	awsStsService = "sts"
	awsStsBody    = "Action=GetCallerIdentity&Version=2011-06-15"
)

// AWSTokenProvider generates a pre-signed STS GetCallerIdentity POST request
// and returns it as a JSON object for the AWS Workload Identity Federation
// token exchange flow. An audience is not necessary for AWS because the token is
// not a JWT, rather a pre-signed request as a JSON object.
type AWSTokenProvider struct{}

func (p *AWSTokenProvider) GetToken(ctx context.Context, _ string) (string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", err
	}

	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", awsStsURL, strings.NewReader(awsStsBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// SignHTTP attaches the following headers to the request:
	// - Authorization: SigV4 signature (algorithm, credential scope, signed headers, signature)
	// - X-Amz-Date: timestamp used during signing; AWS rejects requests older than ~15 minutes
	// - X-Amz-Security-Token: session token for temporary credentials (SSO, assumed roles, IMDS)
	bodyHash := sha256.Sum256([]byte(awsStsBody))
	err = signerv4.NewSigner().SignHTTP(
		ctx,
		creds,
		req,
		hex.EncodeToString(bodyHash[:]),
		awsStsService,
		awsStsRegion,
		time.Now(),
	)
	if err != nil {
		return "", err
	}

	headers := []map[string]string{}

	// Attach the host header as well, in case it is needed to reconstruct the signed request on the server side.
	if req.Host != "" {
		headers = append(headers, map[string]string{"key": "host", "value": req.Host})
	}

	for _, key := range sortx.Keys(req.Header) {
		values := req.Header.Values(key)
		if len(values) == 0 {
			continue
		}
		headers = append(headers, map[string]string{"key": key, "value": values[0]})
	}

	token := map[string]any{
		"method":  "POST",
		"url":     awsStsURL,
		"headers": headers,
	}
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return string(tokenBytes), nil
}
