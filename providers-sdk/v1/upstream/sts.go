// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/upstream/tokenauth"
	"go.mondoo.com/mql/providers/os/connection/ssh/signers"
	"golang.org/x/crypto/ssh"
)

func ExchangeSSHKey(apiEndpoint string, identityMrn string, resourceMrn string) (*ServiceAccountCredentials, error) {
	stsClient, err := NewSecureTokenServiceClient(apiEndpoint, DefaultHttpClient())
	if err != nil {
		return nil, err
	}

	claims := &Claims{
		Subject:  identityMrn,
		Resource: resourceMrn,
		Exp:      time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Iat:      time.Now().Format(time.RFC3339),
	}

	// fetch all signers from ssh
	sshSigners := signers.GetSignersFromSSHAgent()

	signatures, err := signClaims(claims, sshSigners...)
	if err != nil {
		return nil, err
	}

	resp, err := stsClient.ExchangeSSH(context.Background(), &ExchangeSSHKeyRequest{
		Claims:     claims,
		Signatures: signatures,
	})
	if err != nil {
		return nil, err
	}
	return &ServiceAccountCredentials{
		Mrn:         resp.Mrn,
		ParentMrn:   resp.ParentMrn,
		PrivateKey:  resp.PrivateKey,
		Certificate: resp.Certificate,
		ApiEndpoint: resp.ApiEndpoint,
	}, nil
}

func ExchangeExternalToken(apiEndpoint, audience, issuerURI, jwtToken string, tokenResponse bool) (*ServiceAccountCredentials, error) {
	if jwtToken == "" {
		// Try to fetch the token from an environment variable
		jwtToken = os.Getenv("JWT_TOKEN")
	}

	if jwtToken == "" {
		// Try to resolve a token provider from the issuer URI
		provider, err := tokenauth.Resolve(issuerURI)
		if err != nil {
			return nil, err
		}

		// Try to fetch the identity token from the resolved cloud provider
		jsonToken, err := provider.GetToken(context.Background(), audience)
		if err != nil {
			return nil, err
		}
		jwtToken = jsonToken
	}

	if jwtToken == "" {
		return nil, fmt.Errorf("no identity token to use for an external exchange")
	}

	stsClient, err := NewSecureTokenServiceClient(apiEndpoint, DefaultHttpClient())
	if err != nil {
		return nil, err
	}

	request := &ExchangeExternalTokenRequest{
		Audience:  audience,
		IssuerUri: issuerURI,
		JwtToken:  jwtToken,
	}
	if tokenResponse {
		request.ResponseType = "TOKEN"
	}
	resp, err := stsClient.ExchangeExternalToken(context.Background(), request)
	if err != nil {
		return nil, err
	}

	// Decode the base64 credential string
	credBytes, err := base64.StdEncoding.DecodeString(resp.Base64Credential)
	if err != nil {
		return nil, err
	}

	if tokenResponse {
		var tokenCreds struct {
			Mrn         string `json:"mrn"`
			SpaceMrn    string `json:"space_mrn"`
			Token       string `json:"token"`
			ApiEndpoint string `json:"api_endpoint"`
		}
		if err := json.Unmarshal(credBytes, &tokenCreds); err != nil {
			return nil, err
		}
		return &ServiceAccountCredentials{
			Mrn:         tokenCreds.Mrn,
			ParentMrn:   tokenCreds.SpaceMrn,
			ScopeMrn:    tokenCreds.SpaceMrn,
			Token:       tokenCreds.Token,
			ApiEndpoint: tokenCreds.ApiEndpoint,
		}, nil
	}

	// First unmarshal to a temporary structure to handle the field name mismatch
	var tempCreds struct {
		Mrn         string `json:"mrn"`
		ParentMrn   string `json:"parent_mrn"`
		SpaceMrn    string `json:"space_mrn"`
		PrivateKey  string `json:"private_key"`
		Certificate string `json:"certificate"`
		ApiEndpoint string `json:"api_endpoint"`
	}

	if err := json.Unmarshal(credBytes, &tempCreds); err != nil {
		return nil, err
	}

	// Create the ServiceAccountCredentials with the correct field mapping
	creds := ServiceAccountCredentials{
		Mrn:         tempCreds.Mrn,
		ParentMrn:   tempCreds.SpaceMrn,
		ScopeMrn:    tempCreds.SpaceMrn, // Map SpaceMrn to ScopeMrn
		PrivateKey:  tempCreds.PrivateKey,
		Certificate: tempCreds.Certificate,
		ApiEndpoint: tempCreds.ApiEndpoint,
	}

	return &creds, nil
}

// signClaims implements claims signing with ssh.Signer
//
// To generate a new SSH key use:
// ssh-keygen -t ed25519 -C "your_email@example.com"
func signClaims(claims *Claims, signer ...ssh.Signer) ([]*SshSignature, error) {
	data, err := HashClaimsSha256(claims)
	if err != nil {
		return nil, err
	}

	signatures := make([]*SshSignature, 0, len(signer))
	for i := range signer {
		sig := signer[i]

		// sign content
		sshSign, err := sig.Sign(rand.Reader, data)
		if err != nil {
			return nil, err
		}

		signatures = append(signatures, &SshSignature{
			Alg: "x5t#S256",
			Kid: ssh.FingerprintSHA256(sig.PublicKey()),
			Sig: hex.EncodeToString(ssh.Marshal(sshSign)),
		})
	}
	return signatures, nil
}

// sha256hash returns a hash of the claims data
func sha256hash(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// builds a canonical string from the claims to ensure that the hash is always the same and keys cannot be swapped
func buildCanonicalString(claims *Claims) string {
	params := url.Values{}
	params.Add("subject", claims.Subject)
	params.Add("resource", claims.Resource)
	params.Add("exp", claims.Exp)
	params.Add("iat", claims.Iat)
	return params.Encode() + "\n"
}

// HashClaims returns a hash of the claims data
func HashClaimsSha256(claims *Claims) ([]byte, error) {
	strToHash := buildCanonicalString(claims)
	return []byte(hex.EncodeToString(sha256hash([]byte(strToHash)))), nil
}
