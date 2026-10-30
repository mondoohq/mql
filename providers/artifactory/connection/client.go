// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxResponseBytes bounds how much of a response is read. The instance
// configuration descriptor is the largest document this provider fetches and
// stays well below this on a large instance.
const maxResponseBytes = 64 << 20

// APIError captures a non-2xx response from the JFrog platform.
type APIError struct {
	StatusCode int
	Message    string
	URL        string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("artifactory API %s: %d (%s)", e.URL, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("artifactory API %s: %d", e.URL, e.StatusCode)
}

// IsForbidden reports whether err is an access-denied response. Several
// endpoints this provider reads are administrator-only, so a token issued for
// a normal account reaches them with a 401 or a 403.
func IsForbidden(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// IsNotFound reports whether err is a 404 response. An endpoint added in a
// later product version answers 404 on an older instance, which is how this
// provider tells an absent feature from a denied read.
func IsNotFound(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// GetJSON performs a GET against the platform and decodes the JSON body into
// out. The URL comes from ArtifactoryURL or AccessURL.
func (c *ArtifactoryConnection) GetJSON(ctx context.Context, requestURL string, out any) error {
	body, err := c.get(ctx, requestURL, "application/json")
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("artifactory API %s: decode response: %w", requestURL, err)
	}
	return nil
}

// GetRaw performs a GET and returns the JSON body undecoded, for an endpoint
// that answers with more than one document shape.
func (c *ArtifactoryConnection) GetRaw(ctx context.Context, requestURL string) ([]byte, error) {
	return c.get(ctx, requestURL, "application/json")
}

// GetXML performs a GET against the platform and decodes the XML body into
// out. The instance configuration descriptor is served as XML.
func (c *ArtifactoryConnection) GetXML(ctx context.Context, requestURL string, out any) error {
	body, err := c.get(ctx, requestURL, "application/xml")
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("artifactory API %s: decode response: %w", requestURL, err)
	}
	return nil
}

// GetText performs a GET against the platform and returns the body as a
// string. Some endpoints answer with a bare identifier rather than a document.
func (c *ArtifactoryConnection) GetText(ctx context.Context, requestURL string) (string, error) {
	body, err := c.get(ctx, requestURL, "text/plain")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (c *ArtifactoryConnection) get(ctx context.Context, requestURL string, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	c.authorize(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("artifactory API %s: %w", requestURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("artifactory API %s: read response: %w", requestURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    errorMessage(body),
			URL:        requestURL,
		}
	}

	return body, nil
}

// authorize adds the credential the connection was built with. An access token
// is a bearer token; the legacy API key travels in its own header.
func (c *ArtifactoryConnection) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
		return
	}
	if c.apiKey != "" {
		req.Header.Set("X-JFrog-Art-Api", c.apiKey)
	}
}

// errorMessage pulls the human-readable part out of an error body. The
// platform answers with an errors array, and a few endpoints answer with a
// plain message, so both shapes are read before falling back to nothing.
func errorMessage(body []byte) string {
	var envelope struct {
		Errors []struct {
			Message string `json:"message"`
			Status  int    `json:"status"`
		} `json:"errors"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil {
		messages := make([]string, 0, len(envelope.Errors))
		for _, e := range envelope.Errors {
			if e.Message != "" {
				messages = append(messages, e.Message)
			}
		}
		if len(messages) > 0 {
			return strings.Join(messages, "; ")
		}
		if envelope.Message != "" {
			return envelope.Message
		}
		if envelope.Error != "" {
			return envelope.Error
		}
	}
	return ""
}
