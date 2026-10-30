// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// FreeBSD ships neither curl nor wget in the base system, and its fetch(1)
// cannot send a PUT or custom headers, both of which IMDSv2 needs. nc(1) is
// part of base on every release, so on FreeBSD we write the HTTP request
// ourselves and parse the raw response.

const (
	imdsAddr           = "169.254.169.254"
	imdsTTLHeader      = "X-aws-ec2-metadata-token-ttl-seconds"
	imdsSessionHeader  = "X-aws-ec2-metadata-token"
	imdsSessionTTLSecs = "21600"
)

// ncRequest builds a shell command that sends one HTTP/1.0 request to IMDS
// through nc. The request is a printf format; args are single-quoted printf
// arguments that fill its %s placeholders.
func ncRequest(requestLine string, headers []string, args ...string) string {
	lines := append([]string{requestLine, "Host: " + imdsAddr}, headers...)
	format := strings.Join(lines, `\r\n`) + `\r\n\r\n`
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, "'"+format+"'")
	for _, a := range args {
		quoted = append(quoted, "'"+a+"'")
	}
	return "printf " + strings.Join(quoted, " ") + " | nc -w 5 " + imdsAddr + " 80"
}

// usesNetcat reports whether IMDS requests on this platform go through nc
// instead of curl.
func usesNetcat(pf *inventory.Platform) bool {
	return pf != nil && pf.Name == "freebsd"
}

func ncTokenCmdString() string {
	return ncRequest("PUT /latest/api/token HTTP/1.0", []string{imdsTTLHeader + ": " + imdsSessionTTLSecs})
}

func ncMetadataCmdString(token, metadataPath string) (string, error) {
	if !isTokenSafe(token) {
		return "", errors.New("refusing to build IMDS request for an unexpected token")
	}
	return ncRequest("GET /latest/%s HTTP/1.0", []string{imdsSessionHeader + ": %s"}, escapeIMDSPath(metadataPath), token), nil
}

// escapeIMDSPath percent-encodes every segment of an IMDS path. The result
// holds no quote, whitespace or control character, so it can neither leave the
// single quotes it is placed in nor split the HTTP request line. Separators
// IMDS keys use, like the colons in a MAC address, stay as they are.
func escapeIMDSPath(p string) string {
	segments := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return strings.Join(segments, "/")
}

// isTokenSafe accepts the characters an IMDSv2 token is made of (base64 with
// the URL-safe alphabet). Anything else could break out of the single quotes
// the token is placed in, or out of the header line.
func isTokenSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./=+", r):
		default:
			return false
		}
	}
	return true
}

// parseRawHTTPResponse returns the body of a raw HTTP response as nc prints
// it. Anything other than a 200 is an error, so a 404 page never ends up
// being read as a metadata value.
func parseRawHTTPResponse(r io.Reader) (string, error) {
	resp, err := http.ReadResponse(bufio.NewReader(r), nil)
	if err != nil {
		return "", errors.Wrap(err, "failed to read IMDS response")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "failed to read IMDS response body")
	}
	return strings.TrimSpace(string(body)), nil
}
