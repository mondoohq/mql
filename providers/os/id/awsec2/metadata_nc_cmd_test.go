// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestEC2InstanceIdentityFreeBSDNetcat(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance-identity_document_freebsd_nc.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	require.Equal(t, "freebsd", platform.Name)

	metadata := NewCommandInstanceMetadata(conn, platform, nil)
	ident, err := metadata.Identify()
	require.NoError(t, err)

	// the Name tag lookup returns 404 (tags not exposed in IMDS), so the
	// instance ID is the name
	assert.Equal(t, "i-1234567890abcdef0", ident.InstanceName)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/ec2/v1/accounts/123456789012/regions/us-west-2/instances/i-1234567890abcdef0", ident.InstanceID)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/aws/accounts/123456789012", ident.AccountID)
}

func TestUsesNetcat(t *testing.T) {
	assert.True(t, usesNetcat(&inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}}))
	// Linux and macOS keep using curl
	assert.False(t, usesNetcat(&inventory.Platform{Name: "amazonlinux", Family: []string{"linux", "unix", "os"}}))
	assert.False(t, usesNetcat(&inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}))
	assert.False(t, usesNetcat(nil))
}

func TestNcMetadataCmdString(t *testing.T) {
	cmd, err := ncMetadataCmdString("AQAEAabc-_=", "/meta-data/instance-type")
	require.NoError(t, err)
	assert.Equal(t, `printf 'GET /latest/%s HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: %s\r\n\r\n' 'meta-data/instance-type' 'AQAEAabc-_=' | nc -w 5 169.254.169.254 80`, cmd)

	_, err = ncMetadataCmdString("TOK'EN", "meta-data/")
	assert.Error(t, err)

	// a failed token fetch must not turn into a request with a blank header
	_, err = ncMetadataCmdString("", "meta-data/")
	assert.Error(t, err)
}

func TestNcTokenCmdString(t *testing.T) {
	assert.Equal(t, `printf 'PUT /latest/api/token HTTP/1.0\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n' | nc -w 5 169.254.169.254 80`, ncTokenCmdString())
}

func TestEscapeIMDSPath(t *testing.T) {
	// MAC addresses are path segments in the network tree and must survive
	assert.Equal(t, "meta-data/network/interfaces/macs/06:ff:fa:c9:b7:d3/", escapeIMDSPath("meta-data/network/interfaces/macs/06:ff:fa:c9:b7:d3/"))
	assert.Equal(t, "meta-data/public-keys/0=my-key", escapeIMDSPath("/meta-data/public-keys/0=my-key"))
	// quotes, whitespace and line breaks cannot reach the shell or the request line
	assert.Equal(t, "meta-data/x%27%3B%20id%3B%20%27", escapeIMDSPath("meta-data/x'; id; '"))
	assert.Equal(t, "meta-data/x%0D%0AHost:%20evil", escapeIMDSPath("meta-data/x\r\nHost: evil"))
}

func TestParseRawHTTPResponse(t *testing.T) {
	// status line and headers as the FreeBSD 15.1 EC2 IMDS returned them
	ok := "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nAccept-Ranges: none\r\nContent-Length: 10\r\nServer: EC2ws\r\n\r\nt3.medium\n"
	body, err := parseRawHTTPResponse(strings.NewReader(ok))
	require.NoError(t, err)
	assert.Equal(t, "t3.medium", body)

	notFound := "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 19\r\nServer: EC2ws\r\n\r\n<h1>404 - Not Found"
	_, err = parseRawHTTPResponse(strings.NewReader(notFound))
	assert.ErrorContains(t, err, "404")

	unauthorized := "HTTP/1.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
	_, err = parseRawHTTPResponse(strings.NewReader(unauthorized))
	assert.ErrorContains(t, err, "401")

	// nc prints nothing when IMDS is unreachable
	_, err = parseRawHTTPResponse(strings.NewReader(""))
	assert.Error(t, err)
}
