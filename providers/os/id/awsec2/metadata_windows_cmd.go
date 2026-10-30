// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	baseWindows = `
$Headers = @{
    "X-aws-ec2-metadata-token" = %s
}
Invoke-RestMethod -TimeoutSec 1 -Headers $Headers -Uri "http://169.254.169.254/latest/%s" -UseBasicParsing %s
`
	tokenURLWindows = `
$Headers = @{
    "X-aws-ec2-metadata-token-ttl-seconds" = "21600"
}
Invoke-RestMethod -Method Put -Uri "http://169.254.169.254/latest/api/token" -Headers $Headers -TimeoutSec 1 -UseBasicParsing
`
)

func windowsCurlCmd(token, path string) string {
	pipe := ""
	if windowsPathNeedsJSONConversion(path) {
		pipe = "| ConvertTo-Json"
	}
	// The token has to be a string literal. Unquoted, PowerShell runs it as
	// a command, which it can't find, and the request goes out without it.
	return fmt.Sprintf(baseWindows, powershell.SingleQuote(token), path, pipe)
}

func windowsPathNeedsJSONConversion(path string) bool {
	return strings.Contains(path, identityURLPath) ||
		strings.Contains(path, "meta-data/iam/info")
}

func windowsTokenCmdString() string {
	return powershell.Encode(tokenURLWindows)
}

func windowsMetadataCmdString(token, metadataPath string) string {
	return powershell.Encode(windowsCurlCmd(token, strings.TrimPrefix(metadataPath, "/")))
}
