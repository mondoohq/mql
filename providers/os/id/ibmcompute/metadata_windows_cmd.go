// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ibmcompute

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/powershell"
)

const (
	baseWindows = `
$Headers = @{
    "Authorization" = "Bearer %s"
}
Invoke-RestMethod -TimeoutSec 1 -Headers $Headers -Uri "http://169.254.169.254/%s" -UseBasicParsing | ConvertTo-Json
`
	tokenURLWindows = `
$Headers = @{
    "Metadata-Flavor" = "ibm"
}
Invoke-RestMethod -Method Put -Uri "http://169.254.169.254/instance_identity/v1/token?version=2025-05-20" -Headers $Headers -TimeoutSec 1 -UseBasicParsing | ConvertTo-Json
`
)

func windowsCurlCmd(token, path string) string {
	return fmt.Sprintf(baseWindows, token, path)
}

func windowsTokenCmdString() string {
	return powershell.Encode(tokenURLWindows)
}

func windowsMetadataCmdString(token, metadataPath string) string {
	return powershell.Encode(windowsCurlCmd(token, strings.TrimPrefix(metadataPath, "/")))
}
