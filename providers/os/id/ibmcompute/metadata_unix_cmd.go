// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ibmcompute

import (
	"fmt"
	"strings"
)

const (
	// curlOptsUnix bounds every request. The check runs on every host whose
	// vendor is IBM, every AIX system among them, and where nothing answers on
	// 169.254.169.254 (on premises, or a Power Virtual Server without the
	// metadata service) a connect without a timeout waits for the TCP connect
	// timeout: 75 seconds on AIX 7.3.
	curlOptsUnix = `--retry 3 --retry-delay 1 --connect-timeout 1 --retry-max-time 5 --max-time 10 --noproxy '*'`
	baseUnix     = `-H "Authorization: Bearer %s" -v http://169.254.169.254/%s`
	tokenURLUnix = `-H "Metadata-Flavor: ibm" -X PUT "http://169.254.169.254/instance_identity/v1/token?version=2025-05-20" -d '{}'`
)

func unixCurlParams(token, path string) string {
	return fmt.Sprintf(baseUnix, token, path)
}

func unixTokenCmdString() string {
	return "curl " + curlOptsUnix + " " + tokenURLUnix
}

func unixMetadataCmdString(token, metadataPath string) string {
	return fmt.Sprintf("curl %s %s", curlOptsUnix, unixCurlParams(token, strings.TrimPrefix(metadataPath, "/")))
}
