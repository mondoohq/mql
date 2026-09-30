// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gce

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// curl fetches a single metadata path from the instance metadata service
func (m *CommandInstanceMetadata) curl(metadataPath string) (string, error) {
	var commandString string
	switch {
	case m.platform.IsFamily(inventory.FAMILY_UNIX):
		commandString = unixMetadataCmdString(metadataPath)
	case m.platform.IsFamily(inventory.FAMILY_WINDOWS):
		commandString = windowsMetadataCmdString(metadataPath)
	default:
		return "", errors.New("your platform is not supported by gce metadata identifier resource")
	}

	cmd, err := m.connection.RunCommand(commandString)
	if err != nil {
		return "", err
	}
	data, err := io.ReadAll(cmd.Stdout)
	return strings.TrimSpace(string(data)), err
}

func unixMetadataCmdString(metadataPath string) string {
	return fmt.Sprintf(`curl --noproxy '*' -H "Metadata-Flavor: Google" %s%s`, metadataSvcURL, strings.TrimPrefix(metadataPath, "/"))
}

// windowsMetadataCmdString is the PowerShell command that reads one metadata
// path. The script is multi-line and quoted, so it is encoded, as the AWS
// and IBM metadata commands are: passed as plain text through `powershell -c`
// (what the local connection does with a command) or through the SSH shell,
// its quotes and line breaks do not survive.
func windowsMetadataCmdString(metadataPath string) string {
	pipe := ""
	if windowsPathNeedsJSONConversion(metadataPath) {
		pipe = "| ConvertTo-Json"
	}
	return powershell.Encode(fmt.Sprintf(`$Headers = @{
    "Metadata-Flavor" = "Google"
}
Invoke-RestMethod -TimeoutSec 1 -Headers $Headers -URI "%s%s" -UseBasicParsing %s`, metadataSvcURL, strings.TrimPrefix(metadataPath, "/"), pipe))
}

func windowsPathNeedsJSONConversion(path string) bool {
	return strings.HasSuffix(path, "/token") ||
		strings.HasSuffix(path, "instance/tags")
}
