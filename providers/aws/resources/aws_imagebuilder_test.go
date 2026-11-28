// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ibtypes "github.com/aws/aws-sdk-go-v2/service/imagebuilder/types"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestImagebuilderLaunchPermissionPublic(t *testing.T) {
	assert.False(t, imagebuilderLaunchPermissionPublic(nil))
	assert.False(t, imagebuilderLaunchPermissionPublic(&ibtypes.LaunchPermissionConfiguration{}))
	assert.False(t, imagebuilderLaunchPermissionPublic(&ibtypes.LaunchPermissionConfiguration{
		UserIds:          []string{"123456789012"},
		OrganizationArns: []string{"arn:aws:organizations::123456789012:organization/o-abc"},
	}))
	assert.True(t, imagebuilderLaunchPermissionPublic(&ibtypes.LaunchPermissionConfiguration{
		UserGroups: []string{"all"},
	}))
}

func TestImagebuilderCleanupDetection(t *testing.T) {
	assert.False(t, imagebuilderCleanupScriptDisabled(""))
	assert.False(t, imagebuilderCleanupScriptDisabled("  \n"))
	assert.True(t, imagebuilderCleanupScriptDisabled("#!/bin/bash\nyum install -y amazon-ssm-agent\n"))
	assert.False(t, imagebuilderCleanupScriptDisabled("#!/bin/bash\ntouch /var/lib/amazon/toe/perform_cleanup\n"))

	component := `
phases:
  - name: build
    steps:
      - name: Keep
        action: CreateFile
        inputs:
          - path: /var/lib/amazon/toe/skip_cleanup_ssh_files
          - path: /var/lib/amazon/toe/skip_cleanup_instance_log_files
          - path: /var/lib/amazon/toe/skip_cleanup_ssh_files
`
	assert.Equal(t, []string{"skip_cleanup_ssh_files", "skip_cleanup_instance_log_files"}, imagebuilderSkippedCleanupSections(component))
	assert.Equal(t, []string{}, imagebuilderSkippedCleanupSections("echo hello"))
}

func TestImagebuilderDecodeUserData(t *testing.T) {
	script := "#!/bin/bash\ntouch /var/lib/amazon/toe/perform_cleanup\n"
	assert.Equal(t, script, imagebuilderDecodeUserData(aws.String(base64.StdEncoding.EncodeToString([]byte(script)))))
	assert.Equal(t, "", imagebuilderDecodeUserData(nil))
	assert.Equal(t, "not base64!", imagebuilderDecodeUserData(aws.String("not base64!")))
}

func TestImagebuilderKmsKeyEmptyRefIsNull(t *testing.T) {
	var state plugin.State
	key, err := imagebuilderKmsKey(nil, "us-east-1", "", &state)
	assert.NoError(t, err)
	assert.Nil(t, key)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, state)
}
