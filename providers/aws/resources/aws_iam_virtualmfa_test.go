// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
)

func TestVirtualMfaDeviceArgsUserArn(t *testing.T) {
	enabled := time.Date(2023, 1, 8, 9, 25, 27, 0, time.UTC)

	t.Run("assigned to root", func(t *testing.T) {
		// ListVirtualMFADevices returns the root user with an ARN and no user name.
		args := virtualMfaDeviceArgs(iamtypes.VirtualMFADevice{
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/authenticator"),
			EnableDate:   aws.Time(enabled),
			User:         &iamtypes.User{Arn: aws.String("arn:aws:iam::123456789012:root")},
		})
		assert.Equal(t, "arn:aws:iam::123456789012:root", args["userArn"].Value)
	})

	t.Run("assigned to an IAM user", func(t *testing.T) {
		args := virtualMfaDeviceArgs(iamtypes.VirtualMFADevice{
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/alice"),
			EnableDate:   aws.Time(enabled),
			User: &iamtypes.User{
				Arn:      aws.String("arn:aws:iam::123456789012:user/alice"),
				UserName: aws.String("alice"),
			},
		})
		assert.Equal(t, "arn:aws:iam::123456789012:user/alice", args["userArn"].Value)
	})

	t.Run("unassigned", func(t *testing.T) {
		args := virtualMfaDeviceArgs(iamtypes.VirtualMFADevice{
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/spare"),
		})
		assert.Nil(t, args["userArn"].Value)
	})
}
