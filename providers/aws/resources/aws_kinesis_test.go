// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	firehose_types "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFirehoseDeliveryStreamArgsAreSettableFields pins every argument the
// delivery stream constructor passes to a field the generated schema can
// actually set. SetAllData rejects an unknown key outright, so a stale
// argument left behind by a schema change does not degrade a field - it fails
// the whole lister, on any account that has a delivery stream.
func TestFirehoseDeliveryStreamArgsAreSettableFields(t *testing.T) {
	args := firehoseDeliveryStreamArgs(&firehose_types.DeliveryStreamDescription{
		DeliveryStreamARN:  aws.String("arn:aws:firehose:us-east-1:123456789012:deliverystream/logs"),
		DeliveryStreamName: aws.String("logs"),
		DeliveryStreamEncryptionConfiguration: &firehose_types.DeliveryStreamEncryptionConfiguration{
			Status: firehose_types.DeliveryStreamEncryptionStatusEnabled,
		},
	}, "us-east-1")

	require.NotEmpty(t, args)
	for key := range args {
		if key == "__id" {
			continue
		}
		_, ok := setDataFields["aws.kinesis.firehoseDeliveryStream."+key]
		assert.True(t, ok, "aws.kinesis.firehoseDeliveryStream has no settable field %q", key)
	}

	// The encryption configuration reaches the resource through the typed
	// serverSideEncryption accessor, never as a raw dict argument.
	assert.NotContains(t, args, "encryption")
}
