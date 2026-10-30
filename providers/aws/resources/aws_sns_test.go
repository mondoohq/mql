// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// snsTopicWithAttributes builds a topic whose attribute fetch is already
// satisfied, so the accessors under test run without a connection.
func snsTopicWithAttributes(atts map[string]string) *mqlAwsSnsTopic {
	topic := &mqlAwsSnsTopic{
		Arn:    plugin.TValue[string]{Data: "arn:aws:sns:us-east-1:123456789012:MyTopic", State: plugin.StateIsSet},
		Region: plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet},
	}
	topic.fetched = true
	topic.topicAtts = atts
	return topic
}

// SNS omits SignatureVersion unless the topic was explicitly configured, and
// the default in force is 1. Reporting "" put every never-configured topic
// outside the documented enum, so `signatureVersion == "1"` missed most SigV1
// topics.
func TestSnsTopicSignatureVersion(t *testing.T) {
	tests := []struct {
		name string
		atts map[string]string
		want string
	}{
		{
			name: "absent means the service default of 1",
			atts: map[string]string{"TopicArn": "arn:aws:sns:us-east-1:123456789012:MyTopic"},
			want: "1",
		},
		{
			name: "explicitly set to 1",
			atts: map[string]string{"SignatureVersion": "1"},
			want: "1",
		},
		{
			name: "explicitly set to 2 is never overridden by the default",
			atts: map[string]string{"SignatureVersion": "2"},
			want: "2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			topic := snsTopicWithAttributes(test.atts)
			got, err := topic.signatureVersion()
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestSnsTopicTracingConfig(t *testing.T) {
	tests := []struct {
		name string
		atts map[string]string
		want string
	}{
		{
			name: "absent means the service default of PassThrough",
			atts: map[string]string{"TopicArn": "arn:aws:sns:us-east-1:123456789012:MyTopic"},
			want: "PassThrough",
		},
		{
			name: "explicitly set to PassThrough",
			atts: map[string]string{"TracingConfig": "PassThrough"},
			want: "PassThrough",
		},
		{
			name: "explicitly set to Active is never overridden by the default",
			atts: map[string]string{"TracingConfig": "Active"},
			want: "Active",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			topic := snsTopicWithAttributes(test.atts)
			got, err := topic.tracingConfig()
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestIsSnsOperationUnsupported(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// The exact answer every FIFO topic gives, in every account and
			// every region.
			name: "get data protection policy on a fifo topic",
			err: &smithy.GenericAPIError{
				Code:    "InvalidAction",
				Message: "Operation (GetDataProtectionPolicy) is not supported on FIFO topics",
			},
			want: true,
		},
		{
			// Must stay an error: a denial leaves the policy unknown and must
			// never become a silent null.
			name: "access denied is still an error",
			err:  &smithy.GenericAPIError{Code: "AuthorizationError", Message: "User is not authorized to perform: SNS:GetDataProtectionPolicy"},
			want: false,
		},
		{
			name: "not found is still an error here",
			err:  &smithy.GenericAPIError{Code: "NotFound", Message: "Topic does not exist"},
			want: false,
		},
		{
			name: "a throttle is still an error",
			err:  &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"},
			want: false,
		},
		{
			// A transport failure carries no API error and must never be read
			// as "this topic has no data protection policy".
			name: "a transport error is not an api error",
			err:  errors.New("dial tcp: lookup sns.us-east-1.amazonaws.com: no such host"),
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, isSnsOperationUnsupported(test.err))
		})
	}
}

// A FIFO topic has no data protection policy and SNS rejects the call, so the
// field reads null. It used to error on every FIFO topic in every region.
func TestSnsTopicDataProtectionPolicyIsNullOnFifoTopic(t *testing.T) {
	topic := snsTopicWithAttributes(map[string]string{"FifoTopic": "true"})

	policy, err := topic.dataProtectionPolicy()
	require.NoError(t, err)
	assert.Nil(t, policy)
	assert.True(t, topic.DataProtectionPolicy.IsSet(), "field must be marked resolved")
	assert.True(t, topic.DataProtectionPolicy.IsNull(), "a fifo topic must read null, not error")
}

func TestSnsTopicCachedFifoTopic(t *testing.T) {
	fifo, known := snsTopicWithAttributes(map[string]string{"FifoTopic": "true"}).cachedFifoTopic()
	assert.True(t, known)
	assert.True(t, fifo)

	standard, known := snsTopicWithAttributes(map[string]string{}).cachedFifoTopic()
	assert.True(t, known)
	assert.False(t, standard)

	// Nothing fetched yet, so the caller must not skip the API call on the
	// strength of a false it never read.
	unfetched := &mqlAwsSnsTopic{}
	_, known = unfetched.cachedFifoTopic()
	assert.False(t, known)
}

// A subscription that has not been confirmed carries the literal
// "PendingConfirmation" placeholder instead of an ARN, so SNS has no
// attributes to give for it. Those fields used to be synthesized: a reader saw
// confirmationWasAuthenticated:false ("not authenticated") when the truth was
// "not yet confirmed".
func TestSnsPendingSubscriptionReportsNullNotFalse(t *testing.T) {
	sub := &mqlAwsSnsSubscription{
		Arn:      plugin.TValue[string]{Data: "PendingConfirmation", State: plugin.StateIsSet},
		Protocol: plugin.TValue[string]{Data: "email", State: plugin.StateIsSet},
		Region:   plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet},
	}

	raw, err := sub.rawMessageDelivery()
	require.NoError(t, err)
	assert.False(t, raw)
	assert.True(t, sub.RawMessageDelivery.IsNull(), "rawMessageDelivery was never read")

	authed, err := sub.confirmationWasAuthenticated()
	require.NoError(t, err)
	assert.False(t, authed)
	assert.True(t, sub.ConfirmationWasAuthenticated.IsNull(), "there is no confirmation to authenticate yet")

	scope, err := sub.filterPolicyScope()
	require.NoError(t, err)
	assert.Empty(t, scope)
	assert.True(t, sub.FilterPolicyScope.IsNull(), "filterPolicyScope was never read")

	attrs, err := sub.attributes()
	require.NoError(t, err)
	assert.Nil(t, attrs, "attributes must not be a fabricated one-key map")
	assert.True(t, sub.Attributes.IsNull())

	// The one fact we do know stays a measured true.
	pending, err := sub.pendingConfirmation()
	require.NoError(t, err)
	assert.True(t, pending)
	assert.False(t, sub.PendingConfirmation.IsNull(), "pendingConfirmation is measured, not null")
}

// The confirmed path must keep reporting what SNS returned.
func TestSnsConfirmedSubscriptionReportsAttributes(t *testing.T) {
	sub := &mqlAwsSnsSubscription{
		Arn:    plugin.TValue[string]{Data: "arn:aws:sns:us-east-1:123456789012:MyTopic:5b9f3f4a-1c2d-4e5f-8a9b-0c1d2e3f4a5b", State: plugin.StateIsSet},
		Region: plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet},
	}
	sub.fetched = true
	sub.attrs = map[string]string{
		"RawMessageDelivery":           "true",
		"ConfirmationWasAuthenticated": "true",
		"FilterPolicyScope":            "MessageBody",
		"PendingConfirmation":          "false",
	}

	raw, err := sub.rawMessageDelivery()
	require.NoError(t, err)
	assert.True(t, raw)
	assert.False(t, sub.RawMessageDelivery.IsNull())

	authed, err := sub.confirmationWasAuthenticated()
	require.NoError(t, err)
	assert.True(t, authed)
	assert.False(t, sub.ConfirmationWasAuthenticated.IsNull())

	scope, err := sub.filterPolicyScope()
	require.NoError(t, err)
	assert.Equal(t, "MessageBody", scope)
	assert.False(t, sub.FilterPolicyScope.IsNull())

	pending, err := sub.pendingConfirmation()
	require.NoError(t, err)
	assert.False(t, pending)

	attrs, err := sub.attributes()
	require.NoError(t, err)
	assert.False(t, sub.Attributes.IsNull())
	dict, ok := attrs.(map[string]any)
	require.True(t, ok, "attributes must serialize to a map")
	assert.Equal(t, "MessageBody", dict["FilterPolicyScope"])
}
