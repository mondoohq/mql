// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2/apiv1/pubsubpb"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestPubsubSchemaTypeString(t *testing.T) {
	t.Run("protocol buffer", func(t *testing.T) {
		assert.Equal(t, "PROTOCOL_BUFFER", pubsubSchemaTypeString(pubsubpb.Schema_PROTOCOL_BUFFER))
	})

	t.Run("avro", func(t *testing.T) {
		assert.Equal(t, "AVRO", pubsubSchemaTypeString(pubsubpb.Schema_AVRO))
	})

	t.Run("unspecified", func(t *testing.T) {
		assert.Equal(t, "TYPE_UNSPECIFIED", pubsubSchemaTypeString(pubsubpb.Schema_TYPE_UNSPECIFIED))
	})

	t.Run("unknown value", func(t *testing.T) {
		assert.Equal(t, "TYPE_UNSPECIFIED", pubsubSchemaTypeString(pubsubpb.Schema_Type(99)))
	})
}

func TestPubsubSchemaEncodingString(t *testing.T) {
	t.Run("JSON encoding", func(t *testing.T) {
		assert.Equal(t, "JSON", pubsubSchemaEncodingString(pubsubpb.Encoding_JSON))
	})

	t.Run("binary encoding", func(t *testing.T) {
		assert.Equal(t, "BINARY", pubsubSchemaEncodingString(pubsubpb.Encoding_BINARY))
	})

	t.Run("unspecified encoding", func(t *testing.T) {
		assert.Equal(t, "ENCODING_UNSPECIFIED", pubsubSchemaEncodingString(pubsubpb.Encoding(99)))
	})
}

func TestBuildTopicSchemaSettings(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildTopicSchemaSettings(nil, "parent", nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestLastPathSegment(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"full topic path", "projects/my-project/topics/my-topic", "my-topic"},
		{"full subscription path", "projects/my-project/subscriptions/my-sub", "my-sub"},
		{"full snapshot path", "projects/my-project/snapshots/my-snap", "my-snap"},
		{"already short id", "my-topic", "my-topic"},
		{"deleted topic literal", "_deleted-topic_", "_deleted-topic_"},
		{"empty string", "", ""},
		{"trailing slash", "projects/p/topics/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, lastPathSegment(tc.in))
		})
	}
}

func TestPbDurationToTime(t *testing.T) {
	t.Run("nil returns zero duration", func(t *testing.T) {
		assert.Equal(t, llx.DurationToTime(0), pbDurationToTime(nil))
	})

	t.Run("populated returns matching seconds", func(t *testing.T) {
		got := pbDurationToTime(durationpb.New(7 * 24 * time.Hour))
		assert.Equal(t, llx.DurationToTime(int64((7 * 24 * time.Hour).Seconds())), got)
	})

	t.Run("sub-second duration truncates to zero", func(t *testing.T) {
		assert.Equal(t, llx.DurationToTime(0), pbDurationToTime(durationpb.New(500*time.Millisecond)))
	})
}

func TestTopicStateToString(t *testing.T) {
	cases := []struct {
		name  string
		state pubsubpb.Topic_State
		want  string
	}{
		{"active", pubsubpb.Topic_ACTIVE, "ACTIVE"},
		{"ingestion error", pubsubpb.Topic_INGESTION_RESOURCE_ERROR, "INGESTION_RESOURCE_ERROR"},
		{"unspecified", pubsubpb.Topic_STATE_UNSPECIFIED, "STATE_UNSPECIFIED"},
		{"unknown value", pubsubpb.Topic_State(99), "STATE_UNSPECIFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, topicStateToString(tc.state))
		})
	}
}

func TestSubscriptionStateToString(t *testing.T) {
	cases := []struct {
		name  string
		state pubsubpb.Subscription_State
		want  string
	}{
		{"active", pubsubpb.Subscription_ACTIVE, "ACTIVE"},
		{"resource error", pubsubpb.Subscription_RESOURCE_ERROR, "RESOURCE_ERROR"},
		{"unspecified", pubsubpb.Subscription_STATE_UNSPECIFIED, "STATE_UNSPECIFIED"},
		{"unknown value", pubsubpb.Subscription_State(99), "STATE_UNSPECIFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, subscriptionStateToString(tc.state))
		})
	}
}

// TestPubsubTopicRefPathParsing covers the project + short-name extraction that
// resolvePubsubTopicRef relies on to resolve a typed pubsub topic from a full
// "projects/{project}/topics/{topic}" reference. The cross-reference bug it
// guards against passed the full path as the topic name and dropped the
// project, so the topic init (which matches on the short name and needs the
// project to build its parent service) never resolved the reference.
func TestPubsubTopicRefPathParsing(t *testing.T) {
	const ref = "projects/my-project/topics/my-topic"
	assert.Equal(t, "my-project", parseProjectFromPath(ref))
	assert.Equal(t, "my-topic", parseResourceName(ref))

	// a bare topic name carries no project segment
	assert.Equal(t, "", parseProjectFromPath("my-topic"))
	assert.Equal(t, "my-topic", parseResourceName("my-topic"))
}
