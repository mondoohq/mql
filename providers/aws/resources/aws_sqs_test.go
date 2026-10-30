// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestSqsQueueName(t *testing.T) {
	tests := []struct {
		name     string
		queueURL string
		expected string
	}{
		{"standard url", "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue", "MyQueue"},
		{"fifo queue", "https://sqs.eu-west-1.amazonaws.com/123456789012/MyQueue.fifo", "MyQueue.fifo"},
		{"china partition", "https://sqs.cn-north-1.amazonaws.com.cn/123456789012/MyQueue", "MyQueue"},
		{"legacy host", "https://us-east-1.queue.amazonaws.com/123456789012/MyQueue", "MyQueue"},
		{"no path separator", "MyQueue", "MyQueue"},
		{"empty", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, sqsQueueName(test.queueURL))
		})
	}
}

func TestRegionFromSqsQueueURL(t *testing.T) {
	tests := []struct {
		name     string
		queueURL string
		expected string
	}{
		{"standard url", "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue", "us-east-1"},
		{"fips url", "https://sqs-fips.us-gov-west-1.amazonaws.com/123456789012/MyQueue", "us-gov-west-1"},
		{"china partition", "https://sqs.cn-north-1.amazonaws.com.cn/123456789012/MyQueue", "cn-north-1"},
		{"legacy host", "https://us-east-1.queue.amazonaws.com/123456789012/MyQueue", "us-east-1"},
		{"region-less legacy host", "https://queue.amazonaws.com/123456789012/MyQueue", ""},
		{"unrecognized host", "https://example.com/123456789012/MyQueue", ""},
		{"not a url", "MyQueue", ""},
		{"empty", "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, regionFromSqsQueueURL(test.queueURL))
		})
	}
}

func TestParseRedriveMaxReceiveCount(t *testing.T) {
	tests := []struct {
		name      string
		attr      string
		wantCount int64
		wantOk    bool
		wantErr   bool
	}{
		{
			// 10 of 11 live queues looked like this. The queue has no
			// receive-attempt limit, so there is no number to report.
			name:   "no redrive policy at all",
			attr:   "",
			wantOk: false,
		},
		{
			name:      "redrive policy set",
			attr:      `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":7}`,
			wantCount: 7,
			wantOk:    true,
		},
		{
			// The console has written the count as a quoted number.
			name:      "count written as a string",
			attr:      `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":"7"}`,
			wantCount: 7,
			wantOk:    true,
		},
		{
			name:      "a real limit of one is not absence",
			attr:      `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":1}`,
			wantCount: 1,
			wantOk:    true,
		},
		{
			name:   "policy without a maxReceiveCount",
			attr:   `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq"}`,
			wantOk: false,
		},
		{
			name:   "explicit json null",
			attr:   `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":null}`,
			wantOk: false,
		},
		{
			name:    "malformed json is an error, not an absence",
			attr:    `{"maxReceiveCount":`,
			wantErr: true,
		},
		{
			name:    "non-numeric count is an error, not an absence",
			attr:    `{"maxReceiveCount":"many"}`,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			count, ok, err := parseRedriveMaxReceiveCount(test.attr)
			if test.wantErr {
				assert.Error(t, err)
				assert.False(t, ok)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantOk, ok)
			assert.Equal(t, test.wantCount, count)
		})
	}
}

// sqsQueueWithAttributes builds a queue whose attribute fetch is already
// satisfied, so the accessors under test run without a connection.
func sqsQueueWithAttributes(atts map[string]string) *mqlAwsSqsQueue {
	q := &mqlAwsSqsQueue{
		Url:    plugin.TValue[string]{Data: "https://sqs.us-east-1.amazonaws.com/123456789012/MyQueue", State: plugin.StateIsSet},
		Region: plugin.TValue[string]{Data: "us-east-1", State: plugin.StateIsSet},
	}
	q.fetched = true
	q.queueAtts = atts
	return q
}

// A queue with no redrive policy has no maxReceiveCount attribute at all.
// Reporting 0 made `maxReceiveCount >= 3` fail on queues that never had the
// setting, and `maxReceiveCount < 100` pass as though it had been measured.
func TestSqsQueueMaxReceiveCountIsNullWithoutRedrivePolicy(t *testing.T) {
	q := sqsQueueWithAttributes(map[string]string{
		"QueueArn":          "arn:aws:sqs:us-east-1:123456789012:MyQueue",
		"VisibilityTimeout": "30",
	})

	count, err := q.maxReceiveCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
	assert.True(t, q.MaxReceiveCount.IsSet(), "field must be marked resolved")
	assert.True(t, q.MaxReceiveCount.IsNull(), "absent redrive policy must read null, not 0")
}

func TestSqsQueueMaxReceiveCountReportsConfiguredLimit(t *testing.T) {
	q := sqsQueueWithAttributes(map[string]string{
		"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":7}`,
	})

	count, err := q.maxReceiveCount()
	require.NoError(t, err)
	assert.Equal(t, int64(7), count)
	assert.False(t, q.MaxReceiveCount.IsNull(), "a configured limit must not read null")
}

// A queue whose redrive policy really sets 0 attempts is a measured 0 and must
// stay distinguishable from the absent case above.
func TestSqsQueueMaxReceiveCountZeroIsNotNull(t *testing.T) {
	q := sqsQueueWithAttributes(map[string]string{
		"RedrivePolicy": `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dlq","maxReceiveCount":0}`,
	})

	count, err := q.maxReceiveCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
	assert.False(t, q.MaxReceiveCount.IsNull(), "a measured 0 must not read null")
}
