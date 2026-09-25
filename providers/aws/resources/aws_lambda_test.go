// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func TestGetLambdaArn(t *testing.T) {
	t.Run("standard function ARN", func(t *testing.T) {
		arn := getLambdaArn("my-function", "us-east-1", "123456789012")
		assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:my-function", arn)
	})

	t.Run("different region and account", func(t *testing.T) {
		arn := getLambdaArn("process-orders", "eu-west-1", "987654321098")
		assert.Equal(t, "arn:aws:lambda:eu-west-1:987654321098:function:process-orders", arn)
	})

	t.Run("empty account ID", func(t *testing.T) {
		arn := getLambdaArn("my-function", "us-east-1", "")
		assert.Equal(t, "arn:aws:lambda:us-east-1::function:my-function", arn)
	})
}

func TestLambdaFunctionRole(t *testing.T) {
	t.Run("nil cacheRoleArn sets null state", func(t *testing.T) {
		fn := &mqlAwsLambdaFunction{}
		// cacheRoleArn is nil by default
		result, err := fn.role()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fn.Role.IsNull())
		assert.True(t, fn.Role.IsSet())
	})

	t.Run("empty cacheRoleArn sets null state", func(t *testing.T) {
		fn := &mqlAwsLambdaFunction{}
		empty := ""
		fn.cacheRoleArn = &empty
		result, err := fn.role()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fn.Role.IsNull())
		assert.True(t, fn.Role.IsSet())
	})
}

// TestGetLambdaArnFromRawDataArgs pins the ARN a name-and-region lookup
// composes from its init arguments. RawData.String() is the display form and
// wraps a string in quote characters, so reading an argument that way puts the
// quotes inside the ARN and the lookup can never match a real function.
func TestGetLambdaArnFromRawDataArgs(t *testing.T) {
	nameArg := llx.StringData("my-function")
	regionArg := llx.StringData("us-east-1")

	// The display form is what the bug used.
	assert.Equal(t, `"my-function"`, nameArg.String())

	name, _ := nameArg.Value.(string)
	region, _ := regionArg.Value.(string)
	assert.Equal(t,
		"arn:aws:lambda:us-east-1:123456789012:function:my-function",
		getLambdaArn(name, region, "123456789012"))
}

// TestLambdaStatusFromConfiguration pins the difference between a
// ListFunctions summary and a real function configuration. ListFunctions
// returns none of the lifecycle fields, so reading them off a summary reported
// "" as a measured state for every function in every account, and
// `functions.all(state == "Active")` failed everywhere.
func TestLambdaStatusFromConfiguration(t *testing.T) {
	t.Run("nil configuration carries no status", func(t *testing.T) {
		assert.Nil(t, lambdaStatusFromConfiguration(nil))
	})

	t.Run("ListFunctions summary carries no status", func(t *testing.T) {
		// The shape ListFunctions actually returns: identity and code
		// settings, no lifecycle fields at all.
		summary := lambdatypes.FunctionConfiguration{
			FunctionName: aws.String("my-function"),
			FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
			Runtime:      lambdatypes.RuntimePython313,
			MemorySize:   aws.Int32(128),
		}
		assert.Nil(t, lambdaStatusFromConfiguration(&summary))
	})

	t.Run("GetFunction configuration carries the status", func(t *testing.T) {
		cfg := lambdatypes.FunctionConfiguration{
			FunctionName:     aws.String("my-function"),
			State:            lambdatypes.StateActive,
			LastUpdateStatus: lambdatypes.LastUpdateStatusSuccessful,
			RuntimeVersionConfig: &lambdatypes.RuntimeVersionConfig{
				RuntimeVersionArn: aws.String("arn:aws:lambda:us-east-1::runtime:abc123"),
			},
		}
		status := lambdaStatusFromConfiguration(&cfg)
		require.NotNil(t, status)
		assert.Equal(t, "Active", status.State())
		assert.Equal(t, "Successful", status.LastUpdateStatus())
		assert.Equal(t, "arn:aws:lambda:us-east-1::runtime:abc123", status.RuntimeVersionArn())
		// AWS names no reason for a healthy function.
		assert.Equal(t, "", status.StateReason())
		assert.Equal(t, "", status.LastUpdateStatusReason())
	})

	t.Run("failed function reports its reasons", func(t *testing.T) {
		cfg := lambdatypes.FunctionConfiguration{
			State:                  lambdatypes.StateFailed,
			StateReason:            aws.String("The function is missing its VPC configuration"),
			LastUpdateStatus:       lambdatypes.LastUpdateStatusFailed,
			LastUpdateStatusReason: aws.String("ENI limit exceeded"),
		}
		status := lambdaStatusFromConfiguration(&cfg)
		require.NotNil(t, status)
		assert.Equal(t, "Failed", status.State())
		assert.Equal(t, "The function is missing its VPC configuration", status.StateReason())
		assert.Equal(t, "Failed", status.LastUpdateStatus())
		assert.Equal(t, "ENI limit exceeded", status.LastUpdateStatusReason())
	})
}

func TestLambdaStatusFromConfigurationOutput(t *testing.T) {
	t.Run("flattened response carries the status", func(t *testing.T) {
		resp := &lambda.GetFunctionConfigurationOutput{
			State:            lambdatypes.StateInactive,
			StateReason:      aws.String("Function is idle"),
			LastUpdateStatus: lambdatypes.LastUpdateStatusInProgress,
			RuntimeVersionConfig: &lambdatypes.RuntimeVersionConfig{
				RuntimeVersionArn: aws.String("arn:aws:lambda:eu-west-1::runtime:def456"),
			},
		}
		status := lambdaStatusFromConfigurationOutput(resp)
		require.NotNil(t, status)
		assert.Equal(t, "Inactive", status.State())
		assert.Equal(t, "Function is idle", status.StateReason())
		assert.Equal(t, "InProgress", status.LastUpdateStatus())
		assert.Equal(t, "arn:aws:lambda:eu-west-1::runtime:def456", status.RuntimeVersionArn())
	})

	t.Run("nil response carries no status", func(t *testing.T) {
		assert.Nil(t, lambdaStatusFromConfigurationOutput(nil))
	})
}

// TestLambdaFunctionStatusAccessorsReportNullWhenUnread covers the branch the
// 404 path lands in: the lookup ran and returned nothing, so every field
// derived from it has to read null rather than "".
func TestLambdaFunctionStatusAccessorsReportNullWhenUnread(t *testing.T) {
	newUnread := func() *mqlAwsLambdaFunction {
		fn := &mqlAwsLambdaFunction{}
		// What fetchStatus leaves behind on a 404.
		fn.statusFetched.Store(true)
		return fn
	}

	t.Run("state", func(t *testing.T) {
		fn := newUnread()
		v, err := fn.state()
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, fn.State.IsSet())
		assert.True(t, fn.State.IsNull())
	})

	t.Run("stateReason", func(t *testing.T) {
		fn := newUnread()
		v, err := fn.stateReason()
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, fn.StateReason.IsSet())
		assert.True(t, fn.StateReason.IsNull())
	})

	t.Run("lastUpdateStatus", func(t *testing.T) {
		fn := newUnread()
		v, err := fn.lastUpdateStatus()
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, fn.LastUpdateStatus.IsSet())
		assert.True(t, fn.LastUpdateStatus.IsNull())
	})

	t.Run("lastUpdateStatusReason", func(t *testing.T) {
		fn := newUnread()
		v, err := fn.lastUpdateStatusReason()
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, fn.LastUpdateStatusReason.IsSet())
		assert.True(t, fn.LastUpdateStatusReason.IsNull())
	})

	t.Run("runtimeVersionArn", func(t *testing.T) {
		fn := newUnread()
		v, err := fn.runtimeVersionArn()
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, fn.RuntimeVersionArn.IsSet())
		assert.True(t, fn.RuntimeVersionArn.IsNull())
	})
}

// TestLambdaFunctionStatusAccessorsReadSeededStatus exercises the accessors
// against a status seeded the way newLambdaFunctionResource seeds it from a
// GetFunction lookup, so no configuration call is needed.
func TestLambdaFunctionStatusAccessorsReadSeededStatus(t *testing.T) {
	cfg := lambdatypes.FunctionConfiguration{
		State:            lambdatypes.StateActive,
		LastUpdateStatus: lambdatypes.LastUpdateStatusSuccessful,
	}

	fn := &mqlAwsLambdaFunction{}
	if status := lambdaStatusFromConfiguration(&cfg); status != nil {
		fn.status = status
		fn.statusFetched.Store(true)
	}

	state, err := fn.state()
	require.NoError(t, err)
	assert.Equal(t, "Active", state)
	assert.False(t, fn.State.IsNull())

	lastUpdate, err := fn.lastUpdateStatus()
	require.NoError(t, err)
	assert.Equal(t, "Successful", lastUpdate)
	assert.False(t, fn.LastUpdateStatus.IsNull())

	// A healthy function has no reason, and an absent reason is null.
	reason, err := fn.stateReason()
	require.NoError(t, err)
	assert.Equal(t, "", reason)
	assert.True(t, fn.StateReason.IsNull())
}

func TestNullOnEmpty(t *testing.T) {
	t.Run("empty value marks the field null", func(t *testing.T) {
		var field plugin.TValue[string]
		v, err := nullOnEmpty(&field, "")
		require.NoError(t, err)
		assert.Equal(t, "", v)
		assert.True(t, field.IsSet())
		assert.True(t, field.IsNull())
	})

	t.Run("real value passes through untouched", func(t *testing.T) {
		var field plugin.TValue[string]
		v, err := nullOnEmpty(&field, "Active")
		require.NoError(t, err)
		assert.Equal(t, "Active", v)
		assert.False(t, field.IsNull())
	})
}

// TestReservedConcurrency pins the distinction a hard 0 destroyed: a reserved
// concurrency of 0 throttles the function so it cannot be invoked, while no
// reservation lets it draw on the account's unreserved pool. Reporting 0 for
// both inverted the security posture of every unreserved function.
func TestReservedConcurrency(t *testing.T) {
	t.Run("absent reservation reads null", func(t *testing.T) {
		var field plugin.TValue[int64]
		v, err := reservedConcurrency(&field, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(0), v)
		assert.True(t, field.IsSet())
		assert.True(t, field.IsNull())
	})

	t.Run("explicit zero reads as a real zero", func(t *testing.T) {
		var field plugin.TValue[int64]
		v, err := reservedConcurrency(&field, aws.Int32(0))
		require.NoError(t, err)
		assert.Equal(t, int64(0), v)
		assert.False(t, field.IsNull())
	})

	t.Run("the two are distinguishable", func(t *testing.T) {
		var absent, throttled plugin.TValue[int64]
		absentVal, err := reservedConcurrency(&absent, nil)
		require.NoError(t, err)
		throttledVal, err := reservedConcurrency(&throttled, aws.Int32(0))
		require.NoError(t, err)

		assert.Equal(t, absentVal, throttledVal)
		assert.NotEqual(t, absent.IsNull(), throttled.IsNull())
	})

	t.Run("a real reservation passes through", func(t *testing.T) {
		var field plugin.TValue[int64]
		v, err := reservedConcurrency(&field, aws.Int32(50))
		require.NoError(t, err)
		assert.Equal(t, int64(50), v)
		assert.False(t, field.IsNull())
	})
}

// TestEventSourceMappingArn pins that the ARN comes from the API. The composed
// fallback hardcodes the `aws` partition, which names a resource that does not
// exist in GovCloud or China.
func TestEventSourceMappingArn(t *testing.T) {
	t.Run("uses the ARN the API reports", func(t *testing.T) {
		sdkArn := "arn:aws-us-gov:lambda:us-gov-west-1:123456789012:event-source-mapping:8bd1f2a4-1c3e-4d5f-9a0b-1c2d3e4f5a6b"
		got := eventSourceMappingArn(sdkArn, "us-gov-west-1", "123456789012",
			"8bd1f2a4-1c3e-4d5f-9a0b-1c2d3e4f5a6b")
		assert.Equal(t, sdkArn, got)
	})

	t.Run("composes only when the API names no ARN", func(t *testing.T) {
		got := eventSourceMappingArn("", "us-east-1", "123456789012",
			"8bd1f2a4-1c3e-4d5f-9a0b-1c2d3e4f5a6b")
		assert.Equal(t,
			"arn:aws:lambda:us-east-1:123456789012:event-source-mapping:8bd1f2a4-1c3e-4d5f-9a0b-1c2d3e4f5a6b",
			got)
	})
}

func TestLambdaRegionFromArn(t *testing.T) {
	t.Run("qualified version ARN", func(t *testing.T) {
		assert.Equal(t, "eu-central-1",
			lambdaRegionFromArn("arn:aws:lambda:eu-central-1:123456789012:function:my-function:3"))
	})

	t.Run("unqualified function ARN", func(t *testing.T) {
		assert.Equal(t, "us-east-1",
			lambdaRegionFromArn("arn:aws:lambda:us-east-1:123456789012:function:my-function"))
	})

	t.Run("non-ARN value has no region", func(t *testing.T) {
		assert.Equal(t, "", lambdaRegionFromArn("my-function"))
	})
}

// rawDataIsNull reports whether a resource argument was handed over as null.
func rawDataIsNull(t *testing.T, args map[string]*llx.RawData, key string) bool {
	t.Helper()
	raw, ok := args[key]
	require.True(t, ok, "argument %q missing", key)
	return raw.Type == types.Nil
}

// TestEventSourceMappingArgsAbsentSettings pins that settings an SQS mapping
// does not carry stay null. Zero is outside the valid range of
// parallelizationFactor (1-10) and maximumConcurrency (2-1000), so reporting
// it named a value that cannot exist.
func TestEventSourceMappingArgsAbsentSettings(t *testing.T) {
	// The shape an SQS mapping comes back as: no shards, no window, no scaling
	// config, no starting position, no on-failure destination.
	esm := lambdatypes.EventSourceMappingConfiguration{
		UUID:                  aws.String("8bd1f2a4-1c3e-4d5f-9a0b-1c2d3e4f5a6b"),
		EventSourceArn:        aws.String("arn:aws:sqs:us-east-1:123456789012:my-queue"),
		FunctionArn:           aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-function"),
		EventSourceMappingArn: aws.String("arn:aws:lambda:us-east-1:123456789012:event-source-mapping:8bd1f2a4-1c3e-4d5f-9a0b-1c2d3e4f5a6b"),
		State:                 aws.String("Enabled"),
		BatchSize:             aws.Int32(10),
	}

	args, err := eventSourceMappingArgs(esm, "us-east-1")
	require.NoError(t, err)

	assert.True(t, rawDataIsNull(t, args, "parallelizationFactor"))
	assert.True(t, rawDataIsNull(t, args, "tumblingWindowInSeconds"))
	assert.True(t, rawDataIsNull(t, args, "maximumConcurrency"))
	assert.True(t, rawDataIsNull(t, args, "startingPosition"))
	assert.True(t, rawDataIsNull(t, args, "onFailureDestinationArn"))

	// -1 is the documented "retry forever" / "no maximum age" sentinel, not a
	// stand-in for an unread value.
	assert.Equal(t, int64(-1), args["maximumRetryAttempts"].Value)
	assert.Equal(t, int64(-1), args["maximumRecordAgeInSeconds"].Value)
	assert.Equal(t, int64(10), args["batchSize"].Value)
	assert.Equal(t, "Enabled", args["state"].Value)
}

// TestEventSourceMappingArgsReportedSettings pins that a mapping that does
// carry these settings reports them, so the null handling above cannot be
// satisfied by dropping the values altogether.
func TestEventSourceMappingArgsReportedSettings(t *testing.T) {
	esm := lambdatypes.EventSourceMappingConfiguration{
		UUID:                    aws.String("11111111-2222-3333-4444-555555555555"),
		EventSourceArn:          aws.String("arn:aws:kinesis:us-east-1:123456789012:stream/my-stream"),
		ParallelizationFactor:   aws.Int32(4),
		TumblingWindowInSeconds: aws.Int32(30),
		StartingPosition:        lambdatypes.EventSourcePositionTrimHorizon,
		ScalingConfig:           &lambdatypes.ScalingConfig{MaximumConcurrency: aws.Int32(20)},
		DestinationConfig: &lambdatypes.DestinationConfig{
			OnFailure: &lambdatypes.OnFailure{
				Destination: aws.String("arn:aws:sqs:us-east-1:123456789012:dlq"),
			},
		},
	}

	args, err := eventSourceMappingArgs(esm, "us-east-1")
	require.NoError(t, err)

	assert.Equal(t, int64(4), args["parallelizationFactor"].Value)
	assert.Equal(t, int64(30), args["tumblingWindowInSeconds"].Value)
	assert.Equal(t, int64(20), args["maximumConcurrency"].Value)
	assert.Equal(t, "TRIM_HORIZON", args["startingPosition"].Value)
	assert.Equal(t, "arn:aws:sqs:us-east-1:123456789012:dlq", args["onFailureDestinationArn"].Value)
}

// TestEventSourceMappingArgsZeroTumblingWindow pins that a window AWS actually
// reports as 0 stays a measured 0, so the null handling does not swallow a
// real value. 0 is inside the documented range for this field.
func TestEventSourceMappingArgsZeroTumblingWindow(t *testing.T) {
	esm := lambdatypes.EventSourceMappingConfiguration{
		UUID:                    aws.String("11111111-2222-3333-4444-555555555555"),
		TumblingWindowInSeconds: aws.Int32(0),
	}

	args, err := eventSourceMappingArgs(esm, "us-east-1")
	require.NoError(t, err)

	assert.False(t, rawDataIsNull(t, args, "tumblingWindowInSeconds"))
	assert.Equal(t, int64(0), args["tumblingWindowInSeconds"].Value)
}

// TestRuntimeManagementArgs pins that the pinned-version ARN is null for a
// function on automatic runtime updates. The deprecated dict left the key out
// entirely, so its typed replacement asserting "" was weaker than the field it
// replaces.
func TestRuntimeManagementArgs(t *testing.T) {
	t.Run("automatic updates pin no version", func(t *testing.T) {
		args := runtimeManagementArgs("arn:aws:lambda:us-east-1:123456789012:function:my-function",
			&lambda.GetRuntimeManagementConfigOutput{UpdateRuntimeOn: lambdatypes.UpdateRuntimeOnAuto})
		assert.Equal(t, "Auto", args["updateRuntimeOn"].Value)
		assert.True(t, rawDataIsNull(t, args, "runtimeVersionArn"))
	})

	t.Run("manual updates report the pinned version", func(t *testing.T) {
		args := runtimeManagementArgs("arn:aws:lambda:us-east-1:123456789012:function:my-function",
			&lambda.GetRuntimeManagementConfigOutput{
				UpdateRuntimeOn:   lambdatypes.UpdateRuntimeOnManual,
				RuntimeVersionArn: aws.String("arn:aws:lambda:us-east-1::runtime:abc123"),
			})
		assert.Equal(t, "Manual", args["updateRuntimeOn"].Value)
		assert.Equal(t, "arn:aws:lambda:us-east-1::runtime:abc123", args["runtimeVersionArn"].Value)
	})
}
