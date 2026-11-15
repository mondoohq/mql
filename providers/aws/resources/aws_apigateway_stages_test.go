// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/aws/connection"
)

// A REST API selected by a tag filter must report all of its stages. Stages
// carry their own tags, usually none, and filtering them by the discovery tag
// emptied the list, so every stages.all(...) assertion passed vacuously.
func TestApigatewayRestapiStagesIgnoreTagFilters(t *testing.T) {
	stub := func(s *middleware.Stack) error {
		return s.Initialize.Add(middleware.InitializeMiddlewareFunc("mqlApigatewayStagesStub",
			func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
				middleware.InitializeOutput, middleware.Metadata, error,
			) {
				if _, ok := in.Parameters.(*apigateway.GetStagesInput); !ok {
					return middleware.InitializeOutput{}, middleware.Metadata{},
						fmt.Errorf("test called unstubbed API Gateway operation %T", in.Parameters)
				}
				return middleware.InitializeOutput{Result: &apigateway.GetStagesOutput{
					Item: []types.Stage{
						{StageName: aws.String("prod"), TracingEnabled: false},
						{StageName: aws.String("dev"), Tags: map[string]string{"env": "dev"}},
					},
				}}, middleware.Metadata{}, nil
			}), middleware.Before)
	}
	conn := connection.NewTestConnection(aws.Config{
		Region:     "us-east-1",
		APIOptions: []func(*middleware.Stack) error{stub},
	})
	conn.Filters.General.Tags = map[string]string{"team": "payments"}

	rt := testRuntime()
	rt.Connection = conn
	api := &mqlAwsApigatewayRestapi{
		MqlRuntime: rt,
		Id:         setString("abc123"),
		Region:     setString("us-east-1"),
	}

	stages, err := api.stages()
	require.NoError(t, err)
	require.Len(t, stages, 2)
	assert.Equal(t, "prod", stages[0].(*mqlAwsApigatewayStage).Name.Data)
	assert.False(t, stages[0].(*mqlAwsApigatewayStage).TracingEnabled.Data)
	assert.Equal(t, "dev", stages[1].(*mqlAwsApigatewayStage).Name.Data)
}
