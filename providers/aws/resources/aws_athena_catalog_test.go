// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
)

func athenaAPIErr(code, message string) error {
	return &smithy.GenericAPIError{Code: code, Message: message}
}

func TestAthenaCatalogHasNoDetail(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{
			// The exact response AwsDataCatalog gives, in every account and
			// every region.
			name: "the built-in catalog cannot be described",
			err: athenaAPIErr("InvalidRequestException",
				"DataCatalog AwsDataCatalog was not found. Please check your account settings"),
			want: true,
		},
		{
			name: "a user catalog that was deleted mid-read",
			err:  athenaAPIErr("InvalidRequestException", "DataCatalog my_catalog was not found"),
			want: true,
		},
		{
			// Same code, different meaning: this one is a real error and must
			// still surface.
			name: "a malformed request is still an error",
			err: athenaAPIErr("InvalidRequestException",
				"1 validation error detected: Value at 'name' failed to satisfy constraint"),
			want: false,
		},
		{
			name: "access denied is still an error",
			err:  athenaAPIErr("AccessDeniedException", "not authorized to perform athena:GetDataCatalog"),
			want: false,
		},
		{
			name: "a throttle is still an error",
			err:  athenaAPIErr("ThrottlingException", "Rate exceeded"),
			want: false,
		},
		{
			// A transport failure carries no API error and must never be read as
			// "this catalog has no detail".
			name: "a transport error is not an api error",
			err:  errors.New("dial tcp: lookup athena.us-east-1.amazonaws.com: no such host"),
			want: false,
		},
		{
			name: "nil is not a match",
			err:  nil,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, athenaCatalogHasNoDetail(tc.err))
		})
	}
}

// The classifier has to survive the wrapping the SDK and the provider apply on
// the way back up.
func TestAthenaCatalogHasNoDetailThroughWrapping(t *testing.T) {
	base := athenaAPIErr("InvalidRequestException", "DataCatalog AwsDataCatalog was not found")

	assert.True(t, athenaCatalogHasNoDetail(fmt.Errorf("could not describe catalog: %w", base)))
	assert.True(t, athenaCatalogHasNoDetail(fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", base))))
}
