// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package printer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// markedPrinter tags dimmed and error text, so a test can tell them apart.
var markedPrinter = func() Printer {
	p := PlainNoColorPrinter
	p.Error = func(a ...any) string { return "E(" + fmt.Sprint(a...) + ")" }
	p.Disabled = func(a ...any) string { return "D(" + fmt.Sprint(a...) + ")" }
	return p
}()

func denied(perm string) error {
	return llx.Forbidden(errors.New("User is not authorized"), llx.WithPermissions(perm))
}

func TestFieldError(t *testing.T) {
	p := markedPrinter
	t.Run("kind and permissions lead, message follows", func(t *testing.T) {
		assert.Equal(t, "E(access denied (ec2:DescribeTags): User is not authorized)",
			p.fieldError(denied("ec2:DescribeTags")))
	})
	t.Run("classification survives a wrap", func(t *testing.T) {
		err := fmt.Errorf("listing: %w", denied("ec2:DescribeTags"))
		assert.Equal(t, "E(access denied (ec2:DescribeTags): listing: User is not authorized)", p.fieldError(err))
	})
	t.Run("not applicable is dimmed", func(t *testing.T) {
		assert.Equal(t, "D(not applicable: Macie is not enabled)",
			p.fieldError(llx.NotApplicable(errors.New("Macie is not enabled"))))
	})
	t.Run("no upstream message does not repeat the kind", func(t *testing.T) {
		assert.Equal(t, "E(not found)", p.fieldError(llx.NotFound(nil)))
	})
	t.Run("partition is named", func(t *testing.T) {
		err := llx.Unavailable(nil, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"))
		assert.Equal(t, "E(unavailable in eu-west-1)", p.fieldError(err))
	})
	t.Run("permissions are sorted, the error is not touched", func(t *testing.T) {
		e := llx.Forbidden(nil, llx.WithPermissions("s3:GetObject", "ec2:DescribeTags"))
		assert.Equal(t, "E(access denied (ec2:DescribeTags, s3:GetObject))", p.fieldError(e))
		assert.Equal(t, []string{"s3:GetObject", "ec2:DescribeTags"}, e.Permissions)
	})
	t.Run("unclassified stays as it was", func(t *testing.T) {
		assert.Equal(t, "E(boom)", p.fieldError(errors.New(" boom\n")))
	})
}

func TestErrorSummary(t *testing.T) {
	p := markedPrinter
	field := func(err error) *llx.RawData { return &llx.RawData{Type: types.String, Error: err} }

	// Three refused tag reads group into one line. A refusal that differs only
	// in its permission is its own group, seen once, so it is not repeated
	// below. Unclassified errors never group.
	instances := &llx.RawData{Type: types.Array(types.Block), Value: []any{
		map[string]any{"tags": field(denied("ec2:DescribeTags")), "name": &llx.RawData{Type: types.String, Value: "a"}},
		map[string]any{"tags": field(denied("ec2:DescribeTags"))},
		map[string]any{"tags": field(denied("ec2:DescribeTags")), "detail": field(denied("ec2:DescribeInstanceAttribute"))},
		map[string]any{"macie": field(llx.NotApplicable(errors.New("a"))), "other": field(llx.NotApplicable(errors.New("b")))},
		map[string]any{"plain": field(errors.New("boom")), "plain2": field(errors.New("boom"))},
	}}
	results := map[string]*llx.RawResult{"x": {Data: instances}}

	assert.Equal(t, []string{
		"E(access denied x3 (ec2:DescribeTags))",
		"D(not applicable x2)",
	}, p.errorSummary(results))

	t.Run("nothing repeated, nothing to say", func(t *testing.T) {
		one := map[string]*llx.RawResult{"x": {Data: field(denied("ec2:DescribeTags"))}}
		assert.Empty(t, p.errorSummary(one))
	})
}

func TestCoverageGapLines(t *testing.T) {
	p := markedPrinter
	gap := func(kind llx.ErrorKind, region string, perms ...string) *llx.Error {
		return llx.NewError(kind, errors.New("upstream message"),
			llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, region), llx.WithPermissions(perms...))
	}
	results := map[string]*llx.RawResult{
		"a": {Data: &llx.RawData{Type: types.Int, Value: int64(3), CoverageGaps: []*llx.Error{
			gap(llx.ErrorKind_ERROR_KIND_FORBIDDEN, "eu-west-1", "ec2:DescribeAddresses"),
		}}},
		// Same kind and region from another result, another permission: one
		// line naming both.
		"b": {Data: &llx.RawData{Type: types.Int, Value: int64(1), CoverageGaps: []*llx.Error{
			gap(llx.ErrorKind_ERROR_KIND_FORBIDDEN, "eu-west-1", "ec2:DescribeVolumes"),
			gap(llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS, "us-east-1"),
			llx.CoverageGapsFrom(errors.New("connection reset"))[0],
		}}},
		"c": {Data: &llx.RawData{Type: types.Int, Value: int64(1)}},
	}
	// Unclassified gaps sort last.
	assert.Equal(t, []string{
		"D(coverage gap: access denied in eu-west-1 (ec2:DescribeAddresses, ec2:DescribeVolumes))",
		"D(coverage gap: too many requests in us-east-1)",
		"D(coverage gap: error: connection reset)",
	}, p.coverageGapLines(results))
}

func TestResults_ClassifiedErrors(t *testing.T) {
	p := markedPrinter
	bundle, err := x.Compile("mondoo.version")
	require.NoError(t, err)
	checksum := bundle.CodeV2.Checksums[bundle.CodeV2.Entrypoints()[0]]

	t.Run("a failed field leads with its kind", func(t *testing.T) {
		results := map[string]*llx.RawResult{checksum: {CodeID: checksum, Data: &llx.RawData{
			Type: types.String, Error: denied("mondoo:Read"),
		}}}
		assert.Equal(t, "E(access denied (mondoo:Read): User is not authorized)\nmondoo.version: null",
			p.Results(bundle, results))
	})

	t.Run("a partial value is followed by its gaps", func(t *testing.T) {
		results := map[string]*llx.RawResult{checksum: {CodeID: checksum, Data: &llx.RawData{
			Type: types.String, Value: "v14",
			CoverageGaps: []*llx.Error{llx.Forbidden(nil, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"))},
		}}}
		assert.Equal(t, "mondoo.version: \"v14\"\nD(coverage gap: access denied in eu-west-1)",
			p.Results(bundle, results))
	})
}
