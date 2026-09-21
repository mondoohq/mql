// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The KMS key policy from mondoohq/cnspec#4020, in the form Terraform writes it
// into plan and state JSON: the resource attribute is typed as a string, so the
// document arrives serialized.
const kmsKeyPolicy = `{"Version":"2012-10-17","Statement":[` +
	`{"Sid":"Root","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*","Resource":"*"},` +
	`{"Sid":"PublicDecrypt","Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:Decrypt","Resource":"*"}]}`

// `json` decodes a serialized document into the same traversable dict that
// `parse.json(...).params` returns for a file, so a check can index into a
// value a provider hands back as a string.
func TestJsonDecodes(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	tests := []struct {
		query string
		want  any
	}{
		// an object decodes to a map, an array to a list
		{`'{"a":23}'.json['a']`, float64(23)},
		{`'[1,2,3]'.json.length`, int64(3)},
		{`'{"a":{"b":"c"}}'.json['a']['b']`, "c"},

		// a decoded number compares as a number, not as its text
		{`'{"a":23}'.json['a'] == 23`, true},

		// list operations reach into the decoded document
		{`'{"s":[{"e":"Allow"},{"e":"Deny"}]}'.json['s'].where(_['e'] == 'Allow').length`, int64(1)},

		// the shape the issue is about: without `json` the index yields a
		// primitive with no type information, `where` sees nothing and `none`
		// passes, so this reads true and the public key goes unreported
		{`'` + kmsKeyPolicy + `'.json['Statement'].where(_['Effect'] == 'Allow').none(_['Principal']['AWS'] == '*')`, false},
	}

	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			q, err := env.Compile(tc.query)
			require.NoError(t, err)

			res, err := q.Eval(ctx)
			require.NoError(t, err)
			require.NoError(t, res.Err())
			assert.Equal(t, tc.want, res.Value())
		})
	}
}

// A document that does not parse is reported as an error rather than returned
// as null. Null would read null through the index, `where` would yield nothing
// and the enclosing `none` would pass, so malformed input would surface as a
// passing check instead of as a problem. Returning `&RawData{Type: types.Dict}`
// from the unmarshal failure in stringJsonV2 flips the second case to true.
func TestJsonMalformedIsAnErrorNotAVacuousPass(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	for _, query := range []string{
		`'not json'.json`,
		`'not json'.json['Statement'].where(_['Effect'] == 'Allow').none(_['Principal']['AWS'] == '*')`,
	} {
		t.Run(query, func(t *testing.T) {
			q, err := env.Compile(query)
			require.NoError(t, err)

			res, err := q.Eval(ctx)
			require.NoError(t, err)
			require.Error(t, res.Err(), "malformed JSON must report, not pass")
			assert.Contains(t, res.Err().Error(), "failed to parse JSON")
			assert.NotEqual(t, true, res.Value())
		})
	}
}

// An absent optional attribute stays null through `json`, so the `== empty`
// guard that every policy check puts ahead of the index still sees it. This is
// why dictJsonV2 returns null for a null bind instead of erroring the way its
// `lines`/`split`/`trim` siblings do; dropping that nil check errors here.
func TestJsonNullStaysNull(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	q, err := env.Compile(`'{"policy":null}'.json['policy'].json == empty`)
	require.NoError(t, err)

	res, err := q.Eval(ctx)
	require.NoError(t, err)
	require.NoError(t, res.Err())
	assert.Equal(t, true, res.Value())
}

// The cost of the name. mqlc resolves a dotted identifier through
// compileBoundIdentifier before it falls back to the dict-key accessor, so a
// dict key literally called `json` is no longer reachable in dot form; the
// index form still reads it. Terraform's aws_iam_policy_document exposes an
// attribute by that name, which is the realistic way to meet this.
//
// Renaming the builtin (to `parseJson`, say) makes the first case return 5 and
// fails this test, which is the point: the collision is a deliberate choice,
// not an accident to rediscover.
func TestJsonShadowsADictKeyOfTheSameName(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	q, err := env.Compile(`'{"json":5}'.json.json`)
	require.NoError(t, err)
	res, err := q.Eval(ctx)
	require.NoError(t, err)
	require.Error(t, res.Err())
	assert.Contains(t, res.Err().Error(), "does not support field `json`")

	q, err = env.Compile(`'{"json":5}'.json['json']`)
	require.NoError(t, err)
	res, err = q.Eval(ctx)
	require.NoError(t, err)
	require.NoError(t, res.Err())
	assert.Equal(t, float64(5), res.Value())
}

// `json` on a value that is already decoded is an error, not a no-op. Adding a
// fast path that returns a map or array bind as-is fails this test, which is
// the point: the error tells the author the attribute never carried a JSON
// string, instead of letting a query pass on a shape they guessed wrong.
func TestJsonOnAnAlreadyDecodedValueErrors(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	for _, query := range []string{
		`'{"a":23}'.json.json`,
		`'[1,2,3]'.json.json`,
	} {
		t.Run(query, func(t *testing.T) {
			q, err := env.Compile(query)
			require.NoError(t, err)
			res, err := q.Eval(ctx)
			require.NoError(t, err)
			require.Error(t, res.Err())
			assert.Contains(t, res.Err().Error(), "does not support field `json`")
		})
	}
}
