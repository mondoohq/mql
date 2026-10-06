// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exceptionsYaml = `
exceptions:
  - title: Central CloudTrail covers this
    checks:
      - mondoo-terraform-aws-security-s3-bucket-logging
      - mondoo-terraform-aws-security-s3-bucket-log-target
    action: risk-accepted
    justification: >
      Access logging is handled centrally by the org-wide CloudTrail trail.
    valid_until: 2026-11-01
  - checks:
      - mondoo-terraform-aws-security-s3-bucket-public-access
    paths:
      - infra/staging
    action: risk-accepted
    justification: Staging buckets serve public test fixtures.
`

func TestParseContextConfig(t *testing.T) {
	t.Run("exceptions", func(t *testing.T) {
		cfg, err := ParseContextConfig([]byte(exceptionsYaml))
		require.NoError(t, err)
		require.Len(t, cfg.Exceptions, 2)

		first := cfg.Exceptions[0]
		assert.Equal(t, "Central CloudTrail covers this", first.Title)
		assert.Equal(t, []string{
			"mondoo-terraform-aws-security-s3-bucket-logging",
			"mondoo-terraform-aws-security-s3-bucket-log-target",
		}, first.Checks)
		assert.Equal(t, "risk-accepted", first.Action)
		assert.Equal(t, "Access logging is handled centrally by the org-wide CloudTrail trail.\n", first.Justification)
		// an unquoted YAML date stays the string the author wrote
		assert.Equal(t, "2026-11-01", first.ValidUntil)

		assert.Equal(t, []string{"infra/staging"}, cfg.Exceptions[1].Paths)
		assert.Empty(t, cfg.IgnoredKeys)
		assert.Empty(t, cfg.SensitiveKeys)
	})

	t.Run("other keys are ignored and credentials are flagged", func(t *testing.T) {
		data := exceptionsYaml + `
api_endpoint: https://attacker.example.com
private_key: |
  -----BEGIN PRIVATE KEY-----
  -----END PRIVATE KEY-----
features: [SomeFeature]
labels:
  a: b
`
		cfg, err := ParseContextConfig([]byte(data))
		require.NoError(t, err)
		assert.Len(t, cfg.Exceptions, 2)
		assert.Equal(t, []string{"api_endpoint", "features", "labels", "private_key"}, cfg.IgnoredKeys)
		assert.Equal(t, []string{"api_endpoint", "private_key"}, cfg.SensitiveKeys)
	})

	t.Run("unknown entry fields are an error", func(t *testing.T) {
		data := `
exceptions:
  - checks: [a]
    action: disable
    justification: x
    valid-until: 2026-11-01
`
		_, err := ParseContextConfig([]byte(data))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid-until")
	})

	t.Run("empty file", func(t *testing.T) {
		cfg, err := ParseContextConfig([]byte("  \n"))
		require.NoError(t, err)
		assert.Empty(t, cfg.Exceptions)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		_, err := ParseContextConfig([]byte("exceptions: [\n"))
		require.Error(t, err)
	})
}

func TestUserScopeExceptions(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigType("yaml")
	viper.SetOptions(viper.KeyDelimiter("\\"))
	require.NoError(t, viper.ReadConfig(strings.NewReader(exceptionsYaml)))

	cfg, err := Read()
	require.NoError(t, err)
	require.Len(t, cfg.Exceptions, 2)
	assert.Equal(t, "risk-accepted", cfg.Exceptions[0].Action)
	assert.Equal(t, "2026-11-01", cfg.Exceptions[0].ValidUntil)
	assert.Equal(t, []string{"infra/staging"}, cfg.Exceptions[1].Paths)
}
