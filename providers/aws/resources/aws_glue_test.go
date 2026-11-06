// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	glue_types "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestRedactedGlueConnectionProperties(t *testing.T) {
	out := redactedGlueConnectionProperties(map[string]string{
		"PASSWORD":                            "jdbc-secret",
		"KAFKA_SASL_PLAIN_PASSWORD":           "sasl-secret",
		"ENCRYPTED_KAFKA_SASL_SCRAM_PASSWORD": "enc-secret",
		"KAFKA_SOME_FUTURE_PASSWORD":          "future-secret",
		"KAFKA_SASL_GSSAPI_KRB5_REALM_CONF":   "[realms] EXAMPLE.COM = {}",
		"USERNAME":                            "admin",
		"SECRET_ID":                           "arn:aws:secretsmanager:us-west-2:111122223333:secret:db",
		"KAFKA_SASL_SCRAM_SECRETS_ARN":        "arn:aws:secretsmanager:us-west-2:111122223333:secret:scram",
		"KAFKA_CLIENT_KEYSTORE_PASSWORD":      "",
	})
	for _, k := range []string{"PASSWORD", "KAFKA_SASL_PLAIN_PASSWORD", "ENCRYPTED_KAFKA_SASL_SCRAM_PASSWORD", "KAFKA_SOME_FUTURE_PASSWORD", "KAFKA_SASL_GSSAPI_KRB5_REALM_CONF"} {
		assert.Equal(t, "<redacted>", out[k], k)
	}
	assert.Equal(t, "admin", out["USERNAME"])
	assert.Equal(t, "arn:aws:secretsmanager:us-west-2:111122223333:secret:db", out["SECRET_ID"],
		"a secret reference is not a secret")
	assert.Equal(t, "arn:aws:secretsmanager:us-west-2:111122223333:secret:scram", out["KAFKA_SASL_SCRAM_SECRETS_ARN"])
	assert.Equal(t, "", out["KAFKA_CLIENT_KEYSTORE_PASSWORD"], "an empty value stays empty so audits can see it is unset")
}

func TestGlueJobAutoUpgradeFields(t *testing.T) {
	t.Run("job without glueVersion auto", func(t *testing.T) {
		// Synthetic: jobs that do not use glueVersion auto carry no metadata.
		f := glueJobAutoUpgradeFields(nil)
		assert.Equal(t, llx.NilData, f.status)
		assert.Equal(t, llx.NilData, f.sourceVersion)
		assert.Equal(t, llx.NilData, f.targetVersion)
		assert.Equal(t, llx.NilData, f.analysisId)
	})

	t.Run("upgrade waiting for consent", func(t *testing.T) {
		// Synthetic: field shape from the v1.173.0 SDK types; no target showed this.
		f := glueJobAutoUpgradeFields(&glue_types.AutoUpgradeMetadata{
			AnalysisId:    aws.String("analysis-1"),
			SourceVersion: aws.String("4.0"),
			Status:        glue_types.AutoUpgradeStatusWaitingForConsent,
			TargetVersion: aws.String("5.0"),
		})
		assert.Equal(t, "WAITING_FOR_CONSENT", f.status.Value)
		assert.Equal(t, "4.0", f.sourceVersion.Value)
		assert.Equal(t, "5.0", f.targetVersion.Value)
		assert.Equal(t, "analysis-1", f.analysisId.Value)
	})

	t.Run("observing without a target yet", func(t *testing.T) {
		// Synthetic: absent status and target version are null, not empty.
		f := glueJobAutoUpgradeFields(&glue_types.AutoUpgradeMetadata{SourceVersion: aws.String("4.0")})
		assert.Equal(t, llx.NilData, f.status)
		assert.Equal(t, llx.NilData, f.targetVersion)
		assert.Equal(t, "4.0", f.sourceVersion.Value)
	})
}
