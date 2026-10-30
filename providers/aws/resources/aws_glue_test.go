// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
