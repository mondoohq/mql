// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
)

func decodeSnowflake(t *testing.T, payload string) datadogV2.SnowflakeIntegrationAccountResponseData {
	t.Helper()
	var acc datadogV2.SnowflakeIntegrationAccountResponseData
	if err := json.Unmarshal([]byte(payload), &acc); err != nil {
		t.Fatalf("could not decode Snowflake account: %v", err)
	}
	if acc.UnparsedObject != nil {
		t.Fatalf("SDK could not decode Snowflake fixture: %v", acc.UnparsedObject)
	}
	return acc
}

func decodeDatabricks(t *testing.T, payload string) datadogV2.DatabricksIntegrationAccountResponseData {
	t.Helper()
	var acc datadogV2.DatabricksIntegrationAccountResponseData
	if err := json.Unmarshal([]byte(payload), &acc); err != nil {
		t.Fatalf("could not decode Databricks account: %v", err)
	}
	if acc.UnparsedObject != nil {
		t.Fatalf("SDK could not decode Databricks fixture: %v", acc.UnparsedObject)
	}
	return acc
}

func TestSnowflakeAccountArgs(t *testing.T) {
	acc := decodeSnowflake(t, `{
	  "id": "sf-1",
	  "type": "integration-account",
	  "attributes": {
	    "name": "warehouse",
	    "settings": {"snowflake_account_identifier": "org-acct", "username": "DATADOG"},
	    "authentication": {"auth_type": "snowflake_private_key", "private_key_name": "k1"},
	    "dataflows": {
	      "snowflake-security-logs": {"enabled": true},
	      "snowflake-query-history-logs": {"enabled": false},
	      "snowflake-event-table-logs": {},
	      "snowflake-future-flow": {"enabled": true}
	    }
	  }
	}`)

	args, err := snowflakeAccountArgs(acc)
	if err != nil {
		t.Fatal(err)
	}
	if got := args["accountIdentifier"].Value; got != "org-acct" {
		t.Fatalf("expected accountIdentifier org-acct, got %v", got)
	}
	if got := args["username"].Value; got != "DATADOG" {
		t.Fatalf("expected username DATADOG, got %v", got)
	}
	if got := args["authType"].Value; got != "snowflake_private_key" {
		t.Fatalf("expected authType snowflake_private_key, got %v", got)
	}

	flows := args["dataflows"].Value.(map[string]interface{})
	if flows["snowflake-security-logs"] != true {
		t.Errorf("expected security logs enabled, got %v", flows["snowflake-security-logs"])
	}
	if v, ok := flows["snowflake-query-history-logs"]; !ok || v != false {
		t.Errorf("expected query history logs reported disabled, got %v (present %v)", v, ok)
	}
	// Reporting a collection without an enabled state as disabled would state
	// something Datadog did not say.
	if _, ok := flows["snowflake-event-table-logs"]; ok {
		t.Errorf("expected a collection without an enabled state to be left out")
	}
	// A collection the SDK does not model yet must not be dropped.
	if flows["snowflake-future-flow"] != true {
		t.Errorf("expected an unmodeled collection to be kept, got %v", flows["snowflake-future-flow"])
	}
}

func TestSnowflakeAccountWithoutAuthOrDataflows(t *testing.T) {
	acc := decodeSnowflake(t, `{"id":"sf-2","type":"integration-account","attributes":{"name":"n","settings":{"snowflake_account_identifier":"a","username":"u"}}}`)
	args, err := snowflakeAccountArgs(acc)
	if err != nil {
		t.Fatal(err)
	}
	if v := args["authType"].Value; v != nil {
		t.Fatalf("expected authType null without authentication, got %v", v)
	}
	if flows := args["dataflows"].Value.(map[string]interface{}); len(flows) != 0 {
		t.Fatalf("expected no dataflows, got %v", flows)
	}
}

func TestDatabricksAuth(t *testing.T) {
	tests := []struct {
		name         string
		auth         string
		wantType     string
		wantClientId string
	}{
		{"oauth", `{"auth_type":"databricks_oauth","client_id":"sp-1","azure_tenant_id":"t"}`, "databricks_oauth", "sp-1"},
		{"bearer token", `{"auth_type":"bearer_token"}`, "bearer_token", ""},
		{"private action runner", `{"auth_type":"private_action_runner","connection_id":"c","user_uuid":"u"}`, "private_action_runner", ""},
		// A method this SDK does not know must still be named, not read as
		// no authentication at all.
		{"unknown method", `{"auth_type":"workload_identity","audience":"x"}`, "workload_identity", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			acc := decodeDatabricks(t, `{"id":"db-1","type":"integration-account","attributes":{"name":"n",`+
				`"settings":{"workspace_url":"https://example.cloud.databricks.com"},"authentication":`+tc.auth+`}}`)
			args, err := databricksAccountArgs(acc)
			if err != nil {
				t.Fatal(err)
			}
			if got := args["authType"].Value; got != tc.wantType {
				t.Fatalf("expected authType %q, got %v", tc.wantType, got)
			}
			got := args["clientId"].Value
			if tc.wantClientId == "" {
				if got != nil {
					t.Fatalf("expected clientId null, got %v", got)
				}
			} else if got != tc.wantClientId {
				t.Fatalf("expected clientId %q, got %v", tc.wantClientId, got)
			}
			if got := args["workspaceUrl"].Value; got != "https://example.cloud.databricks.com" {
				t.Fatalf("unexpected workspaceUrl %v", got)
			}
		})
	}
}

func TestDatabricksDataflows(t *testing.T) {
	acc := decodeDatabricks(t, `{"id":"db-2","type":"integration-account","attributes":{"name":"n",
	  "settings":{"workspace_url":"https://w"},
	  "dataflows":{"databricks-cloud-cost-metrics":{"enabled":true},"databricks-model-serving-metrics":{"enabled":false}}}}`)
	args, err := databricksAccountArgs(acc)
	if err != nil {
		t.Fatal(err)
	}
	flows := args["dataflows"].Value.(map[string]interface{})
	if flows["databricks-cloud-cost-metrics"] != true || flows["databricks-model-serving-metrics"] != false || len(flows) != 2 {
		t.Fatalf("unexpected dataflows %v", flows)
	}
	if v := args["authType"].Value; v != nil {
		t.Fatalf("expected authType null without authentication, got %v", v)
	}
}
