// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stackitcloud/stackit-sdk-go/core/oapierror"
	observability "github.com/stackitcloud/stackit-sdk-go/services/observability/v1api"
	postgresflexv3 "github.com/stackitcloud/stackit-sdk-go/services/postgresflex/v3api"
	serviceenablement "github.com/stackitcloud/stackit-sdk-go/services/serviceenablement/v2api"
	sqlserverflexv3 "github.com/stackitcloud/stackit-sdk-go/services/sqlserverflex/v3api"
	valkey "github.com/stackitcloud/stackit-sdk-go/services/valkey/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestRefusalKinds(t *testing.T) {
	if k := llx.KindOf(refusal(&oapierror.GenericOpenAPIError{StatusCode: http.StatusUnauthorized})); k != llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED {
		t.Fatalf("401 kind = %v", k)
	}
	if k := llx.KindOf(refusal(&oapierror.GenericOpenAPIError{StatusCode: http.StatusForbidden})); k != llx.ErrorKind_ERROR_KIND_FORBIDDEN {
		t.Fatalf("403 kind = %v", k)
	}
	if k := llx.KindOf(refusal(errors.New("request failed with status 403"))); k != llx.ErrorKind_ERROR_KIND_FORBIDDEN {
		t.Fatalf("403 text kind = %v", k)
	}
	var e *llx.Error
	if errors.As(refusal(&oapierror.GenericOpenAPIError{StatusCode: http.StatusInternalServerError}), &e) {
		t.Fatal("a 500 must stay unclassified")
	}
	if errors.As(refusal(errors.New("dial tcp: connection refused")), &e) {
		t.Fatal("a transport error must stay unclassified")
	}
}

func TestServiceEnablementArgsAndPaging(t *testing.T) {
	var st serviceenablement.ServiceStatus
	if err := json.Unmarshal([]byte(`{"serviceId": "cloud.stackit.cdn", "state": "ENABLED", "enablement": "AUTO", "scope": "PUBLIC", "lifecycle": "PROJECT", "error": {"action": "DISABLE", "reason": "in use"}, "dependencies": {"hard": ["cloud.stackit.iaas"]}}`), &st); err != nil {
		t.Fatalf("decoding status: %v", err)
	}
	args := serviceEnablementArgs("p-1/eu01", &st)
	if args["__id"].Value != "stackit.serviceEnablement/p-1/eu01/cloud.stackit.cdn" {
		t.Fatalf("__id = %v", args["__id"].Value)
	}
	if args["state"].Value != "ENABLED" || args["enablement"].Value != "AUTO" || args["errorAction"].Value != "DISABLE" || args["errorReason"].Value != "in use" {
		t.Fatalf("state/enablement/error = %v/%v/%v/%v", args["state"].Value, args["enablement"].Value, args["errorAction"].Value, args["errorReason"].Value)
	}

	next := "c2"
	pages := map[string]*serviceenablement.ListServiceStatusRegional200Response{
		"":   {Items: []serviceenablement.ServiceStatus{st}, NextCursor: &next},
		"c2": {Items: []serviceenablement.ServiceStatus{st}},
	}
	all, err := listAllServiceStatuses(func(c string) (*serviceenablement.ListServiceStatusRegional200Response, error) { return pages[c], nil })
	if err != nil || len(all) != 2 {
		t.Fatalf("got %d statuses, err %v", len(all), err)
	}
}

func TestValkeyInstanceArgsKeepParametersOff(t *testing.T) {
	var inst valkey.Instance
	if err := json.Unmarshal([]byte(`{"instanceId": "v-1", "name": "cache", "planId": "p", "planName": "single", "offeringName": "valkey", "offeringVersion": "8", "cfGuid": "", "cfOrganizationGuid": "", "cfSpaceGuid": "", "dashboardUrl": "", "imageUrl": "", "status": "active", "lastOperation": {"type": "create", "state": "succeeded", "description": ""}, "parameters": {"sgw_acl": "10.0.0.0/8", "metrics_prefix": "apikey-SECRET"}}`), &inst); err != nil {
		t.Fatalf("decoding instance: %v", err)
	}
	args, params := valkeyInstanceArgs("eu01", &inst)
	if _, ok := args["parameters"]; ok {
		t.Fatal("the parameters blob must not be mapped")
	}
	if argsContain(args, "apikey-SECRET") {
		t.Fatal("metrics_prefix reached the mapped fields")
	}
	if args["id"].Value != "v-1" || args["state"].Value != "active" || args["offeringVersion"].Value != "8" {
		t.Fatalf("id/state/version = %v/%v/%v", args["id"].Value, args["state"].Value, args["offeringVersion"].Value)
	}
	if dbaasInstanceReachable(params) {
		t.Fatal("an instance restricted to 10.0.0.0/8 must not read as internet-reachable")
	}
}

func TestFlexV3Fields(t *testing.T) {
	var pg postgresflexv3.GetInstanceResponse
	if err := json.Unmarshal([]byte(`{"id": "i-1", "name": "db", "backupSchedule": "0 0 * * *", "flavorId": "f", "isDeletable": false, "retentionDays": 45, "state": "READY", "version": "16",
	  "connectionInfo": {"write": {"host": "db.example.com", "port": 5432}}, "storage": {}, "labels": {"env": "prod", "empty": null},
	  "network": {"accessScope": "SNA", "acl": ["10.0.0.0/8"]},
	  "encryption": {"kekKeyId": "k-1", "kekKeyRingId": "r-1", "kekKeyVersion": "3", "serviceAccount": "sa@example.com"}}`), &pg); err != nil {
		t.Fatalf("decoding postgres v3 instance: %v", err)
	}
	f := postgresFlexV3Fields(&pg)
	if f.accessScope == nil || *f.accessScope != "SNA" {
		t.Fatalf("accessScope = %v", f.accessScope)
	}
	if f.kekKeyID != "k-1" || f.kekKeyRingID != "r-1" || f.kekServiceAccount != "sa@example.com" || f.kekVersion == nil || *f.kekVersion != 3 {
		t.Fatalf("encryption = %+v", f)
	}
	if f.deletable == nil || *f.deletable != false || f.retentionDays == nil || *f.retentionDays != 45 {
		t.Fatalf("deletable/retention = %v/%v", f.deletable, f.retentionDays)
	}
	if len(f.labels) != 1 || f.labels["env"] != "prod" {
		t.Fatalf("labels = %v", f.labels)
	}

	var sq sqlserverflexv3.GetInstanceResponse
	if err := json.Unmarshal([]byte(`{"id": "i-2", "name": "mssql", "backupSchedule": "0 0 * * *", "edition": "standard", "flavorId": "f", "isDeletable": true, "retentionDays": 30, "state": "READY", "version": "2022",
	  "replicas": 1, "storage": {}, "network": {"accessScope": "PUBLIC"}}`), &sq); err != nil {
		t.Fatalf("decoding sqlserver v3 instance: %v", err)
	}
	f = sqlServerFlexV3Fields(&sq)
	if f.accessScope == nil || *f.accessScope != "PUBLIC" {
		t.Fatalf("accessScope = %v", f.accessScope)
	}
	if f.kekKeyID != "" || f.kekVersion != nil {
		t.Fatalf("platform-managed encryption should carry no key, got %+v", f)
	}
	var version plugin.TValue[int64]
	if _, err := flexEncryptionKeyVersion(f, &version); err != nil || version.State&plugin.StateIsNull == 0 {
		t.Fatalf("absent key version should mark the field null, state %v", version.State)
	}
}

func TestParseKekVersion(t *testing.T) {
	if v := parseKekVersion(" 7 "); v == nil || *v != 7 {
		t.Fatalf("parseKekVersion(7) = %v", v)
	}
	if parseKekVersion("") != nil || parseKekVersion("latest") != nil {
		t.Fatal("empty or non-numeric versions must read null")
	}
}

func TestScrapeConfigArgsKeepsSecretsOut(t *testing.T) {
	var job observability.Job
	if err := json.Unmarshal([]byte(`{"jobName": "node", "scrapeInterval": "5m", "scrapeTimeout": "2m", "scheme": "https",
	  "staticConfigs": [{"targets": ["10.0.0.5:9100", "10.0.0.6:9100"]}],
	  "httpSdConfigs": [{"url": "https://sd.example.com/targets"}],
	  "basicAuth": {"username": "prom", "password": "basic-SECRET"},
	  "bearerToken": "bearer-SECRET",
	  "oauth2": {"clientId": "c", "clientSecret": "oauth-SECRET", "tokenUrl": "https://idp.example.com/token"},
	  "params": {"token": ["param-SECRET"]},
	  "tlsConfig": {"insecureSkipVerify": true}}`), &job); err != nil {
		t.Fatalf("decoding job: %v", err)
	}
	args := scrapeConfigArgs("o-1", &job)
	for _, secret := range []string{"basic-SECRET", "bearer-SECRET", "oauth-SECRET", "param-SECRET"} {
		if argsContain(args, secret) {
			t.Fatalf("%s reached the mapped fields", secret)
		}
	}
	if args["insecureSkipVerify"].Value != true || args["basicAuthConfigured"].Value != true || args["bearerTokenConfigured"].Value != true || args["oauth2Configured"].Value != true {
		t.Fatalf("flags = %v %v %v %v", args["insecureSkipVerify"].Value, args["basicAuthConfigured"].Value, args["bearerTokenConfigured"].Value, args["oauth2Configured"].Value)
	}
	if tg := args["targets"].Value.([]any); len(tg) != 2 || tg[1] != "10.0.0.6:9100" {
		t.Fatalf("targets = %v", tg)
	}
	if args["__id"].Value != "stackit.observability.scrapeConfig/o-1/node" {
		t.Fatalf("__id = %v", args["__id"].Value)
	}

	var bare observability.Job
	if err := json.Unmarshal([]byte(`{"jobName": "plain", "scrapeInterval": "5m", "scrapeTimeout": "2m", "staticConfigs": []}`), &bare); err != nil {
		t.Fatalf("decoding job: %v", err)
	}
	args = scrapeConfigArgs("o-1", &bare)
	if args["insecureSkipVerify"].Value != nil || args["scheme"].Value != nil || args["sampleLimit"].Value != nil {
		t.Fatalf("absent settings should read null: %v %v %v", args["insecureSkipVerify"].Value, args["scheme"].Value, args["sampleLimit"].Value)
	}
	if args["basicAuthConfigured"].Value != false || args["bearerTokenConfigured"].Value != false {
		t.Fatalf("no auth configured: %v %v", args["basicAuthConfigured"].Value, args["bearerTokenConfigured"].Value)
	}
}
