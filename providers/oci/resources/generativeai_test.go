// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/generativeai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeGenAi[T any](t *testing.T, raw string) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	return v
}

func TestOciHostedApplicationDetailsFrom(t *testing.T) {
	t.Run("private endpoint, custom outbound, mixed env vars", func(t *testing.T) {
		// Synthetic: shape follows the Generative AI API reference for a
		// hosted application; no hosted application exists in the test tenancy.
		app := decodeGenAi[generativeai.HostedApplication](t, `{
			"id": "ocid1.generativeaihostedapplication.oc1.iad.app1",
			"displayName": "app1",
			"lifecycleState": "ACTIVE",
			"lifecycleDetails": "running",
			"applicationEndpoint": "https://app1.example.oci.oraclecloud.com",
			"publicAccessPathPatterns": ["/health", "/docs/*"],
			"inboundAuthConfig": {"inboundAuthConfigType": "IDCS_AUTH_CONFIG", "idcsConfig": {"domainUrl": "https://idcs.example", "scope": "s", "clientSecretVaultId": "ocid1.vaultsecret.oc1.iad.sec"}},
			"networkingConfig": {
				"inboundNetworkingConfig": {"endpointMode": "PRIVATE", "privateEndpointId": "ocid1.generativeaiprivateendpoint.oc1.iad.pe1"},
				"outboundNetworkingConfig": {"networkMode": "CUSTOM", "customSubnetId": "ocid1.subnet.oc1.iad.sn1", "nsgIds": ["ocid1.networksecuritygroup.oc1.iad.n1", "ocid1.networksecuritygroup.oc1.iad.n2"]}
			},
			"environmentVariables": [
				{"name": "LOG_LEVEL", "type": "PLAINTEXT", "value": "debug"},
				{"name": "OPENAI_API_KEY", "type": "VAULT", "value": "ocid1.vaultsecret.oc1.iad.s2"},
				{"name": "DB_PASSWORD", "type": "PLAINTEXT", "value": "hunter2"}
			]
		}`)

		d := ociHostedApplicationDetailsFrom(&app)
		assert.Equal(t, "running", d.lifecycleDetails)
		assert.Equal(t, "IDCS_AUTH_CONFIG", d.inboundAuthType)
		assert.Equal(t, "PRIVATE", d.endpointMode)
		assert.Equal(t, "ocid1.generativeaiprivateendpoint.oc1.iad.pe1", d.privateEndpointID)
		assert.Equal(t, "CUSTOM", d.outboundNetworkMode)
		assert.Equal(t, "ocid1.subnet.oc1.iad.sn1", d.subnetID)
		assert.Equal(t, []string{"ocid1.networksecuritygroup.oc1.iad.n1", "ocid1.networksecuritygroup.oc1.iad.n2"}, d.nsgIDs)
		assert.Equal(t, []string{"/health", "/docs/*"}, d.publicAccessPathPatterns)
		assert.Equal(t, "https://app1.example.oci.oraclecloud.com", d.applicationEndpoint)
		assert.Equal(t, []string{"LOG_LEVEL", "OPENAI_API_KEY", "DB_PASSWORD"}, d.environmentVariableNames)
		assert.Equal(t, []string{"OPENAI_API_KEY"}, d.vaultEnvironmentVariableNames)
		assert.False(t, d.isPublic())

		// No environment variable value may reach the details record.
		assert.NotContains(t, fmt.Sprintf("%+v", *d), "hunter2")
		assert.NotContains(t, fmt.Sprintf("%+v", *d), "debug")
	})

	t.Run("public endpoint without auth", func(t *testing.T) {
		// Synthetic: public, unauthenticated application with managed egress.
		app := decodeGenAi[generativeai.HostedApplication](t, `{
			"id": "ocid1.generativeaihostedapplication.oc1.iad.app2",
			"displayName": "app2",
			"lifecycleState": "ACTIVE",
			"inboundAuthConfig": {"inboundAuthConfigType": "NO_AUTH_CONFIG"},
			"networkingConfig": {
				"inboundNetworkingConfig": {"endpointMode": "PUBLIC"},
				"outboundNetworkingConfig": {"networkMode": "MANAGED"}
			}
		}`)
		d := ociHostedApplicationDetailsFrom(&app)
		assert.True(t, d.isPublic())
		assert.Equal(t, "", d.privateEndpointID)
		assert.Equal(t, "", d.subnetID)
		assert.Empty(t, d.nsgIDs)
		assert.Equal(t, []string{}, d.environmentVariableNames)
		assert.Equal(t, []string{}, d.vaultEnvironmentVariableNames)
	})

	t.Run("public endpoint with auth is not public", func(t *testing.T) {
		// Synthetic: public endpoint guarded by an identity domain session.
		app := decodeGenAi[generativeai.HostedApplication](t, `{
			"id": "ocid1.generativeaihostedapplication.oc1.iad.app3",
			"displayName": "app3",
			"lifecycleState": "ACTIVE",
			"inboundAuthConfig": {"inboundAuthConfigType": "IDCS_SESSION_AUTH_CONFIG"},
			"networkingConfig": {"inboundNetworkingConfig": {"endpointMode": "PUBLIC"}, "outboundNetworkingConfig": {"networkMode": "MANAGED"}}
		}`)
		assert.False(t, ociHostedApplicationDetailsFrom(&app).isPublic())
	})

	t.Run("no auth or networking config", func(t *testing.T) {
		// Synthetic: record with the optional configs absent.
		app := decodeGenAi[generativeai.HostedApplication](t, `{"id": "x", "displayName": "x", "lifecycleState": "CREATING"}`)
		d := ociHostedApplicationDetailsFrom(&app)
		assert.Equal(t, "", d.inboundAuthType)
		assert.Equal(t, "", d.endpointMode)
		assert.False(t, d.isPublic())
	})
}

func TestOciHostedDeploymentArtifactFrom(t *testing.T) {
	t.Run("docker artifact", func(t *testing.T) {
		// Synthetic: shape follows the API reference for a hosted deployment summary.
		d := decodeGenAi[generativeai.HostedDeploymentSummary](t, `{
			"id": "ocid1.generativeaihosteddeployment.oc1.iad.d1",
			"lifecycleState": "ACTIVE",
			"activeArtifact": {"artifactType": "SIMPLE_DOCKER_ARTIFACT", "status": "ACTIVE", "isVulnerabilityScanRequired": false, "containerUri": "iad.ocir.io/ns/agent", "tag": "1.2.3"}
		}`)
		a := ociHostedDeploymentArtifactFrom(d.ActiveArtifact)
		assert.Equal(t, "SIMPLE_DOCKER_ARTIFACT", a.artifactType)
		assert.Equal(t, "ACTIVE", a.status)
		assert.Equal(t, "iad.ocir.io/ns/agent", a.containerURI)
		assert.Equal(t, "1.2.3", a.tag)
		require.NotNil(t, a.vulnerabilityScanRequired)
		assert.False(t, *a.vulnerabilityScanRequired)
	})

	t.Run("no active artifact", func(t *testing.T) {
		// Synthetic: deployment still being created.
		d := decodeGenAi[generativeai.HostedDeploymentSummary](t, `{"id": "d2", "lifecycleState": "CREATING"}`)
		a := ociHostedDeploymentArtifactFrom(d.ActiveArtifact)
		assert.Equal(t, "", a.artifactType)
		assert.Equal(t, "", a.containerURI)
		assert.Nil(t, a.vulnerabilityScanRequired)
	})
}

func TestOciApiKeyItemArgs(t *testing.T) {
	// Synthetic values in a measured shape: on a live API key (us-sanjose-1,
	// 2026-11-06) ListApiKeys returned no key value and a 51-character mask
	// revealing the first 4 and the last 4 characters, which is why neither is
	// exposed. The key here is made up to prove it is dropped.
	k := decodeGenAi[generativeai.ApiKeySummary](t, `{
		"id": "ocid1.generativeaiapikey.oc1.iad.k1",
		"displayName": "k1",
		"compartmentId": "ocid1.compartment.oc1..c",
		"timeCreated": "2026-10-01T00:00:00Z",
		"lifecycleState": "ACTIVE",
		"keys": [
			{"keyName": "key-one", "keyMask": "sk-a*******************************************wxyz", "key": "sk-abcdSECRETVALUEwxyz", "state": "ACTIVE",
			 "timeCreated": "2026-10-01T00:00:00Z", "timeExpiry": "2027-10-01T00:00:00Z", "timeLastUsed": "2026-11-01T12:00:00Z"},
			{"keyName": "key-two", "keyMask": "sk-e*******************************************hijk", "state": "REVOKED",
			 "timeCreated": "2026-10-02T00:00:00Z", "timeExpiry": "2027-10-02T00:00:00Z", "timeRevoked": "2026-10-03T00:00:00Z"}
		]
	}`)
	require.Len(t, k.Keys, 2)

	args := ociApiKeyItemArgs("ocid1.generativeaiapikey.oc1.iad.k1", &k.Keys[0])
	assert.Equal(t, "ocid1.generativeaiapikey.oc1.iad.k1/key-one", args["__id"].Value)
	assert.Equal(t, "key-one", args["name"].Value)
	assert.Equal(t, "ACTIVE", args["state"].Value)
	assert.NotNil(t, args["timeLastUsed"].Value)
	assert.Nil(t, args["timeRevoked"].Value)
	for field, v := range args {
		s, _ := v.Value.(string)
		assert.NotContains(t, s, "SECRET", field)
		assert.NotContains(t, s, "wxyz", field)
	}
	assert.NotContains(t, args, "key")
	assert.NotContains(t, args, "keyMask")

	args2 := ociApiKeyItemArgs("ocid1.generativeaiapikey.oc1.iad.k1", &k.Keys[1])
	assert.NotEqual(t, args["__id"].Value, args2["__id"].Value)
	assert.Equal(t, "REVOKED", args2["state"].Value)
	assert.NotNil(t, args2["timeRevoked"].Value)
	assert.Nil(t, args2["timeLastUsed"].Value)
}

func TestOciGenerativeAiProjectDetailsFrom(t *testing.T) {
	t.Run("managed sandbox allowing all egress", func(t *testing.T) {
		// Synthetic: shape follows the API reference for a project.
		p := decodeGenAi[generativeai.GenerativeAiProject](t, `{
			"id": "ocid1.generativeaiproject.oc1.iad.p1", "displayName": "p1",
			"compartmentId": "c", "timeCreated": "2026-10-01T00:00:00Z", "lifecycleState": "ACTIVE",
			"freeformTags": {}, "definedTags": {},
			"conversationConfig": {"responsesRetentionInHours": 720, "conversationsRetentionInHours": 0},
			"shortTermMemoryOptimizationConfig": {"isEnabled": true},
			"sandboxConfig": {
				"isEnabled": true, "isPersistenceEnabled": true,
				"sandboxOutboundNetworkingConfig": {"networkMode": "MANAGED", "networkPolicy": {"mode": "ALLOW_ALL"}},
				"credentialProfiles": [
					{"label": "github", "credentialInjectionRules": [{"ruleType": "HTTP_HEADER", "headers": [{"name": "Authorization", "secretId": "ocid1.vaultsecret.oc1.iad.s"}]}]},
					{"label": "jira", "credentialInjectionRules": []}
				]
			}
		}`)
		d := ociGenerativeAiProjectDetailsFrom(&p)
		require.NotNil(t, d.responsesRetentionInHours)
		assert.Equal(t, int64(720), *d.responsesRetentionInHours)
		require.NotNil(t, d.conversationsRetentionInHours)
		assert.Equal(t, int64(0), *d.conversationsRetentionInHours)
		assert.True(t, d.shortTermMemoryOptimizationEnabled)
		assert.True(t, d.sandboxEnabled)
		assert.True(t, d.sandboxPersistenceEnabled)
		assert.Equal(t, "MANAGED", d.sandboxOutboundNetworkMode)
		assert.Equal(t, "ALLOW_ALL", d.sandboxNetworkPolicyMode)
		assert.Equal(t, "", d.sandboxSubnetID)
		assert.Equal(t, []string{"github", "jira"}, d.sandboxCredentialProfileLabels)
	})

	t.Run("managed sandbox with allow list and deny all", func(t *testing.T) {
		// Synthetic: the other two managed network policy modes.
		allow := decodeGenAi[generativeai.GenerativeAiProject](t, `{"id": "p", "displayName": "p", "compartmentId": "c", "timeCreated": "2026-10-01T00:00:00Z", "lifecycleState": "ACTIVE", "freeformTags": {}, "definedTags": {},
			"sandboxConfig": {"isEnabled": true, "sandboxOutboundNetworkingConfig": {"networkMode": "MANAGED", "networkPolicy": {"mode": "ALLOW", "allowedDomains": [{"domain": "pypi.org"}]}}}}`)
		assert.Equal(t, "ALLOW", ociGenerativeAiProjectDetailsFrom(&allow).sandboxNetworkPolicyMode)
		deny := decodeGenAi[generativeai.GenerativeAiProject](t, `{"id": "p", "displayName": "p", "compartmentId": "c", "timeCreated": "2026-10-01T00:00:00Z", "lifecycleState": "ACTIVE", "freeformTags": {}, "definedTags": {},
			"sandboxConfig": {"isEnabled": true, "sandboxOutboundNetworkingConfig": {"networkMode": "MANAGED", "networkPolicy": {"mode": "DENY_ALL"}}}}`)
		assert.Equal(t, "DENY_ALL", ociGenerativeAiProjectDetailsFrom(&deny).sandboxNetworkPolicyMode)
	})

	t.Run("custom sandbox subnet", func(t *testing.T) {
		// Synthetic: sandbox egress through a customer subnet.
		p := decodeGenAi[generativeai.GenerativeAiProject](t, `{"id": "p", "displayName": "p", "compartmentId": "c", "timeCreated": "2026-10-01T00:00:00Z", "lifecycleState": "ACTIVE", "freeformTags": {}, "definedTags": {},
			"sandboxConfig": {"isEnabled": true, "sandboxOutboundNetworkingConfig": {"networkMode": "CUSTOM", "subnetId": "ocid1.subnet.oc1.iad.sn", "nsgIds": ["ocid1.networksecuritygroup.oc1.iad.n"]}}}`)
		d := ociGenerativeAiProjectDetailsFrom(&p)
		assert.Equal(t, "CUSTOM", d.sandboxOutboundNetworkMode)
		assert.Equal(t, "", d.sandboxNetworkPolicyMode)
		assert.Equal(t, "ocid1.subnet.oc1.iad.sn", d.sandboxSubnetID)
		assert.Equal(t, []string{"ocid1.networksecuritygroup.oc1.iad.n"}, d.sandboxNsgIDs)
		assert.False(t, d.sandboxPersistenceEnabled)
	})

	t.Run("no optional configs", func(t *testing.T) {
		// Synthetic: project record without conversation or sandbox config.
		p := decodeGenAi[generativeai.GenerativeAiProject](t, `{"id": "p", "displayName": "p", "compartmentId": "c", "timeCreated": "2026-10-01T00:00:00Z", "lifecycleState": "ACTIVE", "freeformTags": {}, "definedTags": {}}`)
		d := ociGenerativeAiProjectDetailsFrom(&p)
		assert.Nil(t, d.responsesRetentionInHours)
		assert.Nil(t, d.conversationsRetentionInHours)
		assert.False(t, d.sandboxEnabled)
		assert.Equal(t, "", d.sandboxOutboundNetworkMode)
		assert.Equal(t, []string{}, d.sandboxCredentialProfileLabels)
	})
}

func TestOciImportedModelSourceFrom(t *testing.T) {
	t.Run("hugging face", func(t *testing.T) {
		// Synthetic: shape follows the API reference; the access token is made up.
		m := decodeGenAi[generativeai.ImportedModelSummary](t, `{
			"id": "ocid1.generativeaiimportedmodel.oc1.iad.m1", "compartmentId": "c", "lifecycleState": "ACTIVE", "timeCreated": "2026-10-01T00:00:00Z",
			"dataSource": {"sourceType": "HUGGING_FACE_MODEL", "modelId": "meta-llama/Llama-3.1-8B", "branch": "main", "commit": "abc123", "accessToken": "hf_SECRET"}
		}`)
		src := ociImportedModelSourceFrom(m.DataSource)
		assert.Equal(t, ociImportedModelSource{
			sourceType:         "HUGGING_FACE_MODEL",
			huggingFaceModelID: "meta-llama/Llama-3.1-8B",
			huggingFaceBranch:  "main",
			huggingFaceCommit:  "abc123",
		}, src)
	})

	t.Run("object storage", func(t *testing.T) {
		// Synthetic: weights in a bucket in another region.
		m := decodeGenAi[generativeai.ImportedModelSummary](t, `{
			"id": "ocid1.generativeaiimportedmodel.oc1.iad.m2", "compartmentId": "c", "lifecycleState": "ACTIVE", "timeCreated": "2026-10-01T00:00:00Z",
			"dataSource": {"sourceType": "OBJECT_STORAGE_OBJECT", "namespaceName": "ns", "bucketName": "weights", "prefixName": "llama/", "region": "us-chicago-1"}
		}`)
		src := ociImportedModelSourceFrom(m.DataSource)
		assert.Equal(t, ociImportedModelSource{
			sourceType: "OBJECT_STORAGE_OBJECT",
			namespace:  "ns",
			bucket:     "weights",
			prefix:     "llama/",
			region:     "us-chicago-1",
		}, src)
	})

	t.Run("no data source", func(t *testing.T) {
		assert.Equal(t, ociImportedModelSource{}, ociImportedModelSourceFrom(nil))
	})
}
