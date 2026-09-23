// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// The tests below pin the SDK struct tags for the security-relevant fields this
// provider reads, against payloads shaped like the documented Atlas responses.
// A tag naming a different key decodes to the zero value, which is how a
// "server-side JavaScript is disabled" or "the bucket is not public" reading
// gets reported on a deployment where the opposite is true.
//
// Each decode is checked twice: once with the field present, and once with it
// absent, where the pointer must stay nil so the schema renders null rather
// than a fabricated false.

func TestDecodeGroupSettings(t *testing.T) {
	var s admin.GroupSettings
	require.NoError(t, json.Unmarshal([]byte(`{
		"isClusterAiAssistantEnabled": true,
		"isCollectDatabaseSpecificsStatisticsEnabled": false,
		"isDataExplorerEnabled": true,
		"isDataExplorerGenAIFeaturesEnabled": true,
		"isDataExplorerGenAISampleDocumentPassingEnabled": true,
		"isDataValidationEnabled": false,
		"isExtendedStorageSizesEnabled": false,
		"isNativeRerankingEnabled": true,
		"isPerformanceAdvisorEnabled": true,
		"isRealtimePerformancePanelEnabled": true,
		"isSchemaAdvisorEnabled": true
	}`), &s))

	require.NotNil(t, s.IsDataExplorerGenAISampleDocumentPassingEnabled)
	assert.True(t, *s.IsDataExplorerGenAISampleDocumentPassingEnabled,
		"sample document passing is the flag that sends real documents to a third-party model")
	require.NotNil(t, s.IsClusterAiAssistantEnabled)
	assert.True(t, *s.IsClusterAiAssistantEnabled)
	require.NotNil(t, s.IsNativeRerankingEnabled)
	assert.True(t, *s.IsNativeRerankingEnabled)
	require.NotNil(t, s.IsDataValidationEnabled)
	assert.False(t, *s.IsDataValidationEnabled)
}

func TestDecodeGroupSettingsAbsentFlagsStayNull(t *testing.T) {
	var s admin.GroupSettings
	require.NoError(t, json.Unmarshal([]byte(`{"isDataExplorerEnabled": true}`), &s))

	assert.Nil(t, s.IsDataExplorerGenAISampleDocumentPassingEnabled)
	assert.Nil(t, s.IsClusterAiAssistantEnabled)
	assert.Nil(t, s.IsNativeRerankingEnabled)
	assert.Nil(t, s.IsDataValidationEnabled)
}

func TestDecodeClusterProcessArgs(t *testing.T) {
	var a admin.ClusterDescriptionProcessArgs20240805
	require.NoError(t, json.Unmarshal([]byte(`{
		"changeStreamOptionsPreAndPostImagesExpireAfterSeconds": 100,
		"chunkMigrationConcurrency": 4,
		"customOpensslCipherConfigTls12": ["TLS_RSA_WITH_AES_256_CBC_SHA"],
		"customOpensslCipherConfigTls13": ["TLS_AES_256_GCM_SHA384"],
		"defaultMaxTimeMS": 1000,
		"defaultWriteConcern": "majority",
		"javascriptEnabled": true,
		"minimumEnabledTlsProtocol": "TLS1_2",
		"noTableScan": false,
		"oplogMinRetentionHours": 24.5,
		"oplogSizeMB": 2048,
		"queryStatsLogVerbosity": 3,
		"tlsCipherConfigMode": "CUSTOM",
		"transactionLifetimeLimitSeconds": 60
	}`), &a))

	require.NotNil(t, a.JavascriptEnabled)
	assert.True(t, *a.JavascriptEnabled, "server-side JavaScript execution")
	require.NotNil(t, a.NoTableScan)
	assert.False(t, *a.NoTableScan)
	require.NotNil(t, a.TlsCipherConfigMode)
	assert.Equal(t, "CUSTOM", *a.TlsCipherConfigMode)
	assert.Equal(t, []string{"TLS_RSA_WITH_AES_256_CBC_SHA"}, a.GetCustomOpensslCipherConfigTls12())
	assert.Equal(t, []string{"TLS_AES_256_GCM_SHA384"}, a.GetCustomOpensslCipherConfigTls13())
	require.NotNil(t, a.OplogMinRetentionHours)
	assert.InDelta(t, 24.5, *a.OplogMinRetentionHours, 0.0001)
	require.NotNil(t, a.QueryStatsLogVerbosity)
	assert.Equal(t, 3, *a.QueryStatsLogVerbosity)
	require.NotNil(t, a.TransactionLifetimeLimitSeconds)
	assert.Equal(t, int64(60), *a.TransactionLifetimeLimitSeconds)
}

func TestDecodeClusterProcessArgsAbsentSettingsStayNull(t *testing.T) {
	var a admin.ClusterDescriptionProcessArgs20240805
	require.NoError(t, json.Unmarshal([]byte(`{"minimumEnabledTlsProtocol": "TLS1_2"}`), &a))

	// A cluster left at the Atlas default reports nothing for these, and a
	// fabricated false on javascriptEnabled would pass a check that server-side
	// JavaScript is off on a cluster where it was never read.
	assert.Nil(t, a.JavascriptEnabled)
	assert.Nil(t, a.NoTableScan)
	assert.Nil(t, a.OplogMinRetentionHours)
	assert.Empty(t, a.GetCustomOpensslCipherConfigTls12())
}

func TestDecodeUserSecurityLdap(t *testing.T) {
	var s admin.UserSecurity
	require.NoError(t, json.Unmarshal([]byte(`{
		"customerX509": {"cas": "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----"},
		"ldap": {
			"authenticationEnabled": true,
			"authorizationEnabled": false,
			"authzQueryTemplate": "{USER}?memberOf?base",
			"bindUsername": "CN=svc,DC=example,DC=test",
			"caCertificate": "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----",
			"hostname": "ldap.example.test",
			"port": 389,
			"userToDNMapping": [{"match": "(.+)", "substitution": "uid={0},DC=example,DC=test"}]
		}
	}`), &s))

	ldap, ok := s.GetLdapOk()
	require.True(t, ok)
	require.NotNil(t, ldap.AuthenticationEnabled)
	assert.True(t, *ldap.AuthenticationEnabled)
	require.NotNil(t, ldap.AuthorizationEnabled)
	assert.False(t, *ldap.AuthorizationEnabled)
	require.NotNil(t, ldap.Hostname)
	assert.Equal(t, "ldap.example.test", *ldap.Hostname)
	require.NotNil(t, ldap.Port)
	assert.Equal(t, 389, *ldap.Port, "389 is plaintext LDAP; the bind credentials cross unprotected")
	assert.True(t, isSet(ldap.CaCertificate))
	assert.Len(t, ldap.GetUserToDNMapping(), 1)

	x509, ok := s.GetCustomerX509Ok()
	require.True(t, ok)
	assert.True(t, isSet(x509.Cas))
}

func TestDecodeUserSecurityWithoutLdap(t *testing.T) {
	var s admin.UserSecurity
	require.NoError(t, json.Unmarshal([]byte(`{"links": []}`), &s))

	_, ok := s.GetLdapOk()
	assert.False(t, ok, "a project with no LDAP block has no LDAP configuration, which is not the same as LDAP being off")
	_, ok = s.GetCustomerX509Ok()
	assert.False(t, ok)
}

func TestDecodeDataLakeStoreSettings(t *testing.T) {
	var tenant admin.DataLakeTenant
	require.NoError(t, json.Unmarshal([]byte(`{
		"cloudProviderConfig": {"aws": {"roleId": "60d1d0b0e1b2c3d4e5f60000", "testS3Bucket": "example-validation"}},
		"dataProcessRegion": {"cloudProvider": "AWS", "region": "VIRGINIA_USA"},
		"hostnames": ["example.a.query.mongodb.test"],
		"name": "analytics",
		"privateEndpointHostnames": [{"hostname": "example.a.query.mongodb.test", "privateEndpoint": "vpce-0000"}],
		"state": "ACTIVE",
		"storage": {"stores": [
			{"name": "public-logs", "provider": "s3", "bucket": "example-logs", "region": "us-east-1", "prefix": "raw/", "public": true, "delimiter": "/"},
			{"name": "web-source", "provider": "http", "allowInsecure": true, "urls": ["https://data.example.test/x.json"], "defaultFormat": ".json"}
		]}
	}`), &tenant))

	storage, ok := tenant.GetStorageOk()
	require.True(t, ok)
	stores := storage.GetStores()
	require.Len(t, stores, 2)

	require.NotNil(t, stores[0].Public)
	assert.True(t, *stores[0].Public, "a public store is read without credentials")
	assert.Nil(t, stores[0].AllowInsecure)
	assert.Equal(t, "example-logs", stores[0].GetBucket())

	require.NotNil(t, stores[1].AllowInsecure)
	assert.True(t, *stores[1].AllowInsecure, "TLS verification is waived when reaching this store")
	assert.Nil(t, stores[1].Public, "a store that reports no public flag stays null, not false")

	cfg, ok := tenant.GetCloudProviderConfigOk()
	require.True(t, ok)
	aws, ok := cfg.GetAwsOk()
	require.True(t, ok)
	assert.Equal(t, "60d1d0b0e1b2c3d4e5f60000", aws.GetRoleId())
	assert.Equal(t, "example-validation", aws.GetTestS3Bucket())

	require.Len(t, tenant.GetPrivateEndpointHostnames(), 1)
	assert.Equal(t, "vpce-0000", tenant.GetPrivateEndpointHostnames()[0].GetPrivateEndpoint())
}

func TestDecodeThirdPartyIntegrationWebhook(t *testing.T) {
	var i admin.ThirdPartyIntegration
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "60d1d0b0e1b2c3d4e5f60001",
		"type": "WEBHOOK",
		"url": "https://alerts.example.test/atlas?token=REDACTED",
		"secret": "REDACTED"
	}`), &i))

	assert.Equal(t, "WEBHOOK", i.GetType())
	assert.True(t, isSet(i.Secret), "the delivery is signed")

	host := hostPtrOf(integrationEndpoint(i))
	require.NotNil(t, host)
	assert.Equal(t, "alerts.example.test", *host, "the query string carries the token and must not survive")
}

func TestDecodeThirdPartyIntegrationDatadog(t *testing.T) {
	var i admin.ThirdPartyIntegration
	require.NoError(t, json.Unmarshal([]byte(`{
		"type": "DATADOG",
		"region": "US",
		"apiKey": "REDACTED",
		"sendCollectionLatencyMetrics": true,
		"sendDatabaseMetrics": true,
		"sendQueryStatsMetrics": false,
		"sendUserProvidedResourceTags": true
	}`), &i))

	assert.False(t, isSet(i.Secret), "a Datadog integration carries no webhook secret")
	assert.Nil(t, integrationEndpoint(i), "a Datadog integration names no destination address")

	tags := integrationSendsResourceTags(i)
	require.NotNil(t, tags)
	assert.True(t, *tags)

	require.NotNil(t, i.SendQueryStatsMetrics)
	assert.False(t, *i.SendQueryStatsMetrics)
}

func TestDecodeThirdPartyIntegrationPrometheus(t *testing.T) {
	// Prometheus reports the same resource-tag setting under a different name,
	// so reading only the Datadog name would report null on every Prometheus
	// integration.
	var i admin.ThirdPartyIntegration
	require.NoError(t, json.Unmarshal([]byte(`{
		"type": "PROMETHEUS",
		"enabled": true,
		"serviceDiscovery": "http",
		"username": "atlas-prom",
		"sendUserProvidedResourceTagsEnabled": true
	}`), &i))

	assert.Nil(t, i.SendUserProvidedResourceTags)
	tags := integrationSendsResourceTags(i)
	require.NotNil(t, tags)
	assert.True(t, *tags)

	require.NotNil(t, i.Enabled)
	assert.True(t, *i.Enabled)
}

func TestDecodeThirdPartyIntegrationMicrosoftTeams(t *testing.T) {
	var i admin.ThirdPartyIntegration
	require.NoError(t, json.Unmarshal([]byte(`{
		"type": "MICROSOFT_TEAMS",
		"microsoftTeamsWebhookUrl": "https://example.webhook.office.test/webhookb2/aaaa/IncomingWebhook/bbbb"
	}`), &i))

	host := hostPtrOf(integrationEndpoint(i))
	require.NotNil(t, host)
	assert.Equal(t, "example.webhook.office.test", *host)
}

func TestDecodeMetricIntegration(t *testing.T) {
	var m admin.MetricIntegrationResponse
	require.NoError(t, json.Unmarshal([]byte(`{
		"aggregationTemporality": "DELTA",
		"authType": "BEARER",
		"endpoint": "https://otlp.example.test:4318/v1/metrics",
		"headersRedacted": [{"name": "Authorization", "value": "***"}],
		"integrationType": "OTLP",
		"metricSelection": ["DATABASE", "HARDWARE"],
		"metricIntegrationId": "60d1d0b0e1b2c3d4e5f60002",
		"providerType": "GRAFANA_CLOUD"
	}`), &m))

	assert.Equal(t, "60d1d0b0e1b2c3d4e5f60002", m.GetMetricIntegrationId())
	assert.Equal(t, "BEARER", m.GetAuthType())
	assert.Equal(t, "GRAFANA_CLOUD", m.GetProviderType())
	assert.Equal(t, []string{"DATABASE", "HARDWARE"}, m.GetMetricSelection())

	headers := m.GetHeadersRedacted()
	require.Len(t, headers, 1)
	assert.Equal(t, "Authorization", headers[0].GetName())

	endpoint := m.GetEndpoint()
	host := hostPtrOf(&endpoint)
	require.NotNil(t, host)
	assert.Equal(t, "otlp.example.test:4318", *host)
}

func TestDecodeAiModelApiKey(t *testing.T) {
	var k admin.AiModelApiKeyResponse
	require.NoError(t, json.Unmarshal([]byte(`{
		"apiKeyId": "60d1d0b0e1b2c3d4e5f60003",
		"cloud": "AWS",
		"createdAt": "2026-02-03T04:05:06Z",
		"createdBy": "alice@example.test",
		"endpoint": "https://api.example.test/v1/embeddings",
		"geography": "ANY",
		"groupId": "60d1d0b0e1b2c3d4e5f60004",
		"lastUsedAt": "2026-02-04T05:06:07Z",
		"name": "embeddings",
		"status": "ACTIVE"
	}`), &k))

	assert.Equal(t, "60d1d0b0e1b2c3d4e5f60003", k.GetApiKeyId())
	assert.Equal(t, "60d1d0b0e1b2c3d4e5f60004", k.GetGroupId())
	assert.Equal(t, "ACTIVE", k.GetStatus())

	created := parseAtlasTime(k.CreatedAt)
	require.NotNil(t, created)
	assert.Equal(t, 2026, created.UTC().Year())

	lastUsed := parseAtlasTime(k.LastUsedAt)
	require.NotNil(t, lastUsed)
	assert.Equal(t, 4, lastUsed.UTC().Day())
}

func TestDecodeAiModelApiKeyNeverUsed(t *testing.T) {
	var k admin.AiModelApiKeyResponse
	require.NoError(t, json.Unmarshal([]byte(`{"apiKeyId": "60d1d0b0e1b2c3d4e5f60005", "status": "ACTIVE"}`), &k))

	// A key that has never been used reports no lastUsedAt at all; turning that
	// into the zero time would date it to the year 1 and make every staleness
	// check fire on it.
	assert.Nil(t, parseAtlasTime(k.LastUsedAt))
	assert.Empty(t, k.GetGroupId(), "an organization-wide key names no project")
}

func TestDecodeUserCert(t *testing.T) {
	var c admin.UserCert
	require.NoError(t, json.Unmarshal([]byte(`{
		"_id": 1234567890,
		"createdAt": "2026-01-02T03:04:05Z",
		"groupId": "60d1d0b0e1b2c3d4e5f60006",
		"notAfter": "2027-01-02T03:04:05Z",
		"subject": "CN=alice,OU=users,DC=example,DC=test"
	}`), &c))

	assert.Equal(t, int64(1234567890), c.GetId(), "the certificate id decodes from _id, not id")
	require.NotNil(t, c.NotAfter)
	assert.Equal(t, 2027, c.NotAfter.UTC().Year())
	assert.Equal(t, "CN=alice,OU=users,DC=example,DC=test", c.GetSubject())
}

func TestDecodeMaintenanceWindow(t *testing.T) {
	var w admin.GroupMaintenanceWindow
	require.NoError(t, json.Unmarshal([]byte(`{
		"autoDeferOnceEnabled": true,
		"dayOfWeek": 3,
		"hourOfDay": 2,
		"numberOfDeferrals": 4,
		"protectedHours": {"endHourOfDay": 6, "startHourOfDay": 1},
		"startASAP": false,
		"timeZoneId": "America/New_York"
	}`), &w))

	assert.Equal(t, 3, w.GetDayOfWeek())
	require.NotNil(t, w.NumberOfDeferrals)
	assert.Equal(t, 4, *w.NumberOfDeferrals, "repeated deferral is how a cluster stays on an unpatched build")
	require.NotNil(t, w.StartASAP)
	assert.False(t, *w.StartASAP, "startASAP decodes from the upper-case ASAP key")

	ph, ok := w.GetProtectedHoursOk()
	require.True(t, ok)
	assert.Equal(t, 1, ph.GetStartHourOfDay())
	assert.Equal(t, 6, ph.GetEndHourOfDay())
}

func TestDecodeMaintenanceWindowNeverDeferred(t *testing.T) {
	var w admin.GroupMaintenanceWindow
	require.NoError(t, json.Unmarshal([]byte(`{"dayOfWeek": 1}`), &w))

	assert.Nil(t, w.NumberOfDeferrals)
	assert.Nil(t, w.AutoDeferOnceEnabled)
	_, ok := w.GetProtectedHoursOk()
	assert.False(t, ok)
}

func TestDecodeOnlineArchive(t *testing.T) {
	var a admin.BackupOnlineArchive
	require.NoError(t, json.Unmarshal([]byte(`{
		"_id": "60d1d0b0e1b2c3d4e5f60007",
		"clusterName": "example-0",
		"collName": "events",
		"collectionType": "STANDARD",
		"criteria": {"type": "DATE", "dateField": "createdAt", "expireAfterDays": 30},
		"dataExpirationRule": {"expireAfterDays": 365},
		"dataProcessRegion": {"cloudProvider": "AWS", "region": "US_EAST_1"},
		"dataSetName": "atlas_example",
		"dbName": "app",
		"partitionFields": [{"fieldName": "createdAt", "fieldType": "date", "order": 0}],
		"paused": false,
		"schedule": {"type": "DAILY", "startHour": 1, "endHour": 3},
		"state": "ACTIVE"
	}`), &a))

	assert.Equal(t, "60d1d0b0e1b2c3d4e5f60007", a.GetId(), "the archive id decodes from _id, not id")
	assert.Equal(t, "app", a.GetDbName())
	assert.Equal(t, "events", a.GetCollName())
	require.NotNil(t, a.Paused)
	assert.False(t, *a.Paused)

	c, ok := a.GetCriteriaOk()
	require.True(t, ok)
	assert.Equal(t, "DATE", c.GetType())
	assert.Equal(t, 30, c.GetExpireAfterDays())

	rule, ok := a.GetDataExpirationRuleOk()
	require.True(t, ok)
	assert.Equal(t, 365, rule.GetExpireAfterDays(),
		"the archive expiry is a separate rule from the criteria's own age threshold")

	s, ok := a.GetScheduleOk()
	require.True(t, ok)
	assert.Equal(t, "DAILY", s.Type)
}

func TestDecodeOnlineArchiveWithoutExpiry(t *testing.T) {
	var a admin.BackupOnlineArchive
	require.NoError(t, json.Unmarshal([]byte(`{"_id": "60d1d0b0e1b2c3d4e5f60008", "dbName": "app", "collName": "events"}`), &a))

	// An archive with no expiry rule keeps its data indefinitely, which must
	// read as null rather than as an expiry of zero days.
	_, ok := a.GetDataExpirationRuleOk()
	assert.False(t, ok)
	assert.Nil(t, a.Paused)
}

func TestDecodeConnectedOrgConfig(t *testing.T) {
	var c admin.ConnectedOrgConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"dataAccessIdentityProviderIds": ["60d1d0b0e1b2c3d4e5f60009"],
		"domainAllowList": ["example.test"],
		"domainRestrictionEnabled": true,
		"identityProviderId": "60d1d0b0e1b2c3d4e5f6000a",
		"instantUserProvisioningDisabled": false,
		"orgId": "60d1d0b0e1b2c3d4e5f6000b",
		"postAuthRoleGrants": ["ORG_MEMBER"],
		"roleMappings": [{
			"externalGroupName": "atlas-admins",
			"id": "60d1d0b0e1b2c3d4e5f6000c",
			"roleAssignments": [
				{"orgId": "60d1d0b0e1b2c3d4e5f6000b", "role": "ORG_OWNER"},
				{"groupId": "60d1d0b0e1b2c3d4e5f6000d", "orgId": "60d1d0b0e1b2c3d4e5f6000b", "role": "GROUP_OWNER"}
			]
		}],
		"userConflicts": [{"emailAddress": "bob@example.test", "federationSettingsId": "f1", "firstName": "Bob", "lastName": "B"}]
	}`), &c))

	assert.True(t, c.GetDomainRestrictionEnabled())
	assert.Equal(t, []string{"ORG_MEMBER"}, c.GetPostAuthRoleGrants(),
		"post-auth grants reach every federated user regardless of any mapping")
	assert.Equal(t, "60d1d0b0e1b2c3d4e5f6000a", c.GetIdentityProviderId())
	assert.Equal(t, []string{"60d1d0b0e1b2c3d4e5f60009"}, c.GetDataAccessIdentityProviderIds())

	require.NotNil(t, c.RoleMappings)
	mappings := *c.RoleMappings
	require.Len(t, mappings, 1)
	assert.Equal(t, "atlas-admins", mappings[0].GetExternalGroupName())

	orgRoles, projectRoles, order := splitRoleAssignments(mappings[0].GetRoleAssignments())
	assert.Equal(t, []string{"ORG_OWNER"}, orgRoles, "this is the mapping that grants ORG_OWNER")
	assert.Equal(t, []string{"60d1d0b0e1b2c3d4e5f6000d"}, order)
	assert.Equal(t, []string{"GROUP_OWNER"}, projectRoles["60d1d0b0e1b2c3d4e5f6000d"])

	require.Len(t, c.GetUserConflicts(), 1)
	assert.Equal(t, "bob@example.test", c.GetUserConflicts()[0].GetEmailAddress())
}

func TestDecodeConnectedOrgConfigWithoutRoleMappings(t *testing.T) {
	var c admin.ConnectedOrgConfig
	require.NoError(t, json.Unmarshal([]byte(`{"orgId": "60d1d0b0e1b2c3d4e5f6000b", "domainRestrictionEnabled": false}`), &c))

	// A listing that carries no roleMappings key at all is the signal to read
	// them from the mapping endpoint instead, so it must stay distinguishable
	// from a listing that carries an empty array.
	assert.Nil(t, c.RoleMappings)
	assert.False(t, c.GetDomainRestrictionEnabled())
}

func TestDecodeGroupAlertsConfig(t *testing.T) {
	var c admin.GroupAlertsConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"created": "2026-01-02T03:04:05Z",
		"enabled": true,
		"eventTypeName": "USER_ROLES_CHANGED_AUDIT",
		"groupId": "60d1d0b0e1b2c3d4e5f6000e",
		"id": "60d1d0b0e1b2c3d4e5f6000f",
		"matchers": [{"fieldName": "CLUSTER_NAME", "operator": "EQUALS", "value": "example-0"}],
		"notifications": [
			{"typeName": "GROUP", "emailEnabled": true, "smsEnabled": false, "roles": ["GROUP_OWNER"], "delayMin": 0, "intervalMin": 60},
			{"typeName": "WEBHOOK", "webhookUrl": "https://alerts.example.test/hook?token=REDACTED", "webhookSecret": "REDACTED", "notifierId": "60d1d0b0e1b2c3d4e5f60010"},
			{"typeName": "SLACK", "apiToken": "REDACTED", "channelName": "#alerts"}
		],
		"severityOverride": "WARNING",
		"updated": "2026-01-03T03:04:05Z"
	}`), &c))

	assert.Equal(t, "USER_ROLES_CHANGED_AUDIT", c.GetEventTypeName())
	require.NotNil(t, c.Enabled)
	assert.True(t, *c.Enabled)
	require.Len(t, c.GetMatchers(), 1)
	assert.Equal(t, "CLUSTER_NAME", c.GetMatchers()[0].GetFieldName())

	notifications := c.GetNotifications()
	require.Len(t, notifications, 3)

	assert.Equal(t, "GROUP", notifications[0].GetTypeName())
	require.NotNil(t, notifications[0].EmailEnabled)
	assert.True(t, *notifications[0].EmailEnabled)
	assert.Equal(t, []string{"GROUP_OWNER"}, notifications[0].GetRoles())

	assert.True(t, isSet(notifications[1].WebhookSecret), "the webhook delivery is signed")
	host := hostPtrOf(notifications[1].WebhookUrl)
	require.NotNil(t, host)
	assert.Equal(t, "alerts.example.test", *host)

	// The Slack target carries an API token inline; nothing reads it, and the
	// notification has no webhook of its own.
	assert.True(t, isSet(notifications[2].ApiToken))
	assert.Nil(t, hostPtrOf(notifications[2].WebhookUrl))
	assert.False(t, isSet(notifications[2].WebhookSecret))
}

func TestDecodeGroupAlertsConfigMetricThreshold(t *testing.T) {
	var c admin.GroupAlertsConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"enabled": false,
		"eventTypeName": "OUTSIDE_METRIC_THRESHOLD",
		"id": "60d1d0b0e1b2c3d4e5f60011",
		"metricThreshold": {"metricName": "NORMALIZED_SYSTEM_CPU_USER", "mode": "AVERAGE", "operator": "GREATER_THAN", "threshold": 90.0, "units": "RAW"}
	}`), &c))

	require.NotNil(t, c.MetricThreshold)
	assert.Nil(t, c.Threshold, "only one of the two threshold shapes is ever populated")
	assert.Equal(t, "NORMALIZED_SYSTEM_CPU_USER", c.MetricThreshold.GetMetricName())
	assert.Equal(t, "GREATER_THAN", c.MetricThreshold.GetOperator())
	assert.InDelta(t, 90.0, c.MetricThreshold.GetThreshold(), 0.0001)
}

func TestDecodeGroupUserResponse(t *testing.T) {
	var u admin.GroupUserResponse
	require.NoError(t, json.Unmarshal([]byte(`{
		"country": "US",
		"createdAt": "2025-06-01T00:00:00Z",
		"id": "60d1d0b0e1b2c3d4e5f60012",
		"invitationCreatedAt": "2026-02-01T00:00:00Z",
		"invitationExpiresAt": "2026-03-01T00:00:00Z",
		"inviterUsername": "alice@example.test",
		"orgMembershipStatus": "PENDING",
		"roles": ["GROUP_OWNER"],
		"username": "carol@example.test"
	}`), &u))

	assert.Equal(t, "PENDING", u.OrgMembershipStatus)
	assert.Equal(t, []string{"GROUP_OWNER"}, u.Roles)
	assert.Nil(t, u.LastAuth, "a member who has never signed in reports no last authentication")
	require.NotNil(t, u.InvitationExpiresAt)
	assert.Equal(t, 2026, u.InvitationExpiresAt.UTC().Year())
}

func TestDecodeGroupInvitation(t *testing.T) {
	var i admin.GroupInvitation
	require.NoError(t, json.Unmarshal([]byte(`{
		"createdAt": "2026-02-01T00:00:00Z",
		"expiresAt": "2026-03-01T00:00:00Z",
		"groupId": "60d1d0b0e1b2c3d4e5f60013",
		"id": "60d1d0b0e1b2c3d4e5f60014",
		"inviterUsername": "alice@example.test",
		"roles": ["GROUP_DATA_ACCESS_ADMIN"],
		"username": "dave@example.test"
	}`), &i))

	assert.Equal(t, "dave@example.test", i.GetUsername())
	assert.Equal(t, []string{"GROUP_DATA_ACCESS_ADMIN"}, i.GetRoles())
	require.NotNil(t, i.ExpiresAt)
	assert.Equal(t, 3, int(i.ExpiresAt.UTC().Month()))
}

func TestDecodeTeamRole(t *testing.T) {
	var tr admin.TeamRole
	require.NoError(t, json.Unmarshal([]byte(`{"roleNames": ["GROUP_OWNER"], "teamId": "60d1d0b0e1b2c3d4e5f60015"}`), &tr))

	assert.Equal(t, "60d1d0b0e1b2c3d4e5f60015", tr.GetTeamId())
	assert.Equal(t, []string{"GROUP_OWNER"}, tr.GetRoleNames())
}

func TestDecodeMaintenanceWindowWaves(t *testing.T) {
	var w admin.GroupMaintenanceWindow
	require.NoError(t, json.Unmarshal([]byte(`{
		"autoDeferOnceEnabled": false,
		"dayOfWeek": 1,
		"hourOfDay": 3,
		"numberOfDeferrals": 0,
		"startASAP": false,
		"timeZoneId": "UTC",
		"waveAssignment": 3,
		"effectiveWaveAssignment": 1
	}`), &w))

	// A project whose organization derives waves from environment tags reports
	// a stored assignment that differs from the wave actually scheduled.
	require.NotNil(t, w.WaveAssignment)
	assert.Equal(t, 3, *w.WaveAssignment)
	require.NotNil(t, w.EffectiveWaveAssignment)
	assert.Equal(t, 1, *w.EffectiveWaveAssignment)

	// dayOfWeek 1 is Sunday, a real value that must not be confused with unset.
	require.NotNil(t, w.DayOfWeek)
	assert.Equal(t, 1, *w.DayOfWeek)
	require.NotNil(t, w.NumberOfDeferrals, "zero deferrals is a reading, not an absence")
	assert.Equal(t, 0, *w.NumberOfDeferrals)
}

func TestDecodeMaintenanceWindowWithoutWavesOrDayStaysNull(t *testing.T) {
	var w admin.GroupMaintenanceWindow
	require.NoError(t, json.Unmarshal([]byte(`{
		"hourOfDay": 0,
		"numberOfDeferrals": 0,
		"timeZoneId": "UTC",
		"waveAssignment": null
	}`), &w))

	assert.Nil(t, w.WaveAssignment, "a cleared or never-set wave stays null, not wave 0")
	assert.Nil(t, w.EffectiveWaveAssignment)
	assert.Nil(t, w.DayOfWeek, "a project without a configured window reports no day")
	require.NotNil(t, w.HourOfDay)
	assert.Equal(t, 0, *w.HourOfDay, "hour 0 is midnight, not an absence")

	assert.Nil(t, llx.IntDataPtr(w.WaveAssignment).Value)
	assert.Nil(t, llx.IntDataPtr(w.DayOfWeek).Value)
}
