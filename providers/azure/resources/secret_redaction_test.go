// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	aci "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// These tests assert on the SERIALIZED form, not on the struct fields, because
// serialization is what actually reaches MQL. A redaction that nils a field the
// marshaller does not emit would pass a struct-level assertion and still leak.

const (
	fakeStorageConnString = "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=SUPERSECRETKEY==;"
	fakeClientSecret      = "SUPERSECRETCLIENTSECRET"
	fakeRegistryPassword  = "SUPERSECRETREGISTRYPW"
	fakeSecureEnvValue    = "SUPERSECRETENVVALUE"
	fakeSecretVolumeData  = "SUPERSECRETVOLUMEDATA"
	fakeFileShareKey      = "SUPERSECRETSHAREKEY"
)

func TestRedactedRedisConfigurationDropsStorageCredentials(t *testing.T) {
	cfg := &armredis.CommonPropertiesRedisConfiguration{
		AofStorageConnectionString0: new(fakeStorageConnString + "aof0"),
		AofStorageConnectionString1: new(fakeStorageConnString + "aof1"),
		RdbStorageConnectionString:  new(fakeStorageConnString + "rdb"),
		RdbBackupEnabled:            new("true"),
		MaxmemoryPolicy:             new("allkeys-lru"),
	}

	dict, err := convert.JsonToDict(redactedRedisConfiguration(cfg))
	require.NoError(t, err)
	serialized := mustJSON(t, dict)

	assert.NotContains(t, serialized, "SUPERSECRETKEY",
		"the storage account key must not reach MQL")
	assert.NotContains(t, serialized, "AccountKey")

	// The audit signal has to survive the redaction, or the fix trades one
	// wrong answer for another.
	assert.Contains(t, serialized, "true", "rdbBackupEnabled is still reported")
	assert.Contains(t, serialized, "allkeys-lru")

	// The source is not mutated -- callers downstream still see the original.
	assert.Equal(t, fakeStorageConnString+"rdb", *cfg.RdbStorageConnectionString)

	assert.Nil(t, redactedRedisConfiguration(nil))
}

// TestRedactedRedisResourceDropsStorageCredentials covers the second, easier to
// miss leak: properties serializes the whole ResourceInfo, so redacting only
// the redisConfiguration field would have left the same secrets readable one
// field over.
func TestRedactedRedisResourceDropsStorageCredentials(t *testing.T) {
	cache := &armredis.ResourceInfo{
		Name: new("my-cache"),
		Properties: &armredis.Properties{
			RedisConfiguration: &armredis.CommonPropertiesRedisConfiguration{
				RdbStorageConnectionString: new(fakeStorageConnString),
			},
		},
	}

	dict, err := convert.JsonToDict(redactedRedisResource(cache))
	require.NoError(t, err)
	serialized := mustJSON(t, dict)

	assert.NotContains(t, serialized, "SUPERSECRETKEY")
	assert.Contains(t, serialized, "my-cache", "the rest of the record is untouched")

	// The copy must be deep enough that the caller's struct is unchanged; the
	// same *ResourceInfo is used afterwards to seed the resource's caches.
	require.NotNil(t, cache.Properties.RedisConfiguration.RdbStorageConnectionString)
	assert.Equal(t, fakeStorageConnString, *cache.Properties.RedisConfiguration.RdbStorageConnectionString)

	assert.Nil(t, redactedRedisResource(nil))

	// A cache with no properties must not panic.
	assert.NotNil(t, redactedRedisResource(&armredis.ResourceInfo{Name: new("bare")}))
}

func TestRedactedAuthSettingsDropsEveryProviderSecret(t *testing.T) {
	props := &web.SiteAuthSettingsProperties{
		Enabled:                      new(true),
		ClientID:                     new("client-id-is-not-a-secret"),
		ClientSecret:                 new(fakeClientSecret + "-aad"),
		FacebookAppSecret:            new(fakeClientSecret + "-fb"),
		GitHubClientSecret:           new(fakeClientSecret + "-gh"),
		GoogleClientSecret:           new(fakeClientSecret + "-goog"),
		MicrosoftAccountClientSecret: new(fakeClientSecret + "-msa"),
		TwitterConsumerSecret:        new(fakeClientSecret + "-tw"),
	}

	dict, err := convert.JsonToDict(redactedAuthSettings(props))
	require.NoError(t, err)
	serialized := mustJSON(t, dict)

	// One assertion per provider: a redaction that misses one is the whole bug.
	for _, suffix := range []string{"-aad", "-fb", "-gh", "-goog", "-msa", "-tw"} {
		assert.NotContains(t, serialized, fakeClientSecret+suffix,
			"secret %q must not reach MQL", suffix)
	}
	assert.NotContains(t, serialized, fakeClientSecret)

	// Everything that is not a secret is still reported: the resource exists to
	// say whether Easy Auth is on and how it is configured.
	assert.Contains(t, serialized, "client-id-is-not-a-secret")
	assert.Contains(t, serialized, "true")

	assert.Equal(t, fakeClientSecret+"-aad", *props.ClientSecret, "source not mutated")
	assert.Nil(t, redactedAuthSettings(nil))
}

// TestCreateRedisInstanceRawDataLeavesTheSourceAlone pins the guarantee at the
// level that actually matters to the caller.
//
// The redaction helpers copy before editing, but the function around them used
// to normalize a nil Properties by writing back through the caller's pointer.
// The caller keeps using that same *ResourceInfo afterwards to seed the
// resource's caches, behind an `if cache.Properties != nil` guard -- so filling
// the field in here quietly turned that guard into a read of an empty struct.
func TestCreateRedisInstanceRawDataLeavesTheSourceAlone(t *testing.T) {
	bare := &armredis.ResourceInfo{Name: new("no-properties")}

	_, err := createRedisInstanceRawData(azureTestRuntime(), bare)
	require.NoError(t, err)

	assert.Nil(t, bare.Properties,
		"a cache that arrived without properties must still have none afterwards")

	// The id is what keys the configuration sub-resource; a cache carrying a
	// configuration block and no id is rejected rather than given a colliding
	// cache key, so the fixture carries the id ARM always reports.
	withSecret := &armredis.ResourceInfo{
		ID:   new("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Cache/redis/has-properties"),
		Name: new("has-properties"),
		Properties: &armredis.Properties{
			RedisConfiguration: &armredis.CommonPropertiesRedisConfiguration{
				RdbStorageConnectionString: new(fakeStorageConnString),
			},
		},
	}

	args, err := createRedisInstanceRawData(azureTestRuntime(), withSecret)
	require.NoError(t, err)

	// The secret is gone from both fields it used to reach.
	for _, field := range []string{"properties", "redisConfiguration"} {
		require.Contains(t, args, field)
		assert.NotContains(t, mustJSON(t, args[field].Value), "SUPERSECRETKEY",
			"%s must not carry the storage credential", field)
	}

	// ...and still present on the caller's own struct.
	require.NotNil(t, withSecret.Properties.RedisConfiguration.RdbStorageConnectionString)
	assert.Equal(t, fakeStorageConnString,
		*withSecret.Properties.RedisConfiguration.RdbStorageConnectionString)
}

func TestRedactedImageRegistryCredentialsDropsThePassword(t *testing.T) {
	creds := []*aci.ImageRegistryCredential{
		{
			Server:   new("myregistry.azurecr.io"),
			Username: new("pull-user"),
			Password: new(fakeRegistryPassword),
		},
		{
			Server:   new("identity.azurecr.io"),
			Identity: new("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/pull"),
		},
		nil,
	}

	dict, err := convert.JsonToDictSlice(redactedImageRegistryCredentials(creds))
	require.NoError(t, err)
	serialized := mustJSON(t, dict)

	assert.NotContains(t, serialized, fakeRegistryPassword,
		"the registry password must not reach MQL")

	// The audit signal has to survive: which registry a group pulls from, and
	// whether it authenticates with an identity rather than a password.
	assert.Contains(t, serialized, "myregistry.azurecr.io")
	assert.Contains(t, serialized, "pull-user", "the username is not a credential")
	assert.Contains(t, serialized, "userAssignedIdentities/pull",
		"the managed identity is what registryAuthUsesIdentity reads")

	// The source is not mutated: registryAuthUsesIdentity is computed from the
	// caller's own records after this runs.
	require.NotNil(t, creds[0].Password)
	assert.Equal(t, fakeRegistryPassword, *creds[0].Password)

	assert.Nil(t, redactedImageRegistryCredentials(nil))
}

// TestRedactedVolumesDropsSecretContentsAndShareKey covers two secrets in one
// field: a secret volume's file contents, and the storage account key that
// grants access to an entire Azure File share.
func TestRedactedVolumesDropsSecretContentsAndShareKey(t *testing.T) {
	volumes := []*aci.Volume{
		{
			Name: new("secrets"),
			Secret: map[string]*string{
				"app.key": new(fakeSecretVolumeData + "-app"),
				"tls.pem": new(fakeSecretVolumeData + "-tls"),
				"absent":  nil,
			},
		},
		{
			Name: new("share"),
			AzureFile: &aci.AzureFileVolume{
				ShareName:          new("data"),
				StorageAccountName: new("acct"),
				ReadOnly:           new(true),
				StorageAccountKey:  new(fakeFileShareKey),
			},
		},
		{
			Name:    new("repo"),
			GitRepo: &aci.GitRepoVolume{Repository: new("https://example.invalid/repo.git")},
		},
		nil,
	}

	dict, err := convert.JsonToDictSlice(redactedVolumes(volumes))
	require.NoError(t, err)
	serialized := mustJSON(t, dict)

	for _, suffix := range []string{"-app", "-tls"} {
		assert.NotContains(t, serialized, fakeSecretVolumeData+suffix,
			"secret volume contents %q must not reach MQL", suffix)
	}
	assert.NotContains(t, serialized, fakeSecretVolumeData)
	assert.NotContains(t, serialized, fakeFileShareKey,
		"the Azure File storage account key must not reach MQL")

	// The audit signal has to survive: which files a secret volume mounts, and
	// which share is mounted read-only from where.
	assert.Contains(t, serialized, "app.key", "the mounted file names are kept")
	assert.Contains(t, serialized, "tls.pem")
	assert.Contains(t, serialized, "data", "the share name is kept")
	assert.Contains(t, serialized, "acct", "the storage account name is kept")
	assert.Contains(t, serialized, "https://example.invalid/repo.git",
		"a git repo volume carries no credential and is untouched")

	// The source is not mutated: hasSecretVolume is computed from the caller's
	// own records after this runs.
	require.NotNil(t, volumes[0].Secret["app.key"])
	assert.Equal(t, fakeSecretVolumeData+"-app", *volumes[0].Secret["app.key"])
	require.NotNil(t, volumes[1].AzureFile.StorageAccountKey)
	assert.Equal(t, fakeFileShareKey, *volumes[1].AzureFile.StorageAccountKey)

	assert.Nil(t, redactedVolumes(nil))
}

func TestRedactedEnvironmentVariablesDropsTheSecureValue(t *testing.T) {
	env := []*aci.EnvironmentVariable{
		{Name: new("LOG_LEVEL"), Value: new("debug")},
		{Name: new("DB_PASSWORD"), SecureValue: new(fakeSecureEnvValue)},
		nil,
	}

	dict, err := convert.JsonToDictSlice(redactedEnvironmentVariables(env))
	require.NoError(t, err)
	serialized := mustJSON(t, dict)

	assert.NotContains(t, serialized, fakeSecureEnvValue,
		"a secure environment value must not reach MQL")

	// The audit signal has to survive: which variables a container declares,
	// including the secure ones, and the plain values that are not credentials.
	assert.Contains(t, serialized, "DB_PASSWORD", "the variable name is kept")
	assert.Contains(t, serialized, "LOG_LEVEL")
	assert.Contains(t, serialized, "debug",
		"a plain value is not secure by declaration and is kept")

	require.NotNil(t, env[1].SecureValue)
	assert.Equal(t, fakeSecureEnvValue, *env[1].SecureValue, "source not mutated")

	assert.Nil(t, redactedEnvironmentVariables(nil))
}

// mustJSON serializes exactly as the value will reach MQL. It deliberately does
// NOT normalize case: the assertions below search for upper-case secret
// markers, and lower-casing here would make every NotContains unfalsifiable.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}
