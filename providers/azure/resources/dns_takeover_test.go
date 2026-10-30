// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestNormalizeDnsTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"App.AzureWebsites.NET.", "app.azurewebsites.net"},
		{"  app.azurewebsites.net  ", "app.azurewebsites.net"},
		{"app.azurewebsites.net", "app.azurewebsites.net"},
		{"", ""},
		{".", ""},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, normalizeDnsTarget(c.in), "input %q", c.in)
	}
}

func TestAzureServiceForHostname(t *testing.T) {
	t.Run("common services", func(t *testing.T) {
		cases := []struct{ host, want string }{
			{"contoso.azurewebsites.net", "App Service"},
			{"contoso.trafficmanager.net", "Traffic Manager"},
			{"contoso.azurefd.net", "Front Door"},
			{"contoso.azureedge.net", "CDN"},
			{"contoso.azure-api.net", "API Management"},
			{"contoso.azurecr.io", "Container Registry"},
			{"contoso.vault.azure.net", "Key Vault"},
			{"contoso.database.windows.net", "Azure SQL"},
			{"eastus.cloudapp.azure.com", "Public IP"},
			{"contoso.azurecontainerapps.io", "Container Apps"},
		}
		for _, c := range cases {
			assert.Equalf(t, c.want, azureServiceForHostname(c.host), "host %q", c.host)
		}
	})

	t.Run("longest suffix wins over the shared platform domain", func(t *testing.T) {
		// Both blob.core.windows.net and web.core.windows.net sit under
		// core.windows.net; the specific service must be reported.
		assert.Equal(t, "Storage (blob)", azureServiceForHostname("contoso.blob.core.windows.net"))
		assert.Equal(t, "Storage (static website)", azureServiceForHostname("contoso.web.core.windows.net"))
		assert.Equal(t, "Storage (Data Lake)", azureServiceForHostname("contoso.dfs.core.windows.net"))
		// scm.azurewebsites.net is longer than azurewebsites.net.
		assert.Equal(t, "App Service (SCM)", azureServiceForHostname("contoso.scm.azurewebsites.net"))
	})

	t.Run("suffix must land on a label boundary", func(t *testing.T) {
		// This is the check that keeps lookalike domains from being reported as
		// Azure resources: the string ends with the same characters but is a
		// different domain entirely.
		assert.Equal(t, "", azureServiceForHostname("notazurewebsites.net"))
		assert.Equal(t, "", azureServiceForHostname("evil-azurewebsites.net"))
		assert.Equal(t, "", azureServiceForHostname("myazurecr.io"))
	})

	t.Run("the bare suffix itself matches", func(t *testing.T) {
		assert.Equal(t, "App Service", azureServiceForHostname("azurewebsites.net"))
	})

	t.Run("non-Azure and empty hostnames", func(t *testing.T) {
		assert.Equal(t, "", azureServiceForHostname("example.com"))
		assert.Equal(t, "", azureServiceForHostname("contoso.cloudfront.net"))
		assert.Equal(t, "", azureServiceForHostname(""))
	})

	t.Run("case and trailing dot are normalized", func(t *testing.T) {
		assert.Equal(t, "App Service", azureServiceForHostname("Contoso.AzureWebsites.Net."))
	})
}

// TestCnameTargetFromSdkRecordSet drives the parser with a real
// armdns.RecordSetProperties put through the same convert.JsonToDict the
// production path uses, rather than a hand-built map.
//
// This is the test that was missing. The parser read "cnameRecord" while the
// SDK's marshaller emits "CNAMERecord", so cnameTarget and targetAzureService
// were empty on every DNS record in every subscription and a dangling-CNAME
// audit passed vacuously. A hand-built fixture agreed with the code and stayed
// green; only a round-trip through the SDK type can catch this, and only a
// round-trip will catch it again if Azure changes the casing.
func TestCnameTargetFromSdkRecordSet(t *testing.T) {
	t.Run("cname record", func(t *testing.T) {
		cname := "Contoso.AzureWebsites.NET."
		ttl := int64(300)
		props, err := convert.JsonToDict(&armdns.RecordSetProperties{
			TTL:         &ttl,
			CnameRecord: &armdns.CnameRecord{Cname: &cname},
		})
		require.NoError(t, err)

		// guard the premise: if the SDK ever lower-camel-cases this key, the
		// assertion below would pass for the wrong reason
		_, upper := props["CNAMERecord"]
		require.True(t, upper, "expected the SDK to marshal the key as CNAMERecord, got %v", props)

		assert.Equal(t, "contoso.azurewebsites.net", cnameTargetFromProperties(props))
		assert.Equal(t, "App Service", azureServiceForHostname(cnameTargetFromProperties(props)))
	})

	t.Run("alias record target resource", func(t *testing.T) {
		id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/trafficManagerProfiles/tm"
		props, err := convert.JsonToDict(&armdns.RecordSetProperties{
			TargetResource: &armdns.SubResource{ID: &id},
		})
		require.NoError(t, err)
		assert.Equal(t, id, targetResourceIDFromProperties(props))
	})

	t.Run("an A record has no cname target", func(t *testing.T) {
		ip := "10.0.0.1"
		props, err := convert.JsonToDict(&armdns.RecordSetProperties{
			ARecords: []*armdns.ARecord{{IPv4Address: &ip}},
		})
		require.NoError(t, err)
		assert.Equal(t, "", cnameTargetFromProperties(props))
	})
}

func TestDictValueFold(t *testing.T) {
	m := map[string]any{"CNAMERecord": "upper", "other": "lower"}
	assert.Equal(t, "upper", dictValueFold(m, "CNAMERecord"), "exact match")
	assert.Equal(t, "upper", dictValueFold(m, "cnameRecord"), "case-insensitive match")
	assert.Equal(t, "lower", dictValueFold(m, "OTHER"))
	assert.Nil(t, dictValueFold(m, "absent"))
	assert.Nil(t, dictValueFold(nil, "anything"))
}

func TestCnameTargetFromProperties(t *testing.T) {
	t.Run("cname record", func(t *testing.T) {
		props := map[string]any{
			"cnameRecord": map[string]any{"cname": "Contoso.AzureWebsites.NET."},
		}
		assert.Equal(t, "contoso.azurewebsites.net", cnameTargetFromProperties(props))
	})
	t.Run("non-cname record types yield nothing", func(t *testing.T) {
		props := map[string]any{
			"aRecords": []any{map[string]any{"ipv4Address": "10.0.0.1"}},
		}
		assert.Equal(t, "", cnameTargetFromProperties(props))
	})
	t.Run("malformed shapes are tolerated", func(t *testing.T) {
		assert.Equal(t, "", cnameTargetFromProperties(map[string]any{}))
		assert.Equal(t, "", cnameTargetFromProperties(map[string]any{"cnameRecord": "not-an-object"}))
		assert.Equal(t, "", cnameTargetFromProperties(map[string]any{"cnameRecord": map[string]any{}}))
		assert.Equal(t, "", cnameTargetFromProperties(map[string]any{"cnameRecord": map[string]any{"cname": 42}}))
		assert.Equal(t, "", cnameTargetFromProperties(nil))
	})
}

func TestTargetResourceIDFromProperties(t *testing.T) {
	t.Run("alias record", func(t *testing.T) {
		id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"
		props := map[string]any{"targetResource": map[string]any{"id": id}}
		assert.Equal(t, id, targetResourceIDFromProperties(props))
	})
	t.Run("ordinary record has no target resource", func(t *testing.T) {
		assert.Equal(t, "", targetResourceIDFromProperties(map[string]any{}))
		// Azure returns an empty object rather than omitting the key.
		assert.Equal(t, "", targetResourceIDFromProperties(map[string]any{"targetResource": map[string]any{}}))
		assert.Equal(t, "", targetResourceIDFromProperties(nil))
	})
}
