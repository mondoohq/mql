// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strings"
)

// azureHostnameSuffixes maps the DNS suffixes Azure services hand out to the
// service that owns them. A CNAME pointing at one of these is pointing at an
// Azure-allocated hostname, and if no resource holds that name any more, whoever
// creates a resource with the same name inherits the record: a subdomain
// takeover.
//
// Suffixes overlap (blob.core.windows.net sits under core.windows.net), so
// lookup below matches the longest one first to report the specific service
// rather than the shared platform domain.
var azureHostnameSuffixes = map[string]string{
	"azurewebsites.net":             "App Service",
	"azurestaticapps.net":           "Static Web Apps",
	"azurefd.net":                   "Front Door",
	"azureedge.net":                 "CDN",
	"trafficmanager.net":            "Traffic Manager",
	"cloudapp.azure.com":            "Public IP",
	"cloudapp.net":                  "Cloud Services (classic)",
	"azure-api.net":                 "API Management",
	"azurecontainer.io":             "Container Instances",
	"azurecr.io":                    "Container Registry",
	"blob.core.windows.net":         "Storage (blob)",
	"queue.core.windows.net":        "Storage (queue)",
	"table.core.windows.net":        "Storage (table)",
	"file.core.windows.net":         "Storage (file)",
	"dfs.core.windows.net":          "Storage (Data Lake)",
	"web.core.windows.net":          "Storage (static website)",
	"redis.cache.windows.net":       "Azure Cache for Redis",
	"database.windows.net":          "Azure SQL",
	"mysql.database.azure.com":      "Azure Database for MySQL",
	"postgres.database.azure.com":   "Azure Database for PostgreSQL",
	"documents.azure.com":           "Cosmos DB",
	"servicebus.windows.net":        "Service Bus / Event Hubs",
	"search.windows.net":            "Azure AI Search",
	"vault.azure.net":               "Key Vault",
	"azurehdinsight.net":            "HDInsight",
	"azuredatabricks.net":           "Databricks",
	"kusto.windows.net":             "Data Explorer",
	"azconfig.io":                   "App Configuration",
	"service.signalr.net":           "SignalR",
	"webpubsub.azure.com":           "Web PubSub",
	"cognitiveservices.azure.com":   "Azure AI Services",
	"openai.azure.com":              "Azure OpenAI",
	"azurehealthcareapis.com":       "Health Data Services",
	"azuremicroservices.io":         "Spring Apps",
	"azurewebsites.windows.net":     "App Service (legacy)",
	"azureapiminternal.azure.com":   "API Management (internal)",
	"scm.azurewebsites.net":         "App Service (SCM)",
	"azurewebsites.us":              "App Service (US Gov)",
	"cloudapp.usgovcloudapi.net":    "Public IP (US Gov)",
	"blob.core.usgovcloudapi.net":   "Storage (blob, US Gov)",
	"database.usgovcloudapi.net":    "Azure SQL (US Gov)",
	"azurewebsites.de":              "App Service (Germany)",
	"blob.core.chinacloudapi.cn":    "Storage (blob, China)",
	"azurewebsites.cn":              "App Service (China)",
	"trafficmanager.cn":             "Traffic Manager (China)",
	"database.chinacloudapi.cn":     "Azure SQL (China)",
	"azurecontainerapps.io":         "Container Apps",
	"azurewebsites.net.cdn.net":     "CDN (legacy)",
	"blob.storage.azure.net":        "Storage (blob, alt endpoint)",
	"azuresynapse.net":              "Synapse",
	"azuredatafactory.net":          "Data Factory",
	"azuremlsdk.net":                "Machine Learning",
	"inference.ml.azure.com":        "Machine Learning (inference)",
	"azurewebsites.azurefd.net":     "App Service (via Front Door)",
	"azurewebsitesstaging.net":      "App Service (staging)",
	"privatelink.azurewebsites.net": "App Service (private endpoint)",
}

// sortedAzureHostnameSuffixes is the suffix list ordered longest first, so a
// lookup reports the most specific service. Built once at init because the map's
// iteration order is deliberately random.
var sortedAzureHostnameSuffixes = func() []string {
	suffixes := make([]string, 0, len(azureHostnameSuffixes))
	for s := range azureHostnameSuffixes {
		suffixes = append(suffixes, s)
	}
	sort.Slice(suffixes, func(i, j int) bool {
		if len(suffixes[i]) != len(suffixes[j]) {
			return len(suffixes[i]) > len(suffixes[j])
		}
		return suffixes[i] < suffixes[j]
	})
	return suffixes
}()

// normalizeDnsTarget lower-cases a DNS name and strips the trailing dot, so a
// CNAME target compares directly against the hostname fields Azure resources
// report (a web app's defaultHostName, a public IP's fqdn).
func normalizeDnsTarget(target string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
}

// azureServiceForHostname returns the Azure service that owns a hostname's DNS
// suffix, or "" when the hostname is not Azure-allocated.
//
// The suffix must sit on a label boundary: "contoso.azurewebsites.net" matches
// App Service, but "notazurewebsites.net" does not, even though it ends with the
// same characters. Without that check every lookalike domain would be reported
// as an Azure resource.
func azureServiceForHostname(hostname string) string {
	h := normalizeDnsTarget(hostname)
	if h == "" {
		return ""
	}
	for _, suffix := range sortedAzureHostnameSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return azureHostnameSuffixes[suffix]
		}
	}
	return ""
}

// cnameTargetFromProperties pulls the CNAME target out of a record set's
// properties, normalized. Returns "" for every record type other than CNAME.
//
// The key is matched case-insensitively because the armdns marshaller does not
// lower-camel-case it: RecordSetProperties.MarshalJSON writes "CNAMERecord"
// (likewise "ARecords", "MXRecords", "TXTRecords"). Reading "cnameRecord"
// matched nothing, so cnameTarget and targetAzureService were empty on every
// record in every subscription and a dangling-CNAME audit passed vacuously.
// Accepting either spelling keeps this working if the SDK ever normalizes.
func cnameTargetFromProperties(properties map[string]any) string {
	cname, ok := dictValueFold(properties, "CNAMERecord").(map[string]any)
	if !ok {
		return ""
	}
	target, ok := dictValueFold(cname, "cname").(string)
	if !ok {
		return ""
	}
	return normalizeDnsTarget(target)
}

// dictValueFold looks up key in m, ignoring case. Azure's generated marshallers
// are inconsistent about the casing of JSON keys, and a lookup that assumes one
// spelling fails silently -- it is indistinguishable from an absent value.
//
// An exact hit returns without scanning. Only a miss falls back to walking the
// map, which is O(n) in its size and deliberate: these are ARM property bags
// holding a handful of keys, so a case-folded map built per call would cost
// more than the scan it replaced.
func dictValueFold(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}

// targetResourceIDFromProperties pulls the ARM ID an alias record set tracks.
// Alias records are removed by Azure when their target resource is deleted, so a
// non-empty value here means the record cannot be left dangling.
func targetResourceIDFromProperties(properties map[string]any) string {
	target, ok := dictValueFold(properties, "targetResource").(map[string]any)
	if !ok {
		return ""
	}
	id, ok := dictValueFold(target, "id").(string)
	if !ok {
		return ""
	}
	return id
}
