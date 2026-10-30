// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms the OCI provider can emit: the
// tenancy root ("oci", an "api" platform) plus one entry per discoverable OCI
// object type. Each object is an "oci-object" running in the "oci" runtime and
// belongs to the "oci" family. This is the single source of truth for both the
// provider config (config.Config.Platforms) and the runtime platform builders.
var Platforms = []*plugin.PlatformInfo{
	{Name: "oci", Title: "Oracle Cloud Infrastructure", Family: []string{"oci"}, Kind: []string{"api"}, Runtime: []string{"oci"}},
	{Name: "oci-network-securitylist", Title: "OCI Network Security List", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-identity-user", Title: "OCI Identity User", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-identity-policy", Title: "OCI Identity Policy", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-objectstorage-bucket", Title: "OCI Object Storage Bucket", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-apigateway-deployment", Title: "OCI API Gateway Deployment", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-loadbalancer", Title: "OCI Load Balancer", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-redis-cluster", Title: "OCI Redis Cluster", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-vault-secret", Title: "OCI Vault Secret", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-oke-cluster", Title: "OCI OKE Cluster", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
	{Name: "oci-ai-generativeai-endpoint", Title: "OCI Generative AI Endpoint", Family: []string{"oci"}, Kind: []string{"oci-object"}, Runtime: []string{"oci"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static descriptor for a platform name, or nil if
// the name is not in the catalog.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
