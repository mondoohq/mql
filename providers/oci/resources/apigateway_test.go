// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/apigateway"
	"github.com/stretchr/testify/assert"
)

// unknownAuthPolicy is a stand-in for a future SDK authentication type the
// deployment code hasn't mapped yet. Satisfies apigateway.AuthenticationPolicy.
type unknownAuthPolicy struct {
	anonymous *bool
}

func (u unknownAuthPolicy) GetIsAnonymousAccessAllowed() *bool { return u.anonymous }

func TestFlattenAuthenticationType(t *testing.T) {
	tests := []struct {
		name string
		rp   *apigateway.ApiSpecificationRequestPolicies
		want string
	}{
		{
			name: "nil policies returns NONE",
			rp:   nil,
			want: "NONE",
		},
		{
			name: "nil authentication returns NONE",
			rp:   &apigateway.ApiSpecificationRequestPolicies{},
			want: "NONE",
		},
		{
			name: "JWT maps to JWT_AUTHENTICATION",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: apigateway.JwtAuthenticationPolicy{},
			},
			want: "JWT_AUTHENTICATION",
		},
		{
			name: "Token maps to TOKEN_AUTHENTICATION",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: apigateway.TokenAuthenticationPolicy{},
			},
			want: "TOKEN_AUTHENTICATION",
		},
		{
			name: "Custom maps to CUSTOM_AUTHENTICATION",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: apigateway.CustomAuthenticationPolicy{},
			},
			want: "CUSTOM_AUTHENTICATION",
		},
		{
			name: "unknown SDK type maps to UNKNOWN",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: unknownAuthPolicy{},
			},
			want: "UNKNOWN",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, flattenAuthenticationType(tc.rp))
		})
	}
}

func TestFlattenIsAnonymousAccessAllowed(t *testing.T) {
	yes := true
	no := false
	tests := []struct {
		name string
		rp   *apigateway.ApiSpecificationRequestPolicies
		want bool
	}{
		// No authentication policy means nothing is enforced, so every
		// request reaches the backend unauthenticated.
		{"nil policies", nil, true},
		{"nil authentication", &apigateway.ApiSpecificationRequestPolicies{}, true},
		{
			name: "JWT with anonymous=true",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: apigateway.JwtAuthenticationPolicy{IsAnonymousAccessAllowed: &yes},
			},
			want: true,
		},
		{
			name: "JWT with anonymous=false",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: apigateway.JwtAuthenticationPolicy{IsAnonymousAccessAllowed: &no},
			},
			want: false,
		},
		{
			name: "JWT with unset anonymous flag",
			rp: &apigateway.ApiSpecificationRequestPolicies{
				Authentication: apigateway.JwtAuthenticationPolicy{},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, flattenIsAnonymousAccessAllowed(tc.rp))
		})
	}
}

func TestFlattenJwtAudiencesAndIssuers(t *testing.T) {
	t.Run("nil policies returns empty slices", func(t *testing.T) {
		assert.Equal(t, []any{}, flattenJwtAudiences(nil))
		assert.Equal(t, []any{}, flattenJwtIssuers(nil))
	})

	t.Run("non-JWT auth returns empty slices", func(t *testing.T) {
		rp := &apigateway.ApiSpecificationRequestPolicies{
			Authentication: apigateway.TokenAuthenticationPolicy{},
		}
		assert.Equal(t, []any{}, flattenJwtAudiences(rp))
		assert.Equal(t, []any{}, flattenJwtIssuers(rp))
	})

	t.Run("JWT populates both lists", func(t *testing.T) {
		rp := &apigateway.ApiSpecificationRequestPolicies{
			Authentication: apigateway.JwtAuthenticationPolicy{
				Audiences: []string{"aud-a", "aud-b"},
				Issuers:   []string{"https://issuer.example.com"},
			},
		}
		assert.Equal(t, []any{"aud-a", "aud-b"}, flattenJwtAudiences(rp))
		assert.Equal(t, []any{"https://issuer.example.com"}, flattenJwtIssuers(rp))
	})
}

func TestFlattenMutualTls(t *testing.T) {
	t.Run("nil policies yields (false, empty)", func(t *testing.T) {
		required, sans := flattenMutualTls(nil)
		assert.False(t, required)
		assert.Equal(t, []any{}, sans)
	})

	t.Run("nil mTLS block yields (false, empty)", func(t *testing.T) {
		required, sans := flattenMutualTls(&apigateway.ApiSpecificationRequestPolicies{})
		assert.False(t, required)
		assert.Equal(t, []any{}, sans)
	})

	t.Run("partial: required flag only", func(t *testing.T) {
		required, sans := flattenMutualTls(&apigateway.ApiSpecificationRequestPolicies{
			MutualTls: &apigateway.MutualTlsDetails{
				IsVerifiedCertificateRequired: new(true),
			},
		})
		assert.True(t, required)
		assert.Equal(t, []any{}, sans)
	})

	t.Run("partial: SANs only", func(t *testing.T) {
		required, sans := flattenMutualTls(&apigateway.ApiSpecificationRequestPolicies{
			MutualTls: &apigateway.MutualTlsDetails{
				AllowedSans: []string{"cn-one", "cn-two"},
			},
		})
		assert.False(t, required)
		assert.Equal(t, []any{"cn-one", "cn-two"}, sans)
	})

	t.Run("populated: both fields", func(t *testing.T) {
		required, sans := flattenMutualTls(&apigateway.ApiSpecificationRequestPolicies{
			MutualTls: &apigateway.MutualTlsDetails{
				IsVerifiedCertificateRequired: new(true),
				AllowedSans:                   []string{"client.example.com"},
			},
		})
		assert.True(t, required)
		assert.Equal(t, []any{"client.example.com"}, sans)
	})

	t.Run("required explicitly false is preserved", func(t *testing.T) {
		required, _ := flattenMutualTls(&apigateway.ApiSpecificationRequestPolicies{
			MutualTls: &apigateway.MutualTlsDetails{
				IsVerifiedCertificateRequired: new(false),
			},
		})
		assert.False(t, required)
	})
}

func TestFlattenCors(t *testing.T) {
	t.Run("nil policies yields (false, empty)", func(t *testing.T) {
		allow, origins := flattenCors(nil)
		assert.False(t, allow)
		assert.Equal(t, []any{}, origins)
	})

	t.Run("nil Cors block yields (false, empty)", func(t *testing.T) {
		allow, origins := flattenCors(&apigateway.ApiSpecificationRequestPolicies{})
		assert.False(t, allow)
		assert.Equal(t, []any{}, origins)
	})

	t.Run("populated", func(t *testing.T) {
		allow, origins := flattenCors(&apigateway.ApiSpecificationRequestPolicies{
			Cors: &apigateway.CorsPolicy{
				AllowedOrigins:            []string{"https://a.example.com", "https://b.example.com"},
				IsAllowCredentialsEnabled: new(true),
			},
		})
		assert.True(t, allow)
		assert.Equal(t, []any{"https://a.example.com", "https://b.example.com"}, origins)
	})

	t.Run("partial: origins without credentials flag defaults to false", func(t *testing.T) {
		allow, origins := flattenCors(&apigateway.ApiSpecificationRequestPolicies{
			Cors: &apigateway.CorsPolicy{
				AllowedOrigins: []string{"*"},
			},
		})
		assert.False(t, allow)
		assert.Equal(t, []any{"*"}, origins)
	})
}

func TestFlattenRateLimiting(t *testing.T) {
	t.Run("nil policies yields (0, empty)", func(t *testing.T) {
		rate, key := flattenRateLimiting(nil)
		assert.Equal(t, int64(0), rate)
		assert.Equal(t, "", key)
	})

	t.Run("nil rate-limiting block yields (0, empty)", func(t *testing.T) {
		rate, key := flattenRateLimiting(&apigateway.ApiSpecificationRequestPolicies{})
		assert.Equal(t, int64(0), rate)
		assert.Equal(t, "", key)
	})

	t.Run("populated", func(t *testing.T) {
		perSec := 500
		rate, key := flattenRateLimiting(&apigateway.ApiSpecificationRequestPolicies{
			RateLimiting: &apigateway.RateLimitingPolicy{
				RateInRequestsPerSecond: &perSec,
				RateKey:                 apigateway.RateLimitingPolicyRateKeyEnum("CLIENT_IP"),
			},
		})
		assert.Equal(t, int64(500), rate)
		assert.Equal(t, "CLIENT_IP", key)
	})

	t.Run("rate unset, key present", func(t *testing.T) {
		rate, key := flattenRateLimiting(&apigateway.ApiSpecificationRequestPolicies{
			RateLimiting: &apigateway.RateLimitingPolicy{
				RateKey: apigateway.RateLimitingPolicyRateKeyEnum("TOTAL"),
			},
		})
		assert.Equal(t, int64(0), rate)
		assert.Equal(t, "TOTAL", key)
	})
}

func TestHasDynamicAuthentication(t *testing.T) {
	t.Run("nil policies", func(t *testing.T) {
		assert.False(t, hasDynamicAuthentication(nil))
	})
	t.Run("nil dynamic authentication", func(t *testing.T) {
		assert.False(t, hasDynamicAuthentication(&apigateway.ApiSpecificationRequestPolicies{}))
	})
	t.Run("dynamic authentication configured", func(t *testing.T) {
		rp := &apigateway.ApiSpecificationRequestPolicies{
			DynamicAuthentication: &apigateway.DynamicAuthenticationPolicy{},
		}
		assert.True(t, hasDynamicAuthentication(rp))
	})
}
