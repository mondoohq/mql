// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
)

// initAuth0Guardian reads the tenant-wide multi-factor authentication policy and
// the set of enabled MFA factors. It is queried directly (auth0.guardian); its
// cache key is the tenant domain, since there is exactly one Guardian
// configuration per tenant.
func initAuth0Guardian(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	client := conn.Client()
	ctx := context.Background()

	factors, err := client.Guardian.MultiFactor.List(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Map each factor's enabled state by its Guardian factor name. Factors the
	// API does not return default to false so a disabled factor never reads null.
	enabled := map[string]bool{}
	for _, f := range factors {
		if f == nil || f.Name == nil {
			continue
		}
		enabled[*f.Name] = f.Enabled != nil && *f.Enabled
	}

	policy := "never"
	pols, err := client.Guardian.MultiFactor.Policy(ctx)
	if err != nil {
		return nil, nil, err
	}
	if pols != nil {
		for _, p := range *pols {
			if p == "all-applications" || p == "confidence-score" {
				policy = p
				break
			}
		}
	}

	// WebAuthn user-verification settings live behind separate endpoints and
	// return an error when the factor is not configured; tolerate that and leave
	// the field empty rather than failing the whole resource.
	var platformUV, roamingUV *string
	if s, err := client.Guardian.MultiFactor.WebAuthnPlatform.Read(ctx); err == nil && s != nil {
		platformUV = s.UserVerification
	} else if err != nil {
		log.Debug().Err(err).Msg("auth0> unable to read webauthn-platform settings")
	}
	if s, err := client.Guardian.MultiFactor.WebAuthnRoaming.Read(ctx); err == nil && s != nil {
		roamingUV = s.UserVerification
	} else if err != nil {
		log.Debug().Err(err).Msg("auth0> unable to read webauthn-roaming settings")
	}

	args["__id"] = llx.StringData(conn.Domain())
	args["policy"] = llx.StringData(policy)
	args["otpEnabled"] = llx.BoolData(enabled["otp"])
	args["webAuthnPlatformEnabled"] = llx.BoolData(enabled["webauthn-platform"])
	args["webAuthnRoamingEnabled"] = llx.BoolData(enabled["webauthn-roaming"])
	args["pushEnabled"] = llx.BoolData(enabled["push-notification"])
	args["duoEnabled"] = llx.BoolData(enabled["duo"])
	args["phoneEnabled"] = llx.BoolData(enabled["sms"])
	args["emailEnabled"] = llx.BoolData(enabled["email"])
	args["recoveryCodeEnabled"] = llx.BoolData(enabled["recovery-code"])
	args["webAuthnPlatformUserVerification"] = llx.StringDataPtr(platformUV)
	args["webAuthnRoamingUserVerification"] = llx.StringDataPtr(roamingUV)
	return args, nil, nil
}
