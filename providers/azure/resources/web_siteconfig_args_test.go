// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

var siteConfigFields = []string{
	"minTlsVersion", "ftpsState", "remoteDebuggingEnabled", "http20Enabled", "alwaysOn",
	"webSocketsEnabled", "httpLoggingEnabled", "detailedErrorLoggingEnabled", "autoHealEnabled",
	"minTlsCipherSuite", "scmMinTlsVersion",
}

// Azure omits minTlsCipherSuite (and the other enum fields) for an app that
// never configured them. A field left out of the args is never set on the
// resource, so every one must be present, as null when Azure has no value.
func TestAddSiteConfigArgsSetsEveryField(t *testing.T) {
	for name, props := range map[string]*web.SiteConfig{
		"no properties":    nil,
		"nothing reported": {},
	} {
		t.Run(name, func(t *testing.T) {
			args := map[string]*llx.RawData{}
			addSiteConfigArgs(args, props)
			for _, f := range siteConfigFields {
				require.Contains(t, args, f)
				require.Nil(t, args[f].Value, f)
			}
		})
	}

	t.Run("values reported", func(t *testing.T) {
		suite := web.TLSCipherSuitesTLSAES128GCMSHA256
		tls := web.SupportedTLSVersionsOne2
		args := map[string]*llx.RawData{}
		addSiteConfigArgs(args, &web.SiteConfig{MinTLSCipherSuite: &suite, MinTLSVersion: &tls})
		require.Equal(t, string(suite), args["minTlsCipherSuite"].Value)
		require.Equal(t, "1.2", args["minTlsVersion"].Value)
		require.Nil(t, args["ftpsState"].Value)
	})
}
