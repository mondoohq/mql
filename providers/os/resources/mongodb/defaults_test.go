// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/mongodb"
)

func parseTestdata(t *testing.T, name string) map[string]any {
	t.Helper()
	content, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	c, err := mongodb.ParseConf(string(content))
	require.NoError(t, err)
	return c.Params
}

// testdata/rhel-mongodb-org-8.0-mongod.conf is /etc/mongod.conf as the
// mongodb-org 8.0 RPM installs it. It sets neither authenticationMechanisms
// nor scramIterationCount, and the running 8.0.32 server (and 7.0.43 on
// RHEL 7) reports getParameter authenticationMechanisms
// [MONGODB-X509, SCRAM-SHA-1, SCRAM-SHA-256] and scramIterationCount 10000.
// Fails if the unset defaults go back to [] and 15000 (the SCRAM-SHA-256
// iteration default).
func TestServerDefaultsForStockRpmConfig(t *testing.T) {
	p := parseTestdata(t, "rhel-mongodb-org-8.0-mongod.conf")
	assert.Empty(t, mongodb.List(p, "setParameter", "authenticationMechanisms"))

	for _, version := range []string{"8.0.32", "7.0.43"} {
		assert.Equal(t, []string{"MONGODB-X509", "SCRAM-SHA-1", "SCRAM-SHA-256"},
			mongodb.DefaultAuthenticationMechanisms(version, false), version)
		n, ok := mongodb.DefaultScramIterationCount(version)
		assert.True(t, ok, version)
		assert.Equal(t, int64(10000), n, version)
	}
}

func TestDefaultAuthenticationMechanisms(t *testing.T) {
	for _, tc := range []struct {
		version string
		fips    bool
		want    []string
	}{
		// 3.0 through 3.6 (sasl_options.cpp): MONGODB-CR, MONGODB-X509, SCRAM-SHA-1
		{"3.0.15", false, []string{"MONGODB-CR", "MONGODB-X509", "SCRAM-SHA-1"}},
		{"3.6.3", false, []string{"MONGODB-CR", "MONGODB-X509", "SCRAM-SHA-1"}},
		// 4.0 removed MONGODB-CR and added SCRAM-SHA-256
		{"4.0.28", false, []string{"MONGODB-X509", "SCRAM-SHA-1", "SCRAM-SHA-256"}},
		{"8.0.32", true, []string{"MONGODB-X509", "SCRAM-SHA-1", "SCRAM-SHA-256"}},
		// 8.3 drops SCRAM-SHA-1 from the default in FIPS mode
		{"8.3.0", false, []string{"MONGODB-X509", "SCRAM-SHA-1", "SCRAM-SHA-256"}},
		{"8.3.0", true, []string{"MONGODB-X509", "SCRAM-SHA-256"}},
		{"9.0.0", true, []string{"MONGODB-X509", "SCRAM-SHA-256"}},
		// no verified default before 3.0, and none without a version
		{"2.6.10", false, nil},
		{"", false, nil},
		{"unknown", false, nil},
	} {
		assert.Equal(t, tc.want, mongodb.DefaultAuthenticationMechanisms(tc.version, tc.fips), "version %q fips %v", tc.version, tc.fips)
	}
}

func TestDefaultScramIterationCount(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    int64
		ok      bool
	}{
		{"3.0.15", 10000, true},
		{"4.0.28", 10000, true},
		// the default has been 10000 in every version that has the
		// parameter, so an unreadable version still has an answer
		{"", 10000, true},
		// 2.6 has no SCRAM and no such parameter
		{"2.6.10", 0, false},
	} {
		n, ok := mongodb.DefaultScramIterationCount(tc.version)
		assert.Equal(t, tc.ok, ok, tc.version)
		assert.Equal(t, tc.want, n, tc.version)
	}
}

// testdata/bindipall-mongod.conf is the sweep's non-compliant config: no
// bindIp, net.bindIpAll true. The running server's getCmdLineOpts reports
// net.bindIp "*" (every interface), so reporting the 127.0.0.1 default let
// `bindIp.none(_ == "0.0.0.0")` pass on a server listening everywhere.
// Fails if BindAddresses ignores bindIpAll.
func TestBindAddressesBindIpAll(t *testing.T) {
	p := parseTestdata(t, "bindipall-mongod.conf")
	assert.Empty(t, mongodb.List(p, "net", "bindIp"))
	assert.Equal(t, []string{"0.0.0.0"}, mongodb.BindAddresses(p, "8.0.32"))
	assert.Equal(t, []string{"0.0.0.0"}, mongodb.BindAddresses(p, ""))

	p["net"].(map[string]any)["ipv6"] = true
	assert.Equal(t, []string{"0.0.0.0", "::"}, mongodb.BindAddresses(p, "8.0.32"))
}

func TestBindAddresses(t *testing.T) {
	stock := parseTestdata(t, "rhel-mongodb-org-8.0-mongod.conf")
	assert.Equal(t, []string{"127.0.0.1"}, mongodb.BindAddresses(stock, "8.0.32"))

	unset := map[string]any{"net": map[string]any{"port": int64(27017)}}
	assert.Equal(t, []string{"127.0.0.1"}, mongodb.BindAddresses(unset, "8.0.32"))
	assert.Equal(t, []string{"0.0.0.0"}, mongodb.BindAddresses(unset, "3.4.24"))
	assert.Nil(t, mongodb.BindAddresses(unset, ""))

	off := map[string]any{"net": map[string]any{"bindIpAll": false}}
	assert.Equal(t, []string{"127.0.0.1"}, mongodb.BindAddresses(off, "8.0.32"))
}
