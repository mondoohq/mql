// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb

// BindAddresses returns the addresses the server listens on for the given
// configuration and server version.
//
// net.bindIpAll binds every IPv4 address, plus every IPv6 address with
// net.ipv6, whatever net.bindIp says. Otherwise the listed bindIp addresses
// apply, and with none listed the version's default (see DefaultBindIp). It
// returns nil when the answer depends on a version that is unknown.
func BindAddresses(params map[string]any, version string) []string {
	ipv6 := Bool(params, false, "net", "ipv6")
	if Bool(params, false, "net", "bindIpAll") {
		if ipv6 {
			return []string{"0.0.0.0", "::"}
		}
		return []string{"0.0.0.0"}
	}
	if addrs := List(params, "net", "bindIp"); len(addrs) > 0 {
		return addrs
	}
	return DefaultBindIp(version, ipv6)
}

// DefaultAuthenticationMechanisms returns the mechanisms the server accepts
// when setParameter.authenticationMechanisms is unset, in the order
// getParameter reports them.
//
// 3.0 through 3.6 accept MONGODB-CR, MONGODB-X509 and SCRAM-SHA-1. 4.0
// removed MONGODB-CR and added SCRAM-SHA-256. From 8.3 on, a server in TLS
// FIPS mode leaves SCRAM-SHA-1 out. It returns nil for an unknown version,
// and for versions before 3.0, whose default is not verified.
func DefaultAuthenticationMechanisms(version string, fipsMode bool) []string {
	major, minor, ok := majorMinor(version)
	if !ok || major < 3 {
		return nil
	}
	if major == 3 {
		return []string{"MONGODB-CR", "MONGODB-X509", "SCRAM-SHA-1"}
	}
	if fipsMode && (major > 8 || (major == 8 && minor >= 3)) {
		return []string{"MONGODB-X509", "SCRAM-SHA-256"}
	}
	return []string{"MONGODB-X509", "SCRAM-SHA-1", "SCRAM-SHA-256"}
}

// DefaultScramIterationCount returns the SCRAM-SHA-1 iteration count the
// server uses when setParameter.scramIterationCount is unset: 10000 in every
// version that has the parameter (15000 is scramSHA256IterationCount). An
// unknown version still gets 10000. Before 3.0 there is no SCRAM and no such
// parameter, so it reports false.
func DefaultScramIterationCount(version string) (int64, bool) {
	if major, _, ok := majorMinor(version); ok && major < 3 {
		return 0, false
	}
	return 10000, true
}
