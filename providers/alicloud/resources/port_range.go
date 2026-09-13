// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"
)

const (
	// minPortNumber and maxPortNumber bound the ports a rule may name. Alibaba
	// Cloud writes a rule that matches every port as -1/-1, and the widest
	// explicit range it accepts is 1/65535.
	minPortNumber = int64(1)
	maxPortNumber = int64(65535)
)

// parsePortRange resolves an Alibaba Cloud port range into its numeric bounds.
//
// Security group rules and network ACL rules both write the range as
// "first/last", for example "22/22" or "1/65535". A rule that matches every
// port is written "-1/-1", which is the form a rule takes when its protocol
// carries no ports at all, and resolves here to the full 1 to 65535 span so a
// query asking whether a port is covered does not have to special-case it.
//
// The third return value reports whether the range resolved. A range that did
// not resolve leaves the numeric fields null rather than reporting a port the
// rule does not name.
func parsePortRange(portRange string) (int64, int64, bool) {
	s := strings.TrimSpace(portRange)
	if s == "" {
		return 0, 0, false
	}

	first, last, found := strings.Cut(s, "/")
	if !found {
		// A bare port stands for a range of one port.
		last = first
	}

	low, ok := parsePortNumber(first)
	if !ok {
		return 0, 0, false
	}
	high, ok := parsePortNumber(last)
	if !ok {
		return 0, 0, false
	}

	// -1 is only meaningful as the pair -1/-1. A range that names it on one
	// side alone is not a span this can resolve.
	if low == -1 && high == -1 {
		return minPortNumber, maxPortNumber, true
	}
	if low == -1 || high == -1 {
		return 0, 0, false
	}

	return low, high, true
}

// parsePortNumber reads one side of a port range. It accepts the ports a rule
// may name plus the -1 sentinel, and rejects anything outside that.
func parsePortNumber(s string) (int64, bool) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	if v == -1 {
		return -1, true
	}
	// 0 is not a port a rule can name, and neither is anything above 65535.
	if v < minPortNumber || v > maxPortNumber {
		return 0, false
	}
	return v, true
}

// portRangeBounds resolves a port range into the pointer pair the schema's
// fromPort and toPort fields are built from. Both are nil when the range did
// not resolve, which reports the fields as null.
func portRangeBounds(portRange string) (*int64, *int64) {
	low, high, ok := parsePortRange(portRange)
	if !ok {
		return nil, nil
	}
	return &low, &high
}
