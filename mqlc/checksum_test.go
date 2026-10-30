// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
)

func TestIfChecksumming(t *testing.T) {
	queries := []string{
		`
			a = "a"
			if(a == "a") {
				return [1,2,3]
			}
			return [4,5,6]
	`,
		`
			a = "b"
			if(a == "a") {
				return [1,2,3]
			}
			return [4,5,6]
	`,
		`
			a = "a"
			if(a == "a") {
				return [1,2,3,4]
			}
			return [4,5,6]
	`,
		`
			a = "a"
			if(a == "a") {
				return [1,2,3]
			}
			return [4,5,6,7]
	`,
		`
			a = "a"
			if(a == "a") {
				[1,2,3] == [1,2,3]
			} else if (a == "b") {
				[1,2,3] == [1,2,3]
			} else {
				[1,2,3] != [1,2,3]
			}
	`,
		`
			a = "a"
			if(a == "a") {
				[1,2,3] == [1,2,3]
			} else if (a == "c") {
				[1,2,3] == [1,2,3]
			} else {
				[1,2,3] != [1,2,3]
			}
	`,
		`
			a = "a"
			if(a == "a") {
				[1,2,3] == [1,2,3]
			} else if (a == "c") {
				[1,2,3] == [1,2,3,4]
			} else {
				[1,2,3] != [1,2,3]
			}
	`,
		`
			a = "a"
			if(a == "a") {
				[1,2,3] == [1,2,3]
			} else if (a == "c") {
				[1,2,3] == [1,2,3]
			} else {
				[1,2,3] != [1,2,3,4]
			}
	`,
	}

	checksums := map[string]struct{}{}

	for _, q := range queries {
		res, err := mqlc.Compile(q, nil, conf)
		require.Nil(t, err)
		require.NotNil(t, res)
		if res == nil {
			return
		}

		checksum := res.CodeV2.Checksums[res.CodeV2.TailRef(1<<32)]
		require.Equal(t, res.Labels.Labels[checksum], "if")
		checksums[checksum] = struct{}{}

		rechecksum := res.CodeV2.Blocks[0].LastChunk().ChecksumV2(1<<32, res.CodeV2)
		require.Equal(t, checksum, rechecksum)
	}

	require.Equal(t, len(checksums), len(queries))
}

func TestSwitchChecksumming(t *testing.T) {
	queries := []string{
		`
		switch {
		case 1 == 2:
			return [1,2,3];
		default:
			return [4,5,6];
		}
	`,
		`
		switch {
		case 1 == 2:
			return [1,2,3];
		case 1 == 1:
			return [1,2,3];
		default:
			return [4,5,6];
		}
	`,
		`
		switch {
		case 1 == 2:
			return [1,2,3,4];
		default:
			return [4,5,6];
		}
	`,
		`
		switch {
		case 1 == 2:
			return [1,2,3];
		default:
			return [4,5,6,7];
		}
	`,
	}

	checksums := map[string]struct{}{}

	for _, q := range queries {
		res, err := mqlc.Compile(q, nil, conf)
		require.Nil(t, err)
		require.NotNil(t, res)
		if res == nil {
			return
		}

		checksum := res.CodeV2.Checksums[res.CodeV2.TailRef(1<<32)]
		require.Equal(t, res.Labels.Labels[checksum], "switch")
		checksums[checksum] = struct{}{}

		rechecksum := res.CodeV2.Blocks[0].LastChunk().ChecksumV2(1<<32, res.CodeV2)
		require.Equal(t, checksum, rechecksum)
	}

	require.Equal(t, len(checksums), len(queries))
}
