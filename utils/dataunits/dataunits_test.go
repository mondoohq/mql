// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dataunits_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/utils/dataunits"
)

func TestBytes(t *testing.T) {
	assert.Equal(t, "0 B", dataunits.Bytes(0))
	assert.Equal(t, "512 B", dataunits.Bytes(512))
	assert.Equal(t, "1023 B", dataunits.Bytes(1023))
	assert.Equal(t, "1.0 KB", dataunits.Bytes(1024))
	assert.Equal(t, "1.5 KB", dataunits.Bytes(1536))
	assert.Equal(t, "12.5 GB", dataunits.Bytes(int64(13421772800)))
	assert.Equal(t, "1.0 TB", dataunits.Bytes(uint64(1)<<40))
	assert.Equal(t, "16.0 EB", dataunits.Bytes(uint64(math.MaxUint64)))
	assert.Equal(t, "-1.5 KB", dataunits.Bytes(-1536))
	// 1048575 B is 1023.999 KB, which rounds up into the next unit
	assert.Equal(t, "1.0 MB", dataunits.Bytes(1048575))
	// beyond the largest unit, the value keeps growing instead of carrying
	assert.Equal(t, "1024.0 EB", dataunits.Bytes(math.Pow(1024, 7)))
}

func TestBits(t *testing.T) {
	assert.Equal(t, "999 b", dataunits.Bits(999))
	assert.Equal(t, "1.0 Kb", dataunits.Bits(1000))
	assert.Equal(t, "1.0 Kb", dataunits.Bits(1024))
	assert.Equal(t, "1.5 Mb", dataunits.Bits(1500000))
	assert.Equal(t, "1.0 Mb", dataunits.Bits(999999))
}

func TestSpeed(t *testing.T) {
	assert.Equal(t, "0 bps", dataunits.Speed(0))
	assert.Equal(t, "0.5 bps", dataunits.Speed(0.5))
	assert.Equal(t, "1.3 Mbps", dataunits.Speed(1300000))
	assert.Equal(t, "10.0 Gbps", dataunits.Speed(float32(1e10)))
	assert.Equal(t, "0.0 bps", dataunits.Speed(-0.01))
}

func TestOptions(t *testing.T) {
	assert.Equal(t, "12.5GB", dataunits.Bytes(13421772800, dataunits.WithSpace(false)))
	assert.Equal(t, "1.3Mbps", dataunits.Speed(1300000, dataunits.WithSpace(false)))
	assert.Equal(t, "1.46 KB", dataunits.Bytes(1500, dataunits.WithDecimals(2)))
	assert.Equal(t, "2 KB", dataunits.Bytes(1536, dataunits.WithDecimals(0)))
	assert.Equal(t, "2 KB", dataunits.Bytes(1536, dataunits.WithDecimals(-3)))
	assert.Equal(t, "512 B", dataunits.Bytes(512, dataunits.WithDecimals(3)))
	assert.Equal(t, "1.235Mb", dataunits.Bits(1234567, dataunits.WithDecimals(3), dataunits.WithSpace(false)))
	// with no decimals, 1023.6 KB rounds to "1024" and carries into MB
	assert.Equal(t, "1 MB", dataunits.Bytes(1023.6*1024, dataunits.WithDecimals(0)))
}
