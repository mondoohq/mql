// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dataunits formats byte counts, bit counts and bit rates for humans.
//
// Bytes scale by 1024 (1 KB = 1024 B). Bits and speeds scale by 1000
// (1 Kb = 1000 b, 1 Mbps = 1,000,000 bps).
package dataunits

import (
	"math"
	"strconv"
)

// Number is any integer or floating point type accepted by the formatters.
type Number interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

// Format controls how values are printed. Its zero value prints no decimal
// places and a space before the unit. The package-level Bytes, Bits and
// Speed use one decimal place.
type Format struct {
	// Decimals is the number of decimal places printed for scaled units.
	// Negative values are treated as 0.
	Decimals int
	// NoSpace removes the space between the number and the unit.
	NoSpace bool
}

var defaultFormat = Format{Decimals: 1}

var (
	byteUnits  = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
	bitUnits   = []string{"b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb"}
	speedUnits = []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps"}
)

// Bytes formats a number of bytes on base 1024 with one decimal place,
// e.g. 13421772800 => "12.5 GB".
func Bytes[T Number](n T) string {
	return defaultFormat.Bytes(float64(n))
}

// Bits formats a number of bits on base 1000 with one decimal place,
// e.g. 1500000 => "1.5 Mb".
func Bits[T Number](n T) string {
	return defaultFormat.Bits(float64(n))
}

// Speed formats a rate in bits per second on base 1000 with one decimal
// place, e.g. 1300000 => "1.3 Mbps".
func Speed[T Number](bitsPerSecond T) string {
	return defaultFormat.Speed(float64(bitsPerSecond))
}

// Bytes formats a number of bytes on base 1024.
func (f Format) Bytes(n float64) string {
	return f.format(n, 1024, byteUnits)
}

// Bits formats a number of bits on base 1000.
func (f Format) Bits(n float64) string {
	return f.format(n, 1000, bitUnits)
}

// Speed formats a rate in bits per second on base 1000.
func (f Format) Speed(bitsPerSecond float64) string {
	return f.format(bitsPerSecond, 1000, speedUnits)
}

func (f Format) format(v float64, base float64, units []string) string {
	// Fits every value below the largest unit at a sane number of decimals,
	// so the only allocation is the final string.
	var buf [32]byte
	return string(f.appendFormat(buf[:0], v, base, units))
}

func (f Format) appendFormat(dst []byte, v float64, base float64, units []string) []byte {
	decimals := max(f.Decimals, 0)

	start := len(dst)
	if v < 0 {
		dst = append(dst, '-')
		v = -v
	}
	numStart := len(dst)

	unit := 0
	for v >= base && unit < len(units)-1 {
		v /= base
		unit++
	}

	dst = appendNumber(dst, v, unit, decimals)
	// Rounding can carry into the next unit: 1023.96 KB would print as "1024.0 KB".
	if unit < len(units)-1 && integerPart(dst[numStart:]) >= int(base) {
		v /= base
		unit++
		dst = appendNumber(dst[:numStart], v, unit, decimals)
	}

	// Don't print "-0.0" for values that round to zero.
	if numStart > start && isZero(dst[numStart:]) {
		dst = append(dst[:start], dst[numStart:]...)
	}

	if !f.NoSpace {
		dst = append(dst, ' ')
	}
	return append(dst, units[unit]...)
}

// appendNumber prints whole values of the base unit without decimals
// ("512 B", not "512.0 B"), everything else with the given decimals.
func appendNumber(dst []byte, v float64, unit int, decimals int) []byte {
	if unit == 0 && v == math.Trunc(v) {
		return strconv.AppendFloat(dst, v, 'f', 0, 64)
	}
	return strconv.AppendFloat(dst, v, 'f', decimals, 64)
}

// integerPart reads the digits before the decimal point of a formatted
// number. Only called below the largest unit, where it has at most 4 digits.
func integerPart(num []byte) int {
	n := 0
	for _, c := range num {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func isZero(num []byte) bool {
	for _, c := range num {
		if c != '0' && c != '.' {
			return false
		}
	}
	return true
}
