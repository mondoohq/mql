// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dataunits formats byte counts, bit counts and bit rates for humans.
//
// Bytes scale by 1024 (1 KB = 1024 B). Bits and speeds scale by 1000
// (1 Kb = 1000 b, 1 Mbps = 1,000,000 bps).
package dataunits

import (
	"strconv"
)

// Number is any integer or floating point type accepted by the formatters.
type Number interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

// Option changes how a value is formatted.
type Option func(*config)

type config struct {
	decimals int
	space    bool
}

// WithDecimals sets the number of decimal places printed for scaled units
// (default 1). Negative values are treated as 0.
func WithDecimals(n int) Option {
	return func(c *config) { c.decimals = max(n, 0) }
}

// WithSpace sets whether a space separates the number and the unit
// (default true).
func WithSpace(space bool) Option {
	return func(c *config) { c.space = space }
}

var (
	byteUnits  = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
	bitUnits   = []string{"b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb"}
	speedUnits = []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps"}
)

// Bytes formats a number of bytes on base 1024, e.g. 13421772800 => "12.5 GB".
func Bytes[T Number](n T, opts ...Option) string {
	return format(float64(n), 1024, byteUnits, opts)
}

// Bits formats a number of bits on base 1000, e.g. 1500000 => "1.5 Mb".
func Bits[T Number](n T, opts ...Option) string {
	return format(float64(n), 1000, bitUnits, opts)
}

// Speed formats a rate in bits per second on base 1000, e.g. 1300000 => "1.3 Mbps".
func Speed[T Number](bitsPerSecond T, opts ...Option) string {
	return format(float64(bitsPerSecond), 1000, speedUnits, opts)
}

func format(v float64, base float64, units []string, opts []Option) string {
	cfg := config{decimals: 1, space: true}
	for _, opt := range opts {
		opt(&cfg)
	}

	negative := v < 0
	if negative {
		v = -v
	}

	unit := 0
	for v >= base && unit < len(units)-1 {
		v /= base
		unit++
	}

	num := formatNumber(v, unit, cfg.decimals)
	// Rounding can carry into the next unit: 1023.96 KB would print as "1024.0 KB".
	if unit < len(units)-1 {
		if rounded, _ := strconv.ParseFloat(num, 64); rounded >= base {
			v /= base
			unit++
			num = formatNumber(v, unit, cfg.decimals)
		}
	}

	// Don't print "-0.0" for values that round to zero.
	if negative {
		if rounded, _ := strconv.ParseFloat(num, 64); rounded != 0 {
			num = "-" + num
		}
	}

	if cfg.space {
		return num + " " + units[unit]
	}
	return num + units[unit]
}

// formatNumber prints whole values of the base unit without decimals
// ("512 B", not "512.0 B"), everything else with the configured decimals.
func formatNumber(v float64, unit int, decimals int) string {
	if unit == 0 && v == float64(int64(v)) {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', decimals, 64)
}
