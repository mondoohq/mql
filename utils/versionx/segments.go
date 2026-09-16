// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versionx

import "strings"

// compareRelease orders the numeric-ish core of two versions (everything before the
// first '-'). Components split on '.', and a missing trailing component counts as 0 so
// that 1.2 and 1.2.0 are the same version — the semver reading, and the only one that
// keeps a fleet's mixed-precision strings ("1.2" next to "1.2.0") from sorting apart.
//
// There is no cap on component count: four- and five-component versions (Chrome's
// 126.0.6478.126, a Windows driver's 4.40.0.0) are ordinary here, not a parse failure
// to be lexically guessed at.
func compareRelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")

	n := max(len(as), len(bs))
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if c := compareRuns(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareRuns orders two strings as alternating runs of digits and non-digits: 425.13
// beats 425.3 because 13 > 3 numerically, and 1.1.1k beats 1.1.1f because k > f
// lexically. This is the natural-order compare every packaging scheme converges on
// once its own grammar stops applying.
//
// Three rules resolve the mixed cases:
//
//   - A run starting with '~' sorts before everything, including the absence of a run.
//     That is Debian's pre-release marker: 1.0~rc1 < 1.0 < 1.0a.
//   - A digit run outranks a letter run at the same position (rpm's rule). The versions
//     where this fires are already outside any single scheme's grammar; what matters is
//     that the answer is stable.
//   - When one side runs out, the longer one wins — 1.1.1k > 1.1.1 — unless its next
//     run is a '~' run, which is the first rule again.
func compareRuns(a, b string) int {
	ra, rb := splitRuns(a), splitRuns(b)

	for i := 0; i < len(ra) && i < len(rb); i++ {
		x, y := ra[i], rb[i]
		if x == y {
			continue
		}

		xt, yt := isTilde(x), isTilde(y)
		if xt != yt {
			if xt {
				return -1
			}
			return 1
		}

		xn, yn := isDigits(x), isDigits(y)
		switch {
		case xn && yn:
			if c := compareNumeric(x, y); c != 0 {
				return c
			}
		case xn != yn:
			// One numeric, one not: the numeric side is the higher one.
			if xn {
				return 1
			}
			return -1
		default:
			// Two letter runs. A release-stage word ("beta", "rc") carries an
			// order the alphabet does not — "rc" follows "beta", and both
			// precede a distro build id — so the stage scale decides first and
			// lexical order only breaks ties within a tier. Runs that are not
			// stage words both rank rankRelease and compare as text, which is
			// the behavior every non-PEP-440 string keeps.
			if rx, ry := markerRank(x), markerRank(y); rx != ry {
				if rx < ry {
					return -1
				}
				return 1
			}
			return strings.Compare(x, y)
		}
	}

	switch {
	case len(ra) == len(rb):
		return 0
	case len(ra) < len(rb):
		return -extraRunOrder(rb[len(ra)])
	default:
		return extraRunOrder(ra[len(rb)])
	}
}

// compareNumeric orders two digit runs by value, without converting them: version
// components are unbounded in principle (a date-stamped build is 8 digits, a CI counter
// can be longer), and strconv would have to decide what to do with an overflow.
// Stripping leading zeros makes length the primary key and the digits the tiebreak.
func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// splitRuns cuts a string at every digit/non-digit boundary. "1ubuntu4.6" becomes
// ["1", "ubuntu", "4", ".", "6"], so the separators travel with the letter runs and
// never need their own vocabulary — '.', '-', '_' and '~' all just fall out.
func splitRuns(s string) []string {
	if s == "" {
		return nil
	}

	out := make([]string, 0, 8)
	start := 0
	digits := isDigit(s[0])
	for i := 1; i < len(s); i++ {
		d := isDigit(s[i])
		if d != digits {
			out = append(out, s[start:i])
			start, digits = i, d
		}
	}
	return append(out, s[start:])
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isDigits(s string) bool { return s != "" && isDigit(s[0]) }

// isTilde reports whether a run opens with Debian's pre-release marker. Only the
// leading character matters: "~rc" and "~" are both markers, "a~b" is not one.
func isTilde(s string) bool { return s != "" && s[0] == '~' }

// extraRunOrder reports how a string that keeps going compares against one that has
// run out, by looking at the first run it has left over.
//
// The default is that more is newer — "1.1.1k" is a later release than "1.1.1" — and
// two things override it. A '~' run is Debian's pre-release marker and sorts before
// everything, including the absence of a run. A prerelease-stage word does the same for
// the attached spelling that PEP 440 and several upstreams use, where the marker hangs
// straight off the number: "3.7.0beta2" and "1.0rc1" are candidates for 3.7.0 and 1.0,
// not builds on top of them.
//
// A post-release word is NOT an override: "1.0post1" really does follow 1.0, which is
// what the default already says.
func extraRunOrder(extra string) int {
	if isTilde(extra) {
		return -1
	}
	if markerRank(extra) < rankRelease {
		return -1
	}
	return 1
}
