// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cvss

import (
	"errors"
	fmt "fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

//go:generate protoc --plugin=protoc-gen-go=../../../../../scripts/protoc/protoc-gen-go --plugin=protoc-gen-go-vtproto=../../../../../scripts/protoc/protoc-gen-go-vtproto --proto_path=. --go_out=. --go_opt=paths=source_relative --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size cvss.proto
//go:generate go run golang.org/x/tools/cmd/stringer -type=Severity

var (
	Metrics   map[string][]string
	MetricsV4 map[string][]string
)

// 5.8/AV:N/AC:M/Au:N/C:P/I:P/A:N
func init() {
	// defines the valid metrics
	// CVSS v3 https://www.first.org/cvss/specification-document#2-Base-Metrics
	// CVSS v2 https://www.first.org/cvss/v2/guide
	Metrics = map[string][]string{
		// Version
		"CVSS": {"3.0", "3.1"},
		// Attack Vector
		"AV": {"N", "A", "L", "P"},
		// Attack Complexity
		"AC": {
			// CVSS 3.0
			"L", "H",
			// CVSS 2.0
			"M",
		},
		// Privileges Required
		"PR": {"N", "L", "H"},
		// User Interaction
		"UI": {"N", "R"},
		// Scope
		"S": {"U", "C"},
		// Confidentiality Impact
		"C": {
			// CVSS 3.0
			"H", "L", "N",
			// CVSS 2.0
			"P", "C",
		},
		//  Integrity Impact
		"I": {
			// CVSS 3.0
			"H", "L", "N",
			// CVSS 2.0
			"P", "C",
		},
		// Availability Impact
		"A": {
			// CVSS 3.0
			"H", "L", "N",
			// CVSS 2.0
			"P", "C",
		},
		// Exploit Code Maturity
		"E": {
			// CVSS 3.0
			"X", "H", "F", "P", "U",
			// CVSS 2.0
			"POC", "ND",
		},
		// Remediation Level
		"RL": {
			// CVSS 3.0
			"X", "U", "W", "T", "O",
			// CVSS 2.0
			"OF", "TF", "ND",
		},
		// Report Confidence
		"RC": {
			// CVSS 3.0
			"X", "C", "R", "U",
			// CVSS 2.0
			"UC", "UR", "ND",
		},
		// Confidentiality Requirement
		"CR": {
			// CVSS 3.0
			"X", "H", "M", "L",
			// CVSS 2.0
			"ND",
		},
		// Integrity Req
		"IR": {
			// CVSS 3.0
			"X", "H", "M", "L",
			// CVSS 2.0
			"ND",
		},
		// Availability Req
		"AR": {
			// CVSS 3.0
			"X", "H", "M", "L",
			// CVSS 2.0
			"ND",
		},

		// Authentication, CVSS 2.0 only
		// https://www.first.org/cvss/v2/guide#2-1-3-Authentication-Au
		"AU": {
			"M", "S", "N",
		},
		// https://www.first.org/cvss/v2/guide#2-3-1-Collateral-Damage-Potential-CDP
		"CDP": {
			"N", "L", "LM", "MH", "H", "ND",
		},
		// https://www.first.org/cvss/v2/guide#2-3-2-Target-Distribution-TD
		"TD": {
			"M", "L", "M", "H", "ND",
		},

		// Modified Base Metrics (Non-mandatory)
		// Modified Attack Vector (MAV): [X, N, A, L, P]
		"MAV": {"X", "N", "A", "L", "P"},
		// Modified Attack Complexity (MAC): [X, L, H]
		"MAC": {"X", "L", "H"},
		// Modified Privileges Required (MPR): [X, N, L, H]
		"MPR": {"X", "N", "L", "H"},
		// Modified User Interaction (MUI): [X, N, P, A]
		"MUI": {"X", "N", "R"},
		// Modified Scope (MS): [X, N, L, H]
		"MS": {"X", "U", "C"},
		// Modified Confidentiality (MC): [X, N, L, H]
		"MC": {"X", "N", "L", "H"},
		// Modified Integrity (MI): [X, N, L, H, S]
		"MI": {"X", "N", "L", "H"},
		// Modified Availability (MA): [X, N, L, H, S]
		"MA": {"X", "N", "L", "H"},
	}
	// MetricsV4 defines the valid CVSS 4.0 metrics and their allowed values.
	// CVSS v4 https://www.first.org/cvss/v4.0/specification-document
	// We use a separate map here because the metrics have diverged from v3 enough to
	// justify a new map.
	MetricsV4 = map[string][]string{
		// Version
		"CVSS": {"4.0"},
		// Base Metrics (Mandatory)
		// Attack Vector (AV): [N, A, L, P]
		"AV": {"N", "A", "L", "P"},
		// Attack Complexity (AC): [L, H]
		"AC": {"L", "H"},
		// Attack Requirements (AT): [N, P]
		"AT": {"N", "P"},
		// Privileges Required (PR): [N, L, H]
		"PR": {"N", "L", "H"},
		// User Interaction (UI): [N, P, A]
		"UI": {"N", "P", "A"},

		// Vulnerable System Impacts (Mandatory)
		// Vulnerable System Confidentiality Impact (VC): [H, L, N]
		"VC": {"H", "L", "N"},
		// Vulnerable System Integrity Impact (VI): [H, L, N]
		"VI": {"H", "L", "N"},
		// Vulnerable System Availability Impact (VA): [H, L, N]
		"VA": {"H", "L", "N"},

		// Subsequent System Impacts (Mandatory)
		// Subsequent System Confidentiality Impact (SC): [H, L, N]
		"SC": {"H", "L", "N"},
		// Subsequent System Integrity Impact (SI): [H, L, N]
		"SI": {"H", "L", "N"},
		// Subsequent System Availability Impact (SA): [H, L, N]
		"SA": {"H", "L", "N"},

		// Threat Metrics (Non-mandatory)
		// Exploit Maturity (E): [X, A, P, U]
		"E": {"X", "A", "P", "U"},

		// Environmental Metrics (Non-mandatory)
		// Confidentiality Requirement (CR): [X, H, M, L]
		"CR": {"X", "H", "M", "L"},
		// Integrity Requirement (IR): [X, H, M, L]
		"IR": {"X", "H", "M", "L"},
		// Availability Requirement (AR): [X, H, M, L]
		"AR": {"X", "H", "M", "L"},

		// Modified Base Metrics (Non-mandatory)
		// Modified Attack Vector (MAV): [X, N, A, L, P]
		"MAV": {"X", "N", "A", "L", "P"},
		// Modified Attack Complexity (MAC): [X, L, H]
		"MAC": {"X", "L", "H"},
		// Modified Attack Requirements (MAT): [X, N, P]
		"MAT": {"X", "N", "P"},
		// Modified Privileges Required (MPR): [X, N, L, H]
		"MPR": {"X", "N", "L", "H"},
		// Modified User Interaction (MUI): [X, N, P, A]
		"MUI": {"X", "N", "P", "A"},
		// Modified Vulnerable System Confidentiality (MVC): [X, N, L, H]
		"MVC": {"X", "N", "L", "H"},
		// Modified Vulnerable System Integrity (MVI): [X, N, L, H]
		"MVI": {"X", "N", "L", "H"},
		// Modified Vulnerable System Availability (MVA): [X, N, L, H]
		"MVA": {"X", "N", "L", "H"},
		// Modified Subsequent System Confidentiality (MSC): [X, N, L, H]
		"MSC": {"X", "N", "L", "H"},
		// Modified Subsequent System Integrity (MSI): [X, N, L, H, S]
		"MSI": {"X", "N", "L", "H", "S"},
		// Modified Subsequent System Availability (MSA): [X, N, L, H, S]
		"MSA": {"X", "N", "L", "H", "S"},

		// Supplemental Metrics (Non-mandatory)
		// Safety (S): [X, N, P]
		"S": {"X", "N", "P"},
		// Automatable (AU): [X, N, Y]
		"AU": {"X", "N", "Y"},
		// Recovery (R): [X, A, U, I]
		"R": {"X", "A", "U", "I"},
		// Value Density (V): [X, D, C]
		"V": {"X", "D", "C"},
		// Vulnerability Response Effort (RE): [X, L, M, H]
		"RE": {"X", "L", "M", "H"},
		// Provider Urgency (U): [X, Clear, Green, Amber, Red]
		"U": {"X", "CLEAR", "GREEN", "AMBER", "RED"},
	}
}

const NoneVector = "0.0/CVSS:3.0"

var CVSS_VERSION = regexp.MustCompile(`^(?:.*\/)?CVSS:([\d.]+)(?:\/.*)*$`)

func New(vector string) (*Cvss, error) {
	if len(vector) == 0 {
		return nil, errors.New("vector cannot be empty")
	}

	// trim whitespace
	vector = strings.TrimSpace(vector)

	c := &Cvss{Vector: vector}

	// ensure score field is set
	c.Score = c.DetermineScore()

	// check that the vector is parsable and the metrics are correct
	if !c.Verify() {
		return nil, errors.New("cvss vector is not parsable or valid: " + vector)
	}

	return c, nil
}

func (c *Cvss) Version() string {
	m := CVSS_VERSION.FindStringSubmatch(c.Vector)

	if len(m) == 2 {
		return m[1]
	} else {
		return "2.0"
	}
}

func (c *Cvss) DetermineScore() float32 {
	var err error
	vector := c.Vector
	pairs := strings.Split(vector, "/")

	var parsedScore float64
	if len(pairs) < 1 {
		// No score present, calculate from vector
		score, err := c.calculateScoreFromVector()
		if err != nil {
			return 0.0
		}
		parsedScore = score
	} else {
		// first entry includes the score
		if parsedScore, err = strconv.ParseFloat(pairs[0], 32); err != nil {
			// error handling, fallback to calculating score from vector
			score, err := c.calculateScoreFromVector()
			if err != nil {
				return 0.0
			}
			parsedScore = score
		}
	}

	c.Score = float32(parsedScore)
	return c.Score
}

func (c *Cvss) Metrics() (map[string]string, error) {
	values := make(map[string]string)

	vector := c.Vector
	pairs := strings.Split(vector, "/")

	if len(pairs) < 1 {
		return nil, errors.New("invalid cvss string: " + vector)
	}

	// parse the key values
	for i, entry := range pairs {
		// ignore first entry which is a score, do not save it here to avoid side-effects
		// functionality has moved ParseScore
		if i == 0 {
			continue
		}

		// likely an entry  with trailing slash (6.5/AV:N/AC:L/Au:S/C:P/I:P/A:P/), that is okay
		if len(entry) == 0 {
			continue
		}

		// split key value
		kv := strings.Split(entry, ":")
		if len(kv) < 2 {
			log.Debug().Str("vector", vector).Msg("could not parse vector properly")
		} else {
			values[strings.ToUpper(kv[0])] = strings.ToUpper(kv[1])
		}
	}

	return values, nil
}

// Severity converts the CVSS Score (0.0 - 10.0) as specified in CVSS v3.0
// specification (https://www.first.org/cvss/specification-document) table 14
// to qualitative severity rating scale
func (c *Cvss) Severity() Severity {
	return Rating(c.Score)
}

func (c *Cvss) Verify() bool {
	values, err := c.Metrics()
	if err != nil {
		return false
	}

	// If the version is 4.0, we need to use the new metrics
	version := c.Version()
	metrics := Metrics
	if version == "4.0" {
		metrics = MetricsV4
	}

	for k, v := range values {
		values, ok := metrics[k]
		if !ok {
			return false
		}
		if !slices.Contains(values, v) {
			return false
		}
	}
	return true
}

// Compare returns an integer comparing two cvss scores
// The result will be 0 if a==b, -1 if a < b, and +1 if a > b
func (c *Cvss) Compare(d *Cvss) int {
	if c.Score == d.Score {
		return 0
	} else if c.Score < d.Score {
		return -1
	} else {
		return 1
	}
}

func Rating(score float32) Severity {
	switch {
	case score == 0.0:
		return None
	case score > 0 && score < 4.0:
		return Low
	case score >= 4.0 && score < 7.0:
		return Medium
	case score >= 7.0 && score < 9.0:
		return High
	case score >= 9.0:
		return Critical
	}
	// negative numbers may be used for no-parsable cvss vectors
	return Unknown
}

// Severity defines the cvss v3 range
// in addition is defines an additional state unknown
// iota is sorted by criticality to ease easy int comparison to detect the severity with the
// highest criticality
type Severity int

const (
	Unknown  Severity = iota // could not be determined
	None                     // 0.0, e.g. mapped ubuntu negligible is mapped to none
	Low                      // 0.1 - 3.9
	Medium                   // 4.0 - 6.9
	High                     // 7.0 - 8.9
	Critical                 // 9.0 - 10.0
)

func MaxScore(cvsslist []*Cvss) (*Cvss, error) {
	none, _ := New(NoneVector)

	// no entry, no return :-)
	if len(cvsslist) == 0 {
		return none, nil
	}

	res := cvsslist[0]

	// easy, we just have one entry
	if len(cvsslist) == 1 {
		return res, nil
	}

	// fun starts, we need to compare cvss scores now
	max := res
	maxScore, err := New(max.Vector)
	if err != nil {
		return none, err
	}

	for i := 1; i < len(cvsslist); i++ {
		entry := cvsslist[i]
		if entry == nil {
			log.Warn().Msg("nil cvss entry found in list")
			continue
		}

		vector := entry.Vector
		score, err := New(vector)
		if err != nil {
			return none, err
		}

		if maxScore.Compare(score) < 0 {
			max = entry
			maxScore = score
		}
	}

	return max, nil
}

func (c *Cvss) calculateScoreFromVector() (float64, error) {
	version := c.Version()
	switch version {
	case "4.0":
		cvss40, err := gocvss40.ParseVector(c.Vector)
		if err != nil {
			return 0.0, err
		}
		return cvss40.Score(), nil
	case "3.0":
		cvss30, err := gocvss30.ParseVector(c.Vector)
		if err != nil {
			return 0.0, err
		}
		return cvss30.BaseScore(), nil
	case "3.1":
		cvss31, err := gocvss31.ParseVector(c.Vector)
		if err != nil {
			return 0.0, err
		}
		return cvss31.BaseScore(), nil
	case "2.0":
		cvss20, err := gocvss20.ParseVector(c.Vector)
		if err != nil {
			return 0.0, err
		}
		return cvss20.BaseScore(), nil
	default:
		return 0.0, fmt.Errorf("unsupported CVSS version: %s", version)
	}
}
