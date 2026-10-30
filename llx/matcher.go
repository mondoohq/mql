// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"regexp"

	"go.mondoo.com/mql/types"
)

func falseMatcher(s string) bool {
	return false
}

// StringOrRegexMatcher uses an input term, as rawdata, to create
// a matcher that can be used against strings. This is useful when
// you have create function that takes an argument that is meant to
// be used as a matcher or filter against a string.
//
// For example:
//
//	myresource.list( nameFilter )
//
// In this example, nameFilter is the term, specified by a user,
// which can be a string or a regex. We return a matcher function you
// can now use against any string to see if it satisfies the criteria.
//
// Returns nil, nil if term == nil
// In all other cases you will get either a matcher or an error.
func StringOrRegexMatcher(term *RawData) (func(string) bool, error) {
	if term == nil || term.Type == types.Nil {
		return nil, nil
	}

	if term.Value == nil {
		return falseMatcher, nil
	}

	switch term.Type {
	case types.Regex:
		v, ok := term.Value.(string)
		if !ok {
			return nil, errors.New("incorrect value for a regex: " + term.String())
		}
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, errors.New("invalid regex: /" + v + "/")
		}
		return func(in string) bool {
			return re.MatchString(in)
		}, nil

	case types.String, types.Dict:
		v, ok := term.Value.(string)
		if !ok {
			return nil, errors.New("not a valid string: " + term.String())
		}
		return func(in string) bool {
			return in == v
		}, nil

	default:
		return nil, errors.New("matcher must be a string or regex")
	}
}
