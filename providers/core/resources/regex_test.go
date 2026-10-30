// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

var emojiTestString = []rune("☀⛺➿🌀🎂👍🔒😀🙈🚵🛼🤌🤣🥳🧡🧿🩰🫖")

func TestRegex_Methods(t *testing.T) {
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "'hello bob'.find(/he\\w*\\s?[bo]+/)",
			ResultIndex: 0,
			Expectation: []any{"hello bob"},
		},
		{
			Code:        "'HellO'.find(/hello/i)",
			ResultIndex: 0,
			Expectation: []any{"HellO"},
		},
		{
			Code:        "'hello\nworld'.find(/hello.world/s)",
			ResultIndex: 0,
			Expectation: []any{"hello\nworld"},
		},
		{
			Code:        "'yo! hello\nto the world'.find(/\\w+$/m)",
			ResultIndex: 0,
			Expectation: []any{"hello", "world"},
		},
		{
			Code:        "'IPv4: 0.0.0.0, 255.255.255.255, 1.50.120.230, 256.0.0.0 '.find(regex.ipv4)",
			ResultIndex: 0,
			Expectation: []any{"0.0.0.0", "255.255.255.255", "1.50.120.230"},
		},
		{
			Code:        "'IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334'.find(regex.ipv6)",
			ResultIndex: 0,
			Expectation: []any{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		},
		{
			Code:        "'Sarah Summers <sarah@summe.rs>'.find( regex.email )",
			ResultIndex: 0,
			Expectation: []any{"sarah@summe.rs"},
		},
		{
			Code:        "'one+1@sum.me.rs:'.find( regex.email )",
			ResultIndex: 0,
			Expectation: []any{"one+1@sum.me.rs"},
		},
		{
			Code:        "'Urls: http://mondoo.com/welcome'.find( regex.url )",
			ResultIndex: 0,
			Expectation: []any{"http://mondoo.com/welcome"},
		},
		{
			Code:        "'mac 01:23:45:67:89:ab attack'.find(regex.mac)",
			ResultIndex: 0,
			Expectation: []any{"01:23:45:67:89:ab"},
		},
		{
			Code:        "'uuid: b7f99555-5bca-48f4-b86f-a953a4883383.'.find(regex.uuid)",
			ResultIndex: 0,
			Expectation: []any{"b7f99555-5bca-48f4-b86f-a953a4883383"},
		},
		{
			Code:        "'some ⮆" + string(emojiTestString) + " ⮄ emojis'.find(regex.emoji).length",
			ResultIndex: 0, Expectation: int64(len(emojiTestString)),
		},
		{
			Code:        "'semvers: 1, 1.2, 1.2.3, 1.2.3-4'.find(regex.semver)",
			ResultIndex: 0,
			Expectation: []any{"1.2.3", "1.2.3-4"},
		},
	})
}
