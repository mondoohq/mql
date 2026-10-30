// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"
)

func TestParseKeySetStatement(t *testing.T) {
	cases := []struct {
		name      string
		statement string
		wantUser  string
		wantSlot  int
		wantOK    bool
	}{
		{
			// Verbatim shape from ACCOUNT_USAGE on a live account, after the
			// projection redacts the key material.
			"alter user sets the primary key",
			"ALTER USER tas50 SET RSA_PUBLIC_KEY = '<redacted>';",
			"TAS50", 1, true,
		},
		{
			// The trap: RSA_PUBLIC_KEY_2 contains RSA_PUBLIC_KEY as a prefix,
			// so a substring test would record this as a primary-slot rotation
			// and report the primary key as newer than it really is.
			"alter user sets the secondary key",
			"ALTER USER svc_etl SET RSA_PUBLIC_KEY_2 = '<redacted>';",
			"SVC_ETL", 2, true,
		},
		{
			"create user with a key",
			"CREATE USER bot_1 PASSWORD = '<redacted>' RSA_PUBLIC_KEY = '<redacted>'",
			"BOT_1", 1, true,
		},
		{
			"if not exists is skipped over",
			"CREATE USER IF NOT EXISTS bot_2 RSA_PUBLIC_KEY='<redacted>'",
			"BOT_2", 1, true,
		},
		{
			"if exists is skipped over",
			"ALTER USER IF EXISTS bot_3 SET RSA_PUBLIC_KEY='<redacted>'",
			"BOT_3", 1, true,
		},
		{
			"quoted identifier",
			`ALTER USER "Mixed_Case" SET RSA_PUBLIC_KEY = '<redacted>'`,
			"MIXED_CASE", 1, true,
		},
		{
			"lower case statement",
			"alter user tas50 set rsa_public_key = '<redacted>'",
			"TAS50", 1, true,
		},
		{
			// Removing a key is not installing one. Counting it would report a
			// withdrawn credential as freshly rotated.
			"unset is not a set",
			"ALTER USER tas50 UNSET RSA_PUBLIC_KEY",
			"", 0, false,
		},
		{
			"unset of the second slot is not a set",
			"ALTER USER tas50 UNSET RSA_PUBLIC_KEY_2",
			"", 0, false,
		},
		{
			// Targets the current user, who is not named; attributing it to
			// anyone would be a guess.
			"statement with no user name",
			"ALTER USER SET RSA_PUBLIC_KEY = '<redacted>'",
			"", 0, false,
		},
		{
			"unrelated alter user",
			"ALTER USER tas50 SET NETWORK_POLICY = MQL_VERIFY_POLICY;",
			"", 0, false,
		},
		{"empty", "", "", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseKeySetStatement(tc.statement)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.user != tc.wantUser || got.slot != tc.wantSlot {
				t.Errorf("got user=%q slot=%d, want user=%q slot=%d",
					got.user, got.slot, tc.wantUser, tc.wantSlot)
			}
		})
	}
}

func TestFoldKeySetRows(t *testing.T) {
	at := func(day int) time.Time {
		return time.Date(2026, 8, day, 12, 0, 0, 0, time.UTC)
	}

	t.Run("keeps the most recent rotation per slot", func(t *testing.T) {
		// Rows arrive oldest first, so the later statement must win. Keeping
		// the earlier one would report a rotated key as overdue.
		got := foldKeySetRows([]keySetRow{
			{at(1), "ALTER USER tas50 SET RSA_PUBLIC_KEY = '<redacted>'"},
			{at(11), "ALTER USER tas50 SET RSA_PUBLIC_KEY = '<redacted>'"},
		})
		entry := got["TAS50"]
		if entry[0] == nil || !entry[0].Equal(at(11)) {
			t.Errorf("primary slot = %v, want %v", entry[0], at(11))
		}
		if entry[1] != nil {
			t.Errorf("secondary slot = %v, want nil", entry[1])
		}
	})

	t.Run("tracks the two slots independently", func(t *testing.T) {
		got := foldKeySetRows([]keySetRow{
			{at(1), "ALTER USER svc SET RSA_PUBLIC_KEY = '<redacted>'"},
			{at(9), "ALTER USER svc SET RSA_PUBLIC_KEY_2 = '<redacted>'"},
		})
		entry := got["SVC"]
		if entry[0] == nil || !entry[0].Equal(at(1)) {
			t.Errorf("primary slot = %v, want %v", entry[0], at(1))
		}
		if entry[1] == nil || !entry[1].Equal(at(9)) {
			t.Errorf("secondary slot = %v, want %v", entry[1], at(9))
		}
	})

	t.Run("separates users", func(t *testing.T) {
		got := foldKeySetRows([]keySetRow{
			{at(1), "ALTER USER a SET RSA_PUBLIC_KEY = '<redacted>'"},
			{at(2), "ALTER USER b SET RSA_PUBLIC_KEY = '<redacted>'"},
		})
		if len(got) != 2 {
			t.Fatalf("got %d users, want 2", len(got))
		}
		if got["A"][0].Equal(*got["B"][0]) {
			t.Error("two users must not share a timestamp")
		}
	})

	t.Run("ignores statements that set no key", func(t *testing.T) {
		got := foldKeySetRows([]keySetRow{
			{at(1), "ALTER USER tas50 SET NETWORK_POLICY = P"},
			{at(2), "ALTER USER tas50 UNSET RSA_PUBLIC_KEY"},
		})
		if len(got) != 0 {
			t.Errorf("got %v, want no entries", got)
		}
	})

	t.Run("no rows yields no entries, never a zero time", func(t *testing.T) {
		// A zero time would date every key to year one and read as long
		// overdue for rotation.
		got := foldKeySetRows(nil)
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}
