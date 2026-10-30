// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package limits_test

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/limits"
)

// Tests using TOML-based mock connection

func TestLimitsParser_MainConfig(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux.toml"))
	require.NoError(t, err)

	f, err := conn.FileSystem().Open("/etc/security/limits.conf")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)

	entries := limits.ParseLines("/etc/security/limits.conf", string(content))

	require.Len(t, entries, 6)

	// First entry: * soft core 0
	assert.Equal(t, "/etc/security/limits.conf", entries[0].File)
	assert.Equal(t, 5, entries[0].LineNumber)
	assert.Equal(t, "*", entries[0].Domain)
	assert.Equal(t, "soft", entries[0].Type)
	assert.Equal(t, "core", entries[0].Item)
	assert.Equal(t, "0", entries[0].Value)

	// Second entry: * hard core unlimited
	assert.Equal(t, 6, entries[1].LineNumber)
	assert.Equal(t, "*", entries[1].Domain)
	assert.Equal(t, "hard", entries[1].Type)
	assert.Equal(t, "core", entries[1].Item)
	assert.Equal(t, "unlimited", entries[1].Value)

	// Third entry: * soft nofile 65536
	assert.Equal(t, "nofile", entries[2].Item)
	assert.Equal(t, "65536", entries[2].Value)

	// Fifth entry: @admin soft nproc unlimited
	assert.Equal(t, "@admin", entries[4].Domain)
	assert.Equal(t, "soft", entries[4].Type)
	assert.Equal(t, "nproc", entries[4].Item)
	assert.Equal(t, "unlimited", entries[4].Value)

	// Sixth entry: root - nofile 1000000
	assert.Equal(t, "root", entries[5].Domain)
	assert.Equal(t, "-", entries[5].Type)
	assert.Equal(t, "nofile", entries[5].Item)
	assert.Equal(t, "1000000", entries[5].Value)
}

func TestLimitsParser_CustomConfig(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux.toml"))
	require.NoError(t, err)

	f, err := conn.FileSystem().Open("/etc/security/limits.d/99-custom.conf")
	require.NoError(t, err)
	defer f.Close()

	content, err := io.ReadAll(f)
	require.NoError(t, err)

	entries := limits.ParseLines("/etc/security/limits.d/99-custom.conf", string(content))

	require.Len(t, entries, 3)

	// First entry: @developers - nofile 100000
	assert.Equal(t, "/etc/security/limits.d/99-custom.conf", entries[0].File)
	assert.Equal(t, 2, entries[0].LineNumber)
	assert.Equal(t, "@developers", entries[0].Domain)
	assert.Equal(t, "-", entries[0].Type)
	assert.Equal(t, "nofile", entries[0].Item)
	assert.Equal(t, "100000", entries[0].Value)

	// Second entry: postgres soft nproc 65536
	assert.Equal(t, "postgres", entries[1].Domain)
	assert.Equal(t, "soft", entries[1].Type)
	assert.Equal(t, "nproc", entries[1].Item)
	assert.Equal(t, "65536", entries[1].Value)

	// Third entry: postgres hard nproc 65536
	assert.Equal(t, "postgres", entries[2].Domain)
	assert.Equal(t, "hard", entries[2].Type)
}

func TestLimitsParser_DirectoryExists(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/linux.toml"))
	require.NoError(t, err)

	stat, err := conn.FileSystem().Stat("/etc/security/limits.d")
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
}

// Tests for EntryRegex

func TestEntryRegex_Wildcard(t *testing.T) {
	content := "* soft core 0"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])    // domain
	assert.Equal(t, "soft", matches[2]) // type
	assert.Equal(t, "core", matches[3]) // item
	assert.Equal(t, "0", matches[4])    // value
}

func TestEntryRegex_HardLimit(t *testing.T) {
	content := "* hard rss 10000"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])     // domain
	assert.Equal(t, "hard", matches[2])  // type
	assert.Equal(t, "rss", matches[3])   // item
	assert.Equal(t, "10000", matches[4]) // value
}

func TestEntryRegex_BothType(t *testing.T) {
	content := "@student - maxlogins 4"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "@student", matches[1])  // domain (group)
	assert.Equal(t, "-", matches[2])         // type (both)
	assert.Equal(t, "maxlogins", matches[3]) // item
	assert.Equal(t, "4", matches[4])         // value
}

func TestEntryRegex_Username(t *testing.T) {
	content := "john soft nofile 4096"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "john", matches[1])   // domain (user)
	assert.Equal(t, "soft", matches[2])   // type
	assert.Equal(t, "nofile", matches[3]) // item
	assert.Equal(t, "4096", matches[4])   // value
}

func TestEntryRegex_GroupName(t *testing.T) {
	content := "@admin hard nproc 50"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "@admin", matches[1]) // domain (group)
	assert.Equal(t, "hard", matches[2])   // type
	assert.Equal(t, "nproc", matches[3])  // item
	assert.Equal(t, "50", matches[4])     // value
}

func TestEntryRegex_Unlimited(t *testing.T) {
	content := "root soft core unlimited"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "root", matches[1])      // domain
	assert.Equal(t, "soft", matches[2])      // type
	assert.Equal(t, "core", matches[3])      // item
	assert.Equal(t, "unlimited", matches[4]) // value
}

func TestEntryRegex_MemoryLock(t *testing.T) {
	content := "* hard memlock 64"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])       // domain
	assert.Equal(t, "hard", matches[2])    // type
	assert.Equal(t, "memlock", matches[3]) // item
	assert.Equal(t, "64", matches[4])      // value
}

func TestEntryRegex_Stack(t *testing.T) {
	content := "apache soft stack 8192"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "apache", matches[1]) // domain
	assert.Equal(t, "soft", matches[2])   // type
	assert.Equal(t, "stack", matches[3])  // item
	assert.Equal(t, "8192", matches[4])   // value
}

func TestEntryRegex_CPUTime(t *testing.T) {
	content := "@users hard cpu 60"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "@users", matches[1]) // domain
	assert.Equal(t, "hard", matches[2])   // type
	assert.Equal(t, "cpu", matches[3])    // item
	assert.Equal(t, "60", matches[4])     // value
}

func TestEntryRegex_Priority(t *testing.T) {
	content := "@realtime hard priority 10"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "@realtime", matches[1]) // domain
	assert.Equal(t, "hard", matches[2])      // type
	assert.Equal(t, "priority", matches[3])  // item
	assert.Equal(t, "10", matches[4])        // value
}

func TestEntryRegex_Nice(t *testing.T) {
	content := "postgres - nice -10"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "postgres", matches[1]) // domain
	assert.Equal(t, "-", matches[2])        // type
	assert.Equal(t, "nice", matches[3])     // item
	assert.Equal(t, "-10", matches[4])      // value (negative)
}

func TestEntryRegex_Comment(t *testing.T) {
	content := "# This is a comment"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	// Comments should not match
	assert.Nil(t, matches)
}

func TestEntryRegex_EmptyLine(t *testing.T) {
	content := ""
	matches := limits.EntryRegex.FindStringSubmatch(content)

	// Empty lines should not match
	assert.Nil(t, matches)
}

func TestEntryRegex_InvalidFormat(t *testing.T) {
	content := "invalid line without proper format"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	// Invalid format should not match
	assert.Nil(t, matches)
}

func TestEntryRegex_ExtraWhitespace(t *testing.T) {
	content := "  *     soft     nofile     65536  "
	matches := limits.EntryRegex.FindStringSubmatch(strings.TrimSpace(content))

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])      // domain
	assert.Equal(t, "soft", matches[2])   // type
	assert.Equal(t, "nofile", matches[3]) // item
	assert.Equal(t, "65536", matches[4])  // value
}

func TestEntryRegex_FileSize(t *testing.T) {
	content := "* hard fsize 1000000"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])       // domain
	assert.Equal(t, "hard", matches[2])    // type
	assert.Equal(t, "fsize", matches[3])   // item
	assert.Equal(t, "1000000", matches[4]) // value
}

func TestEntryRegex_DataSegment(t *testing.T) {
	content := "oracle soft data unlimited"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "oracle", matches[1])    // domain
	assert.Equal(t, "soft", matches[2])      // type
	assert.Equal(t, "data", matches[3])      // item
	assert.Equal(t, "unlimited", matches[4]) // value
}

func TestEntryRegex_Locks(t *testing.T) {
	content := "database hard locks 2048"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "database", matches[1]) // domain
	assert.Equal(t, "hard", matches[2])     // type
	assert.Equal(t, "locks", matches[3])    // item
	assert.Equal(t, "2048", matches[4])     // value
}

func TestEntryRegex_SigPending(t *testing.T) {
	content := "* soft sigpending 1024"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])          // domain
	assert.Equal(t, "soft", matches[2])       // type
	assert.Equal(t, "sigpending", matches[3]) // item
	assert.Equal(t, "1024", matches[4])       // value
}

func TestEntryRegex_MsgQueue(t *testing.T) {
	content := "* soft msgqueue 819200"
	matches := limits.EntryRegex.FindStringSubmatch(content)

	require.NotNil(t, matches)
	assert.Equal(t, "*", matches[1])        // domain
	assert.Equal(t, "soft", matches[2])     // type
	assert.Equal(t, "msgqueue", matches[3]) // item
	assert.Equal(t, "819200", matches[4])   // value
}

// Tests for ParseLines function

func TestParseLines_EmptyContent(t *testing.T) {
	entries := limits.ParseLines("/etc/security/limits.conf", "")
	assert.Empty(t, entries)
}

func TestParseLines_OnlyComments(t *testing.T) {
	content := `# This is a comment
# Another comment
# /etc/security/limits.conf`
	entries := limits.ParseLines("/etc/security/limits.conf", content)
	assert.Empty(t, entries)
}

func TestParseLines_OnlyEmptyLines(t *testing.T) {
	content := `


`
	entries := limits.ParseLines("/etc/security/limits.conf", content)
	assert.Empty(t, entries)
}

func TestParseLines_SingleEntry(t *testing.T) {
	content := "* soft nofile 65536"
	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 1)
	assert.Equal(t, "/etc/security/limits.conf", entries[0].File)
	assert.Equal(t, 1, entries[0].LineNumber)
	assert.Equal(t, "*", entries[0].Domain)
	assert.Equal(t, "soft", entries[0].Type)
	assert.Equal(t, "nofile", entries[0].Item)
	assert.Equal(t, "65536", entries[0].Value)
}

func TestParseLines_MultipleEntries(t *testing.T) {
	content := `* soft nofile 65536
* hard nofile 65536
@admin soft nproc unlimited`
	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 3)

	// First entry
	assert.Equal(t, 1, entries[0].LineNumber)
	assert.Equal(t, "*", entries[0].Domain)
	assert.Equal(t, "soft", entries[0].Type)
	assert.Equal(t, "nofile", entries[0].Item)
	assert.Equal(t, "65536", entries[0].Value)

	// Second entry
	assert.Equal(t, 2, entries[1].LineNumber)
	assert.Equal(t, "*", entries[1].Domain)
	assert.Equal(t, "hard", entries[1].Type)
	assert.Equal(t, "nofile", entries[1].Item)
	assert.Equal(t, "65536", entries[1].Value)

	// Third entry
	assert.Equal(t, 3, entries[2].LineNumber)
	assert.Equal(t, "@admin", entries[2].Domain)
	assert.Equal(t, "soft", entries[2].Type)
	assert.Equal(t, "nproc", entries[2].Item)
	assert.Equal(t, "unlimited", entries[2].Value)
}

func TestParseLines_MixedWithComments(t *testing.T) {
	content := `# /etc/security/limits.conf
#
# This file sets resource limits for users
#
* soft core 0
# Increase file limits for all users
* soft nofile 65536
* hard nofile 65536`
	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 3)

	// Line numbers should skip comments
	assert.Equal(t, 5, entries[0].LineNumber)
	assert.Equal(t, "core", entries[0].Item)

	assert.Equal(t, 7, entries[1].LineNumber)
	assert.Equal(t, "nofile", entries[1].Item)
	assert.Equal(t, "soft", entries[1].Type)

	assert.Equal(t, 8, entries[2].LineNumber)
	assert.Equal(t, "nofile", entries[2].Item)
	assert.Equal(t, "hard", entries[2].Type)
}

func TestParseLines_MixedWithEmptyLines(t *testing.T) {
	content := `* soft core 0

* hard core unlimited

@developers - nofile 100000`
	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 3)

	assert.Equal(t, 1, entries[0].LineNumber)
	assert.Equal(t, 3, entries[1].LineNumber)
	assert.Equal(t, 5, entries[2].LineNumber)
}

func TestParseLines_SkipsInvalidLines(t *testing.T) {
	content := `* soft nofile 65536
invalid line here
* hard nofile 65536
another invalid
root - nproc unlimited`
	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 3)

	assert.Equal(t, 1, entries[0].LineNumber)
	assert.Equal(t, "soft", entries[0].Type)

	assert.Equal(t, 3, entries[1].LineNumber)
	assert.Equal(t, "hard", entries[1].Type)

	assert.Equal(t, 5, entries[2].LineNumber)
	assert.Equal(t, "root", entries[2].Domain)
}

func TestParseLines_RealWorldConfig(t *testing.T) {
	// Simulates a real-world limits.conf file
	content := `# /etc/security/limits.conf
#
#Each line describes a limit for a user in the form:
#
#<domain>        <type>  <item>  <value>
#
#Where:
#<domain> can be:
#        - a user name
#        - a group name, with @group syntax
#        - the wildcard *, for default entry
#
#<type> can have the two values:
#        - "soft" for enforcing the soft limits
#        - "hard" for enforcing hard limits
#
#<item> can be one of the following:
#        - core - limits the core file size (KB)
#        - nofile - max number of open files
#        - nproc - max number of processes
#

* soft core 0
* hard core unlimited
* soft nofile 65536
* hard nofile 65536
@wheel - nproc unlimited
root soft nofile 1000000
root hard nofile 1000000

# End of file`
	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 7)

	// Verify correct parsing
	assert.Equal(t, "*", entries[0].Domain)
	assert.Equal(t, "core", entries[0].Item)
	assert.Equal(t, "0", entries[0].Value)

	assert.Equal(t, "*", entries[1].Domain)
	assert.Equal(t, "core", entries[1].Item)
	assert.Equal(t, "unlimited", entries[1].Value)

	assert.Equal(t, "@wheel", entries[4].Domain)
	assert.Equal(t, "-", entries[4].Type)
	assert.Equal(t, "nproc", entries[4].Item)

	assert.Equal(t, "root", entries[5].Domain)
	assert.Equal(t, "1000000", entries[5].Value)
}

func TestParseLines_FilePath(t *testing.T) {
	content := "* soft nofile 65536"

	// Test with main config file
	entries1 := limits.ParseLines("/etc/security/limits.conf", content)
	assert.Equal(t, "/etc/security/limits.conf", entries1[0].File)

	// Test with limits.d file
	entries2 := limits.ParseLines("/etc/security/limits.d/99-custom.conf", content)
	assert.Equal(t, "/etc/security/limits.d/99-custom.conf", entries2[0].File)
}

func TestParseLines_AllDomainTypes(t *testing.T) {
	content := `* soft nofile 1000
root soft nofile 2000
@admin soft nofile 3000
%group soft nofile 4000`

	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 4)
	assert.Equal(t, "*", entries[0].Domain)      // wildcard
	assert.Equal(t, "root", entries[1].Domain)   // user
	assert.Equal(t, "@admin", entries[2].Domain) // group with @
	assert.Equal(t, "%group", entries[3].Domain) // group with %
}

func TestParseLines_AllLimitTypes(t *testing.T) {
	content := `* soft nofile 1000
* hard nofile 2000
* - nofile 3000`

	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 3)
	assert.Equal(t, "soft", entries[0].Type)
	assert.Equal(t, "hard", entries[1].Type)
	assert.Equal(t, "-", entries[2].Type) // both soft and hard
}

func TestParseLines_AllCommonItems(t *testing.T) {
	content := `* soft core 0
* soft data unlimited
* soft fsize unlimited
* soft memlock 64
* soft nofile 1024
* soft rss 10000
* soft stack 8192
* soft cpu 60
* soft nproc 50
* soft as unlimited
* soft maxlogins 4
* soft maxsyslogins 10
* soft priority 0
* soft locks 100
* soft sigpending 1024
* soft msgqueue 819200
* soft nice 0
* soft rtprio 0`

	entries := limits.ParseLines("/etc/security/limits.conf", content)

	require.Len(t, entries, 18)

	// Verify all items were parsed
	items := make([]string, len(entries))
	for i, e := range entries {
		items[i] = e.Item
	}

	expectedItems := []string{
		"core", "data", "fsize", "memlock", "nofile", "rss", "stack",
		"cpu", "nproc", "as", "maxlogins", "maxsyslogins", "priority",
		"locks", "sigpending", "msgqueue", "nice", "rtprio",
	}

	for _, expected := range expectedItems {
		assert.Contains(t, items, expected, "missing item: %s", expected)
	}
}
