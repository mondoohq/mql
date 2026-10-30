// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "luks", name))
	require.NoError(t, err)
	return string(data)
}

func TestParseLuksDump_LUKS1(t *testing.T) {
	out := loadTestdata(t, "luks1_dump.txt")
	d, err := parseLuksDump(out)
	require.NoError(t, err)

	assert.Equal(t, 1, d.Version)
	assert.Equal(t, "fd44f17a-0b3b-44c0-a4a4-6bea30b3c6bf", d.UUID)
	assert.Empty(t, d.Label, "LUKS1 has no label field")
	assert.Empty(t, d.Subsystem, "LUKS1 has no subsystem field")
	assert.Equal(t, 512, d.MasterKeyBits)
	assert.Equal(t, 4096, d.PayloadOffset)

	assert.Equal(t, "aes", d.Cipher.Name)
	assert.Equal(t, "xts-plain64", d.Cipher.Mode)
	assert.Equal(t, "aes-xts-plain64", d.Cipher.Spec)
	assert.Equal(t, 512, d.Cipher.KeySize)
	assert.Equal(t, "sha256", d.Cipher.Hash)

	require.Len(t, d.Keyslots, 8)

	slot0 := d.Keyslots[0]
	assert.Equal(t, 0, slot0.Index)
	assert.Equal(t, "ENABLED", slot0.State)
	assert.Equal(t, "pbkdf2", slot0.KDF)
	assert.Equal(t, "sha256", slot0.Hash, "LUKS1 keyslots inherit the volume's hash spec")
	assert.Equal(t, 623013, slot0.Iterations)
	assert.Equal(t, 8, slot0.KeyMaterialOffset)
	assert.Equal(t, 4000, slot0.Stripes)
	assert.Zero(t, slot0.Time, "LUKS1 doesn't use argon2 time cost")
	assert.Zero(t, slot0.Memory)
	assert.Zero(t, slot0.Parallel)

	slot1 := d.Keyslots[1]
	assert.Equal(t, 1, slot1.Index)
	assert.Equal(t, "DISABLED", slot1.State)
	assert.Empty(t, slot1.KDF, "DISABLED slots have no KDF — leave empty so audits skip them")
	assert.Empty(t, slot1.Hash, "DISABLED slots have no hash")
	assert.Zero(t, slot1.Iterations)
	assert.Zero(t, slot1.Stripes)

	slot2 := d.Keyslots[2]
	assert.Equal(t, 2, slot2.Index)
	assert.Equal(t, "ENABLED", slot2.State)
	assert.Equal(t, 312456, slot2.Iterations)
	assert.Equal(t, 1008, slot2.KeyMaterialOffset)

	for i := 3; i < 8; i++ {
		assert.Equalf(t, i, d.Keyslots[i].Index, "slot %d index", i)
		assert.Equalf(t, "DISABLED", d.Keyslots[i].State, "slot %d state", i)
	}

	assert.Empty(t, d.Tokens, "LUKS1 never has tokens")
}

func TestParseLuksDump_LUKS1_AllDisabled(t *testing.T) {
	d, err := parseLuksDump(loadTestdata(t, "luks1_all_disabled.txt"))
	require.NoError(t, err)

	assert.Equal(t, 1, d.Version)
	assert.Equal(t, "serpent", d.Cipher.Name)
	assert.Equal(t, "cbc-essiv:sha256", d.Cipher.Mode)
	assert.Equal(t, "serpent-cbc-essiv:sha256", d.Cipher.Spec)
	assert.Equal(t, "sha512", d.Cipher.Hash)
	assert.Equal(t, 256, d.Cipher.KeySize)
	assert.Equal(t, 256, d.MasterKeyBits)

	require.Len(t, d.Keyslots, 8)
	for _, slot := range d.Keyslots {
		assert.Equal(t, "DISABLED", slot.State)
		assert.Empty(t, slot.KDF, "DISABLED slots have no KDF configured")
		assert.Empty(t, slot.Hash, "DISABLED slots have no hash")
		assert.Zero(t, slot.Iterations)
		assert.Zero(t, slot.Stripes)
	}
}

func TestParseLuksDump_LUKS2(t *testing.T) {
	d, err := parseLuksDump(loadTestdata(t, "luks2_dump.txt"))
	require.NoError(t, err)

	assert.Equal(t, 2, d.Version)
	assert.Equal(t, "7a3f1c4e-8d2b-4a9c-9e1f-5b6c7d8e9f01", d.UUID)
	assert.Equal(t, "root", d.Label)
	assert.Empty(t, d.Subsystem)

	// Cipher info on LUKS2 comes from the `Data segments:` section, not
	// the global header.
	assert.Equal(t, "aes", d.Cipher.Name)
	assert.Equal(t, "xts-plain64", d.Cipher.Mode)
	assert.Equal(t, "aes-xts-plain64", d.Cipher.Spec)
	assert.Equal(t, 512, d.Cipher.KeySize, "master key bits sourced from first keyslot")
	assert.Equal(t, 512, d.MasterKeyBits)

	require.Len(t, d.Keyslots, 2)

	slot0 := d.Keyslots[0]
	assert.Equal(t, 0, slot0.Index)
	assert.Equal(t, "active", slot0.State)
	assert.Equal(t, "argon2id", slot0.KDF)
	assert.Equal(t, 7, slot0.Time)
	assert.Equal(t, 1048576, slot0.Memory)
	assert.Equal(t, 4, slot0.Parallel)
	assert.Equal(t, 4000, slot0.Stripes)
	assert.Empty(t, slot0.Hash, "argon2 keyslots don't carry a KDF hash")
	assert.Equal(t, 32768/512, slot0.KeyMaterialOffset, "area offset converts from bytes to 512-byte sectors")
	assert.Zero(t, slot0.Iterations, "argon2 slots use time cost, not iterations")

	slot1 := d.Keyslots[1]
	assert.Equal(t, 1, slot1.Index)
	assert.Equal(t, "pbkdf2", slot1.KDF)
	assert.Equal(t, "sha512", slot1.Hash)
	assert.Equal(t, 1879041, slot1.Iterations)
	assert.Zero(t, slot1.Time, "pbkdf2 slots don't carry argon2 time cost")
	assert.Equal(t, 290816/512, slot1.KeyMaterialOffset)

	require.Len(t, d.Tokens, 1)
	token := d.Tokens[0]
	assert.Equal(t, int64(0), token["id"])
	assert.Equal(t, "systemd-tpm2", token["type"])
	keyslots, ok := token["keyslots"].([]int64)
	require.True(t, ok)
	assert.Equal(t, []int64{1}, keyslots)
}

func TestParseLuksDump_LUKS2_MultipleTokens(t *testing.T) {
	d, err := parseLuksDump(loadTestdata(t, "luks2_multitoken.txt"))
	require.NoError(t, err)

	assert.Equal(t, "data", d.Label)
	assert.Equal(t, "systemd", d.Subsystem, "subsystem string survives the parser")
	assert.Equal(t, "aes-xts-plain64", d.Cipher.Spec)
	assert.Equal(t, 512, d.MasterKeyBits)

	require.Len(t, d.Keyslots, 2)
	assert.Equal(t, 0, d.Keyslots[0].Index)
	assert.Equal(t, "argon2id", d.Keyslots[0].KDF)
	assert.Equal(t, 524288, d.Keyslots[0].Memory)

	// Note: keyslot 1 is skipped; the parser preserves the actual index
	// from the dump rather than the position in the array.
	assert.Equal(t, 2, d.Keyslots[1].Index)
	assert.Equal(t, "argon2i", d.Keyslots[1].KDF)
	assert.Equal(t, 262144, d.Keyslots[1].Memory)
	assert.Equal(t, 1, d.Keyslots[1].Parallel)

	require.Len(t, d.Tokens, 3)

	tpm2 := d.Tokens[0]
	assert.Equal(t, int64(0), tpm2["id"])
	assert.Equal(t, "systemd-tpm2", tpm2["type"])
	assert.Equal(t, []int64{0}, tpm2["keyslots"])

	fido2 := d.Tokens[1]
	assert.Equal(t, int64(1), fido2["id"])
	assert.Equal(t, "systemd-fido2", fido2["type"])
	assert.Equal(t, []int64{2}, fido2["keyslots"])

	recovery := d.Tokens[2]
	assert.Equal(t, int64(2), recovery["id"])
	assert.Equal(t, "systemd-recovery", recovery["type"])
	assert.Equal(t, []int64{0, 2}, recovery["keyslots"], "multiple Keyslot lines accumulate")
}

func TestParseLuksDump_LUKS2_NoTokens(t *testing.T) {
	d, err := parseLuksDump(loadTestdata(t, "luks2_no_tokens.txt"))
	require.NoError(t, err)

	assert.Equal(t, "", d.Label, "'(no label)' decodes to empty string")
	assert.Equal(t, "", d.Subsystem, "'(no subsystem)' decodes to empty string")
	assert.Equal(t, "aes-xts-plain64", d.Cipher.Spec)
	assert.Equal(t, 512, d.MasterKeyBits)

	require.Len(t, d.Keyslots, 1)
	slot := d.Keyslots[0]
	assert.Equal(t, "pbkdf2", slot.KDF, "LUKS2 still supports pbkdf2 slots")
	assert.Equal(t, "sha512", slot.Hash)
	assert.Equal(t, 2345678, slot.Iterations)
	assert.Zero(t, slot.Time)
	assert.Zero(t, slot.Memory)

	assert.Empty(t, d.Tokens, "empty Tokens: section produces no entries")
}

func TestParseLuksDump_LUKS2_Twofish(t *testing.T) {
	// Cipher spec contains both a hyphen and a colon
	// (`twofish-cbc-essiv:sha256`); makes sure the cipher splitter and
	// the colon-splitter cooperate.
	d, err := parseLuksDump(loadTestdata(t, "luks2_twofish.txt"))
	require.NoError(t, err)

	assert.Equal(t, "twofish", d.Cipher.Name)
	assert.Equal(t, "cbc-essiv:sha256", d.Cipher.Mode, "mode preserves both hyphens and colons after the cipher family")
	assert.Equal(t, "twofish-cbc-essiv:sha256", d.Cipher.Spec)
	assert.Equal(t, 256, d.Cipher.KeySize)
	assert.Equal(t, 256, d.MasterKeyBits)

	require.Len(t, d.Keyslots, 1)
	assert.Equal(t, "argon2id", d.Keyslots[0].KDF)
}

func TestSetLuks2CipherSpec(t *testing.T) {
	cases := []struct {
		spec, name, mode string
	}{
		{"aes-xts-plain64", "aes", "xts-plain64"},
		{"serpent-cbc-essiv:sha256", "serpent", "cbc-essiv:sha256"},
		{"twofish-cbc-essiv:sha256", "twofish", "cbc-essiv:sha256"},
		{"camellia-xts-plain64", "camellia", "xts-plain64"},
		// No mode separator — entire value becomes the cipher family.
		{"aes", "aes", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		var info luksCipherInfo
		setLuks2CipherSpec(&info, c.spec)
		assert.Equalf(t, c.spec, info.Spec, "input %q spec", c.spec)
		assert.Equalf(t, c.name, info.Name, "input %q name", c.spec)
		assert.Equalf(t, c.mode, info.Mode, "input %q mode", c.spec)
	}
}

func TestParseLuksDump_MissingVersion(t *testing.T) {
	_, err := parseLuksDump("not a luks dump\n")
	assert.Error(t, err)
}

func TestParseLuksDump_EmptyInput(t *testing.T) {
	_, err := parseLuksDump("")
	assert.Error(t, err, "empty input should be rejected for missing Version")
}

func TestParseLuksDump_HeaderOnly(t *testing.T) {
	// LUKS2 header with no Keyslots/Tokens/Digests sections. Valid output
	// when only the global fields are requested or the user lacks access.
	in := `LUKS header information
Version:       	2
UUID:          	cccccccc-dddd-eeee-ffff-000000000000
Label:         	(no label)
Cipher name:   	aes
Cipher mode:   	xts-plain64
MK bits:       	512
`
	d, err := parseLuksDump(in)
	require.NoError(t, err)
	assert.Equal(t, 2, d.Version)
	assert.Equal(t, "cccccccc-dddd-eeee-ffff-000000000000", d.UUID)
	assert.Equal(t, "aes-xts-plain64", d.Cipher.Spec)
	assert.Empty(t, d.Keyslots)
	assert.Empty(t, d.Tokens)
}

// --- helper functions ---

func TestSplitColon(t *testing.T) {
	cases := []struct {
		in         string
		key, value string
		ok         bool
	}{
		{"Version: 2", "Version", "2", true},
		{"UUID:          \tfd44f17a-...", "UUID", "fd44f17a-...", true},
		{"Hash spec:     \tsha256", "Hash spec", "sha256", true},
		{"no colon here", "", "", false},
		{"", "", "", false},
		{":", "", "", true},
		{"Empty value:    ", "Empty value", "", true},
	}
	for _, c := range cases {
		k, v, ok := splitColon(c.in)
		assert.Equalf(t, c.ok, ok, "input %q ok", c.in)
		assert.Equalf(t, c.key, k, "input %q key", c.in)
		assert.Equalf(t, c.value, v, "input %q value", c.in)
	}
}

func TestDecodeNoneSentinel(t *testing.T) {
	assert.Equal(t, "", decodeNoneSentinel("(no label)"))
	assert.Equal(t, "", decodeNoneSentinel("(no subsystem)"))
	assert.Equal(t, "", decodeNoneSentinel("(no flags)"))
	assert.Equal(t, "root", decodeNoneSentinel("root"))
	assert.Equal(t, "", decodeNoneSentinel(""))
	// Looks similar but not the sentinel format — preserved verbatim.
	assert.Equal(t, "(nope)", decodeNoneSentinel("(nope)"))
	assert.Equal(t, "no label", decodeNoneSentinel("no label"))
}

func TestIsSectionHeader(t *testing.T) {
	assert.True(t, isSectionHeader("Keyslots:"))
	assert.True(t, isSectionHeader("Tokens:"))
	assert.True(t, isSectionHeader("Digests:"))
	assert.True(t, isSectionHeader("Data segments:"))
	assert.False(t, isSectionHeader("Keyslots"))
	assert.False(t, isSectionHeader("Key Slot 0: ENABLED"))
	assert.False(t, isSectionHeader(""))
}

func TestIsSubsectionStart(t *testing.T) {
	assert.True(t, isSubsectionStart("0: luks2"))
	assert.True(t, isSubsectionStart("12: systemd-tpm2"))
	assert.False(t, isSubsectionStart("Key Slot 0: ENABLED"), "alpha prefix should not match")
	assert.False(t, isSubsectionStart(": no number"))
	assert.False(t, isSubsectionStart("no colon"))
	assert.False(t, isSubsectionStart(""))
	assert.False(t, isSubsectionStart("0x12: hex"), "only decimal digits")
}

func TestFirstInt(t *testing.T) {
	assert.Equal(t, 32768, firstInt("32768 [bytes]"))
	assert.Equal(t, 4096, firstInt("4096"))
	assert.Equal(t, 16777216, firstInt("offset: 16777216 [bytes]"))
	assert.Equal(t, 0, firstInt("no digits"))
	assert.Equal(t, 0, firstInt(""))
	assert.Equal(t, 42, firstInt("42"))
}

func TestLowerFirst(t *testing.T) {
	assert.Equal(t, "keyslot", lowerFirst("Keyslot"))
	assert.Equal(t, "priority", lowerFirst("Priority"))
	assert.Equal(t, "", lowerFirst(""))
	assert.Equal(t, "a", lowerFirst("a"))
	assert.Equal(t, "a", lowerFirst("A"))
}

func TestIsLuksFstype(t *testing.T) {
	assert.True(t, isLuksFstype("crypto_LUKS"))
	assert.False(t, isLuksFstype("ext4"))
	assert.False(t, isLuksFstype(""))
	assert.False(t, isLuksFstype("crypto_luks"), "matching is case-sensitive (lsblk emits crypto_LUKS)")
}

func TestLuksTokensToDicts(t *testing.T) {
	in := []map[string]any{
		{"id": int64(0), "type": "systemd-tpm2", "keyslots": []int64{1, 2}},
		{"id": int64(1), "type": "systemd-fido2"},
	}
	out := luksTokensToDicts(in)
	require.Len(t, out, 2)

	first, ok := out[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, int64(0), first["id"])
	assert.Equal(t, "systemd-tpm2", first["type"])
	// keyslots is normalized from []int64 to []any so it serializes as
	// an llx dict array.
	keyslots, ok := first["keyslots"].([]any)
	require.True(t, ok, "keyslots must become []any after normalization")
	assert.Equal(t, []any{int64(1), int64(2)}, keyslots)

	second, ok := out[1].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "systemd-fido2", second["type"])
	assert.NotContains(t, second, "keyslots", "tokens without keyslots stay missing the field")
}

func TestLuksTokensToDicts_DoesNotMutateInput(t *testing.T) {
	in := []map[string]any{
		{"keyslots": []int64{1}},
	}
	_ = luksTokensToDicts(in)
	// Input slice should still hold the original []int64 — the converter
	// builds a new map rather than mutating the caller's data.
	original, ok := in[0]["keyslots"].([]int64)
	require.True(t, ok, "input keyslots must remain []int64")
	assert.Equal(t, []int64{1}, original)
}

func TestLuksTokensToDicts_Empty(t *testing.T) {
	out := luksTokensToDicts(nil)
	assert.Empty(t, out)

	out = luksTokensToDicts([]map[string]any{})
	assert.Empty(t, out)
}

func TestValidDevicePath(t *testing.T) {
	accepted := []string{
		"/dev/sda3",
		"/dev/nvme0n1p2",
		"/dev/vda",
		"/dev/mapper/vg-root",
		"/dev/disk/by-uuid/fd44f17a-0b3b-44c0-a4a4-6bea30b3c6bf",
		"/dev/dm-0",
	}
	for _, p := range accepted {
		assert.Truef(t, validDevicePath.MatchString(p), "should accept %q", p)
	}

	rejected := []string{
		"",
		"sda3",                // missing /dev/ prefix
		"/etc/passwd",         // outside /dev
		"/dev/sda3; rm -rf /", // shell metacharacters
		"/dev/sda3 && id",
		"/dev/$(whoami)",
		"/dev/`id`",
		"/dev/sda3|cat",
		"/dev/sda\n3",
	}
	for _, p := range rejected {
		assert.Falsef(t, validDevicePath.MatchString(p), "should reject %q", p)
	}
}

func TestCollectLuksDevices(t *testing.T) {
	// Mixed tree: a top-level whole-disk LUKS (vdb), a LUKS partition
	// (sda3) nested under a regular disk, a non-LUKS partition (sda1),
	// and a LUKS volume nested two levels deep (lvm-on-luks).
	tree := []blockdevice{
		{Name: "/dev/sda", Fstype: "", Children: []blockdevice{
			{Name: "/dev/sda1", Fstype: "ext4"},
			{Name: "/dev/sda3", Fstype: "crypto_LUKS", Children: []blockdevice{
				{Name: "/dev/mapper/root", Fstype: "ext4"},
			}},
		}},
		{Name: "/dev/vdb", Fstype: "crypto_LUKS"},
		{Name: "/dev/vg0", Fstype: "", Children: []blockdevice{
			{Name: "/dev/vg0/data", Fstype: "crypto_LUKS"},
		}},
	}
	out := collectLuksDevices(tree)
	names := make([]string, 0, len(out))
	for _, d := range out {
		names = append(names, d.Name)
	}
	assert.ElementsMatch(t,
		[]string{"/dev/sda3", "/dev/vdb", "/dev/vg0/data"},
		names,
		"should find LUKS devices at every depth and skip non-LUKS",
	)
}

func TestLuksVolumeID_RequiresUUID(t *testing.T) {
	// id() guards against an unset uuid arg; otherwise multiple volumes
	// without a UUID would all collide on the empty-string cache key.
	v := &mqlLuksVolume{}
	_, err := v.id()
	assert.Error(t, err)

	v.Uuid.Data = "fd44f17a-0b3b-44c0-a4a4-6bea30b3c6bf"
	id, err := v.id()
	require.NoError(t, err)
	assert.Equal(t, "fd44f17a-0b3b-44c0-a4a4-6bea30b3c6bf", id)
}

func TestCollectLuksDevices_Empty(t *testing.T) {
	assert.Empty(t, collectLuksDevices(nil))
	assert.Empty(t, collectLuksDevices([]blockdevice{}))
	assert.Empty(t, collectLuksDevices([]blockdevice{
		{Name: "/dev/sda", Fstype: "ext4"},
	}))
}

// cryptsetup 2.0.3 (RHEL 7) prints the keyslot's volume key size as "Key:"
// and has no "Cipher key:" line.
func TestParseLuksDump_LUKS2_Cryptsetup203(t *testing.T) {
	d, err := parseLuksDump(loadTestdata(t, "luks2_cryptsetup_2.0.3.txt"))
	require.NoError(t, err)

	assert.Equal(t, 2, d.Version)
	assert.Equal(t, "2e5cfd73-618a-4bc6-b2ae-eb90a9d06ee0", d.UUID)
	assert.Equal(t, "g05label", d.Label)
	assert.Equal(t, "g05sub", d.Subsystem)
	assert.Equal(t, 256, d.MasterKeyBits)
	assert.Equal(t, 256, d.Cipher.KeySize)
	assert.Equal(t, "aes-xts-plain64", d.Cipher.Spec)
	require.Len(t, d.Keyslots, 2)
	assert.Equal(t, []int{0, 2}, []int{d.Keyslots[0].Index, d.Keyslots[1].Index})
	assert.Equal(t, "argon2i", d.Keyslots[1].KDF)
}
