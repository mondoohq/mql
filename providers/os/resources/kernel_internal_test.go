// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestParseModprobeConfig locks down the modprobe.d parser used by the
// kernel.module {blacklisted, installBypass, disabled} accessors. The
// shapes here are taken from CIS Linux benchmarks (cramfs, usb-storage,
// freevxfs, jffs2, hfs) and from the in-the-wild quirks the parser has
// to tolerate — `exec /bin/false`, leading whitespace, comments mid-line,
// and unrelated directives (alias, options, softdep) that must be ignored
// without poisoning a sibling module's rule.
func TestParseModprobeConfig(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    map[string]modprobeRule
	}{
		{
			name:    "simple blacklist",
			content: "blacklist cramfs\n",
			want: map[string]modprobeRule{
				"cramfs": {blacklisted: true},
			},
		},
		{
			name:    "install short-circuit to /bin/true",
			content: "install usb-storage /bin/true\n",
			want: map[string]modprobeRule{
				"usb-storage": {installBypass: true},
			},
		},
		{
			name:    "install short-circuit to /bin/false",
			content: "install usb-storage /bin/false\n",
			want: map[string]modprobeRule{
				"usb-storage": {installBypass: true},
			},
		},
		{
			name:    "install short-circuit to /usr/bin/true",
			content: "install usb-storage /usr/bin/true\n",
			want: map[string]modprobeRule{
				"usb-storage": {installBypass: true},
			},
		},
		{
			name:    "install short-circuit to /usr/bin/false",
			content: "install usb-storage /usr/bin/false\n",
			want: map[string]modprobeRule{
				"usb-storage": {installBypass: true},
			},
		},
		{
			name:    "install via exec wrapper to /bin/false",
			content: "install usb-storage exec /bin/false\n",
			want: map[string]modprobeRule{
				"usb-storage": {installBypass: true},
			},
		},
		{
			name:    "install via exec wrapper to /usr/bin/false",
			content: "install usb-storage exec /usr/bin/false\n",
			want: map[string]modprobeRule{
				"usb-storage": {installBypass: true},
			},
		},
		{
			name:    "install to real modprobe is not a bypass",
			content: "install usb-storage /sbin/modprobe usb-storage-real\n",
			want:    map[string]modprobeRule{},
		},
		{
			name: "comments and blank lines are ignored",
			content: `# CIS Linux Benchmark 1.1.1.1
# Disable mounting of cramfs
blacklist cramfs

# Disable mounting of freevxfs

blacklist freevxfs   # trailing comment
`,
			want: map[string]modprobeRule{
				"cramfs":   {blacklisted: true},
				"freevxfs": {blacklisted: true},
			},
		},
		{
			name: "multiple modules combine across lines",
			content: `blacklist cramfs
install usb-storage /bin/false
blacklist freevxfs
install jffs2 /bin/true
`,
			want: map[string]modprobeRule{
				"cramfs":      {blacklisted: true},
				"usb-storage": {installBypass: true},
				"freevxfs":    {blacklisted: true},
				"jffs2":       {installBypass: true},
			},
		},
		{
			name: "same module blacklisted and install-bypassed unions both flags",
			content: `blacklist usb-storage
install usb-storage /bin/false
`,
			want: map[string]modprobeRule{
				"usb-storage": {blacklisted: true, installBypass: true},
			},
		},
		{
			name:    "leading whitespace, tabs, and mixed indentation tolerated",
			content: "  blacklist cramfs\n\tinstall usb-storage\t/bin/false\n  \t blacklist  freevxfs \n",
			want: map[string]modprobeRule{
				"cramfs":      {blacklisted: true},
				"usb-storage": {installBypass: true},
				"freevxfs":    {blacklisted: true},
			},
		},
		{
			name: "alias / options / softdep / remove are ignored",
			content: `alias net-pf-10 ipv6
options ipv6 disable=1
softdep nf_conntrack pre: nf_defrag_ipv4
remove fuse /sbin/modprobe -r fuse
blacklist cramfs
`,
			want: map[string]modprobeRule{
				"cramfs": {blacklisted: true},
			},
		},
		{
			name:    "blacklist without a module name is dropped",
			content: "blacklist\n",
			want:    map[string]modprobeRule{},
		},
		{
			name:    "install without a command is dropped",
			content: "install usb-storage\n",
			want:    map[string]modprobeRule{},
		},
		{
			name:    "empty content yields empty map",
			content: "",
			want:    map[string]modprobeRule{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseModprobeConfig(tc.content)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestStripModprobeComment guards the modprobe-flavoured comment stripper
// against drift toward rsyslog's quote-aware shape — modprobe has no
// string literals, so `#` always introduces a comment.
func TestStripModprobeComment(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{"blacklist cramfs", "blacklist cramfs"},
		{"blacklist cramfs # comment", "blacklist cramfs "},
		{"# entire line is a comment", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.out, stripModprobeComment(tc.in))
		})
	}
}

// TestRpmKernelMatchesRunning is the unit-level reproducer for
// customer-issues #178: AL2023's `kernel` rpm carries epoch 1, so
// pkg.Version is "1:6.1.170-210.320.amzn2023" while /proc/version returns
// "6.1.170-210.320.amzn2023.x86_64". A naive `pkgVersion+"."+arch ==
// runningKernelVersion` check fails for every installed kernel image, and
// the entire kernel.installed list comes back with running:false.
func TestRpmKernelMatchesRunning(t *testing.T) {
	cases := []struct {
		name           string
		pkgVersion     string
		pkgArch        string
		runningKernel  string
		expectedResult bool
	}{
		{
			name:           "AL2023 epoch-1 kernel matches running",
			pkgVersion:     "1:6.1.170-210.320.amzn2023",
			pkgArch:        "x86_64",
			runningKernel:  "6.1.170-210.320.amzn2023.x86_64",
			expectedResult: true,
		},
		{
			name:           "AL2023 epoch-1 kernel at older ABI does not match running",
			pkgVersion:     "1:6.1.166-197.305.amzn2023",
			pkgArch:        "x86_64",
			runningKernel:  "6.1.170-210.320.amzn2023.x86_64",
			expectedResult: false,
		},
		{
			name:           "RHEL legacy kernel with no epoch still matches",
			pkgVersion:     "3.10.0-1160.11.1.el7",
			pkgArch:        "x86_64",
			runningKernel:  "3.10.0-1160.11.1.el7.x86_64",
			expectedResult: true,
		},
		{
			name:           "Oracle UEK kernel with epoch matches running",
			pkgVersion:     "1:6.12.0-105.51.5.el9uek",
			pkgArch:        "x86_64",
			runningKernel:  "6.12.0-105.51.5.el9uek.x86_64",
			expectedResult: true,
		},
		{
			name:           "different architectures never match",
			pkgVersion:     "1:6.1.170-210.320.amzn2023",
			pkgArch:        "aarch64",
			runningKernel:  "6.1.170-210.320.amzn2023.x86_64",
			expectedResult: false,
		},
		{
			name:           "running-kernel string is empty (kernel.info unavailable)",
			pkgVersion:     "1:6.1.170-210.320.amzn2023",
			pkgArch:        "x86_64",
			runningKernel:  "",
			expectedResult: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rpmKernelMatchesRunning(tc.pkgVersion, tc.pkgArch, tc.runningKernel)
			assert.Equal(t, tc.expectedResult, got)
		})
	}
}

func TestStripRPMEpoch(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"no epoch", "6.1.170-210.320.amzn2023", "6.1.170-210.320.amzn2023"},
		{"epoch 1", "1:6.1.170-210.320.amzn2023", "6.1.170-210.320.amzn2023"},
		{"epoch 10 (multi-digit)", "10:6.1.170", "6.1.170"},
		{"empty", "", ""},
		{"bare colon", ":6.1.170", "6.1.170"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.out, stripRPMEpoch(tc.in))
		})
	}
}

// TestPhotonKernelMatchesRunning locks down the Photon comparison shape
// (version + flavor-suffix-from-name == runningKernelVersion) and proves
// the shared stripRPMEpoch primitive keeps the comparison working should
// Photon ever ship a kernel rpm with an Epoch declared.
func TestPhotonKernelMatchesRunning(t *testing.T) {
	cases := []struct {
		name           string
		pkgVersion     string
		pkgName        string
		runningKernel  string
		expectedResult bool
	}{
		{
			name:           "bare linux package matches running",
			pkgVersion:     "4.19.97-1.ph3",
			pkgName:        "linux",
			runningKernel:  "4.19.97-1.ph3",
			expectedResult: true,
		},
		{
			name:           "linux-esx flavor matches running with -esx suffix",
			pkgVersion:     "4.19.97-1.ph3",
			pkgName:        "linux-esx",
			runningKernel:  "4.19.97-1.ph3-esx",
			expectedResult: true,
		},
		{
			name:           "older inactive kernel does not match",
			pkgVersion:     "4.19.90-1.ph3",
			pkgName:        "linux",
			runningKernel:  "4.19.97-1.ph3",
			expectedResult: false,
		},
		{
			name:           "wrong flavor does not match",
			pkgVersion:     "4.19.97-1.ph3",
			pkgName:        "linux-rt",
			runningKernel:  "4.19.97-1.ph3-esx",
			expectedResult: false,
		},
		{
			name:           "hypothetical epoch-1 photon kernel still matches running",
			pkgVersion:     "1:4.19.97-1.ph3",
			pkgName:        "linux-esx",
			runningKernel:  "4.19.97-1.ph3-esx",
			expectedResult: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := photonKernelMatchesRunning(tc.pkgVersion, tc.pkgName, tc.runningKernel)
			assert.Equal(t, tc.expectedResult, got)
		})
	}
}

// TestSuseKernelMatchesRunning locks down the SUSE comparison shape:
// running ends with the package's -flavor suffix AND the trimmed running
// version is a prefix of the package version (accounting for the extra
// dpkg-release segment on pkg.Version). stripRPMEpoch is in the path so
// the comparison still works if a SUSE kernel rpm ever declares an Epoch.
func TestSuseKernelMatchesRunning(t *testing.T) {
	cases := []struct {
		name           string
		pkgVersion     string
		pkgName        string
		runningKernel  string
		expectedResult bool
	}{
		{
			name:           "kernel-default matches running with extra release segment",
			pkgVersion:     "4.12.14-122.23.1",
			pkgName:        "kernel-default",
			runningKernel:  "4.12.14-122.23-default",
			expectedResult: true,
		},
		{
			name:           "kernel-default at older version does not match",
			pkgVersion:     "4.12.14-122.20.1",
			pkgName:        "kernel-default",
			runningKernel:  "4.12.14-122.23-default",
			expectedResult: false,
		},
		{
			name:           "kernel-rt does not match a -default running kernel",
			pkgVersion:     "4.12.14-122.23.1",
			pkgName:        "kernel-rt",
			runningKernel:  "4.12.14-122.23-default",
			expectedResult: false,
		},
		{
			name:           "hypothetical epoch-1 SUSE kernel still matches running",
			pkgVersion:     "1:4.12.14-122.23.1",
			pkgName:        "kernel-default",
			runningKernel:  "4.12.14-122.23-default",
			expectedResult: true,
		},
		{
			name:           "empty running-kernel string never matches",
			pkgVersion:     "4.12.14-122.23.1",
			pkgName:        "kernel-default",
			runningKernel:  "",
			expectedResult: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := suseKernelMatchesRunning(tc.pkgVersion, tc.pkgName, tc.runningKernel)
			assert.Equal(t, tc.expectedResult, got)
		})
	}
}

// TestModuleNameFromPath locks down the extraction of a bare module name
// from the path entries found in modules.dep and modules.builtin. The tricky
// parts are the compression suffixes that modern kernels apply to .ko files
// (.xz / .zst / .gz) and the dash↔underscore normalization the kernel applies
// to module names.
func TestModuleNameFromPath(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{"kernel/net/netfilter/nf_conntrack.ko", "nf_conntrack"},
		{"kernel/fs/cramfs/cramfs.ko.xz", "cramfs"},
		{"kernel/fs/squashfs/squashfs.ko.zst", "squashfs"},
		{"kernel/drivers/usb/storage/usb-storage.ko.gz", "usb_storage"},
		// leading/trailing whitespace (modules.dep keeps the colon on the LHS,
		// which the caller strips, but tabs around builtin entries appear too)
		{"\tkernel/fs/ext4/ext4.ko\t", "ext4"},
		{"snd-hda-intel.ko", "snd_hda_intel"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.out, moduleNameFromPath(tc.in))
		})
	}
}

// TestNormalizeModuleName confirms dashes collapse to underscores so a lookup
// by either spelling resolves the same module (the kernel treats them as
// equivalent and lsmod always reports underscores).
func TestNormalizeModuleName(t *testing.T) {
	assert.Equal(t, "usb_storage", normalizeModuleName("usb-storage"))
	assert.Equal(t, "usb_storage", normalizeModuleName("usb_storage"))
	assert.Equal(t, "nf_conntrack", normalizeModuleName("nf_conntrack"))
	assert.Equal(t, "", normalizeModuleName(""))
}

// TestParseModulesDep locks down the modules.dep parser behind
// kernel.module.onDisk. Real Debian/Ubuntu indexes compress modules
// (.ko.zst / .ko.xz), list each loadable module as the left-hand side of a
// "module: deps" line, and may carry hundreds of dependency paths on the
// right that must NOT be treated as separately installed modules unless they
// appear as their own left-hand entry.
func TestParseModulesDep(t *testing.T) {
	cases := []struct {
		name    string
		content string
		present []string // expected onDisk
		absent  []string // expected NOT onDisk
	}{
		{
			name:    "single module, no deps, trailing colon",
			content: "kernel/fs/overlayfs/overlay.ko.zst:",
			present: []string{"overlay"},
		},
		{
			name: "module with deps records only the left-hand side",
			content: "kernel/net/netfilter/nf_conntrack.ko: " +
				"kernel/net/netfilter/nf_defrag_ipv4.ko kernel/lib/libcrc32c.ko",
			present: []string{"nf_conntrack"},
			// deps on the RHS are not independently installed unless they
			// also appear as their own left-hand entry.
			absent: []string{"nf_defrag_ipv4", "libcrc32c"},
		},
		{
			name: "dep that also has its own line is present",
			content: "kernel/net/netfilter/nf_conntrack.ko: kernel/lib/libcrc32c.ko\n" +
				"kernel/lib/libcrc32c.ko:",
			present: []string{"nf_conntrack", "libcrc32c"},
		},
		{
			name: "all compression suffixes and dash normalization",
			content: "kernel/fs/cramfs/cramfs.ko.xz:\n" +
				"kernel/fs/squashfs/squashfs.ko.zst:\n" +
				"kernel/drivers/usb/storage/usb-storage.ko.gz:\n" +
				"kernel/sound/pci/hda/snd-hda-intel.ko:",
			present: []string{"cramfs", "squashfs", "usb_storage", "snd_hda_intel"},
		},
		{
			name:    "blank lines, whitespace-only lines, and a trailing newline are ignored",
			content: "\n  \n\t\nkernel/fs/jffs2/jffs2.ko:\n\n",
			present: []string{"jffs2"},
		},
		{
			name:    "duplicate module across lines is idempotent",
			content: "kernel/fs/hfs/hfs.ko:\nkernel/fs/hfs/hfs.ko: kernel/dep.ko",
			present: []string{"hfs"},
		},
		{
			name:    "empty content yields no modules",
			content: "",
			absent:  []string{"anything"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseModulesDep(tc.content)
			for _, name := range tc.present {
				assert.True(t, got[name], "expected %q to be on disk", name)
			}
			for _, name := range tc.absent {
				assert.False(t, got[name], "expected %q NOT to be on disk", name)
			}
		})
	}
}

// TestParseModulesBuiltin locks down the modules.builtin parser behind
// kernel.module.builtIn. Each non-blank line is one module path; the file
// uses the ".ko" suffix on modern kernels but historically listed bare paths
// without an extension, and dash/underscore normalization applies the same
// way as modules.dep.
func TestParseModulesBuiltin(t *testing.T) {
	cases := []struct {
		name    string
		content string
		present []string
		absent  []string
	}{
		{
			name:    "modern .ko-suffixed entries",
			content: "kernel/fs/ext4/ext4.ko\nkernel/net/ipv4/tcp_cubic.ko",
			present: []string{"ext4", "tcp_cubic"},
		},
		{
			name:    "legacy entries without a .ko extension",
			content: "kernel/fs/ext4/ext4\nkernel/drivers/char/random",
			present: []string{"ext4", "random"},
		},
		{
			name:    "dash normalization",
			content: "kernel/drivers/usb/storage/usb-storage.ko",
			present: []string{"usb_storage"},
		},
		{
			name:    "blank lines and trailing newline ignored",
			content: "\nkernel/fs/ext4/ext4.ko\n  \n",
			present: []string{"ext4"},
		},
		{
			name:    "empty content yields no modules",
			content: "",
			absent:  []string{"ext4"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseModulesBuiltin(tc.content)
			for _, name := range tc.present {
				assert.True(t, got[name], "expected %q to be builtin", name)
			}
			for _, name := range tc.absent {
				assert.False(t, got[name], "expected %q NOT to be builtin", name)
			}
		})
	}
}

// TestArchKernelMatchesRunning is the unit-level reproducer for the Arch
// half of the silent-empty bug. Read off a live Arch host: pacman reports
// `linux 7.1.9.arch1-2` while uname reports `7.1.8-arch1-3`. The two
// spellings disagree on the separator in front of the arch patch level, so
// a naive string equality reports running:false for every kernel including
// the one that is actually booted.
func TestArchKernelMatchesRunning(t *testing.T) {
	cases := []struct {
		name           string
		pkgVersion     string
		pkgName        string
		runningKernel  string
		expectedResult bool
	}{
		{
			name:           "live Arch host: newer kernel installed, older still running",
			pkgVersion:     "7.1.9.arch1-2",
			pkgName:        "linux",
			runningKernel:  "7.1.8-arch1-3",
			expectedResult: false,
		},
		{
			name:           "booted kernel matches across the dot/dash separator",
			pkgVersion:     "7.1.8.arch1-3",
			pkgName:        "linux",
			runningKernel:  "7.1.8-arch1-3",
			expectedResult: true,
		},
		{
			name:           "linux-lts carries its flavor as a release suffix",
			pkgVersion:     "6.6.67-1",
			pkgName:        "linux-lts",
			runningKernel:  "6.6.67-1-lts",
			expectedResult: true,
		},
		{
			name:           "linux-zen matches with both a patch marker and a flavor suffix",
			pkgVersion:     "6.12.4.zen1-1",
			pkgName:        "linux-zen",
			runningKernel:  "6.12.4-zen1-1-zen",
			expectedResult: true,
		},
		{
			name:           "linux-hardened matches with both a patch marker and a flavor suffix",
			pkgVersion:     "6.12.4.hardened1-1",
			pkgName:        "linux-hardened",
			runningKernel:  "6.12.4-hardened1-1-hardened",
			expectedResult: true,
		},
		{
			name:           "mainline linux does not claim a running lts kernel",
			pkgVersion:     "6.6.67-1",
			pkgName:        "linux",
			runningKernel:  "6.6.67-1-lts",
			expectedResult: false,
		},
		{
			name:           "lts does not claim a running mainline kernel",
			pkgVersion:     "7.1.8.arch1-3",
			pkgName:        "linux-lts",
			runningKernel:  "7.1.8-arch1-3",
			expectedResult: false,
		},
		{
			name:           "older lts build does not match the running one",
			pkgVersion:     "6.6.60-1",
			pkgName:        "linux-lts",
			runningKernel:  "6.6.67-1-lts",
			expectedResult: false,
		},
		{
			name:           "running-kernel string is empty (kernel.info unavailable)",
			pkgVersion:     "7.1.9.arch1-2",
			pkgName:        "linux",
			runningKernel:  "",
			expectedResult: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := archKernelMatchesRunning(tc.pkgVersion, tc.pkgName, tc.runningKernel)
			assert.Equal(t, tc.expectedResult, got)
		})
	}
}

// TestDpkgStatusIsInstalled locks down the dpkg status gate behind the
// debian branch of kernel.installed. The case that motivated it was found
// on Linux Mint: a kernel removed but not purged keeps its
// linux-image-<release> entry in /var/lib/dpkg/status with the state
// "config-files" and no files on disk, and was being reported as installed.
func TestDpkgStatusIsInstalled(t *testing.T) {
	cases := []struct {
		status    string
		installed bool
		why       string
	}{
		{"install ok installed", true, "the ordinary installed package"},
		{"deinstall ok config-files", false, "removed but not purged: the files are gone"},
		{"purge ok config-files", false, "queued for purge, files already gone"},
		{"hold ok installed", true, "a held package is still installed"},
		{"install ok half-installed", false, "an interrupted install is not bootable"},
		{"install ok unpacked", false, "unpacked but never configured"},
		{"deinstall ok not-installed", false, "explicitly not installed"},
		{"", true, "no status at all: distroless status.d stanzas omit the field, so unknown rather than removed"},
		{"install ok", true, "not a full triple: unknown rather than removed"},
	}

	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			assert.Equal(t, tc.installed, dpkgStatusIsInstalled(tc.status), tc.why)
		})
	}
}

// TestKernelFilters covers each per-family filter end to end: which
// packages it accepts as kernels, what it names them, and whether it marks
// the running one. The redhat / oraclelinux / photon / suse / debian rows
// are regression coverage that the extraction of these closures into pure
// functions did not change what they report.
func TestKernelFilters(t *testing.T) {
	cases := []struct {
		name          string
		filter        kernelFilter
		pkg           kernelPackage
		runningKernel string
		wantOK        bool
		want          KernelVersion
	}{
		// --- arch (new) ---
		{
			name:          "arch: installed mainline kernel, older one running",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux", Version: "7.1.9.arch1-2"},
			runningKernel: "7.1.8-arch1-3",
			wantOK:        true,
			want:          KernelVersion{Name: "linux", Version: "7.1.9.arch1-2", Running: false},
		},
		{
			name:          "arch: the booted kernel is marked running",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux", Version: "7.1.8.arch1-3"},
			runningKernel: "7.1.8-arch1-3",
			wantOK:        true,
			want:          KernelVersion{Name: "linux", Version: "7.1.8.arch1-3", Running: true},
		},
		{
			name:          "arch: linux-headers is not a kernel",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux-headers", Version: "7.1.9.arch1-2"},
			runningKernel: "7.1.8-arch1-3",
			wantOK:        false,
		},
		{
			name:          "arch: linux-lts-headers is not a kernel",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux-lts-headers", Version: "6.6.67-1"},
			runningKernel: "6.6.67-1-lts",
			wantOK:        false,
		},
		{
			name:          "arch: linux-api-headers is not a kernel",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux-api-headers", Version: "6.10-1"},
			runningKernel: "7.1.8-arch1-3",
			wantOK:        false,
		},
		{
			name:          "arch: linux-firmware is not a kernel",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux-firmware", Version: "20241210.20e46d0f-1"},
			runningKernel: "7.1.8-arch1-3",
			wantOK:        false,
		},
		{
			name:          "arch: an unrelated package is not a kernel",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "bash", Version: "5.2.037-1"},
			runningKernel: "7.1.8-arch1-3",
			wantOK:        false,
		},
		{
			name:          "arch: linux-lts is a kernel and is marked running",
			filter:        archKernelVersion,
			pkg:           kernelPackage{Name: "linux-lts", Version: "6.6.67-1"},
			runningKernel: "6.6.67-1-lts",
			wantOK:        true,
			want:          KernelVersion{Name: "linux-lts", Version: "6.6.67-1", Running: true},
		},

		// --- debian (status gate is new, naming is regression) ---
		{
			name:          "debian: install ok installed is accepted and marked running",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-4.19.0-13-cloud-amd64", Version: "4.19.160-2", Status: "install ok installed"},
			runningKernel: "4.19.0-13-cloud-amd64",
			wantOK:        true,
			want:          KernelVersion{Name: "4.19.0-13-cloud-amd64", Version: "4.19.160-2", Running: true},
		},
		{
			name:          "debian: an older installed image is accepted but not running",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-4.19.0-12-cloud-amd64", Version: "4.19.152-1", Status: "install ok installed"},
			runningKernel: "4.19.0-13-cloud-amd64",
			wantOK:        true,
			want:          KernelVersion{Name: "4.19.0-12-cloud-amd64", Version: "4.19.152-1", Running: false},
		},
		{
			name:          "debian: deinstall ok config-files is rejected",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-5.15.0-91-generic", Version: "5.15.0-91.101", Status: "deinstall ok config-files"},
			runningKernel: "5.15.0-94-generic",
			wantOK:        false,
		},
		{
			name:          "debian: a removed image is rejected even when it names the running kernel",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-5.15.0-94-generic", Version: "5.15.0-94.104", Status: "purge ok config-files"},
			runningKernel: "5.15.0-94-generic",
			wantOK:        false,
		},
		{
			name:          "debian: a held image is still installed",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-5.15.0-94-generic", Version: "5.15.0-94.104", Status: "hold ok installed"},
			runningKernel: "5.15.0-94-generic",
			wantOK:        true,
			want:          KernelVersion{Name: "5.15.0-94-generic", Version: "5.15.0-94.104", Running: true},
		},
		{
			name:          "debian: an image with no status is kept (distroless status.d omits it)",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-4.19.0-13-cloud-amd64", Version: "4.19.160-2", Status: ""},
			runningKernel: "4.19.0-13-cloud-amd64",
			wantOK:        true,
			want:          KernelVersion{Name: "4.19.0-13-cloud-amd64", Version: "4.19.160-2", Running: true},
		},
		{
			name:          "debian: the metapackage carries no kernel",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-image-cloud-amd64", Version: "4.19+105+deb10u8", Status: "install ok installed"},
			runningKernel: "4.19.0-13-cloud-amd64",
			wantOK:        false,
		},
		{
			name:          "debian: an unrelated package is not a kernel",
			filter:        debianKernelVersion,
			pkg:           kernelPackage{Name: "linux-headers-4.19.0-13-cloud-amd64", Version: "4.19.160-2", Status: "install ok installed"},
			runningKernel: "4.19.0-13-cloud-amd64",
			wantOK:        false,
		},

		// --- redhat (regression) ---
		{
			name:          "redhat: kernel package matches running via arch suffix",
			filter:        redhatKernelVersion,
			pkg:           kernelPackage{Name: "kernel", Version: "3.10.0-1160.11.1.el7", Arch: "x86_64"},
			runningKernel: "3.10.0-1160.11.1.el7.x86_64",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel", Version: "3.10.0-1160.11.1.el7", Running: true},
		},
		{
			name:          "redhat: an older kernel is listed but not running",
			filter:        redhatKernelVersion,
			pkg:           kernelPackage{Name: "kernel", Version: "3.10.0-1127.el7", Arch: "x86_64"},
			runningKernel: "3.10.0-1160.11.1.el7.x86_64",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel", Version: "3.10.0-1127.el7", Running: false},
		},
		{
			name:          "redhat: kernel-devel is not a kernel",
			filter:        redhatKernelVersion,
			pkg:           kernelPackage{Name: "kernel-devel", Version: "3.10.0-1160.11.1.el7", Arch: "x86_64"},
			runningKernel: "3.10.0-1160.11.1.el7.x86_64",
			wantOK:        false,
		},
		{
			name:          "redhat: amazonlinux epoch is stripped before matching",
			filter:        redhatKernelVersion,
			pkg:           kernelPackage{Name: "kernel", Version: "1:6.1.170-210.320.amzn2023", Arch: "x86_64"},
			runningKernel: "6.1.170-210.320.amzn2023.x86_64",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel", Version: "1:6.1.170-210.320.amzn2023", Running: true},
		},

		// --- oraclelinux (regression) ---
		{
			name:          "oraclelinux: the UEK kernel is recognised",
			filter:        oracleKernelVersion,
			pkg:           kernelPackage{Name: "kernel-uek", Version: "1:6.12.0-105.51.5.el9uek", Arch: "x86_64"},
			runningKernel: "6.12.0-105.51.5.el9uek.x86_64",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel-uek", Version: "1:6.12.0-105.51.5.el9uek", Running: true},
		},
		{
			name:          "oraclelinux: the stock kernel is listed but not running under UEK",
			filter:        oracleKernelVersion,
			pkg:           kernelPackage{Name: "kernel", Version: "5.14.0-427.el9", Arch: "x86_64"},
			runningKernel: "6.12.0-105.51.5.el9uek.x86_64",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel", Version: "5.14.0-427.el9", Running: false},
		},
		{
			name:          "oraclelinux: kernel-uek-devel is not a kernel",
			filter:        oracleKernelVersion,
			pkg:           kernelPackage{Name: "kernel-uek-devel", Version: "1:6.12.0-105.51.5.el9uek", Arch: "x86_64"},
			runningKernel: "6.12.0-105.51.5.el9uek.x86_64",
			wantOK:        false,
		},

		// --- photon (regression) ---
		{
			name:          "photon: the esx flavor is recognised and marked running",
			filter:        photonKernelVersion,
			pkg:           kernelPackage{Name: "linux-esx", Version: "4.19.97-1.ph3"},
			runningKernel: "4.19.97-1.ph3-esx",
			wantOK:        true,
			want:          KernelVersion{Name: "linux-esx", Version: "4.19.97-1.ph3-esx", Running: true},
		},
		{
			name:          "photon: the bare linux package is recognised",
			filter:        photonKernelVersion,
			pkg:           kernelPackage{Name: "linux", Version: "4.19.97-1.ph3"},
			runningKernel: "4.19.97-1.ph3",
			wantOK:        true,
			want:          KernelVersion{Name: "linux", Version: "4.19.97-1.ph3", Running: true},
		},
		{
			name:          "photon: a non-linux package is skipped",
			filter:        photonKernelVersion,
			pkg:           kernelPackage{Name: "bash", Version: "5.0-1.ph3"},
			runningKernel: "4.19.97-1.ph3",
			wantOK:        false,
		},

		// --- suse (regression) ---
		{
			name:          "suse: kernel-default is recognised and marked running",
			filter:        suseKernelVersion,
			pkg:           kernelPackage{Name: "kernel-default", Version: "4.12.14-122.23.1"},
			runningKernel: "4.12.14-122.23-default",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel-default", Version: "4.12.14-122.23.1-default", Running: true},
		},
		{
			name:          "suse: an older kernel-default is listed but not running",
			filter:        suseKernelVersion,
			pkg:           kernelPackage{Name: "kernel-default", Version: "4.12.14-122.20.1"},
			runningKernel: "4.12.14-122.23-default",
			wantOK:        true,
			want:          KernelVersion{Name: "kernel-default", Version: "4.12.14-122.20.1-default", Running: false},
		},
		{
			name:          "suse: the bare kernel name without a dash is skipped",
			filter:        suseKernelVersion,
			pkg:           kernelPackage{Name: "kernel", Version: "4.12.14-122.23.1"},
			runningKernel: "4.12.14-122.23-default",
			wantOK:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.filter(tc.pkg, tc.runningKernel)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// TestKernelFilterForPlatform locks down the dispatch. The rows that matter
// are the ones returning false: before this changed, a platform with no
// filter fell through a no-op closure and kernel.installed answered with an
// empty list and no error, which reads as "no kernels installed" on a host
// that is demonstrably running one.
func TestKernelFilterForPlatform(t *testing.T) {
	cases := []struct {
		name      string
		platform  *inventory.Platform
		supported bool
	}{
		{
			name:      "arch linux is now supported",
			platform:  &inventory.Platform{Name: "arch", Family: []string{"arch", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "manjaro rides the arch family",
			platform:  &inventory.Platform{Name: "manjaro", Family: []string{"arch", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "debian",
			platform:  &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "ubuntu rides the debian family",
			platform:  &inventory.Platform{Name: "ubuntu", Family: []string{"ubuntu", "debian", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "oraclelinux",
			platform:  &inventory.Platform{Name: "oraclelinux", Family: []string{"redhat", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "redhat",
			platform:  &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "amazonlinux",
			platform:  &inventory.Platform{Name: "amazonlinux", Family: []string{"linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "photon",
			platform:  &inventory.Platform{Name: "photon", Family: []string{"linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "suse",
			platform:  &inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}},
			supported: true,
		},
		{
			name:      "alpine has no kernel-package filter and must not answer with an empty list",
			platform:  &inventory.Platform{Name: "alpine", Family: []string{"linux", "unix", "os"}},
			supported: false,
		},
		{
			name:      "gentoo has no kernel-package filter and must not answer with an empty list",
			platform:  &inventory.Platform{Name: "gentoo", Family: []string{"linux", "unix", "os"}},
			supported: false,
		},
		{
			name:      "macos is not linux",
			platform:  &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}},
			supported: false,
		},
		{
			name:      "a nil platform is not supported and does not panic",
			platform:  nil,
			supported: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, ok := kernelFilterForPlatform(tc.platform)
			assert.Equal(t, tc.supported, ok)
			if tc.supported {
				assert.NotNil(t, filter)
			} else {
				assert.Nil(t, filter)
			}
		})
	}
}

// TestPlatformLabel confirms the unsupported-platform error always names
// something: the platform name when there is one, the family when the name
// is empty, so the message never trails off.
func TestPlatformLabel(t *testing.T) {
	assert.Equal(t, "arch", platformLabel(&inventory.Platform{Name: "arch", Family: []string{"arch", "linux"}}))
	assert.Equal(t, "linux/unix", platformLabel(&inventory.Platform{Family: []string{"linux", "unix"}}))
	assert.Equal(t, "unknown", platformLabel(&inventory.Platform{}))
	assert.Equal(t, "unknown", platformLabel(nil))
}

// kernelFilterForPlatform returns false for two very different situations, and
// kernelInstalledFilter is what tells them apart. Pin the distinction so the
// non-Linux contract cannot be widened into an error by accident: an SBOM run
// on macOS has always recorded an empty list here, and changing that is a
// separate decision about a platform where a package-managed kernel image is
// not a thing that exists.
func TestKernelInstalledFilterSeparatesUnsupportedFromNotLinux(t *testing.T) {
	cases := []struct {
		name     string
		platform *inventory.Platform
		// exactly one of these holds
		wantFilter bool
		wantErr    bool
	}{
		{
			name:       "a supported linux gets a filter",
			platform:   &inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}},
			wantFilter: true,
		},
		{
			name:     "a linux with no filter is an error, not an empty answer",
			platform: &inventory.Platform{Name: "alpine", Family: []string{"linux", "unix", "os"}},
			wantErr:  true,
		},
		{
			name:     "gentoo likewise",
			platform: &inventory.Platform{Name: "gentoo", Family: []string{"linux", "unix", "os"}},
			wantErr:  true,
		},
		{
			name:     "macos keeps answering with an empty list",
			platform: &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}},
		},
		{
			name:     "freebsd likewise",
			platform: &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}},
		},
		{
			name:     "aix likewise",
			platform: &inventory.Platform{Name: "aix", Family: []string{"unix", "os"}},
		},
		{
			name:     "a nil platform does not panic and is not an error",
			platform: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := kernelInstalledFilter(tc.platform)

			if tc.wantErr {
				require.Error(t, err, "a linux host is running a kernel it got from a package manager")
				assert.Contains(t, err.Error(), tc.platform.Name, "the error must name the platform")
				assert.Nil(t, filter)
				return
			}

			require.NoError(t, err)
			if tc.wantFilter {
				assert.NotNil(t, filter)
			} else {
				assert.Nil(t, filter, "a nil filter with a nil error is how installed() knows to answer []")
			}
		})
	}
}
