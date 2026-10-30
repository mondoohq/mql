// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestParseLinuxKernelArguments(t *testing.T) {
	// testing output of /proc/cmdline

	output := "BOOT_IMAGE=/boot/vmlinuz-3.10.0-1127.19.1.el7.x86_64 root=UUID=ff6cbb65-ccab-489c-91a5-61b9b09e4d49 ro crashkernel=auto console=ttyS0,38400n8 elevator=noop\n"
	args, err := ParseLinuxKernelArguments(strings.NewReader(output))
	require.NoError(t, err)
	assert.Equal(t, "/boot/vmlinuz-3.10.0-1127.19.1.el7.x86_64", args.Path)
	assert.Equal(t, "UUID=ff6cbb65-ccab-489c-91a5-61b9b09e4d49", args.Device)
	assert.Equal(t, map[string]string{"console": "ttyS0,38400n8", "crashkernel": "auto", "elevator": "noop", "ro": ""}, args.Arguments)

	output = "earlyprintk=serial console=ttyS0 console=ttyS1 page_poison=1 vsyscall=emulate panic=1 nospec_store_bypass_disable noibrs noibpb no_stf_barrier mitigations=off\n"
	args, err = ParseLinuxKernelArguments(strings.NewReader(output))
	require.NoError(t, err)
	assert.Equal(t, "", args.Path)
	assert.Equal(t, "", args.Device)
	assert.Equal(t, map[string]string{"console": "ttyS1", "earlyprintk": "serial", "mitigations": "off", "no_stf_barrier": "", "noibpb": "", "noibrs": "", "nospec_store_bypass_disable": "", "page_poison": "1", "panic": "1", "vsyscall": "emulate"}, args.Arguments)
}

// /proc/cmdline from the sweep hosts. Fedora Cloud 44 puts root= after other
// parameters and has rootflags=subvol=root.
func TestParseLinuxKernelArguments_Fedora(t *testing.T) {
	output := "BOOT_IMAGE=(hd0,gpt3)/boot/vmlinuz-7.2.8-200.fc44.x86_64 no_timer_check console=tty1 console=ttyS0,115200n8 systemd.firstboot=off root=UUID=b92ff89a-a848-4a55-8968-cc0fb8e60105 rootflags=subvol=root\n"
	args, err := ParseLinuxKernelArguments(strings.NewReader(output))
	require.NoError(t, err)
	assert.Equal(t, "(hd0,gpt3)/boot/vmlinuz-7.2.8-200.fc44.x86_64", args.Path)
	assert.Equal(t, "UUID=b92ff89a-a848-4a55-8968-cc0fb8e60105", args.Device)
	assert.Equal(t, map[string]string{
		"no_timer_check":    "",
		"console":           "ttyS0,115200n8",
		"systemd.firstboot": "off",
		"rootflags":         "subvol=root",
	}, args.Arguments)
}

func TestParseLinuxKernelArguments_EqualsInValue(t *testing.T) {
	// Alma 9 sweep host: crashkernel ranges, root right after BOOT_IMAGE
	output := "BOOT_IMAGE=(hd0,gpt3)/vmlinuz-5.14.0-687.42.1.el9_8.x86_64 root=UUID=42970503-2aa0-4b22-a35f-aad29481a24a console=tty0 console=ttyS0,115200n8 net.ifnames=0 rd.blacklist=nouveau nvme_core.io_timeout=4294967295 crashkernel=1G-2G:192M,2G-64G:256M,64G-:512M\n"
	args, err := ParseLinuxKernelArguments(strings.NewReader(output))
	require.NoError(t, err)
	assert.Equal(t, "UUID=42970503-2aa0-4b22-a35f-aad29481a24a", args.Device)
	assert.Equal(t, "1G-2G:192M,2G-64G:256M,64G-:512M", args.Arguments["crashkernel"])
	assert.Equal(t, "nouveau", args.Arguments["rd.blacklist"])
	assert.NotContains(t, args.Arguments, "root")

	// a value that carries '=' itself, and grub's quoting of a value with spaces
	output = "root=LABEL=rootfs ro dyndbg=\"file drivers/usb/* +p\" \"acpi_osi=Windows 2020\"\n"
	args, err = ParseLinuxKernelArguments(strings.NewReader(output))
	require.NoError(t, err)
	assert.Equal(t, "", args.Path)
	assert.Equal(t, "LABEL=rootfs", args.Device)
	assert.Equal(t, map[string]string{
		"ro":       "",
		"dyndbg":   "file drivers/usb/* +p",
		"acpi_osi": "Windows 2020",
	}, args.Arguments)
}
