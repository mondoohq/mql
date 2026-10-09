// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package usb

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadSysfsFixture builds an in-memory /sys/bus/usb/devices from a testdata
// file with one "<entry>/<attribute>\t<contents>" line per attribute file.
func loadSysfsFixture(t *testing.T, name string) afero.Fs {
	t.Helper()
	f, err := os.Open(path.Join("testdata", name))
	require.NoError(t, err)
	defer f.Close()

	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll(LinuxSysfsDevicesDir, 0o755))
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "\t")
		require.True(t, ok, "malformed fixture line: %q", line)
		p := path.Join(LinuxSysfsDevicesDir, key)
		require.NoError(t, fs.MkdirAll(path.Dir(p), 0o755))
		// sysfs attribute files end with a newline
		require.NoError(t, afero.WriteFile(fs, p, []byte(value+"\n"), 0o444))
	}
	require.NoError(t, scanner.Err())
	return fs
}

func byLocation(devices []USBDevice) map[string]USBDevice {
	res := make(map[string]USBDevice, len(devices))
	for _, d := range devices {
		res[d.LocationID] = d
	}
	return res
}

// Captured from an Oracle Linux 9 Lima VM: two xHCI root hubs plus the
// virtual keyboard and digitizer the hypervisor attaches. Interfaces
// (1-0:1.0, 1-1:1.0, ...) must not be reported as devices.
func TestParseLinuxSysfs_LimaOL9(t *testing.T) {
	fs := loadSysfsFixture(t, "sysfs_ol9_lima.tsv")

	devices, err := ParseLinuxSysfs(fs, LinuxSysfsDevicesDir)
	require.NoError(t, err)

	got := byLocation(devices)
	assert.Len(t, devices, 4)
	assert.ElementsMatch(t, []string{"1-1", "1-2", "usb1", "usb2"}, keys(got))

	assert.Equal(t, USBDevice{
		Name:             "Virtual USB Keyboard",
		Product:          "Virtual USB Keyboard",
		VendorID:         "0x05ac",
		ProductID:        "0x8105",
		Manufacturer:     "Apple Inc.",
		DeviceClass:      "0x00",
		DeviceClassName:  "Device",
		DeviceSubClass:   "0x00",
		DeviceProtocol:   "0x00",
		LocationID:       "1-1",
		BusNumber:        "1",
		DeviceAddress:    "2",
		USBSpeed:         "12 Mbps (Full Speed)",
		BcdDevice:        "0x0000",
		FormattedVersion: "0.0",
		IsRemovable:      true,
	}, got["1-1"])

	hub := got["usb2"]
	assert.Equal(t, "xHCI Host Controller", hub.Name)
	assert.Equal(t, "0x1d6b", hub.VendorID)
	assert.Equal(t, "0x0003", hub.ProductID)
	assert.Equal(t, "Linux 6.12.0-204.92.4.2.el9uek.aarch64 xhci-hcd", hub.Manufacturer)
	assert.Equal(t, "0000:00:0b.0", hub.SerialNumber)
	assert.Equal(t, "0x09", hub.DeviceClass)
	assert.Equal(t, "Hub", hub.DeviceClassName)
	assert.Equal(t, "0x03", hub.DeviceProtocol)
	assert.Equal(t, "10 Gbps (Super Speed+)", hub.USBSpeed)
	assert.Equal(t, "0x0612", hub.BcdDevice)
	assert.Equal(t, "6.1.2", hub.FormattedVersion)
	assert.False(t, hub.IsRemovable, "root hubs are part of the host controller")
}

// Constructed physical-machine layout: a device behind an external hub
// (3-1.2), a device with no manufacturer string, low-speed and fixed ports.
func TestParseLinuxSysfs_PhysicalLayout(t *testing.T) {
	fs := loadSysfsFixture(t, "sysfs_constructed.tsv")

	devices, err := ParseLinuxSysfs(fs, LinuxSysfsDevicesDir)
	require.NoError(t, err)
	got := byLocation(devices)
	assert.ElementsMatch(t, []string{"usb3", "3-1", "3-1.2", "3-2", "3-5"}, keys(got))

	stick := got["3-1.2"]
	assert.Equal(t, "Ultra Fit", stick.Name)
	assert.Equal(t, "SanDisk", stick.Manufacturer)
	assert.Equal(t, "0x0781", stick.VendorID)
	assert.Equal(t, "0x5583", stick.ProductID)
	assert.Equal(t, "4C530001230512115385", stick.SerialNumber)
	assert.Equal(t, "5 Gbps (Super Speed)", stick.USBSpeed)
	assert.Equal(t, "1.0", stick.FormattedVersion)
	assert.True(t, stick.IsRemovable)

	mouse := got["3-2"]
	assert.Equal(t, "", mouse.Manufacturer)
	assert.Equal(t, "", mouse.SerialNumber)
	assert.Equal(t, "1.5 Mbps (Low Speed)", mouse.USBSpeed)
	assert.Equal(t, "72.0", mouse.FormattedVersion)
	assert.True(t, mouse.IsRemovable, "unknown port type defaults to removable")

	camera := got["3-5"]
	assert.Equal(t, "0xef", camera.DeviceClass)
	assert.Equal(t, "Miscellaneous", camera.DeviceClassName)
	assert.Equal(t, "0x02", camera.DeviceSubClass)
	assert.False(t, camera.IsRemovable, "fixed port")
}

// EC2 Nitro instances: Debian 12 has no /sys/bus/usb at all, RHEL 9 has an
// empty /sys/bus/usb/devices. Both mean "no USB devices", not an error.
func TestParseLinuxSysfs_NoUSB(t *testing.T) {
	t.Run("no usb subsystem", func(t *testing.T) {
		devices, err := ParseLinuxSysfs(afero.NewMemMapFs(), LinuxSysfsDevicesDir)
		require.NoError(t, err)
		assert.NotNil(t, devices)
		assert.Empty(t, devices)
	})

	t.Run("empty devices directory", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll(LinuxSysfsDevicesDir, 0o755))
		devices, err := ParseLinuxSysfs(fs, LinuxSysfsDevicesDir)
		require.NoError(t, err)
		assert.NotNil(t, devices)
		assert.Empty(t, devices)
	})
}

// An entry that is not a device (no idVendor) is skipped.
func TestParseLinuxSysfs_SkipsEntriesWithoutDescriptor(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, fs.MkdirAll(path.Join(LinuxSysfsDevicesDir, "1-1"), 0o755))
	require.NoError(t, afero.WriteFile(fs, path.Join(LinuxSysfsDevicesDir, "1-1", "busnum"), []byte("1\n"), 0o444))

	devices, err := ParseLinuxSysfs(fs, LinuxSysfsDevicesDir)
	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestFormatUSBSpeedMbps(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"1.5":      "1.5 Mbps (Low Speed)",
		"12":       "12 Mbps (Full Speed)",
		"480":      "480 Mbps (High Speed)",
		"5000":     "5 Gbps (Super Speed)",
		"10000":    "10 Gbps (Super Speed+)",
		"20000":    "20 Gbps (Super Speed+ Gen 2x2)",
		"53.3-480": "53.3-480 Mbps",
	}
	for in, want := range cases {
		assert.Equal(t, want, formatUSBSpeedMbps(in), in)
	}
}

func keys(m map[string]USBDevice) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	return res
}

func TestFormatLinuxBcdVersion(t *testing.T) {
	cases := map[string]string{
		"0000": "0.0",
		"0100": "1.0",
		"0612": "6.1.2",
		"0660": "6.6",
		"7200": "72.0",
		"1234": "12.3.4",
		"zz":   "",
	}
	for in, want := range cases {
		assert.Equal(t, want, formatLinuxBcdVersion(in), in)
	}
}
