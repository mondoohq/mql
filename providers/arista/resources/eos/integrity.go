// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import "github.com/aristanetworks/goeapi"

// Extension is one installed EOS extension.
//
// Extensions are RPM packages installed onto the switch, which is how
// third-party and in-house software gets onto EOS. Each one is code running
// on a network device outside the vendor image, so the installed set is a
// supply-chain surface worth inventorying, and an extension present but not
// installed at boot is worth explaining.
type Extension struct {
	Version string `json:"version"`
	Release string `json:"release"`
	// Presence is whether the extension file is on the device, for example
	// "present".
	Presence string `json:"presence"`
	// Status is whether it is activated, for example "installed" or
	// "notInstalled".
	Status string `json:"status"`
	// NumPackages is how many RPMs the extension contains.
	NumPackages int64 `json:"numPackages"`
	// Error reports a problem with the extension.
	Error bool `json:"error"`
}

type showExtensions struct {
	Extensions map[string]Extension `json:"extensions"`
	// ExtensionStoredDir is where extension files are kept.
	ExtensionStoredDir string `json:"extensionStoredDir"`
}

func (s *showExtensions) GetCmd() string {
	return "show extensions"
}

// Extensions returns the installed EOS extensions keyed by name.
func (eos *Eos) Extensions() (*showExtensions, error) {
	shRsp := &showExtensions{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if err := handle.AddCommand(shRsp); err != nil {
		return nil, err
	}
	if err := handle.Call(); err != nil {
		return nil, err
	}

	return shRsp, nil
}

// showBootConfig is the boot configuration: which image the device loads on
// its next boot, and the console speed it comes up with.
type showBootConfig struct {
	SoftwareImage string `json:"softwareImage"`
	ConsoleSpeed  int64  `json:"consoleSpeed"`
	MemoryTest    string `json:"memoryTest"`
}

func (s *showBootConfig) GetCmd() string {
	return "show boot-config"
}

// BootConfig returns the configured boot image and console settings.
func (eos *Eos) BootConfig() (*showBootConfig, error) {
	shRsp := &showBootConfig{}

	handle, err := eos.node.GetHandle("json")
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if err := handle.AddCommand(shRsp); err != nil {
		return nil, err
	}
	if err := handle.Call(); err != nil {
		return nil, err
	}

	return shRsp, nil
}

// StartupConfig returns the saved configuration the device loads on boot.
// StartupConfig returns the configuration the device would come back with
// after a reload. See RunningConfig for why the error is not discarded.
func (eos *Eos) StartupConfig() (string, error) {
	return configText(eos.node, goeapi.StartupConfig, "")
}
