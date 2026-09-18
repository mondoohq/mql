// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

// EFI variable GUID for global Secure Boot variables.
const efiGlobalVariable = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

// Directory the kernel exposes the EFI variables under.
const efiVarsDir = "/sys/firmware/efi/efivars"

type mqlMachineSecurebootInternal struct {
	once           sync.Once
	cacheEfi       bool
	cacheEnabled   bool
	cacheSetupMode bool
	fetchErr       error
}

func (s *mqlMachineSecureboot) id() (string, error) {
	return "machine.secureboot", nil
}

// fetchStatus determines the Secure Boot state once and caches the result. On
// Windows it queries the UEFI firmware via PowerShell; on Linux it reads the
// EFI firmware variables directly.
func (s *mqlMachineSecureboot) fetchStatus() error {
	s.once.Do(func() {
		conn := s.MqlRuntime.Connection.(shared.Connection)

		if asset := conn.Asset(); asset != nil && asset.Platform != nil && asset.Platform.IsFamily("windows") {
			s.fetchErr = s.fetchWindowsStatus(conn)
			return
		}

		fs := conn.FileSystem()

		// Check if the system is booted in EFI mode by looking for /sys/firmware/efi.
		_, err := fs.Stat("/sys/firmware/efi")
		if err != nil {
			// No EFI directory means legacy BIOS boot — no Secure Boot possible.
			return
		}
		s.cacheEfi = true

		s.cacheEnabled, s.fetchErr = readEfiVarBool(conn, fs, "SecureBoot-"+efiGlobalVariable)
		if s.fetchErr != nil {
			return
		}
		s.cacheSetupMode, s.fetchErr = readEfiVarBool(conn, fs, "SetupMode-"+efiGlobalVariable)
	})
	return s.fetchErr
}

// fetchWindowsStatus queries the UEFI firmware through PowerShell. A non-UEFI
// (legacy BIOS) host yields efi=false and enabled=false rather than an error,
// because Confirm-SecureBootUEFI throws on such systems.
func (s *mqlMachineSecureboot) fetchWindowsStatus(conn shared.Connection) error {
	executedCmd, err := conn.RunCommand(powershell.Encode(windows.PSConfirmSecureBoot))
	if err != nil {
		return err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(executedCmd.Stderr)
		return errors.New("failed to determine Secure Boot state: " + string(stderr))
	}

	status, err := windows.ParseSecureBoot(executedCmd.Stdout)
	if err != nil {
		return err
	}

	s.cacheEfi = status.Efi
	s.cacheEnabled = status.Enabled
	s.cacheSetupMode = status.SetupMode
	return nil
}

// readEfiVarBool reads an EFI variable from /sys/firmware/efi/efivars/ and
// returns true if its data byte is 1. EFI variable files contain a 4-byte
// attribute header followed by the variable data.
//
// A variable that is simply absent reads as false: firmware only exposes the
// Secure Boot variables once it has them. Any other read failure is returned,
// never flattened into false -- reporting "Secure Boot is off" because the
// bytes could not be read turns an unknown into a security finding, or hides
// one.
func readEfiVarBool(conn shared.Connection, fs afero.Fs, name string) (bool, error) {
	data, err := readEfiVarBytes(conn, fs, name)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}
	return efiVarIsOn(data)
}

// readEfiVarString reads an EFI variable that holds text. A variable that is
// absent reads as an empty string, since firmware exposes a variable only once
// it has one to expose.
func readEfiVarString(conn shared.Connection, fs afero.Fs, name string) (string, error) {
	data, err := readEfiVarBytes(conn, fs, name)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", nil
	}
	return parseEfiVarString(data)
}

// readEfiVarBytes reads an EFI variable's contents, header included. A variable
// that is simply absent reads as nil with no error; any other read failure is
// returned, never flattened into an empty value.
func readEfiVarBytes(conn shared.Connection, fs afero.Fs, name string) ([]byte, error) {
	path := efiVarsDir + "/" + name

	data, err := afero.ReadFile(fs, path)
	if err == nil {
		return data, nil
	}
	if errors.Is(err, iofs.ErrNotExist) {
		return nil, nil
	}

	// efivarfs rejects the positional reads sftp issues, so over SSH every
	// variable fails with SSH_FX_FAILURE even though the file is readable.
	// Read the bytes through a command when the connection has one.
	if conn.Capabilities().Has(shared.Capability_RunCommand) {
		return readEfiVarBytesCmd(conn, path)
	}

	return nil, err
}

// efiVarIsOn reads the variable's data byte. The data portion starts after the
// 4-byte EFI variable attributes header; for SecureBoot/SetupMode it is a
// single uint8, 1 = on, 0 = off.
func efiVarIsOn(data []byte) (bool, error) {
	if len(data) < 5 {
		return false, fmt.Errorf("EFI variable is %d bytes, expected at least 5", len(data))
	}
	return data[4] == 1, nil
}

// readEfiVarBytesCmd reads an EFI variable with od(1), which prints the bytes
// as decimal so they survive the command channel intact.
func readEfiVarBytesCmd(conn shared.Connection, path string) ([]byte, error) {
	cmd, err := conn.RunCommand("od -An -tu1 -- " + shared.ShellEscape(path))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("cannot read %s: %s", path, strings.TrimSpace(string(stderr)))
	}

	stdout, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseEfiVarOdBytes(string(stdout))
}

// parseEfiVarOd turns "od -An -tu1" output into the variable's data byte.
func parseEfiVarOd(out string) (bool, error) {
	data, err := parseEfiVarOdBytes(out)
	if err != nil {
		return false, err
	}
	return efiVarIsOn(data)
}

// parseEfiVarOdBytes turns "od -An -tu1" output back into the bytes it printed.
func parseEfiVarOdBytes(out string) ([]byte, error) {
	fields := strings.Fields(out)
	data := make([]byte, 0, len(fields))
	for _, f := range fields {
		b, err := strconv.ParseUint(f, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("unexpected od output %q", f)
		}
		data = append(data, byte(b))
	}
	return data, nil
}

func (s *mqlMachineSecureboot) efi() (bool, error) {
	if err := s.fetchStatus(); err != nil {
		return false, err
	}
	return s.cacheEfi, nil
}

func (s *mqlMachineSecureboot) enabled() (bool, error) {
	if err := s.fetchStatus(); err != nil {
		return false, err
	}
	return s.cacheEnabled, nil
}

func (s *mqlMachineSecureboot) setupMode() (bool, error) {
	if err := s.fetchStatus(); err != nil {
		return false, err
	}
	return s.cacheSetupMode, nil
}
