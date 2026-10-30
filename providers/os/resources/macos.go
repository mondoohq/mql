// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/macos"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

func (m *mqlMacos) computerName() (string, error) {
	// equivalent to MQL query with:
	// parse.plist("/Library/Preferences/SystemConfiguration/preferences.plist").params.System.System.ComputerName
	res, err := NewResource(m.MqlRuntime, "parse.plist", map[string]*llx.RawData{
		"path": llx.StringData("/Library/Preferences/SystemConfiguration/preferences.plist"),
	})
	if err != nil {
		return "", err
	}
	parsePlist, ok := res.(*mqlParsePlist)
	if !ok {
		return "", errors.New("could not parse plist file")
	}
	params := parsePlist.GetParams().Data.(map[string]any)
	pParams := plist.Data(params)
	name, ok := pParams.GetString("System", "System", "ComputerName")
	if !ok {
		return "", errors.New("could not get computer name")
	}
	return name, nil
}

func (m *mqlMacos) userPreferences() (map[string]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)
	preferences, err := macos.NewPreferences(conn).UserPreferences()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(preferences)
}

func (m *mqlMacos) userHostPreferences() (map[string]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)

	preferences, err := macos.NewPreferences(conn).UserHostPreferences()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(preferences)
}

func (m *mqlMacos) globalAccountPolicies() (map[string]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand("pwpolicy -getaccountpolicies")
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}

	return plist.Decode(bytes.NewReader(data))
}

// GetPreferences returns the time machine preferences
//
// NOTE: this cannot be implemented via:
// parse.plist('/Library/Preferences/com.apple.TimeMachine.plist').params['AutoBackup'] == 1
// since the binary is missing the Full Disk Access (FDA), therefore even applications with
// sudo permissions cannot access the file. Instead we need to call
// defaults read /Library/Preferences/com.apple.TimeMachine.plist which has FDA
// see https://developer.apple.com/forums/thread/108348
func (m *mqlMacosTimemachine) preferences() (map[string]any, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand("defaults read /Library/Preferences/com.apple.TimeMachine.plist")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	scanner := bufio.NewScanner(cmd.Stdout)
	for scanner.Scan() {
		line := scanner.Text()
		// skip the BackupAlias since they are not parsable when returned by the `defaults` command
		if strings.HasPrefix(strings.TrimSpace(line), "BackupAlias") {
			continue
		}
		buf.WriteString(line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return plist.Decode(bytes.NewReader(buf.Bytes()))
}

func (m *mqlMacosSystemsetup) runCmd(command string) (string, error) {
	conn := m.MqlRuntime.Connection.(shared.Connection)

	cmd, err := conn.RunCommand(command)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	// NOTE: systemsetup returns exit 0 even if it does not have enough permissions
	// Therefore we need to handle this case here
	if strings.TrimSpace(string(data)) == "You need administrator access to run this tool... exiting!" {
		return "", errors.New("macos.systemsetup needs elevated permissions")
	}

	return string(data), nil
}

func (m *mqlMacosSystemsetup) date() (string, error) {
	data, err := m.runCmd("systemsetup -getdate")
	return macos.SystemSetupCmdOutput{}.ParseDate(data), err
}

func (m *mqlMacosSystemsetup) time() (string, error) {
	data, err := m.runCmd("systemsetup -gettime")
	return macos.SystemSetupCmdOutput{}.ParseTime(data), err
}

func (m *mqlMacosSystemsetup) timeZone() (string, error) {
	data, err := m.runCmd("systemsetup -gettimezone")
	return macos.SystemSetupCmdOutput{}.ParseTimeZone(data), err
}

func (m *mqlMacosSystemsetup) usingNetworkTime() (string, error) {
	data, err := m.runCmd("systemsetup -getusingnetworktime")
	return macos.SystemSetupCmdOutput{}.ParseUsingNetworktTime(data), err
}

func (m *mqlMacosSystemsetup) networkTimeServer() (string, error) {
	data, err := m.runCmd("systemsetup -getnetworktimeserver")
	return macos.SystemSetupCmdOutput{}.ParseNetworkTimeServer(data), err
}

func (m *mqlMacosSystemsetup) sleep() ([]any, error) {
	data, err := m.runCmd("systemsetup -getsleep")
	return convert.SliceAnyToInterface(macos.SystemSetupCmdOutput{}.ParseSleep(data)), err
}

func (m *mqlMacosSystemsetup) displaySleep() (string, error) {
	data, err := m.runCmd("systemsetup -getdisplaysleep")
	return macos.SystemSetupCmdOutput{}.ParseDisplaySleep(data), err
}

func (m *mqlMacosSystemsetup) harddiskSleep() (string, error) {
	data, err := m.runCmd("systemsetup -getharddisksleep")
	return macos.SystemSetupCmdOutput{}.ParseHardDiskSleep(data), err
}

func (m *mqlMacosSystemsetup) wakeOnModem() (string, error) {
	data, err := m.runCmd("systemsetup -getwakeonmodem")
	return macos.SystemSetupCmdOutput{}.ParseWakeOnModem(data), err
}

func (m *mqlMacosSystemsetup) wakeOnNetworkAccess() (string, error) {
	data, err := m.runCmd("systemsetup -getwakeonnetworkaccess")
	return macos.SystemSetupCmdOutput{}.ParseWakeOnNetwork(data), err
}

func (m *mqlMacosSystemsetup) restartPowerFailure() (string, error) {
	data, err := m.runCmd("systemsetup -getrestartpowerfailure")
	return macos.SystemSetupCmdOutput{}.ParseRestartPowerFailure(data), err
}

func (m *mqlMacosSystemsetup) restartFreeze() (string, error) {
	data, err := m.runCmd("systemsetup -getrestartfreeze")
	return macos.SystemSetupCmdOutput{}.ParseRestartFreeze(data), err
}

func (m *mqlMacosSystemsetup) allowPowerButtonToSleepComputer() (string, error) {
	data, err := m.runCmd("systemsetup -getallowpowerbuttontosleepcomputer")
	return macos.SystemSetupCmdOutput{}.ParseAllowPowerButtonToSleep(data), err
}

func (m *mqlMacosSystemsetup) remoteLogin() (string, error) {
	data, err := m.runCmd("systemsetup -getremotelogin")
	return macos.SystemSetupCmdOutput{}.ParseRemoteLogin(data), err
}

func (m *mqlMacosSystemsetup) remoteAppleEvents() (string, error) {
	data, err := m.runCmd("systemsetup -getremoteappleevents")
	return macos.SystemSetupCmdOutput{}.ParseRemoteAppleEvents(data), err
}

func (m *mqlMacosSystemsetup) computerName() (string, error) {
	data, err := m.runCmd("systemsetup -getcomputername")
	return macos.SystemSetupCmdOutput{}.ParseComputerName(data), err
}

func (m *mqlMacosSystemsetup) localSubnetName() (string, error) {
	data, err := m.runCmd("systemsetup -getlocalsubnetname")
	return macos.SystemSetupCmdOutput{}.ParseLocalSubnetname(data), err
}

func (m *mqlMacosSystemsetup) startupDisk() (string, error) {
	data, err := m.runCmd("systemsetup -getstartupdisk")
	return data, err
}

func (m *mqlMacosSystemsetup) waitForStartupAfterPowerFailure() (string, error) {
	data, err := m.runCmd("systemsetup -getwaitforstartupafterpowerfailure")
	return macos.SystemSetupCmdOutput{}.ParseWaitForStartupAfterPowerFailure(data), err
}

func (m *mqlMacosSystemsetup) disableKeyboardWhenEnclosureLockIsEngaged() (string, error) {
	data, err := m.runCmd("systemsetup -getdisablekeyboardwhenenclosurelockisengaged")
	return macos.SystemSetupCmdOutput{}.ParseDisableKeyboardWhenEnclosureLockIsEngaged(data), err
}
