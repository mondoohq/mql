// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

type mqlSecpolInternal struct {
	lock    sync.Mutex
	_policy *windows.Secpol
}

func (s *mqlSecpol) policy() (*windows.Secpol, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s._policy != nil {
		return s._policy, nil
	}

	out, err := s.export()
	if err != nil {
		return nil, err
	}

	policy, err := windows.ParseSecpol(strings.NewReader(out))
	if err != nil {
		return nil, err
	}
	s._policy = policy

	return policy, nil
}

// export returns the local security policy as `secedit /export` writes it. On
// a local Windows scan with MONDOO_WINDOWS_NATIVE set, it is read through the
// APIs secedit uses, which returns SIDs, so no name needs resolving either;
// otherwise, or when the native read fails, secedit runs through PowerShell.
func (s *mqlSecpol) export() (string, error) {
	if conn, ok := s.MqlRuntime.Connection.(shared.Connection); ok && shared.WindowsNative(conn) {
		out, err := windows.NativeSecpolExport()
		if err == nil {
			return out, nil
		}
		log.Debug().Err(err).Msg("secpol: native read failed, falling back to secedit")
	}
	out, err := s.runPowershell(windows.SecpolScript)
	if err != nil {
		return "", fmt.Errorf("could not run secedit: %w", err)
	}
	return out, nil
}

// resolveSids maps account names to SIDs: an API call on a local Windows scan,
// a second PowerShell command on every other transport.
func (s *mqlSecpol) resolveSids(names []string) (map[string]string, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if ok && conn.Type() == shared.Type_Local {
		if lookup, ok := lookupAccountSids(names); ok {
			return lookup, nil
		}
	}

	out, err := s.runPowershell(windows.SidLookupScript(names))
	if err != nil {
		return nil, err
	}
	return windows.ParseSidLookup(strings.NewReader(out))
}

func (s *mqlSecpol) runPowershell(script string) (string, error) {
	o, err := CreateResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(powershell.Encode(script)),
	})
	if err != nil {
		return "", err
	}

	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", exit.Error
	}
	if exit.Data != 0 {
		// both streams empty is itself a diagnosis: nothing ran
		detail := strings.TrimSpace(cmd.GetStderr().Data)
		if detail == "" {
			detail = strings.TrimSpace(cmd.GetStdout().Data)
		}
		if detail == "" {
			detail = "no output"
		}
		return "", fmt.Errorf("powershell exited with %d: %s", exit.Data, detail)
	}

	out := cmd.GetStdout()
	if out.Error != nil {
		return "", out.Error
	}
	return out.Data, nil
}

func (s *mqlSecpol) systemaccess() (map[string]any, error) {
	policy, err := s.policy()
	if err != nil {
		return nil, err
	}
	return policy.SystemAccess, nil
}

func (s *mqlSecpol) eventaudit() (map[string]any, error) {
	policy, err := s.policy()
	if err != nil {
		return nil, err
	}
	return policy.EventAudit, nil
}

func (s *mqlSecpol) registryvalues() (map[string]any, error) {
	policy, err := s.policy()
	if err != nil {
		return nil, err
	}
	return policy.RegistryValues, nil
}

func (s *mqlSecpol) privilegerights() (map[string]any, error) {
	policy, err := s.policy()
	if err != nil {
		return nil, err
	}
	return policy.PrivilegeRightSids(s.resolveSids)
}
