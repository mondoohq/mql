// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/providers/os/resources/aix"
)

type mqlAixTrustedExecutionInternal struct {
	once   sync.Once
	policy aix.TrustchkPolicy
	err    error
}

func (t *mqlAixTrustedExecution) id() (string, error) {
	return "aix.trustedExecution", nil
}

func (t *mqlAixTrustedExecution) load() (aix.TrustchkPolicy, error) {
	t.once.Do(func() {
		if t.err = requireAix(t.MqlRuntime, "aix.trustedExecution"); t.err != nil {
			return
		}
		out, _, err := runAixCommand(t.MqlRuntime, aix.TrustchkCommand)
		if err != nil {
			t.err = err
			return
		}
		t.policy = aix.ParseTrustchk(out)
	})
	return t.policy, t.err
}

func (t *mqlAixTrustedExecution) state(key string) (string, bool, error) {
	p, err := t.load()
	if err != nil {
		return "", false, err
	}
	v, ok := p.Values[key]
	return v, ok, nil
}

func (t *mqlAixTrustedExecution) enabled() (bool, error) {
	v, ok, err := t.state("TE")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.Enabled, v, ok)
}

func (t *mqlAixTrustedExecution) signatureVerification() (bool, error) {
	v, ok, err := t.state("SIG_VER")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.SignatureVerification, v, ok)
}

func (t *mqlAixTrustedExecution) checkExecutables() (bool, error) {
	v, ok, err := t.state("CHKEXEC")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.CheckExecutables, v, ok)
}

func (t *mqlAixTrustedExecution) checkSharedLibraries() (bool, error) {
	v, ok, err := t.state("CHKSHLIB")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.CheckSharedLibraries, v, ok)
}

func (t *mqlAixTrustedExecution) checkScripts() (bool, error) {
	v, ok, err := t.state("CHKSCRIPT")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.CheckScripts, v, ok)
}

func (t *mqlAixTrustedExecution) checkKernelExtensions() (bool, error) {
	v, ok, err := t.state("CHKKERNEXT")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.CheckKernelExtensions, v, ok)
}

func (t *mqlAixTrustedExecution) stopUntrusted() (string, error) {
	v, ok, err := t.state("STOP_UNTRUSTD")
	if err != nil {
		return "", err
	}
	return aix.StringField(&t.StopUntrusted, v, ok)
}

func (t *mqlAixTrustedExecution) stopOnCheckFail() (bool, error) {
	v, ok, err := t.state("STOP_ON_CHKFAIL")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.StopOnCheckFail, v, ok)
}

func (t *mqlAixTrustedExecution) lockKernelPolicies() (bool, error) {
	v, ok, err := t.state("LOCK_KERN_POLICIES")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.LockKernelPolicies, v, ok)
}

func (t *mqlAixTrustedExecution) trustedExecutionPathEnabled() (bool, error) {
	v, ok, err := t.state("TEP")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.TrustedExecutionPathEnabled, v, ok)
}

func (t *mqlAixTrustedExecution) trustedLibraryPathEnabled() (bool, error) {
	v, ok, err := t.state("TLP")
	if err != nil {
		return false, err
	}
	return aix.BoolField(&t.TrustedLibraryPathEnabled, v, ok)
}

func (t *mqlAixTrustedExecution) path(key string) ([]any, error) {
	p, err := t.load()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, d := range p.Paths[key] {
		res = append(res, d)
	}
	return res, nil
}

func (t *mqlAixTrustedExecution) trustedExecutionPath() ([]any, error) {
	return t.path("TEP")
}

func (t *mqlAixTrustedExecution) trustedLibraryPath() ([]any, error) {
	return t.path("TLP")
}
