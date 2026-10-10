// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import "strings"

// States of the password attribute of an /etc/security/passwd record.
const (
	StateHashed   = "hashed"
	StateEmpty    = "empty"
	StateDisabled = "disabled"
	StateMissing  = "missing"
)

// PasswordState classifies the password attribute of a passwd record and
// names its hashing scheme, without returning the hash:
//
//	{ssha512}06$...  hashed, ssha512
//	sv/7zTKlUuNKg    hashed, crypt (13 characters, legacy DES)
//	*                disabled (no password login)
//	(empty)          empty (no password asked)
func PasswordState(v string, set bool) (string, string) {
	if !set {
		return StateMissing, ""
	}
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return StateEmpty, ""
	case v == "*":
		return StateDisabled, ""
	case strings.HasPrefix(v, "{"):
		if end := strings.IndexByte(v, '}'); end > 1 {
			return StateHashed, strings.ToLower(v[1:end])
		}
		return StateHashed, ""
	case len(v) == 13:
		// Every scheme newer than DES crypt writes its {scheme} prefix, so a
		// bare 13-character value is the legacy crypt form.
		return StateHashed, "crypt"
	}
	return StateHashed, ""
}
