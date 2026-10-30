// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
)

// The parts of the native Windows implementation that need no Windows API,
// so they are tested on every platform. The calls themselves are in
// windows_native_windows.go.

// windowsImage is one process and the path of the file it runs.
type windowsImage struct {
	Pid  int64
	Path string
}

// groupWindowsImages groups processes by the file they run, comparing paths
// the way Windows does, as Group-Object does for the PowerShell path. The
// path keeps the spelling of the first process that reported it.
func groupWindowsImages(images []windowsImage, systemRoot string) []Binary {
	byKey := map[string]int{}
	var res []Binary
	for _, img := range images {
		if img.Path == "" {
			continue
		}
		key := normalizeWindowsPath(img.Path)
		i, ok := byKey[key]
		if !ok {
			i = len(res)
			byKey[key] = i
			res = append(res, Binary{
				Path:   img.Path,
				System: underWindowsDir(img.Path, systemRoot),
			})
		}
		res[i].Pids = append(res[i].Pids, img.Pid)
	}
	for i := range res {
		slices.Sort(res[i].Pids)
	}
	if res == nil {
		res = []Binary{}
	}
	return res
}

// versionInfoTranslations returns the StringFileInfo blocks to read a version
// resource's strings from: the languages its \VarFileInfo\Translation value
// lists, each a little-endian language and code page pair, then the US
// English blocks most resources carry, which is the order .NET's
// FileVersionInfo, and so Get-Item, tries them in.
func versionInfoTranslations(translation []byte) []string {
	var res []string
	for i := 0; i+4 <= len(translation); i += 4 {
		lang := binary.LittleEndian.Uint16(translation[i:])
		codePage := binary.LittleEndian.Uint16(translation[i+2:])
		res = append(res, fmt.Sprintf("%04x%04x", lang, codePage))
	}
	for _, fallback := range []string{"040904b0", "040904e4", "04090000"} {
		if !slices.Contains(res, fallback) {
			res = append(res, fallback)
		}
	}
	return res
}

// WinVerifyTrust results, the HRESULTs signature verification returns.
const (
	trustENoSignature      = 0x800B0100
	trustEProviderUnknown  = 0x800B0001
	trustEBadDigest        = 0x80096010
	cryptEBadMsg           = 0x8009200D
	trustEExplicitDistrust = 0x800B0111
)

// winTrustStatus maps a WinVerifyTrust result to a signature status the way
// Get-AuthenticodeSignature maps it to its own (GetSignatureStatusFromWin32Error
// in PowerShell), so both paths report a file alike. Like PowerShell, it
// reports a certificate that does not chain to a trusted root as unknown,
// not untrusted: only an explicitly distrusted certificate is untrusted.
func winTrustStatus(code uint32) string {
	switch code {
	case 0:
		return SignatureValid
	case trustENoSignature, trustEProviderUnknown:
		return SignatureNotSigned
	case trustEBadDigest, cryptEBadMsg:
		return SignatureInvalid
	case trustEExplicitDistrust:
		return SignatureUntrusted
	default:
		return SignatureUnknown
	}
}

// preferSignature picks a file's signature from its catalog entry (nil when
// no catalog lists the file) and its embedded signature, in the order
// Get-AuthenticodeSignature uses: a valid catalog signature first, then the
// embedded one, and a catalog signature that does not verify only for a
// file with no embedded signature. A file of Windows signed both ways
// reports the catalog's signer, "Microsoft Windows", rather than the
// embedded one, such as "Microsoft Windows Publisher".
func preferSignature(catalog *Signature, embedded Signature) Signature {
	switch {
	case catalog != nil && catalog.Status == SignatureValid:
		return *catalog
	case catalog != nil && embedded.Status == SignatureNotSigned:
		return *catalog
	default:
		return embedded
	}
}

// catalogMemberTag is the tag a signature catalog lists a file under: the
// upper-case hex of the file's hash.
func catalogMemberTag(hash []byte) string {
	return strings.ToUpper(fmt.Sprintf("%x", hash))
}
