// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// Signature statuses, as binary.signatureStatus reports them.
const (
	SignatureValid     = "valid"
	SignatureNotSigned = "notSigned"
	// SignatureInvalid is a signature that does not match the file: it was
	// changed after signing.
	SignatureInvalid = "invalid"
	// SignatureUntrusted is an intact signature by a certificate Windows is
	// told not to trust, or on macOS one that does not chain to Apple's root.
	SignatureUntrusted = "untrusted"
	// SignatureAdhoc is a macOS signature without a signing identity, which
	// the linker writes on Apple silicon so the binary may run at all.
	SignatureAdhoc   = "adhoc"
	SignatureUnknown = "unknown"
)

// Signature is a binary's code signature.
type Signature struct {
	Status string
	// Certificate is the DER encoding of the signing certificate, the leaf
	// of the signer's chain. Nil when no signing identity signed the file:
	// an unsigned or ad hoc signed one.
	Certificate []byte
}

// windowsSignaturesScript verifies the Authenticode signature of every
// running executable. Get-AuthenticodeSignature also checks the signature
// catalogs, which is how most files of Windows itself are signed: the file
// carries no signature of its own.
//
// It lists the processes again rather than taking the paths from the
// listing: a command line has a length limit a long path list can exceed.
//
// The Security module is imported from the running PowerShell's own
// $PSHOME. Windows PowerShell started from PowerShell 7 inherits its
// PSModulePath, finds PowerShell 7's Microsoft.PowerShell.Security first,
// cannot load it, and has no Get-AuthenticodeSignature. That is an error
// here, not a signature status: reporting every file's signature as unknown
// would read as a fact about the files.
const windowsSignaturesScript = `[Console]::OutputEncoding = [Text.Encoding]::UTF8
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction SilentlyContinue
if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
  [Console]::Error.WriteLine('Get-AuthenticodeSignature is not available')
  exit 127
}
Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique | ForEach-Object {
  $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue
  if ($s) {
    [pscustomobject]@{
      Path = $_
      Status = [string]$s.Status
      Certificate = if ($s.SignerCertificate) { [Convert]::ToBase64String($s.SignerCertificate.RawData) } else { '' }
    }
  }
} | ConvertTo-Json`

type windowsSignature struct {
	Path   string `json:"Path"`
	Status string `json:"Status"`
	// Certificate is the signer's certificate, base64 DER
	Certificate string `json:"Certificate"`
}

// WindowsSignatures returns the signatures of the running executables,
// keyed by WindowsPathKey of their path. On the Windows host itself with
// native reads switched on (nativeWindows) it verifies paths with
// WinVerifyTrust; otherwise PowerShell verifies the executables it lists.
func WindowsSignatures(conn shared.Connection, paths []string) (map[string]Signature, error) {
	if nativeWindows(conn) {
		return nativeWindowsSignatures(paths), nil
	}
	cmd, err := runCommand(conn, powershell.Encode(windowsSignaturesScript))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not verify executable signatures")
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseWindowsSignatures(data)
}

// WindowsPathKey is the key WindowsSignatures and WindowsInstallerOwners
// return a path's answer under: Windows compares paths case-insensitively.
func WindowsPathKey(path string) string {
	return normalizeWindowsPath(path)
}

func parseWindowsSignatures(data []byte) (map[string]Signature, error) {
	res := map[string]Signature{}
	if strings.TrimSpace(string(data)) == "" {
		return res, nil
	}
	entries, err := powershell.UnmarshalList[windowsSignature](data)
	if err != nil {
		return nil, llx.MalformedData(errors.New("could not read the executable signatures: " + err.Error()))
	}
	for _, e := range entries {
		if e.Path == "" {
			continue
		}
		sig := Signature{Status: windowsSignatureStatus(e.Status)}
		if sig.Status != SignatureNotSigned && e.Certificate != "" {
			der, err := base64.StdEncoding.DecodeString(e.Certificate)
			if err != nil {
				return nil, llx.MalformedData(errors.New("could not read the signing certificate of " + e.Path + ": " + err.Error()))
			}
			sig.Certificate = der
		}
		res[WindowsPathKey(e.Path)] = sig
	}
	return res, nil
}

// windowsSignatureStatus maps System.Management.Automation.SignatureStatus.
func windowsSignatureStatus(s string) string {
	switch s {
	case "Valid":
		return SignatureValid
	case "NotSigned", "NotSupportedFileFormat":
		return SignatureNotSigned
	case "HashMismatch":
		return SignatureInvalid
	case "NotTrusted":
		return SignatureUntrusted
	default:
		// UnknownError, which includes a certificate that does not chain to
		// a trusted root, and Incompatible
		return SignatureUnknown
	}
}

// darwinSignatureBatch is how many files one codesign command verifies.
// Verifying reads the executable's code pages, which takes a second or more
// for a large one, so one command for every running binary can run past the
// command timeout and lose all of them.
const darwinSignatureBatch = 32

// darwinSignatureWorkers is how many batches are verified at once.
const darwinSignatureWorkers = 4

// DarwinSignatures verifies the code signature of each path with codesign,
// which reads the signature from the file without running it.
func DarwinSignatures(conn shared.Connection, paths []string) (map[string]Signature, error) {
	res := map[string]Signature{}
	if len(paths) == 0 {
		return res, nil
	}

	var (
		lock     sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, darwinSignatureWorkers)
	for batch := range slices.Chunk(paths, darwinSignatureBatch) {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			sigs, err := darwinSignatureBatchRun(conn, batch)
			lock.Lock()
			defer lock.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			maps.Copy(res, sigs)
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return res, nil
}

func darwinSignatureBatchRun(conn shared.Connection, paths []string) (map[string]Signature, error) {
	var b strings.Builder
	b.WriteString("command -v codesign >/dev/null 2>&1 || { echo 'codesign not found' >&2; exit " + strconv.Itoa(exitToolMissing) + "; }\n")
	// codesign writes the certificates it extracts to files, the leaf as
	// <prefix>0
	b.WriteString(`t=$(mktemp -d) || exit 1
trap 'rm -rf "$t"' EXIT
i=0
for f in`)
	for _, p := range paths {
		b.WriteString(" ")
		b.WriteString(shellQuote(p))
	}
	// one record per file: the path, the exit status of the verification,
	// the signature details codesign displays, and the signing certificate
	// in base64, each line prefixed so a record's lines stay together.
	//
	// The requirement makes the verification fail with status 3 for an
	// intact signature that does not chain to Apple's root, which a
	// self-made certificate naming any organization would otherwise pass.
	// --ignore-resources verifies the executable but not the other files of
	// its bundle: reading every resource of a large application takes
	// minutes. --strict is left out: it also fails an intact signature over
	// a Finder extended attribute on the file, which Chrome and App Store
	// applications commonly carry.
	//
	// Every file extracts its certificates under a prefix of its own, so
	// that none is left over from the one before without removing it, and
	// the details are prefixed by the shell: a few processes per file add
	// up over hundreds of files. base64 wraps its lines on Linux, where the
	// tests run the script, so tr joins them.
	b.WriteString(`; do
  i=$((i + 1))
  codesign --verify --ignore-resources -R='anchor apple generic' "$f" >/dev/null 2>&1
  printf 'P\t%s\t%s\n' "$f" "$?"
  codesign -dvv --extract-certificates="$t/$i." "$f" 2>&1 | while IFS= read -r l; do printf 'D\t%s\n' "$l"; done
  [ -s "$t/$i.0" ] && printf 'C\t%s\n' "$(base64 < "$t/$i.0" | tr -d '\n')"
done; exit 0`)

	cmd, err := runCommand(conn, b.String())
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not verify executable signatures")
	}
	return parseDarwinSignatures(cmd.Stdout), nil
}

// codesignRequirementFailed is the exit status of codesign --verify for a
// signature that is intact but does not satisfy the requirement given with -R.
const codesignRequirementFailed = "3"

// parseDarwinSignatures reads the records DarwinSignatures prints. The
// verification exit status says whether the signature is intact and anchored
// to Apple's root; the details say how it was signed, and the certificate
// who signed it. A file that no longer
// exists, because the process outlived an update that removed it, has no
// record.
func parseDarwinSignatures(r io.Reader) map[string]Signature {
	res := map[string]Signature{}
	var path, verifyStatus string
	var notSigned, adhoc, missing bool
	var certificate []byte

	flush := func() {
		if path == "" || missing {
			return
		}
		sig := Signature{}
		switch {
		case notSigned:
			sig.Status = SignatureNotSigned
		case adhoc:
			sig.Status = SignatureAdhoc
		case verifyStatus == "0":
			sig.Status = SignatureValid
		case verifyStatus == codesignRequirementFailed:
			sig.Status = SignatureUntrusted
		default:
			sig.Status = SignatureInvalid
		}
		if sig.Status != SignatureNotSigned && sig.Status != SignatureAdhoc {
			sig.Certificate = certificate
		}
		res[path] = sig
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		kind, rest, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		switch kind {
		case "P":
			flush()
			path, verifyStatus, _ = strings.Cut(rest, "\t")
			notSigned, adhoc, missing, certificate = false, false, false, nil
		case "D":
			switch {
			case strings.Contains(rest, "code object is not signed at all"):
				notSigned = true
			case strings.HasSuffix(rest, ": No such file or directory"):
				missing = true
			case rest == "Signature=adhoc":
				adhoc = true
			}
		case "C":
			// a certificate that does not decode is left out rather than
			// failing every file's signature
			if der, err := base64.StdEncoding.DecodeString(rest); err == nil {
				certificate = der
			}
		}
	}
	flush()
	return res
}
