// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package runningbinaries

import (
	"errors"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// nativeListWindows lists the running executables with the Win32 API: the
// process snapshot, each process's image path from
// QueryFullProcessImageName, and the version resource from
// GetFileVersionInfo. ok is false when the snapshot cannot be taken, and the
// caller asks PowerShell instead.
func nativeListWindows() ([]Binary, bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, false
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var images []windowsImage
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		// The System Idle Process and System have no image file, and a
		// process that exited since the snapshot has none to read either.
		if path, ok := processImagePath(entry.ProcessID); ok {
			images = append(images, windowsImage{Pid: int64(entry.ProcessID), Path: path})
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, false
	}

	systemRoot, _ := windows.GetSystemWindowsDirectory()
	bins := groupWindowsImages(images, systemRoot)
	for i := range bins {
		bins[i].VersionInfo = nativeVersionInfo(bins[i].Path)
	}
	return bins, true
}

// processImagePath is the Win32 path of the file a process runs. A process
// the agent may not query, even with the limited query right, is skipped.
func processImagePath(pid uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil || size == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf[:size]), true
}

// nativeVersionInfo reads the strings of a file's version resource, nil when
// it has none.
func nativeVersionInfo(path string) *PEVersionInfo {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return nil
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return nil
	}
	block := unsafe.Pointer(&buf[0])

	var translation []byte
	var p unsafe.Pointer
	var n uint32
	if windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&p), &n) == nil && n > 0 {
		translation = unsafe.Slice((*byte)(p), n)
	}

	for _, lang := range versionInfoTranslations(translation) {
		vi := PEVersionInfo{
			ProductName:     versionString(block, lang, "ProductName"),
			ProductVersion:  versionString(block, lang, "ProductVersion"),
			FileVersion:     versionString(block, lang, "FileVersion"),
			CompanyName:     versionString(block, lang, "CompanyName"),
			FileDescription: versionString(block, lang, "FileDescription"),
		}
		if vi != (PEVersionInfo{}) {
			return &vi
		}
	}
	return nil
}

func versionString(block unsafe.Pointer, lang, name string) string {
	var p unsafe.Pointer
	var n uint32
	if err := windows.VerQueryValue(block, `\StringFileInfo\`+lang+`\`+name, unsafe.Pointer(&p), &n); err != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(windows.UTF16PtrToString((*uint16)(p)))
}

var (
	modwintrust = windows.NewLazySystemDLL("wintrust.dll")

	procCryptCATAdminAcquireContext2         = modwintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFileHandle2 = modwintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = modwintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext       = modwintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext   = modwintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext          = modwintrust.NewProc("CryptCATAdminReleaseContext")
	procWTHelperProvDataFromStateData        = modwintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = modwintrust.NewProc("WTHelperGetProvSignerFromChain")
)

// wintrustCatalogInfo is WINTRUST_CATALOG_INFO.
type wintrustCatalogInfo struct {
	Size                   uint32
	CatalogVersion         uint32
	CatalogFilePath        *uint16
	MemberTag              *uint16
	MemberFilePath         *uint16
	MemberFile             windows.Handle
	CalculatedFileHash     *byte
	CalculatedFileHashSize uint32
	CatalogContext         uintptr
	CatAdmin               windows.Handle
}

// catalogInfo is CATALOG_INFO.
type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

// cryptProviderSgnr is the head of CRYPT_PROVIDER_SGNR, up to the signer's
// certificate chain.
type cryptProviderSgnr struct {
	Size           uint32
	VerifyAsOf     windows.Filetime
	CertChainCount uint32
	CertChain      *cryptProviderCert
}

// cryptProviderCert is the head of CRYPT_PROVIDER_CERT.
type cryptProviderCert struct {
	Size uint32
	Cert *windows.CertContext
}

// cPointer turns an address a Windows API returned, memory that Windows and
// not the Go runtime owns, into a typed pointer.
func cPointer[T any](addr uintptr) *T {
	return *(**T)(unsafe.Pointer(&addr))
}

// nativeWindowsSignatures verifies each file's Authenticode signature with
// WinVerifyTrust, keyed by WindowsPathKey.
func nativeWindowsSignatures(paths []string) map[string]Signature {
	res := make(map[string]Signature, len(paths))
	for _, p := range paths {
		res[WindowsPathKey(p)] = nativeSignature(p)
	}
	return res
}

// nativeSignature verifies a file's Authenticode signature: its entry in a
// system catalog and the signature embedded in the file, and picks between
// them the way Get-AuthenticodeSignature does (preferSignature). Most files
// of Windows itself are signed only through a catalog, and many carry both.
// Revocation is not checked and nothing is fetched from the network.
func nativeSignature(path string) Signature {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Signature{Status: SignatureUnknown}
	}

	var catalog *Signature
	if sig, ok := catalogSignature(path, path16); ok {
		catalog = &sig
	}

	fileInfo := windows.WinTrustFileInfo{FilePath: path16}
	fileInfo.Size = uint32(unsafe.Sizeof(fileInfo))
	code, cert := verifyTrust(windows.WTD_CHOICE_FILE, unsafe.Pointer(&fileInfo))
	runtime.KeepAlive(path16)

	return preferSignature(catalog, newSignature(code, cert))
}

func newSignature(code uint32, cert []byte) Signature {
	sig := Signature{Status: winTrustStatus(code)}
	if sig.Status != SignatureNotSigned {
		sig.Certificate = cert
	}
	return sig
}

// verifyTrust runs WinVerifyTrust on a file or catalog member and reads the
// signer's certificate from the verification state before closing it.
func verifyTrust(choice uint32, subject unsafe.Pointer) (code uint32, cert []byte) {
	data := windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: subject,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	data.Size = uint32(unsafe.Sizeof(data))

	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	code = hresult(err)
	cert = stateCertificate(data.StateData)

	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	return code, cert
}

func hresult(err error) uint32 {
	if err == nil {
		return 0
	}
	var errno windows.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0xFFFFFFFF
}

// stateCertificate copies the DER encoding of the first signer's
// certificate out of a WinVerifyTrust state, which frees it on close.
func stateCertificate(state windows.Handle) []byte {
	if state == 0 {
		return nil
	}
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return nil
	}
	sgnrAddr, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sgnrAddr == 0 {
		return nil
	}
	sgnr := cPointer[cryptProviderSgnr](sgnrAddr)
	if sgnr.CertChainCount == 0 || sgnr.CertChain == nil || sgnr.CertChain.Cert == nil {
		return nil
	}
	cert := sgnr.CertChain.Cert
	if cert.EncodedCert == nil || cert.Length == 0 {
		return nil
	}
	return slices.Clone(unsafe.Slice(cert.EncodedCert, cert.Length))
}

// catalogSignature finds the system catalog that lists the file's hash and
// verifies the file as a member of it. Catalogs list a file by its SHA-256
// hash, older ones by its SHA-1 hash, so both are tried.
func catalogSignature(path string, path16 *uint16) (Signature, bool) {
	f, err := windows.CreateFile(path16, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return Signature{}, false
	}
	defer windows.CloseHandle(f)

	sha256, _ := windows.UTF16PtrFromString("SHA256")
	for _, alg := range []*uint16{sha256, nil} {
		if sig, ok := catalogSignatureWith(alg, f, path16); ok {
			return sig, true
		}
	}
	return Signature{}, false
}

func catalogSignatureWith(alg *uint16, f windows.Handle, path16 *uint16) (Signature, bool) {
	var admin windows.Handle
	if r, _, _ := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(alg)), 0, 0); r == 0 {
		return Signature{}, false
	}
	defer procCryptCATAdminReleaseContext.Call(uintptr(admin), 0) //nolint:errcheck

	// the handle is hashed once per algorithm, and hashing a file that is
	// no PE image reads it to the end
	if _, err := windows.Seek(f, 0, 0); err != nil {
		return Signature{}, false
	}
	hash := make([]byte, 64)
	hashSize := uint32(len(hash))
	if r, _, _ := procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(admin), uintptr(f),
		uintptr(unsafe.Pointer(&hashSize)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return Signature{}, false
	}
	hash = hash[:hashSize]

	catInfoHandle, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(uintptr(admin),
		uintptr(unsafe.Pointer(&hash[0])), uintptr(hashSize), 0, 0)
	if catInfoHandle == 0 {
		return Signature{}, false
	}
	defer procCryptCATAdminReleaseCatalogContext.Call(uintptr(admin), catInfoHandle, 0) //nolint:errcheck

	var info catalogInfo
	info.Size = uint32(unsafe.Sizeof(info))
	if r, _, _ := procCryptCATCatalogInfoFromContext.Call(catInfoHandle, uintptr(unsafe.Pointer(&info)), 0); r == 0 {
		return Signature{}, false
	}

	tag16, err := windows.UTF16PtrFromString(catalogMemberTag(hash))
	if err != nil {
		return Signature{}, false
	}
	member := wintrustCatalogInfo{
		CatalogFilePath:        &info.CatalogFile[0],
		MemberTag:              tag16,
		MemberFilePath:         path16,
		MemberFile:             f,
		CalculatedFileHash:     &hash[0],
		CalculatedFileHashSize: hashSize,
		CatAdmin:               admin,
	}
	member.Size = uint32(unsafe.Sizeof(member))
	code, cert := verifyTrust(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(&member))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(tag16)
	runtime.KeepAlive(hash)
	return newSignature(code, cert), true
}
