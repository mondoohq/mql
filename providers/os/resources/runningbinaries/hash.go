// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// HashOnAsset reports whether the binaries' digests are computed on the
// asset by a command rather than by reading the files through the
// connection: a remote scan would otherwise copy every binary to the
// scanner, which over SSH takes a round trip for every piece of a file.
func HashOnAsset(conn shared.Connection) bool {
	return conn.Type() != shared.Type_Local && conn.Capabilities().Has(shared.Capability_RunCommand)
}

// SHA256s computes the SHA-256 digest of every binary on the asset, in one
// command, keyed by the binary's path. A binary whose file the command could
// not read has no entry, and is left to SHA256 to tell why.
func SHA256s(conn shared.Connection, bins []Binary) (map[string]string, error) {
	if len(bins) == 0 {
		return map[string]string{}, nil
	}
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil && asset.Platform.IsFamily("windows") {
		byKey, err := windowsSHA256s(conn)
		if err != nil {
			return nil, err
		}
		res := map[string]string{}
		for _, bin := range bins {
			if digest, ok := byKey[WindowsPathKey(bin.Path)]; ok {
				res[bin.Path] = digest
			}
		}
		return res, nil
	}
	return unixSHA256s(conn, bins)
}

// unixSHA256s runs sha256sum, or shasum where it is missing, as on macOS
// before 14. The running file of a binary an upgrade replaced is hashed
// through /proc.
func unixSHA256s(conn shared.Connection, bins []Binary) (map[string]string, error) {
	back := map[string]string{}
	var b strings.Builder
	b.WriteString("if command -v sha256sum >/dev/null 2>&1; then h=sha256sum; elif command -v shasum >/dev/null 2>&1; then h='shasum -a 256'; else echo 'sha256sum not found' >&2; exit 127; fi\n$h")
	for _, bin := range bins {
		file := bin.Path
		if bin.ContentPath != "" {
			file = bin.ContentPath
		}
		back[file] = bin.Path
		b.WriteString(" " + shellQuote(file))
	}
	b.WriteString(" 2>/dev/null; exit 0")

	cmd, err := runCommand(conn, b.String())
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not compute the digests of the running binaries")
	}
	res := map[string]string{}
	for file, digest := range parseSHA256Sums(cmd.Stdout) {
		if p, ok := back[file]; ok {
			res[p] = digest
		}
	}
	return res, nil
}

// parseSHA256Sums reads "<digest>  <file>" lines. GNU sha256sum escapes a
// file name with a backslash or a newline in it and marks the line with a
// leading backslash.
func parseSHA256Sums(r io.Reader) map[string]string {
	res := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		escaped := strings.HasPrefix(line, `\`)
		line = strings.TrimPrefix(line, `\`)
		digest, file, ok := strings.Cut(line, " ")
		if !ok || len(digest) != 64 {
			continue
		}
		// text mode separates with two spaces, binary mode with " *"
		file = strings.TrimPrefix(strings.TrimPrefix(file, " "), "*")
		if escaped {
			file = strings.NewReplacer(`\\`, `\`, `\n`, "\n").Replace(file)
		}
		res[file] = strings.ToLower(digest)
	}
	return res
}

// windowsSHA256Script hashes the executable of each running process. It
// lists the processes itself, as the signature script does, so that the
// paths need not travel on the command line.
const windowsSHA256Script = `[Console]::OutputEncoding = [Text.Encoding]::UTF8
$res = @(Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique | ForEach-Object {
  $h = Get-FileHash -Algorithm SHA256 -LiteralPath $_ -ErrorAction SilentlyContinue
  if ($h) { [pscustomobject]@{ Path = $_; Hash = $h.Hash } }
})
ConvertTo-Json -InputObject $res -Compress`

type windowsFileHash struct {
	Path string `json:"Path"`
	Hash string `json:"Hash"`
}

// windowsSHA256s returns the digests keyed by WindowsPathKey.
func windowsSHA256s(conn shared.Connection) (map[string]string, error) {
	cmd, err := runCommand(conn, powershell.Encode(windowsSHA256Script))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not compute the digests of the running binaries")
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	return parseWindowsFileHashes(data)
}

func parseWindowsFileHashes(data []byte) (map[string]string, error) {
	res := map[string]string{}
	if strings.TrimSpace(string(data)) == "" {
		return res, nil
	}
	entries, err := powershell.UnmarshalList[windowsFileHash](data)
	if err != nil {
		return nil, llx.MalformedData(errors.New("could not read the digests of the running binaries: " + err.Error()))
	}
	for _, e := range entries {
		if e.Path != "" && len(e.Hash) == 64 {
			res[WindowsPathKey(e.Path)] = strings.ToLower(e.Hash)
		}
	}
	return res, nil
}
