// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"gopkg.in/yaml.v3"
)

// provenance exposes the chart's PGP provenance (.prov), parsed offline.
// It's populated only for a chart fetched from a remote source that ships
// a provenance file; charts loaded from a local path and subcharts carry
// none, so this returns null for them.
func (c *mqlHelmChart) provenance() (*mqlHelmChartProvenanceRecord, error) {
	if len(c.provData) == 0 {
		c.Provenance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	info := parseProvenance(c.provData, c.archiveSHA256)

	res, err := CreateResource(c.MqlRuntime, "helm.chart.provenanceRecord", map[string]*llx.RawData{
		"__id":          llx.StringData(c.idKey + "/provenance"),
		"signed":        llx.BoolData(info.signed),
		"digest":        llx.StringData(info.digest),
		"digestMatches": llx.BoolData(info.digestMatches),
		"keyId":         llx.StringData(info.keyId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHelmChartProvenanceRecord), nil
}

// provenanceInfo holds the fields parsed out of a .prov file.
type provenanceInfo struct {
	signed        bool
	digest        string
	digestMatches bool
	keyId         string
}

// parseProvenance decodes a Helm .prov file. The file is a PGP clear-signed
// message whose body is the chart's Chart.yaml followed by a "files:" block
// mapping each packaged file to its sha256. Parsing is offline: the issuer
// key ID comes from the signature packet, and digestMatches is computed by
// comparing the recorded digest against the archive's locally computed
// sha256 (no keyring, no registry).
func parseProvenance(provData []byte, archiveSHA256 string) provenanceInfo {
	var info provenanceInfo

	block, _ := clearsign.Decode(provData)
	if block == nil {
		// Not a parseable clear-signed message; nothing we can report.
		return info
	}

	info.signed = block.ArmoredSignature != nil
	info.keyId = provenanceKeyID(block)
	info.digest = provenanceDigest(block.Plaintext)
	if info.digest != "" && archiveSHA256 != "" {
		info.digestMatches = strings.EqualFold(strings.TrimPrefix(info.digest, "sha256:"), archiveSHA256)
	}
	return info
}

// provenanceKeyID reads the 16-hex issuer key ID from the signature packet,
// identifying the signer without needing their public key. Empty when the
// signature can't be parsed or carries no issuer.
func provenanceKeyID(block *clearsign.Block) string {
	if block.ArmoredSignature == nil {
		return ""
	}
	reader := packet.NewReader(block.ArmoredSignature.Body)
	for {
		p, err := reader.Next()
		if err != nil {
			return ""
		}
		if sig, ok := p.(*packet.Signature); ok && sig.IssuerKeyId != nil {
			return fmt.Sprintf("%016X", *sig.IssuerKeyId)
		}
	}
}

// provenanceDigest extracts the chart archive's recorded sha256 from the
// signed "files:" block. Helm builds the signed message as the chart
// metadata, a "\n...\n" separator, then the sums document, and parses the
// halves separately rather than as a YAML stream — so we split on the same
// separator and inspect each part. It returns the .tgz entry's digest,
// falling back to the first recorded file when no .tgz entry is present.
func provenanceDigest(plaintext []byte) string {
	for part := range bytes.SplitSeq(plaintext, []byte("\n...\n")) {
		var doc map[string]any
		if err := yaml.Unmarshal(part, &doc); err != nil {
			continue
		}
		files, ok := doc["files"].(map[string]any)
		if !ok {
			continue
		}
		// Prefer the .tgz entry; fall back to the lexicographically smallest
		// key so the result is deterministic regardless of map iteration order.
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		var first string
		for _, name := range names {
			s, _ := files[name].(string)
			if strings.HasSuffix(name, ".tgz") {
				return s
			}
			if first == "" {
				first = s
			}
		}
		if first != "" {
			return first
		}
	}
	return ""
}
