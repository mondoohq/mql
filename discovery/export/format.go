// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package export

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/discovery"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/yaml"
)

// Format identifies the serialization format for discovered assets.
type Format string

const (
	FormatYAML  Format = "yaml"  // inventory document containing the discovered assets
	FormatJSON  Format = "json"  // inventory document containing the discovered assets
	FormatJSONL Format = "jsonl" // one asset per line
)

// ParseFormat normalizes and validates s. Returns an error listing the
// supported formats if s is unknown.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case FormatJSON:
		return FormatJSON, nil
	case FormatJSONL:
		return FormatJSONL, nil
	case FormatYAML:
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("unknown format %q (expected json, jsonl, yaml)", s)
	}
}

var marshalOpts = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}

// WriteAssets serializes assets into w using the requested format. Connection
// credentials are stripped before encoding so the resulting file is safe to
// share or commit.
//
// json/yaml emit a single Mondoo inventory document with the assets nested
// under .spec.assets — the result is directly re-feedable to mql via
// --inventory-file. jsonl emits one protojson-encoded asset per line.
func WriteAssets(w io.Writer, assets []*inventory.Asset, format Format) error {
	if len(assets) == 0 {
		log.Warn().Msg("no discovered assets to write")
		return nil
	}

	redacted := make([]*inventory.Asset, 0, len(assets))
	for _, a := range assets {
		redacted = append(redacted, RedactCredentials(a))
	}

	bw := bufio.NewWriter(w)

	var writeErr error
	switch format {
	case FormatJSONL:
		writeErr = writeJSONL(bw, redacted)
	case FormatJSON, FormatYAML:
		writeErr = writeInventoryDoc(bw, redacted, format)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	if writeErr != nil {
		return writeErr
	}
	return bw.Flush()
}

func writeJSONL(bw *bufio.Writer, assets []*inventory.Asset) error {
	written := 0
	for _, a := range assets {
		b, err := marshalOpts.Marshal(a)
		if err != nil {
			log.Warn().Err(err).Str("asset", a.GetName()).Msg("skipping asset")
			continue
		}
		// Compact so each record fits on one line, even if protojson chose
		// to insert whitespace.
		var line bytes.Buffer
		if err := json.Compact(&line, b); err != nil {
			line.Reset()
			line.Write(b)
		}
		if _, err := bw.Write(line.Bytes()); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
		written++
	}
	log.Info().Int("count", written).Msg("discovery complete")
	return nil
}

func writeInventoryDoc(bw *bufio.Writer, assets []*inventory.Asset, format Format) error {
	inv := &inventory.Inventory{
		Spec: &inventory.InventorySpec{Assets: assets},
	}
	data, err := marshalOpts.Marshal(inv)
	if err != nil {
		return err
	}
	if format == FormatYAML {
		// sigs.k8s.io/yaml goes through JSON internally, so proto field
		// names from protojson carry over unchanged.
		data, err = yaml.JSONToYAML(data)
		if err != nil {
			return err
		}
	}
	if _, err := bw.Write(data); err != nil {
		return err
	}
	log.Info().Int("count", len(assets)).Msg("discovery complete")
	return nil
}

// CollectExploredAssets returns Connected roots followed by any remaining
// Discovered assets, in a stable pre-order traversal. Exposed so callers can
// perform their own filtering before passing the slice to WriteAssets.
func CollectExploredAssets(e *discovery.AssetExplorer) []*inventory.Asset {
	var out []*inventory.Asset
	for _, t := range e.Connected() {
		out = append(out, t.Asset)
	}
	for _, t := range e.Discovered() {
		out = append(out, t.Asset)
	}
	return out
}

// RedactCredentials clones the asset and nils out Connections[*].Credentials.
// The original is untouched, so the explorer's tracked asset stays usable.
func RedactCredentials(a *inventory.Asset) *inventory.Asset {
	if a == nil {
		return nil
	}
	clone := proto.Clone(a).(*inventory.Asset)
	for _, c := range clone.Connections {
		c.Credentials = nil
	}
	return clone
}
