// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sbom

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnknownFormat is returned for a document no decoder recognizes.
var ErrUnknownFormat = errors.New("not a supported SBOM format: CycloneDX (JSON, XML), SPDX 2 (JSON, tag-value), SPDX 3.0.1 (JSON-LD) or Mondoo JSON")

// RecognizedFormatError reports a document a decoder recognized as its format
// but could not read. A MultiDecoder stops at it rather than trying the
// remaining decoders, whose errors would only say the document is not their
// format.
type RecognizedFormatError struct {
	Format string
	Err    error
}

func (e *RecognizedFormatError) Error() string {
	return fmt.Sprintf("unable to read %s document: %v", e.Format, e.Err)
}

func (e *RecognizedFormatError) Unwrap() error {
	return e.Err
}

type MultiDecoder struct {
	decoders []Decoder
}

func DefaultMultiDecoder() MultiDecoder {
	return NewMultiDecoder(
		NewCycloneDX(FormatCycloneDxJSON),
		NewCycloneDX(FormatCycloneDxXML),
		NewSPDX(FormatSpdxTagValue),
		NewSPDX(FormatSpdxJSON),
		NewSPDX3(),
		New(FormatJson),
	)
}

func NewMultiDecoder(decoders ...Decoder) MultiDecoder {
	return MultiDecoder{decoders: decoders}
}

func (m MultiDecoder) Parse(r io.ReadSeeker) (*Sbom, error) {
	if len(m.decoders) == 0 {
		return nil, errors.New("no decoders available in multi decoder")
	}

	var decoderErr error
	for _, decoder := range m.decoders {
		_, err := r.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		s, err := decoder.Parse(r)
		if err == nil {
			return s, nil
		}
		if _, ok := errors.AsType[*RecognizedFormatError](err); ok {
			return nil, err
		}
		decoderErr = err
	}
	return nil, fmt.Errorf("%w (last decoder: %v)", ErrUnknownFormat, decoderErr)
}
