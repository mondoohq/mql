// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"archive/tar"
	"bytes"
	"io"
)

// ReadFileFromTarStream returns the content of every entry in the tar stream,
// concatenated in the order the entries appear.
//
// The tar header states the size of an entry, so the buffer is grown to that
// size before the copy. Without it the buffer doubles as it fills, which
// allocates about twice the content and copies the content on every step.
//
// TODO: check size of file to ensure we do not crash the process
func ReadFileFromTarStream(r io.Reader) ([]byte, error) {
	// A container image can come from an untrusted registry, and a malformed
	// header can declare a size that the data does not match. Above this cap
	// the buffer grows on demand instead, so the header alone cannot drive a
	// huge allocation.
	const maxHeaderPrealloc = 64 << 20

	var fileBuffer bytes.Buffer

	// read stream tar, extract on the fly and put it on stdout
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if hdr.Size > 0 && hdr.Size <= maxHeaderPrealloc {
			fileBuffer.Grow(int(hdr.Size))
		}

		if _, err := io.Copy(&fileBuffer, tr); err != nil {
			return nil, err
		}
	}

	return fileBuffer.Bytes(), nil
}
