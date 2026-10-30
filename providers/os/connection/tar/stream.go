// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tar

import (
	"errors"
	"io"
	"os"
)

// StreamToTmpFile streams a binary stream into a file. The user of this method
// is responsible for deleting the file later
func StreamToTmpFile(r io.ReadCloser, outFile *os.File) (err error) {
	// Always close both streams, even when the copy fails, and surface any
	// close error to the caller. A failed outFile.Close can mean buffered
	// data never reached disk, so it must not be silently discarded.
	defer func() { err = errors.Join(err, r.Close()) }()
	defer func() { err = errors.Join(err, outFile.Close()) }()
	_, err = io.Copy(outFile, r)
	return err
}
