// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

// StreamFileAsTar task t
func StreamFileAsTar(
	path string, // file path
	stat os.FileInfo, // stat of the file
	fileReader io.ReadCloser, // raw file byte stream
	writer io.WriteCloser, // tar output stream
) {
	// close all open connection
	defer fileReader.Close()

	// stream content into the pipe
	tw := tar.NewWriter(writer)
	bufReader := bufio.NewReader(fileReader)
	defer tw.Close()
	defer writer.Close()

	// send tar header
	hdr := &tar.Header{
		Name: path,
		Mode: int64(stat.Mode()),
		Size: stat.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		fmt.Print(err)
		writer.Close()
	}

	// copy file content through the tar writer so the body is framed
	// with the rest of the archive (block padding + trailer)
	if _, err := io.Copy(tw, bufReader); err != nil {
		fmt.Print(err)
		writer.Close()
	}
}

// maxTarEntryPrealloc caps the buffer that ExtractFileFromTarStream allocates from the
// declared entry size. A container image can come from an untrusted registry, and a
// malformed header can declare a size that its data does not match. Entries above the cap
// use incremental growth instead, so the header alone cannot drive a huge allocation.
const maxTarEntryPrealloc = 64 << 20

// ExtractFileFromTarStream returns the content of path inside the tar stream.
//
// The tar header states the entry size, so the content goes into a slice of that size.
// This avoids the repeated growth of a bytes.Buffer, which allocates about twice the entry
// size. The size is only trusted up to maxTarEntryPrealloc.
//
// The loop reads the whole stream and concatenates every entry that carries the path. That
// keeps the behaviour of the earlier implementation for a tar that repeats a name.
func ExtractFileFromTarStream(path string, tarReader io.Reader) (io.Reader, error) {
	log.Debug().Str("path", path).Msg("fsutil> extract file from tar")
	var content []byte

	// read stream tar, extract on the fly and put it on stdout
	tr := tar.NewReader(tarReader)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		// log.Debug().Msgf("File %s, Size: %d", h.Name, h.Size)
		if h.Name == path {
			log.Debug().Str("path", path).Msg("fsutil> found file")
			chunk, err := readTarEntry(tr, h.Size)
			if err != nil {
				return nil, err
			}
			if content == nil {
				content = chunk
			} else {
				content = append(content, chunk...)
			}
		}
	}

	return bytes.NewReader(content), nil
}

// readTarEntry reads size bytes of the current tar entry. It allocates the exact size when
// the entry fits the prealloc cap. A larger entry grows a bytes.Buffer instead, so only the
// data that the reader really delivers is allocated.
func readTarEntry(tr *tar.Reader, size int64) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	if size <= maxTarEntryPrealloc {
		chunk := make([]byte, size)
		if _, err := io.ReadFull(tr, chunk); err != nil {
			return nil, err
		}
		return chunk, nil
	}

	var buf bytes.Buffer
	buf.Grow(maxTarEntryPrealloc)
	if _, err := io.CopyN(&buf, tr, size); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
