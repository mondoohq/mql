// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package piped

import (
	"io"
	"os"
	"runtime"

	"github.com/rs/zerolog/log"
)

func IsPipe() bool {
	// when we run the following command, the detection differs between macos and linux
	// cat options.json | mondoo scan
	// for macos, we get isNamedPipe=false, isTerminal=false, size > 0
	// but this only applies to direct terminal execution, for the same command in a bash file, we get
	// for macos bash script, we get isNamedPipe=true, isTerminal=false, size > 0
	// for linux, we get isNamedPipe=true, isTerminal=false, size=0
	// Therefore we always want to check for file size if we detected its not a terminal
	// If we are not checking for fi.Size() > 0 even a run inside of a bash script turn out
	// to be pipes, therefore we need to verify that there is some data available at the pipe
	// also read https://web.archive.org/web/20221204144717/https://flaviocopes.com/go-shell-pipes/
	fi, _ := os.Stdin.Stat()
	isTerminal := (fi.Mode() & os.ModeCharDevice) == os.ModeCharDevice
	isNamedPipe := (fi.Mode() & os.ModeNamedPipe) == os.ModeNamedPipe
	log.Debug().Bool("isTerminal", isTerminal).Bool("isNamedPipe", isNamedPipe).Int64("size", fi.Size()).Msg("check if we got the data from pipe")
	return isNamedPipe || (!isTerminal && fi.Size() > 0)
}

func LoadDataFromPipe() ([]byte, bool) {
	switch runtime.GOOS {
	case "darwin", "dragonfly", "netbsd", "solaris", "linux":
		if IsPipe() {
			// Pipe input
			log.Debug().Msg("read scan config from stdin pipe")

			// read stdin into buffer
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Error().Err(err).Msg("could not read from pipe")
				return nil, false
			}
			return data, true
		}
	}
	return nil, false
}
