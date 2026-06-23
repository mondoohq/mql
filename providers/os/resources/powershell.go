// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"io"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

type mqlPowershellInternal struct {
	lock       sync.Mutex
	executed   bool
	executeErr error
}

// TODO: consider sharing more code with command resource
func (c *mqlPowershell) id() (string, error) {
	return c.Script.Data, nil
}

func (c *mqlPowershell) execute() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.executed {
		return c.executeErr
	}
	c.executed = true

	conn := c.MqlRuntime.Connection.(shared.Connection)
	cmd := c.Script.Data

	// encode the powershell command
	encodedCmd := powershell.Encode(cmd)
	x, err := conn.RunCommand(encodedCmd)
	c.executeErr = err
	if err != nil {
		c.Exitcode = plugin.TValue[int64]{Error: err, State: plugin.StateIsSet}
		c.Stdout = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Stderr = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		return err
	}

	c.Exitcode = plugin.TValue[int64]{Data: int64(x.ExitStatus), State: plugin.StateIsSet}

	stdout, err := io.ReadAll(x.Stdout)
	if err != nil {
		c.Stdout = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
	} else {
		out, err := convertToUtf8Encoding(stdout)
		c.Stdout = plugin.TValue[string]{Data: out, Error: err, State: plugin.StateIsSet}
	}

	stderr, err := io.ReadAll(x.Stderr)
	if err != nil {
		c.Stderr = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
	} else {
		serr, err := convertToUtf8Encoding(stderr)
		c.Stderr = plugin.TValue[string]{Data: string(serr), Error: err, State: plugin.StateIsSet}
	}

	return nil
}

func convertToUtf8Encoding(out []byte) (string, error) {
	enc, name, _ := charset.DetermineEncoding(out, "")
	log.Trace().Str("encoding", name).Msg("check powershell results charset")
	r := transform.NewReader(bytes.NewReader(out), enc.NewDecoder())
	utf8out, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(utf8out), nil
}

func (c *mqlPowershell) stdout() (string, error) {
	return "", c.execute()
}

func (c *mqlPowershell) stderr() (string, error) {
	return "", c.execute()
}

func (c *mqlPowershell) exitcode() (int64, error) {
	return 0, c.execute()
}
