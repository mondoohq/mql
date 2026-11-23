// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const geliListCommand = "geli list"

// geliProvider is one GELI provider from the output of geliListCommand.
type geliProvider struct {
	name                    string
	device                  string
	encryptionAlgorithm     string
	keyLength               int64
	authenticationAlgorithm string
	state                   string
}

// parseGeliList parses the output of `geli list`: one block per geom that
// starts with "Geom name:", followed by the geom's configuration, then a
// numbered "Providers:" and "Consumers:" list. The device is the first
// consumer, the provider the encrypted one is attached to.
func parseGeliList(out string) ([]geliProvider, error) {
	res := []geliProvider{}
	var cur *geliProvider
	section := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if name, ok := strings.CutPrefix(trimmed, "Geom name:"); ok {
			res = append(res, geliProvider{name: strings.TrimSpace(name)})
			cur = &res[len(res)-1]
			section = ""
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("could not parse geli list output: unexpected line %q", trimmed)
		}
		switch trimmed {
		case "Providers:", "Consumers:":
			section = trimmed
			continue
		}

		// "1. Name: ada0p3" opens an entry of the Providers or Consumers list
		if section == "Consumers:" && cur.device == "" {
			if _, entry, ok := strings.Cut(trimmed, ". "); ok {
				if name, ok := strings.CutPrefix(entry, "Name:"); ok {
					cur.device = strings.TrimSpace(name)
				}
			}
			continue
		}
		if section != "" {
			continue
		}

		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "EncryptionAlgorithm":
			cur.encryptionAlgorithm = value
		case "KeyLength":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("could not parse geli key length %q of %s", value, cur.name)
			}
			cur.keyLength = n
		case "AuthenticationAlgorithm":
			cur.authenticationAlgorithm = value
		case "State":
			cur.state = value
		}
	}
	return res, nil
}

// geliClassNotLoaded reports whether geli failed because the g_eli kernel
// class is not loaded. geom(8) refuses the list command then ("Command 'list'
// not available; try 'load' first."), and older releases, as well as the
// race where the class goes away mid-run, say the class was not found.
func geliClassNotLoaded(stderr string) bool {
	return strings.Contains(stderr, "not available; try 'load' first") ||
		strings.Contains(stderr, "Class 'ELI' not found") ||
		strings.Contains(stderr, "Class ELI not found")
}

func (g *mqlGeli) id() (string, error) {
	return "geli", nil
}

func (g *mqlGeli) providers() ([]any, error) {
	conn := g.MqlRuntime.Connection.(shared.Connection)
	if pf := conn.Asset().GetPlatform(); pf == nil || pf.Name != "freebsd" {
		return nil, llx.NotApplicable(errors.New("geli is only available on FreeBSD"))
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, llx.NotApplicable(errors.New("geli needs a running system, and this connection cannot run commands"))
	}

	cmd, err := runSbinCommand(g.MqlRuntime, geliListCommand)
	if err != nil {
		return nil, err
	}
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	if exit.Data != 0 {
		stderr := strings.TrimSpace(cmd.GetStderr().Data)
		if geliClassNotLoaded(stderr) {
			return []any{}, nil
		}
		if stderr == "" {
			stderr = strings.TrimSpace(cmd.GetStdout().Data)
		}
		return nil, fmt.Errorf("geli list failed (exit %d): %s", exit.Data, stderr)
	}

	records, err := parseGeliList(cmd.GetStdout().Data)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(records))
	for _, rec := range records {
		o, err := CreateResource(g.MqlRuntime, ResourceGeliProvider, map[string]*llx.RawData{
			"__id":                    llx.StringData("geli.provider/" + rec.name),
			"name":                    llx.StringData(rec.name),
			"device":                  llx.StringData(rec.device),
			"encryptionAlgorithm":     llx.StringData(rec.encryptionAlgorithm),
			"keyLength":               llx.IntData(rec.keyLength),
			"authenticationAlgorithm": llx.StringData(rec.authenticationAlgorithm),
			"state":                   llx.StringData(rec.state),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}
