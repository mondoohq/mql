// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package domainlist

import (
	"bufio"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func Parse(input io.Reader) (*Inventory, error) {
	inventory := &Inventory{}
	scanner := bufio.NewScanner(input)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		inventory.Hosts = append(inventory.Hosts, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return inventory, nil
}

type Inventory struct {
	Hosts []string
}

func (in *Inventory) ToV1Inventory() *inventory.Inventory {
	out := inventory.New()

	r := &networkResolver{}

	for i := range in.Hosts {
		host := in.Hosts[i]
		name := host

		// prefix with host to ensure the connection parsing works as expected
		if !strings.Contains(host, "//") {
			host = "host://" + host
		}

		tc, err := r.ParseConnectionURL(host, "", "")
		if err != nil {
			log.Warn().Err(err).Str("hostname", host).Msg("could not parse hostname")
		}

		// Deliberately no MarkRequestedNames here: a domainlist file holds targets,
		// not names. The name is a verbatim copy of the line that produced the
		// connection, so marking it would pin `https://example.com` and suppress the
		// normalized `example.com` a provider computes after connecting.
		out.Spec.Assets = append(out.Spec.Assets, &inventory.Asset{
			Name:        name,
			Connections: []*inventory.Config{tc},
		})
	}

	return out
}

type networkResolver struct{}

func (r *networkResolver) ParseConnectionURL(fullUrl string, identityFile string, password string) (*inventory.Config, error) {
	url, err := url.Parse(fullUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse target URL")
	}

	// TODO: Processing the family here needs a bit more work. It is unclear
	// where this will evolve for now, so let's keep watching it.
	// So far we know:
	// - all of them are in the `api` family (also their kind is set this way)
	// - multiple families on one service are possible (eg: http, tls, tcp)
	res := inventory.Config{
		Type:    "host",
		Options: map[string]string{"scheme": url.Scheme},
	}

	schemeBits := strings.Split(url.Scheme, "+")
	for i := range schemeBits {
		x := strings.ToLower(schemeBits[i])
		switch x {
		case "tls", "tcp", "udp":
			// FIXME: properly check for schema bits
			res.Options[x] = ""
		}
	}

	hostBits := strings.Split(url.Host, ":")
	switch len(hostBits) {
	case 1:
		res.Host = hostBits[0]
	case 2:
		res.Host = hostBits[0]
		port, err := strconv.Atoi(hostBits[1])
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse port in target URL")
		}
		res.Port = int32(port)
	default:
		return nil, errors.New("malformed target URL, host cannot be parsed")
	}

	return &res, nil
}
