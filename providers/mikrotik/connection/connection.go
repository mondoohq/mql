// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-routeros/routeros/v3"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	// DefaultAPIPort is the RouterOS API port for plaintext connections.
	DefaultAPIPort = "8728"
	// DefaultAPISSLPort is the RouterOS API port for TLS connections.
	DefaultAPISSLPort = "8729"
)

// rosClient is the subset of *routeros.Client the connection depends on.
// Depending on the interface (rather than the concrete type) lets tests drive
// Print/PrintOptional with a fake reply source; *routeros.Client satisfies it.
type rosClient interface {
	Run(sentences ...string) (*routeros.Reply, error)
	Close() error
}

type MikrotikConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	// client is the underlying RouterOS API client. The RouterOS API
	// multiplexes a single TCP connection, so concurrent commands must be
	// serialized; mu guards every Run call.
	client rosClient
	mu     sync.Mutex

	// printCache memoizes `<menu>/print` results for the lifetime of the
	// connection. A device's configuration is effectively static across a
	// scan, so caching avoids the N+1 device round-trips that occur when
	// several resources (e.g. dhcpServers and each server's leases) read the
	// same menu. cacheMu guards the map independently of the Run mutex.
	printCache map[string][]map[string]string
	cacheMu    sync.Mutex
}

// parseTLSOption reads the tls connection option.
//
// It deliberately rejects anything it does not recognize rather than treating
// it as false. The option selects between the TLS API port and the plaintext
// one, and the RouterOS API sends the password in its very first sentence, so
// silently reading an unrecognized value as "no TLS" would put the device
// password on the wire in the clear and still report a successful scan.
func parseTLSOption(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "false", "0", "no", "off":
		return false, nil
	case "true", "1", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("invalid value %q for the mikrotik tls option, use true or false", v)
	}
}

func NewMikrotikConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*MikrotikConnection, error) {
	host := conf.Host
	if host == "" {
		host = conf.Options["host"]
	}
	if host == "" {
		return nil, fmt.Errorf("a host is required to connect to a mikrotik device, e.g. mikrotik admin@192.168.88.1")
	}

	user := ""
	password := ""
	// A credential that was supplied but could not be resolved is an error, not
	// a reason to fall back to the default account: retrying as admin turns a
	// vault problem into "invalid user name or password" against a username the
	// operator never configured.
	if len(conf.Credentials) > 0 {
		cred, err := vault.GetPassword(conf.Credentials)
		if err != nil {
			return nil, fmt.Errorf("could not resolve credentials for the mikrotik device at %s: %w", host, err)
		}
		if cred != nil {
			user = cred.User
			password = string(cred.Secret)
		}
	}
	if user == "" {
		// RouterOS ships with the "admin" account by default
		user = "admin"
	}

	useTLS, err := parseTLSOption(conf.Options["tls"])
	if err != nil {
		return nil, err
	}

	port := conf.Options["port"]
	if port == "" && conf.Port != 0 {
		port = fmt.Sprintf("%d", conf.Port)
	}
	if port == "" {
		if useTLS {
			port = DefaultAPISSLPort
		} else {
			port = DefaultAPIPort
		}
	}

	address := net.JoinHostPort(host, port)
	timeout := 10 * time.Second

	var client *routeros.Client
	if useTLS {
		tlsConfig := &tls.Config{InsecureSkipVerify: conf.Insecure}
		client, err = routeros.DialTLSTimeout(address, user, password, tlsConfig, timeout)
	} else {
		client, err = routeros.DialTimeout(address, user, password, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mikrotik device at %s: %w", address, err)
	}

	conn := &MikrotikConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client:     client,
	}

	return conn, nil
}

func (c *MikrotikConnection) Name() string {
	return "mikrotik"
}

func (c *MikrotikConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *MikrotikConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
}

// Run executes a RouterOS API command and returns its reply. Calls are
// serialized because the RouterOS API shares a single TCP connection.
func (c *MikrotikConnection) Run(sentences ...string) (*routeros.Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		return nil, errors.New("the mikrotik connection is closed")
	}
	return c.client.Run(sentences...)
}

// Print runs a `<menu>/print` command and returns each reply sentence as a
// map of attribute names to values. For example Print("/interface") issues
// `/interface/print` and returns one map per interface. Results are memoized
// per menu for the connection's lifetime (see printCache). Each call returns
// an independent copy of the cached rows, so a caller mutating a returned map
// can corrupt neither the cache nor the routeros library's internal sentence
// state, and repeated callers always observe the original device values.
func (c *MikrotikConnection) Print(menu string) ([]map[string]string, error) {
	// Hold cacheMu across the fetch (not just the read and the write): this
	// makes concurrent callers for the same menu wait for the first fetch and
	// then read the cache, instead of each issuing a redundant device
	// round-trip. It adds no real contention because device commands are
	// already serialized on the single API connection (see Run), and Run is
	// only ever reached through Print, so the cacheMu→mu lock order can't
	// invert.
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	if c.printCache == nil {
		c.printCache = map[string][]map[string]string{}
	}

	cached, ok := c.printCache[menu]
	if !ok {
		reply, err := c.Run(menu + "/print")
		if err != nil {
			return nil, err
		}
		cached = make([]map[string]string, 0, len(reply.Re))
		for _, re := range reply.Re {
			cached = append(cached, maps.Clone(re.Map))
		}
		c.printCache[menu] = cached
	}

	return cloneRows(cached), nil
}

// cloneRows returns a deep copy of a slice of attribute maps so callers can
// freely read or mutate the result without touching the shared print cache.
func cloneRows(rows []map[string]string) []map[string]string {
	out := make([]map[string]string, len(rows))
	for i, row := range rows {
		out[i] = maps.Clone(row)
	}
	return out
}

// PrintOptional behaves like Print but treats a menu the device does not
// support — for example /interface/wifi on a device without the RouterOS 7
// wifi package — as an empty result rather than an error, so package-dependent
// resources degrade gracefully instead of failing the whole query.
func (c *MikrotikConnection) PrintOptional(menu string) ([]map[string]string, error) {
	rows, err := c.Print(menu)
	if err != nil {
		if isUnknownCommandErr(err) {
			return []map[string]string{}, nil
		}
		return nil, err
	}
	return rows, nil
}

// isUnknownCommandErr reports whether err is the RouterOS trap returned when a
// menu or command does not exist on the device (e.g. "no such command prefix").
func isUnknownCommandErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such command")
}

// PrintOne runs a `<menu>/print` command that is expected to return a single
// record (e.g. /system/resource) and returns its attribute map. If the menu
// returns no records, an empty map is returned.
func (c *MikrotikConnection) PrintOne(menu string) (map[string]string, error) {
	rows, err := c.Print(menu)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return map[string]string{}, nil
	}
	return rows[0], nil
}

// PrintOneOptional behaves like PrintOne but treats a menu the device does not
// support -- for example /system/routerboard/settings on a CHR build, or
// /container without the container package -- as an empty result rather than
// an error, so the caller can report the subsystem as absent instead of
// failing the query.
func (c *MikrotikConnection) PrintOneOptional(menu string) (map[string]string, error) {
	rows, err := c.PrintOptional(menu)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return map[string]string{}, nil
	}
	return rows[0], nil
}
