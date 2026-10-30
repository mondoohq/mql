// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Several of the endpoints in this file sit behind privileges that PVEAuditor
// does not carry: the notification and mapping routes want Mapping.Audit on
// /mapping, and the ACME plugin route wants Sys.Modify. optionalGet treats a
// permission failure on those as "nothing visible to this token" and logs it,
// so a read-only scan degrades instead of failing. Every other error still
// bubbles up.
func (c *PveConnection) optionalGet(path string, result any) error {
	if err := c.apiGet(path, result); err != nil {
		if IsAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Str("path", path).
				Msg("proxmox: skipping endpoint this token cannot read")
			return nil
		}
		return fmt.Errorf("failed to get %s: %w", path, err)
	}
	return nil
}

// getIfAvailable fetches an endpoint that a given cluster may simply not
// serve, and reports whether the read succeeded.
//
// Two of these routes only exist from a certain Proxmox release onward and one
// sits behind a privilege an audit token may not hold. Both cases arrive as a
// 404 or a 403, and neither means "the cluster has none of these". Returning
// readable=false lets the caller report the field as null, so an unread
// posture is never presented as an empty collection that an assertion would
// pass over. A transport or decoding failure is still an error.
func (c *PveConnection) getIfAvailable(path string, result any) (bool, error) {
	if err := c.apiGet(path, result); err != nil {
		if IsAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Str("path", path).
				Msg("proxmox: endpoint not available on this cluster")
			return false, nil
		}
		return false, fmt.Errorf("failed to get %s: %w", path, err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Notification targets and matchers
// ---------------------------------------------------------------------------

type NotificationTarget struct {
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Origin  string  `json:"origin"`
	Disable PveBool `json:"disable"`
	Comment string  `json:"comment"`
}

func (c *PveConnection) GetNotificationTargets() ([]NotificationTarget, error) {
	var targets []NotificationTarget
	return targets, c.optionalGet("/cluster/notifications/targets", &targets)
}

type NotificationMatcher struct {
	Name          string   `json:"name"`
	Mode          string   `json:"mode"`
	MatchSeverity []string `json:"match-severity"`
	MatchField    []string `json:"match-field"`
	MatchCalendar []string `json:"match-calendar"`
	InvertMatch   PveBool  `json:"invert-match"`
	Target        []string `json:"target"`
	Origin        string   `json:"origin"`
	Disable       PveBool  `json:"disable"`
	Comment       string   `json:"comment"`
}

func (c *PveConnection) GetNotificationMatchers() ([]NotificationMatcher, error) {
	var matchers []NotificationMatcher
	return matchers, c.optionalGet("/cluster/notifications/matchers", &matchers)
}

// SMTPEndpoint is a notification target that mails through an SMTP server.
// The authentication password is never returned by the API.
type SMTPEndpoint struct {
	Name        string   `json:"name"`
	Server      string   `json:"server"`
	Port        int      `json:"port"`
	Mode        string   `json:"mode"`
	FromAddress string   `json:"from-address"`
	Author      string   `json:"author"`
	Username    string   `json:"username"`
	Mailto      []string `json:"mailto"`
	MailtoUser  []string `json:"mailto-user"`
	Origin      string   `json:"origin"`
	Disable     PveBool  `json:"disable"`
	Comment     string   `json:"comment"`
}

func (c *PveConnection) GetSMTPEndpoints() ([]SMTPEndpoint, error) {
	var endpoints []SMTPEndpoint
	return endpoints, c.optionalGet("/cluster/notifications/endpoints/smtp", &endpoints)
}

type SendmailEndpoint struct {
	Name        string   `json:"name"`
	FromAddress string   `json:"from-address"`
	Author      string   `json:"author"`
	Mailto      []string `json:"mailto"`
	MailtoUser  []string `json:"mailto-user"`
	Origin      string   `json:"origin"`
	Disable     PveBool  `json:"disable"`
	Comment     string   `json:"comment"`
}

func (c *PveConnection) GetSendmailEndpoints() ([]SendmailEndpoint, error) {
	var endpoints []SendmailEndpoint
	return endpoints, c.optionalGet("/cluster/notifications/endpoints/sendmail", &endpoints)
}

type GotifyEndpoint struct {
	Name    string  `json:"name"`
	Server  string  `json:"server"`
	Origin  string  `json:"origin"`
	Disable PveBool `json:"disable"`
	Comment string  `json:"comment"`
}

func (c *PveConnection) GetGotifyEndpoints() ([]GotifyEndpoint, error) {
	var endpoints []GotifyEndpoint
	return endpoints, c.optionalGet("/cluster/notifications/endpoints/gotify", &endpoints)
}

// WebhookEndpoint posts notifications to an arbitrary URL. Header and Secret
// arrive as property strings; only their names are surfaced, never the
// values, since a header value can itself carry an API token.
type WebhookEndpoint struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Method  string   `json:"method"`
	Header  []string `json:"header"`
	Secret  []string `json:"secret"`
	Origin  string   `json:"origin"`
	Disable PveBool  `json:"disable"`
	Comment string   `json:"comment"`
}

func (c *PveConnection) GetWebhookEndpoints() ([]WebhookEndpoint, error) {
	var endpoints []WebhookEndpoint
	return endpoints, c.optionalGet("/cluster/notifications/endpoints/webhook", &endpoints)
}

// PropertyStringNames pulls the `name=` value out of each entry of a PVE
// property-string list, e.g. `name=Authorization,value=Bearer xyz` yields
// "Authorization". Entries without a name are skipped rather than reported
// under an empty key.
func PropertyStringNames(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		for part := range strings.SplitSeq(entry, ",") {
			key, value, found := strings.Cut(strings.TrimSpace(part), "=")
			if !found || key != "name" || value == "" {
				continue
			}
			out = append(out, value)
			break
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// External metric servers
// ---------------------------------------------------------------------------

// MetricServer is an external InfluxDB or Graphite endpoint the cluster ships
// metrics to. The API token or shared secret is not returned.
type MetricServer struct {
	ID      string  `json:"id"`
	Type    string  `json:"type"`
	Server  string  `json:"server"`
	Port    int     `json:"port"`
	Disable PveBool `json:"disable"`
}

func (c *PveConnection) GetMetricServers() ([]MetricServer, error) {
	var servers []MetricServer
	return servers, c.optionalGet("/cluster/metrics/server", &servers)
}

// ---------------------------------------------------------------------------
// ACME
// ---------------------------------------------------------------------------

type ACMEAccount struct {
	Name string `json:"name"`
}

func (c *PveConnection) GetACMEAccounts() ([]ACMEAccount, error) {
	var accounts []ACMEAccount
	return accounts, c.optionalGet("/cluster/acme/account", &accounts)
}

// ACMEPlugin is a DNS-01 challenge plugin. Reading it needs Sys.Modify, which
// no audit role carries, so this is commonly empty on a read-only token.
type ACMEPlugin struct {
	Plugin          string  `json:"plugin"`
	Type            string  `json:"type"`
	API             string  `json:"api"`
	Nodes           string  `json:"nodes"`
	Disable         PveBool `json:"disable"`
	ValidationDelay int     `json:"validation-delay"`
}

func (c *PveConnection) GetACMEPlugins() ([]ACMEPlugin, error) {
	var plugins []ACMEPlugin
	return plugins, c.optionalGet("/cluster/acme/plugins", &plugins)
}

// ---------------------------------------------------------------------------
// Corosync
// ---------------------------------------------------------------------------

type CorosyncNode struct {
	Name        string `json:"name"`
	NodeID      int    `json:"nodeid"`
	QuorumVotes int    `json:"quorum_votes"`
	Ring0Addr   string `json:"ring0_addr"`
	Ring1Addr   string `json:"ring1_addr"`
	PveAddr     string `json:"pve_addr"`
	PveFP       string `json:"pve_fp"`
}

type CorosyncConfig struct {
	NodeList      []CorosyncNode `json:"nodelist"`
	PreferredNode string         `json:"preferred_node"`
	Totem         map[string]any `json:"totem"`
	ConfigDigest  string         `json:"config_digest"`
}

// corosyncCache memoizes the join configuration. Four separate resource
// fields read from it, and without this each one would re-fetch.
type corosyncCache struct {
	once sync.Once
	cfg  *CorosyncConfig
	err  error
}

func (c *PveConnection) GetCorosyncConfig() (*CorosyncConfig, error) {
	c.corosync.once.Do(func() {
		var cfg CorosyncConfig
		if err := c.apiGet("/cluster/config/join", &cfg); err != nil {
			// A standalone node has no corosync configuration at all, which
			// PVE reports as an error rather than an empty result.
			if IsAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Msg("proxmox: no corosync configuration available")
				return
			}
			c.corosync.err = fmt.Errorf("failed to get corosync configuration: %w", err)
			return
		}
		c.corosync.cfg = &cfg
	})
	return c.corosync.cfg, c.corosync.err
}

func (c *PveConnection) GetQDevice() (map[string]any, error) {
	var qdevice map[string]any
	return qdevice, c.optionalGet("/cluster/config/qdevice", &qdevice)
}

// ---------------------------------------------------------------------------
// Cluster-wide device mappings
// ---------------------------------------------------------------------------

// DeviceMapping is a named, cluster-wide alias for a physical device that
// guests can be granted by name instead of by host address.
type DeviceMapping struct {
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Map         []map[string]any `json:"map"`
}

func (c *PveConnection) GetPCIMappings() ([]DeviceMapping, error) {
	var mappings []DeviceMapping
	return mappings, c.optionalGet("/cluster/mapping/pci", &mappings)
}

func (c *PveConnection) GetUSBMappings() ([]DeviceMapping, error) {
	var mappings []DeviceMapping
	return mappings, c.optionalGet("/cluster/mapping/usb", &mappings)
}

// ---------------------------------------------------------------------------
// SDN controllers, IPAMs, and DNS
// ---------------------------------------------------------------------------

type SDNController struct {
	Controller   string  `json:"controller"`
	Type         string  `json:"type"`
	Node         string  `json:"node"`
	Nodes        string  `json:"nodes"`
	State        string  `json:"state"`
	ASN          int     `json:"asn"`
	Peers        string  `json:"peers"`
	EBGP         PveBool `json:"ebgp"`
	EBGPMultihop int     `json:"ebgp-multihop"`
	BGPMode      string  `json:"bgp-mode"`
	Loopback     string  `json:"loopback"`
	ISISDomain   string  `json:"isis-domain"`
	ISISNet      string  `json:"isis-net"`
	ISISIfaces   string  `json:"isis-ifaces"`
}

func (c *PveConnection) GetSDNControllers() ([]SDNController, error) {
	var controllers []SDNController
	return controllers, c.optionalGet("/cluster/sdn/controllers", &controllers)
}

type SDNIpam struct {
	IPAM string `json:"ipam"`
	Type string `json:"type"`
}

func (c *PveConnection) GetSDNIpams() ([]SDNIpam, error) {
	var ipams []SDNIpam
	return ipams, c.optionalGet("/cluster/sdn/ipams", &ipams)
}

type SDNDns struct {
	DNS  string `json:"dns"`
	Type string `json:"type"`
}

func (c *PveConnection) GetSDNDnsServers() ([]SDNDns, error) {
	var servers []SDNDns
	return servers, c.optionalGet("/cluster/sdn/dns", &servers)
}
