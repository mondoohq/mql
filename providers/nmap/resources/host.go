// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"github.com/rs/zerolog/log"
	"strconv"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/nmap/connection"
)

type mqlNmapHostInternal struct {
	lock sync.Mutex
}

func initNmapHost(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["name"]; !ok {
		// try to get the ip from the connection
		conn := runtime.Connection.(*connection.NmapConnection)
		if conn.Conf.Options != nil && conn.Conf.Options["search"] == "host" {
			args["name"] = llx.StringData(conn.Conf.Host)
		}
	}

	if _, ok := args["name"]; !ok {
		return nil, nil, errors.New("missing required argument 'name'")
	}

	return args, nil, nil
}

// hostScanName picks a single, scannable identifier for a host from its
// addresses. A host frequently reports more than one address (e.g. an IPv4
// address plus a MAC address on a local segment). We must not join them into
// one string, because the result is later handed back to nmap as a scan
// target and a comma-joined value is not a valid target. We prefer an IP
// address (IPv4, then IPv6) and fall back to the first non-empty address.
func hostScanName(addresses []nmap.Address) string {
	var ipv6, fallback string
	for _, addr := range addresses {
		if addr.Addr == "" {
			continue
		}
		switch addr.AddrType {
		case "ipv4":
			return addr.Addr
		case "ipv6":
			if ipv6 == "" {
				ipv6 = addr.Addr
			}
		default:
			if fallback == "" {
				fallback = addr.Addr
			}
		}
	}
	if ipv6 != "" {
		return ipv6
	}
	return fallback
}

func newMqlNmapHost(runtime *plugin.Runtime, host nmap.Host) (*mqlNmapHost, error) {
	name := hostScanName(host.Addresses)

	mqlNmapHostResource, err := CreateResource(runtime, "nmap.host", map[string]*llx.RawData{
		"__id": llx.StringData("nmap.host/" + name),
		"name": llx.StringData(name),
	})
	return mqlNmapHostResource.(*mqlNmapHost), err
}

func (r *mqlNmapHost) id() (string, error) {
	return "nmap.host/" + r.Name.Data, nil
}

func (r *mqlNmapHost) scan() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.Distance = plugin.TValue[any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Os = plugin.TValue[any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.EndTime = plugin.TValue[*time.Time]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Comment = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Trace = plugin.TValue[any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Addresses = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Hostnames = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.State = plugin.TValue[string]{Data: "", Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Ports = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}

	setError := func(err error) {
		r.Distance = plugin.TValue[any]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.Os = plugin.TValue[any]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.EndTime = plugin.TValue[*time.Time]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.Comment = plugin.TValue[string]{Data: "", Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.Trace = plugin.TValue[any]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.Addresses = plugin.TValue[[]any]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.Hostnames = plugin.TValue[[]any]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.State = plugin.TValue[string]{Data: "", Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
		r.Ports = plugin.TValue[[]any]{Data: nil, Error: err, State: plugin.StateIsSet | plugin.StateIsNull}

	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Info().Str("host", r.Name.Data).Str("id", r.MqlID()).Msg("Scanning host")

	// nmap -sT -sV  -n --min-parallelism 100 -T4 [-p ports] <target>
	scanOpts := []nmap.Option{
		nmap.WithConnectScan(),           // -sT
		nmap.WithServiceInfo(),           // -sV
		nmap.WithDisabledDNSResolution(), // -n
		nmap.WithMinParallelism(100),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithTargets(r.Name.Data),
	}

	conn := r.MqlRuntime.Connection.(*connection.NmapConnection)
	if conn.Conf.Options != nil {
		if ports, ok := conn.Conf.Options["ports"]; ok && ports != "" {
			scanOpts = append(scanOpts, nmap.WithPorts(ports)) // -p
		}
	}

	scanner, err := nmap.NewScanner(
		ctx,
		scanOpts...,
	)
	if err != nil {
		setError(err)
		return errors.Wrap(err, "unable to create nmap scanner")
	}

	result, _, err := scanner.Run()
	if err != nil {
		setError(err)
		return errors.Wrap(err, "unable to create nmap scanner")
	}

	if len(result.Hosts) == 0 {
		return nil
	} else if len(result.Hosts) > 1 {
		err := errors.New("nmap scan returned more than one host")
		setError(err)
		return err
	}

	host := result.Hosts[0]
	id := r.Name.Data
	t := time.Time(host.EndTime)

	distance, err := convert.JsonToDict(host.Distance)
	if err == nil {
		r.Distance = plugin.TValue[any]{Data: distance, Error: nil, State: plugin.StateIsSet}
	}

	os, err := convert.JsonToDict(host.OS)
	if err == nil {
		r.Os = plugin.TValue[any]{Data: os, Error: nil, State: plugin.StateIsSet}
	}

	r.EndTime = plugin.TValue[*time.Time]{Data: &t, Error: nil, State: plugin.StateIsSet}
	r.Comment = plugin.TValue[string]{Data: host.Comment, Error: nil, State: plugin.StateIsSet}

	trace, err := convert.JsonToDict(host.Trace)
	if err == nil {
		r.Trace = plugin.TValue[any]{Data: trace, Error: nil, State: plugin.StateIsSet}
	}

	addresses, err := convert.JsonToDictSlice(host.Addresses)
	if err == nil {
		r.Addresses = plugin.TValue[[]any]{Data: addresses, Error: nil, State: plugin.StateIsSet}
	}

	hostnames, err := convert.JsonToDictSlice(host.Hostnames)
	if err == nil {
		r.Hostnames = plugin.TValue[[]any]{Data: hostnames, Error: nil, State: plugin.StateIsSet}
	}

	ports := make([]any, 0)
	for _, port := range host.Ports {
		r, err := newMqlNmapPort(r.MqlRuntime, id, port)
		if err != nil {
			return err
		}
		ports = append(ports, r)
	}

	if len(ports) > 0 {
		r.Ports = plugin.TValue[[]any]{Data: ports, Error: nil, State: plugin.StateIsSet}
	}

	r.State = plugin.TValue[string]{Data: host.Status.State, Error: nil, State: plugin.StateIsSet}

	return nil
}

func (r *mqlNmapHost) distance() (any, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) os() (any, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) endTime() (*time.Time, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) comment() (string, error) {
	return "", r.scan()
}

func (r *mqlNmapHost) trace() (any, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) addresses() ([]any, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) hostnames() ([]any, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) ports() ([]any, error) {
	return nil, r.scan()
}

func (r *mqlNmapHost) state() (string, error) {
	return "", r.scan()
}

func newMqlNmapPort(runtime *plugin.Runtime, id string, port nmap.Port) (*mqlNmapPort, error) {
	mqlPort, err := CreateResource(runtime, "nmap.port", map[string]*llx.RawData{
		"__id":     llx.StringData("nmap.port/" + id + "/" + strconv.Itoa(int(port.ID))),
		"port":     llx.IntData(int64(port.ID)),
		"service":  llx.StringData(port.Service.Name),
		"method":   llx.StringData(port.Service.Method),
		"protocol": llx.StringData(port.Protocol),
		"product":  llx.StringData(port.Service.Product),
		"version":  llx.StringData(port.Service.Version),
		"state":    llx.StringData(port.State.State),
	})
	return mqlPort.(*mqlNmapPort), err
}
