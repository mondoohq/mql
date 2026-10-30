// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

type mqlNmapNetworkInternal struct {
	lock sync.Mutex
}

func (r *mqlNmapNetwork) id() (string, error) {
	return "nmap.target/" + r.Target.Data, nil
}

func (r *mqlNmapNetwork) scan() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// set default values
	r.Hosts = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	r.Warnings = plugin.TValue[[]any]{Data: nil, Error: nil, State: plugin.StateIsSet | plugin.StateIsNull}

	if r.Target.Data == "" {
		return errors.New("target is required")
	}

	// nmap -sn -n --min-parallelism 100 -T4 192.168.1.0/24
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithPingScan(),              // -sn
		nmap.WithDisabledDNSResolution(), // -n
		nmap.WithMinParallelism(100),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithTargets(r.Target.Data),
	)
	if err != nil {
		return errors.Wrap(err, "unable to create nmap scanner")
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return errors.Wrap(err, "unable to create nmap scanner")
	}

	if warnings != nil && len(*warnings) > 0 {
		r.Warnings = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(*warnings), Error: nil, State: plugin.StateIsSet}
	}

	var hosts []any
	for _, host := range result.Hosts {
		r, err := newMqlNmapHost(r.MqlRuntime, host)
		if err != nil {
			return err
		}
		hosts = append(hosts, r)
	}

	r.Hosts = plugin.TValue[[]any]{Data: hosts, Error: nil, State: plugin.StateIsSet}

	return nil
}

func (r *mqlNmapNetwork) hosts() ([]any, error) {
	return nil, r.scan()
}

func (r *mqlNmapNetwork) warnings() ([]any, error) {
	return nil, r.scan()
}
