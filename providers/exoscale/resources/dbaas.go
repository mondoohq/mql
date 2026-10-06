// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
)

type mqlExoscaleDbaasServiceInternal struct {
	detailLock sync.Mutex
	detailDone bool
	detailErr  error
}

func dbaasMqlID(zone, name string) string {
	return "exoscale.dbaas.service/" + zone + "/" + name
}

func (r *mqlExoscaleDbaasService) id() (string, error) {
	return dbaasMqlID(r.Zone.Data, r.Name.Data), nil
}

func (r *mqlExoscale) dbaasServices() ([]any, error) {
	items, err := listAllZones(r.MqlRuntime, "list-dbaas-services", func(c *v3.Client) ([]v3.DBAASServiceCommon, error) {
		res, err := c.ListDBAASServices(ctx())
		if err != nil {
			return nil, err
		}
		return res.DBAASServices, nil
	})
	if err != nil {
		return nil, err
	}
	// DBaaS services carry no labels, so a label include filter drops them.
	filters := conn(r.MqlRuntime).Filters
	out := make([]any, 0, len(items))
	for _, it := range items {
		s := it.item
		if filters.IsFilteredOut(nil) {
			continue
		}
		// The record carries its own zone; prefer it over the endpoint asked.
		zone := s.Zone
		if zone == "" {
			zone = it.zone
		}
		res, err := CreateResource(r.MqlRuntime, "exoscale.dbaas.service", map[string]*llx.RawData{
			"__id":                  llx.StringData(dbaasMqlID(zone, string(s.Name))),
			"name":                  llx.StringData(string(s.Name)),
			"zone":                  llx.StringData(zone),
			"type":                  llx.StringData(string(s.Type)),
			"plan":                  llx.StringData(s.Plan),
			"state":                 llx.StringData(string(s.State)),
			"nodeCount":             llx.IntData(s.NodeCount),
			"nodeCpuCount":          llx.IntData(s.NodeCPUCount),
			"nodeMemory":            llx.IntData(s.NodeMemory),
			"diskSize":              llx.IntData(s.DiskSize),
			"terminationProtection": boolData(s.TerminationProtection),
			"created":               timeData(s.CreatedAT),
			"updated":               timeData(s.UpdatedAT),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func initExoscaleDbaasService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	name, zone := stringArg(args, "name"), stringArg(args, "zone")
	if name == "" {
		c := conn(runtime).Conf
		name = connection.AssetOption(c, connection.OptionDbaasService)
		zone = connection.AssetOption(c, connection.OptionZone)
	}
	if name == "" {
		return nil, nil, fmt.Errorf("exoscale.dbaas.service requires a name, for example exoscale.dbaas.service(name: \"my-db\", zone: \"ch-gva-2\")")
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, nil, err
	}
	list := ns.GetDbaasServices()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, e := range list.Data {
		s := e.(*mqlExoscaleDbaasService)
		if s.Name.Data == name && (zone == "" || s.Zone.Data == zone) {
			return args, s, nil
		}
	}
	return nil, nil, fmt.Errorf("exoscale.dbaas.service %q not found", name)
}

// dbaasDetail is the part of the per-engine service record this resource
// reads. Every engine has its own GET operation and response type.
type dbaasDetail struct {
	version     *string
	ipFilter    []string
	maintenance *v3.DBAASServiceMaintenance
}

func fetchDbaasDetail(c *v3.Client, serviceType, name string) (*dbaasDetail, string, error) {
	str := func(s string) *string { return &s }
	switch serviceType {
	case "pg":
		s, err := c.GetDBAASServicePG(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-pg", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "mysql":
		s, err := c.GetDBAASServiceMysql(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-mysql", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "valkey":
		s, err := c.GetDBAASServiceValkey(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-valkey", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "kafka":
		s, err := c.GetDBAASServiceKafka(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-kafka", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "opensearch":
		s, err := c.GetDBAASServiceOpensearch(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-opensearch", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "grafana":
		s, err := c.GetDBAASServiceGrafana(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-grafana", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "clickhouse":
		s, err := c.GetDBAASServiceClickhouse(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-clickhouse", err
		}
		return &dbaasDetail{str(s.Version), s.IPFilter, s.Maintenance}, "", nil
	case "thanos":
		s, err := c.GetDBAASServiceThanos(ctx(), name)
		if err != nil {
			return nil, "get-dbaas-service-thanos", err
		}
		return &dbaasDetail{nil, s.IPFilter, s.Maintenance}, "", nil
	}
	return nil, "", nil
}

// loadDetail reads the engine-specific record once and fills every field
// that only it carries. An engine this provider does not know leaves them
// null rather than guessing.
func (r *mqlExoscaleDbaasService) loadDetail() error {
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailDone {
		return r.detailErr
	}
	r.detailDone = true

	z, ok, err := zoneByName(r.MqlRuntime, r.Zone.Data)
	if err != nil {
		r.detailErr = err
		return err
	}
	if !ok {
		r.detailErr = fmt.Errorf("exoscale.dbaas.service %s: zone %q is not queried by this connection", r.Name.Data, r.Zone.Data)
		return r.detailErr
	}
	d, op, err := fetchDbaasDetail(conn(r.MqlRuntime).ZoneClient(z), r.Type.Data, r.Name.Data)
	if err != nil {
		r.detailErr = classifyError(err, op)
		return r.detailErr
	}
	r.applyDetail(d)
	return nil
}

func (r *mqlExoscaleDbaasService) applyDetail(d *dbaasDetail) {
	null := plugin.StateIsSet | plugin.StateIsNull
	set := plugin.StateIsSet
	r.Version.State, r.IpFilter.State, r.MaintenanceDow.State, r.MaintenanceTime.State = null, null, null, null
	if d == nil {
		return
	}
	if d.version != nil && *d.version != "" {
		r.Version.Data, r.Version.State = *d.version, set
	}
	ipFilter := make([]any, len(d.ipFilter))
	for i, f := range d.ipFilter {
		ipFilter[i] = f
	}
	r.IpFilter.Data, r.IpFilter.State = ipFilter, set
	if m := d.maintenance; m != nil {
		r.MaintenanceDow.Data, r.MaintenanceDow.State = string(m.Dow), set
		r.MaintenanceTime.Data, r.MaintenanceTime.State = m.Time, set
	}
}

func (r *mqlExoscaleDbaasService) version() (string, error) {
	if err := r.loadDetail(); err != nil {
		return "", err
	}
	return r.Version.Data, nil
}

func (r *mqlExoscaleDbaasService) ipFilter() ([]any, error) {
	if err := r.loadDetail(); err != nil {
		return nil, err
	}
	return r.IpFilter.Data, nil
}

func (r *mqlExoscaleDbaasService) maintenanceDow() (string, error) {
	if err := r.loadDetail(); err != nil {
		return "", err
	}
	return r.MaintenanceDow.Data, nil
}

func (r *mqlExoscaleDbaasService) maintenanceTime() (string, error) {
	if err := r.loadDetail(); err != nil {
		return "", err
	}
	return r.MaintenanceTime.Data, nil
}
