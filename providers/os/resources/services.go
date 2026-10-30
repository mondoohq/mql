// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/services"
)

func initService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}

	x, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("cannot initialize service, need at least a name to look it up")
	}

	name := x.Value.(string)
	if name == "" {
		return nil, nil, errors.New("cannot look for a service with an empty name")
	}

	lookupName := services.NormalizeServiceLookupName(name)

	if runtime.HasRecording {
		recordedArgs, err := runtime.ResourceFromRecording("service", lookupName)
		if err != nil {
			return nil, nil, err
		}
		if recordedArgs != nil {
			res, err := CreateResource(runtime, "service", recordedArgs)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	conn := runtime.Connection.(shared.Connection)
	osm, err := services.ResolveManager(conn)
	if osm == nil || err != nil {
		log.Debug().Err(err).Msg("mql[service]> could not resolve service manager")
		return nil, nil, errors.New("cannot find service manager")
	}

	svc, err := osm.Get(name)
	if err != nil {
		if errors.Is(err, services.ErrServiceNotFound) {
			return nil, missingServiceResource(runtime, lookupName), nil
		}
		return nil, nil, err
	}

	res, err := createServiceResource(runtime, svc)
	if err != nil {
		return nil, nil, err
	}

	return nil, res, nil
}

func createServiceResource(runtime *plugin.Runtime, service *services.Service) (plugin.Resource, error) {
	return CreateResource(runtime, "service", map[string]*llx.RawData{
		"name":        llx.StringData(service.Name),
		"description": llx.StringData(service.Description),
		"installed":   llx.BoolData(service.Installed),
		"enabled":     llx.BoolData(service.Enabled),
		"masked":      llx.BoolData(service.Masked),
		"running":     llx.BoolData(service.Running),
		"type":        llx.StringData(service.Type),
		"static":      llx.BoolData(service.Static),
	})
}

func missingServiceResource(runtime *plugin.Runtime, name string) plugin.Resource {
	res := &mqlService{}
	res.MqlRuntime = runtime
	res.Name = plugin.TValue[string]{Data: name, State: plugin.StateIsSet}
	res.Description.State = plugin.StateIsSet | plugin.StateIsNull
	res.Installed = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Running = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Type.State = plugin.StateIsSet | plugin.StateIsNull
	res.Enabled = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Masked = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.Static = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	res.__id, _ = res.id()
	return res
}
func (x *mqlService) id() (string, error) {
	return x.Name.Data, nil
}

type mqlServicesInternal struct {
	lock          sync.Mutex
	namedServices map[string]*mqlService
}

func (x *mqlServices) list() ([]any, error) {
	x.lock.Lock()
	defer x.lock.Unlock()

	// find suitable service manager
	conn := x.MqlRuntime.Connection.(shared.Connection)
	osm, err := services.ResolveManager(conn)
	if osm == nil || err != nil {
		// there are valid cases where this error is happening, eg. you run a service query in
		// asset filters for non-supported providers
		log.Debug().Err(err).Msg("mql[services]> could not retrieve services list")
		return nil, errors.New("cannot find service manager")
	}

	// retrieve all system services
	services, err := osm.List()
	if err != nil {
		log.Debug().Err(err).Msg("mql[services]> could not retrieve service list")
		return nil, errors.New("could not retrieve service list")
	}
	log.Debug().Int("services", len(services)).Msg("mql[services]> running services")

	// convert to any{}
	mqlSrvs := []any{}

	for i := range services {
		srv := services[i]

		mqlSrv, err := createServiceResource(x.MqlRuntime, srv)
		if err != nil {
			return nil, err
		}

		mqlSrvs = append(mqlSrvs, mqlSrv.(*mqlService))
	}

	return mqlSrvs, x.refreshCache(mqlSrvs)
}

func (x *mqlServices) refreshCache(all []any) error {
	if all == nil {
		raw := x.GetList()
		if raw.Error != nil {
			return raw.Error
		}
		all = raw.Data
	}

	x.namedServices = map[string]*mqlService{}
	for i := range all {
		service := all[i].(*mqlService)
		x.namedServices[service.Name.Data] = service
	}

	return nil
}
