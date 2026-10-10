// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/cli/esx"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/mrn"
)

const (
	VspherePlatform = "vmware-vsphere"
	EsxiPlatform    = "vmware-esxi"
	Family          = "vmware-vsphere"
)

func listDatacenters(c *govmomi.Client) ([]*object.Datacenter, error) {
	finder := find.NewFinder(c.Client, true)
	l, err := finder.ManagedObjectListChildren(context.Background(), "/")
	if err != nil {
		return nil, err
	}
	var dcs []*object.Datacenter
	for _, item := range l {
		if item.Object.Reference().Type == "Datacenter" {
			dc, err := getDatacenter(c, item.Path)
			if err != nil {
				return nil, err
			}
			dcs = append(dcs, dc)
		}
	}
	return dcs, nil
}

func getDatacenter(c *govmomi.Client, dc string) (*object.Datacenter, error) {
	finder := find.NewFinder(c.Client, true)
	t := c.ServiceContent.About.ApiType
	switch t {
	case "HostAgent":
		return finder.DefaultDatacenter(context.Background())
	case "VirtualCenter":
		if dc != "" {
			return finder.Datacenter(context.Background(), dc)
		}
		return finder.DefaultDatacenter(context.Background())
	}
	return nil, fmt.Errorf("unsupported ApiType: %s", t)
}

func listHosts(c *govmomi.Client, dc *object.Datacenter) ([]*object.HostSystem, error) {
	finder := find.NewFinder(c.Client, true)
	finder.SetDatacenter(dc)
	res, err := finder.HostSystemList(context.Background(), "*")
	if err != nil && IsNotFound(err) {
		return []*object.HostSystem{}, nil
	} else if err != nil {
		return nil, err
	}
	return res, nil
}

// IsNotFound returns a boolean indicating whether the error is a not found error.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	var e *find.NotFoundError
	return errors.As(err, &e)
}

type EsxiSystemVersion struct {
	Build   string
	Patch   string
	Product string
	Update  string
	Version string
	Moid    string
}

func (c *VsphereConnection) EsxiVersion(moid string) (*EsxiSystemVersion, error) {
	hostRef, err := DecodeMoid(moid)
	if err != nil {
		return nil, err
	}

	host, err := c.Host(hostRef)
	if err != nil {
		return nil, err
	}

	return esxiVersion(host)
}

// $ESXCli.system.version.get()
// Build   : Releasebuild-8169922
// Patch   : 0
// Product : VMware ESXi
// Update  : 0
// Version : 6.7.0
// see https://knowledge.broadcom.com/external/article?legacyId=2143832 for version and build number mapping
func esxiVersion(host *object.HostSystem) (*EsxiSystemVersion, error) {
	ctx := context.Background()
	e, err := esx.NewExecutor(ctx, host.Client(), host)
	if err != nil {
		return nil, err
	}

	res, err := e.Run(ctx, []string{"system", "version", "get"})
	if err != nil {
		return nil, err
	}

	if len(res.Values) == 0 {
		return nil, errors.New("could not detect esxi system version ")
	}

	if len(res.Values) > 1 {
		return nil, errors.New("ambiguous esxi system version")
	}

	version := EsxiSystemVersion{}
	val := res.Values[0]
	for k := range val {
		if len(val[k]) == 1 {
			value := val[k][0]

			switch k {
			case "Build":
				// ahhhh really? "Releasebuild-8169922"
				if strings.HasPrefix(value, "Releasebuild-") {
					value = strings.Replace(value, "Releasebuild-", "", 1)
				}
				version.Build = value
			case "Patch":
				version.Patch = value
			case "Product":
				version.Product = value
			case "Update":
				version.Update = value
			case "Version":
				version.Version = value
			}
		} else {
			log.Error().Str("key", k).Msg("system version> unsupported key")
		}
	}

	version.Moid = host.Reference().Value
	return &version, nil
}

func getHost(client *govmomi.Client) (*object.HostSystem, error) {
	dcs, err := listDatacenters(client)
	if err != nil {
		return nil, err
	}

	if len(dcs) != 1 {
		return nil, errors.New("esxi version only supported on esxi connection, found zero or multiple datacenters")
	}
	dc := dcs[0]

	hosts, err := listHosts(client, dc)
	if err != nil {
		return nil, err
	}

	if len(hosts) != 1 {
		return nil, errors.New("esxi version only supported on esxi connection, found zero or multiple hosts")
	}
	host := hosts[0]
	return host, nil
}

func (c *VsphereConnection) InstanceUUID() (string, error) {
	// determine identifier since ESXI connections do not return an InstanceUuid
	if !c.client.IsVC() {
		host, err := getHost(c.client)
		if err != nil {
			return "", err
		}

		// NOTE: we do not use the ESXi host identifier here to distinguish between the API and the host itself
		return host.Reference().Value, nil
	}

	v := c.client.ServiceContent.About
	return v.InstanceUuid, nil
}

// Identifier will only identify the connection
// see https://web.archive.org/web/20250625103035/https://blogs.vmware.com/vsphere/2012/02/uniquely-identifying-virtual-machines-in-vsphere-and-vcloud-part-1-overview.html
// To match the vm with the guest, we would need to extract the vm uuid from bios
// https://web.archive.org/web/20240422231644/https://kb.vmware.com/s/article/1009458
// /usr/sbin/dmidecode | grep UUID https://communities.vmware.com/thread/420420
// wmic bios get name,serialnumber,version  https://communities.vmware.com/thread/582729/
func (c *VsphereConnection) Identifier() (string, error) {
	// a specific resource id was passed into the transport eg. for a esxi host or esxi vm
	if len(c.selectedPlatformID) > 0 {
		return c.selectedPlatformID, nil
	}

	id, err := c.InstanceUUID()
	if err != nil {
		log.Warn().Err(err).Msg("failed to get vsphere instance uuid")
		// This error is being ignored
		return "", nil
	}

	return VsphereID(id), nil
}

// Info returns the connection information
func (c *VsphereConnection) Info() types.AboutInfo {
	return c.Client().ServiceContent.About
}

func VsphereResourceID(instance string, moid string) string {
	return "//platformid.api.mondoo.app/runtime/vsphere/instance/" + instance + "/moid/" + moid
}

func DecodeMoid(moid string) (types.ManagedObjectReference, error) {
	r := types.ManagedObjectReference{}

	s := strings.SplitN(moid, "-", 2)

	if len(s) < 2 {
		return r, errors.New("moid not parsable: " + moid)
	}

	r.Type = s[0]
	r.Value = s[1]

	return r, nil
}

func ParseVsphereResourceID(id string) (types.ManagedObjectReference, error) {
	var reference types.ManagedObjectReference
	parsed, err := mrn.NewMRN(id)
	if err != nil {
		return reference, err
	}
	moid, err := parsed.ResourceID("moid")
	if err != nil {
		return reference, errors.New("vsphere platform id has invalid type")
	}

	reference, err = DecodeMoid(moid)
	if err != nil {
		return reference, err
	}

	return reference, nil
}

func IsVsphereResourceID(mrn string) bool {
	return strings.HasPrefix(mrn, "//platformid.api.mondoo.app/runtime/vsphere/instance/") && strings.Contains(mrn, "/moid/")
}

// use in combination with Client.ServiceContent.About.InstanceUuid
func VsphereID(id string) string {
	return "//platformid.api.mondoo.app/runtime/vsphere/instance/" + id
}

func IsVsphereID(mrn string) bool {
	return strings.HasPrefix(mrn, "//platformid.api.mondoo.app/runtime/vsphere/instance/")
}

func (c *VsphereConnection) Host(moid types.ManagedObjectReference) (*object.HostSystem, error) {
	// TODO: how should we handle the case when the moid does not exist
	return object.NewHostSystem(c.Client().Client, moid), nil
}

func (c *VsphereConnection) VirtualMachine(moid types.ManagedObjectReference) (*object.VirtualMachine, error) {
	// TODO: how should we handle the case when the moid does not exist
	return object.NewVirtualMachine(c.Client().Client, moid), nil
}
