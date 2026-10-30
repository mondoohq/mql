// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	osconfig "google.golang.org/api/osconfig/v1"
)

type mqlGcpProjectOsConfigServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) osConfig() (*mqlGcpProjectOsConfigService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	// Check service enablement before creating the resource: a transient error
	// here must not leave a resource cached with serviceEnabled = false, which
	// would make every child accessor silently return nil on later calls.
	serviceEnabled, err := g.isServiceEnabled(service_osconfig)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.osConfigService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectOsConfigService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_osconfig).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectOsConfigService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectOsConfigService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.osConfigService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectOsConfigServicePatchDeployment) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectOsConfigServiceOsPolicyAssignment) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// parseSecondsDuration converts a GCP duration string (e.g. "3600s") to whole seconds.
func parseSecondsDuration(d string) int64 {
	if d == "" {
		return 0
	}
	secs, err := strconv.ParseFloat(strings.TrimSuffix(d, "s"), 64)
	if err != nil {
		return 0
	}
	return int64(secs)
}

func (g *mqlGcpProjectOsConfigService) patchDeployments() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(osconfig.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	osConfigSvc, err := osconfig.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	res := []any{}
	call := osConfigSvc.Projects.PatchDeployments.List("projects/" + projectId)
	if err := call.Pages(ctx, func(page *osconfig.ListPatchDeploymentsResponse) error {
		for _, pd := range page.PatchDeployments {
			instanceFilter, err := convert.JsonToDict(pd.InstanceFilter)
			if err != nil {
				return err
			}
			patchConfig, err := convert.JsonToDict(pd.PatchConfig)
			if err != nil {
				return err
			}
			oneTimeSchedule, err := convert.JsonToDict(pd.OneTimeSchedule)
			if err != nil {
				return err
			}
			recurringSchedule, err := convert.JsonToDict(pd.RecurringSchedule)
			if err != nil {
				return err
			}
			rollout, err := convert.JsonToDict(pd.Rollout)
			if err != nil {
				return err
			}

			mqlPd, err := CreateResource(g.MqlRuntime, "gcp.project.osConfigService.patchDeployment", map[string]*llx.RawData{
				"name":              llx.StringData(pd.Name),
				"description":       llx.StringData(pd.Description),
				"instanceFilter":    llx.DictData(instanceFilter),
				"patchConfig":       llx.DictData(patchConfig),
				"duration":          llx.IntData(parseSecondsDuration(pd.Duration)),
				"oneTimeSchedule":   llx.DictData(oneTimeSchedule),
				"recurringSchedule": llx.DictData(recurringSchedule),
				"rollout":           llx.DictData(rollout),
				"state":             llx.StringData(pd.State),
				"created":           llx.TimeDataPtr(parseTime(pd.CreateTime)),
				"updated":           llx.TimeDataPtr(parseTime(pd.UpdateTime)),
				"lastExecuteTime":   llx.TimeDataPtr(parseTime(pd.LastExecuteTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlPd)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list OS patch deployments")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectOsConfigService) osPolicyAssignments() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(osconfig.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	// OS policy assignments are zonal, so we have to enumerate every zone.
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	var zones []string
	if err := computeSvc.Zones.List(projectId).Pages(ctx, func(page *compute.ZoneList) error {
		for _, zone := range page.Items {
			zones = append(zones, zone.Name)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list zones for OS policy assignments")
			return nil, nil
		}
		return nil, err
	}

	osConfigSvc, err := osconfig.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// Fan out across zones, but cap concurrency so a project with many zones
	// doesn't trigger GCP API rate-limiting. A non-skippable error from any
	// zone fails the whole call so the caller never sees partial results.
	var (
		res []any
		mux sync.Mutex
	)
	grp, grpCtx := errgroup.WithContext(ctx)
	grp.SetLimit(10)
	for i := range zones {
		zone := zones[i]
		grp.Go(func() error {
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, zone)
			err := osConfigSvc.Projects.Locations.OsPolicyAssignments.List(parent).Pages(grpCtx, func(page *osconfig.ListOSPolicyAssignmentsResponse) error {
				for _, a := range page.OsPolicyAssignments {
					mqlAssignment, err := newMqlOsPolicyAssignment(g.MqlRuntime, a)
					if err != nil {
						return err
					}
					mux.Lock()
					res = append(res, mqlAssignment)
					mux.Unlock()
				}
				return nil
			})
			if err != nil {
				if isSkippable(err) {
					log.Warn().Err(err).Str("zone", zone).Msg("could not list OS policy assignments")
					return nil
				}
				return err
			}
			return nil
		})
	}
	if err := grp.Wait(); err != nil {
		return nil, err
	}
	return res, nil
}

func newMqlOsPolicyAssignment(runtime *plugin.Runtime, a *osconfig.OSPolicyAssignment) (plugin.Resource, error) {
	osPolicies, err := convert.JsonToDictSlice(a.OsPolicies)
	if err != nil {
		return nil, err
	}
	instanceFilter, err := convert.JsonToDict(a.InstanceFilter)
	if err != nil {
		return nil, err
	}
	rollout, err := convert.JsonToDict(a.Rollout)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "gcp.project.osConfigService.osPolicyAssignment", map[string]*llx.RawData{
		"name":               llx.StringData(a.Name),
		"description":        llx.StringData(a.Description),
		"osPolicies":         llx.ArrayData(osPolicies, types.Dict),
		"instanceFilter":     llx.DictData(instanceFilter),
		"rollout":            llx.DictData(rollout),
		"revisionId":         llx.StringData(a.RevisionId),
		"revisionCreateTime": llx.TimeDataPtr(parseTime(a.RevisionCreateTime)),
		"rolloutState":       llx.StringData(a.RolloutState),
		"baseline":           llx.BoolData(a.Baseline),
		"deleted":            llx.BoolData(a.Deleted),
		"reconciling":        llx.BoolData(a.Reconciling),
	})
}

func (g *mqlGcpProjectComputeServiceInstanceOsInventory) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectComputeServiceInstanceVulnerabilityReport) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// instanceOsConfigName builds the VM Manager resource path for an instance:
// projects/{project}/locations/{zone}/instances/{instanceId}.
func (g *mqlGcpProjectComputeServiceInstance) instanceOsConfigName() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	zone := g.GetZone()
	if zone.Error != nil {
		return "", zone.Error
	}
	zoneName := zone.Data.GetName()
	if zoneName.Error != nil {
		return "", zoneName.Error
	}
	return fmt.Sprintf("projects/%s/locations/%s/instances/%s", g.ProjectId.Data, zoneName.Data, g.Id.Data), nil
}

func (g *mqlGcpProjectComputeServiceInstance) inventory() (*mqlGcpProjectComputeServiceInstanceOsInventory, error) {
	parent, err := g.instanceOsConfigName()
	if err != nil {
		return nil, err
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(osconfig.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	osConfigSvc, err := osconfig.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	inv, err := osConfigSvc.Projects.Locations.Instances.Inventories.Get(parent + "/inventory").View("FULL").Do()
	if err != nil {
		if isSkippable(err) {
			g.Inventory.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	inventoryItems := make([]any, 0, len(inv.Items))
	for _, item := range inv.Items {
		mqlItem, err := newMqlOsInventoryItem(g.MqlRuntime, inv.Name, &item)
		if err != nil {
			return nil, err
		}
		inventoryItems = append(inventoryItems, mqlItem)
	}

	var osHostname, osLongName, osShortName, osVersion, osArchitecture, kernelVersion, kernelRelease, osConfigAgentVersion string
	if inv.OsInfo != nil {
		osHostname = inv.OsInfo.Hostname
		osLongName = inv.OsInfo.LongName
		osShortName = inv.OsInfo.ShortName
		osVersion = inv.OsInfo.Version
		osArchitecture = inv.OsInfo.Architecture
		kernelVersion = inv.OsInfo.KernelVersion
		kernelRelease = inv.OsInfo.KernelRelease
		osConfigAgentVersion = inv.OsInfo.OsconfigAgentVersion
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.instance.osInventory", map[string]*llx.RawData{
		"name":                 llx.StringData(inv.Name),
		"osHostname":           llx.StringData(osHostname),
		"osLongName":           llx.StringData(osLongName),
		"osShortName":          llx.StringData(osShortName),
		"osVersion":            llx.StringData(osVersion),
		"osArchitecture":       llx.StringData(osArchitecture),
		"kernelVersion":        llx.StringData(kernelVersion),
		"kernelRelease":        llx.StringData(kernelRelease),
		"osConfigAgentVersion": llx.StringData(osConfigAgentVersion),
		"inventoryItems":       llx.ArrayData(inventoryItems, types.Resource("gcp.project.computeService.instance.osInventory.item")),
		"updateTime":           llx.TimeDataPtr(parseTime(inv.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceInstanceOsInventory), nil
}

// osInventorySoftwarePackage extracts the package manager label, name,
// version, and architecture from whichever variant of the inventory software
// package is set.
func osInventorySoftwarePackage(pkg *osconfig.InventorySoftwarePackage) (pkgType, name, version, arch string) {
	if pkg == nil {
		return "", "", "", ""
	}
	switch {
	case pkg.AptPackage != nil:
		v := pkg.AptPackage
		return "apt", v.PackageName, v.Version, v.Architecture
	case pkg.YumPackage != nil:
		v := pkg.YumPackage
		return "yum", v.PackageName, v.Version, v.Architecture
	case pkg.ZypperPackage != nil:
		v := pkg.ZypperPackage
		return "zypper", v.PackageName, v.Version, v.Architecture
	case pkg.GoogetPackage != nil:
		v := pkg.GoogetPackage
		return "googet", v.PackageName, v.Version, v.Architecture
	case pkg.CosPackage != nil:
		v := pkg.CosPackage
		return "cos", v.PackageName, v.Version, v.Architecture
	case pkg.WuaPackage != nil:
		return "wua", pkg.WuaPackage.Title, "", ""
	case pkg.QfePackage != nil:
		return "qfe", pkg.QfePackage.HotFixId, "", ""
	case pkg.WindowsApplication != nil:
		return "windowsApplication", pkg.WindowsApplication.DisplayName, pkg.WindowsApplication.DisplayVersion, ""
	case pkg.ZypperPatch != nil:
		return "zypperPatch", pkg.ZypperPatch.PatchName, "", ""
	default:
		return "", "", "", ""
	}
}

func newMqlOsInventoryItem(runtime *plugin.Runtime, inventoryName string, item *osconfig.InventoryItem) (plugin.Resource, error) {
	pkg := item.InstalledPackage
	if pkg == nil {
		pkg = item.AvailablePackage
	}
	pkgType, name, version, arch := osInventorySoftwarePackage(pkg)

	return CreateResource(runtime, "gcp.project.computeService.instance.osInventory.item", map[string]*llx.RawData{
		"__id":                llx.StringData(inventoryName + "/" + item.Id),
		"itemId":              llx.StringData(item.Id),
		"type":                llx.StringData(item.Type),
		"packageType":         llx.StringData(pkgType),
		"packageName":         llx.StringData(name),
		"packageVersion":      llx.StringData(version),
		"packageArchitecture": llx.StringData(arch),
		"updateTime":          llx.TimeDataPtr(parseTime(item.UpdateTime)),
	})
}

func (g *mqlGcpProjectComputeServiceInstance) vulnerabilityReport() (*mqlGcpProjectComputeServiceInstanceVulnerabilityReport, error) {
	parent, err := g.instanceOsConfigName()
	if err != nil {
		return nil, err
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	client, err := conn.Client(osconfig.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	osConfigSvc, err := osconfig.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	report, err := osConfigSvc.Projects.Locations.Instances.VulnerabilityReports.Get(parent + "/vulnerabilityReport").Do()
	if err != nil {
		if isSkippable(err) {
			g.VulnerabilityReport.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	vulnDetails := make([]any, 0, len(report.Vulnerabilities))
	for i, v := range report.Vulnerabilities {
		mqlVuln, err := newMqlVulnerabilityReportVulnerability(g.MqlRuntime, report.Name, i, v)
		if err != nil {
			return nil, err
		}
		vulnDetails = append(vulnDetails, mqlVuln)
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.instance.vulnerabilityReport", map[string]*llx.RawData{
		"name":                         llx.StringData(report.Name),
		"vulnerabilityDetails":         llx.ArrayData(vulnDetails, types.Resource("gcp.project.computeService.instance.vulnerabilityReport.vulnerability")),
		"highestUpgradableCveSeverity": llx.StringData(report.HighestUpgradableCveSeverity),
		"updateTime":                   llx.TimeDataPtr(parseTime(report.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeServiceInstanceVulnerabilityReport), nil
}

func newMqlVulnerabilityReportVulnerability(runtime *plugin.Runtime, reportName string, idx int, v *osconfig.VulnerabilityReportVulnerability) (plugin.Resource, error) {
	var cve, severity, description string
	var cvssV3Score float64
	var references []any
	if v.Details != nil {
		cve = v.Details.Cve
		severity = v.Details.Severity
		description = v.Details.Description
		if v.Details.CvssV3 != nil {
			cvssV3Score = v.Details.CvssV3.BaseScore
		}
		var err error
		references, err = convert.JsonToDictSlice(v.Details.References)
		if err != nil {
			return nil, err
		}
	}

	fixedCpeUris := []any{}
	upstreamFixes := []any{}
	for _, item := range v.Items {
		if item.FixedCpeUri != "" {
			fixedCpeUris = append(fixedCpeUris, item.FixedCpeUri)
		}
		if item.UpstreamFix != "" {
			upstreamFixes = append(upstreamFixes, item.UpstreamFix)
		}
	}

	// CVE uniquely identifies a vulnerability per VM, but fall back to an index
	// suffix to keep the cache key unique when it is unexpectedly empty.
	idKey := cve
	if idKey == "" {
		idKey = fmt.Sprintf("vuln-%d", idx)
	}

	return CreateResource(runtime, "gcp.project.computeService.instance.vulnerabilityReport.vulnerability", map[string]*llx.RawData{
		"__id":                      llx.StringData(reportName + "/" + idKey),
		"cve":                       llx.StringData(cve),
		"severity":                  llx.StringData(severity),
		"cvssV3Score":               llx.FloatData(cvssV3Score),
		"description":               llx.StringData(description),
		"installedInventoryItemIds": llx.ArrayData(convert.SliceAnyToInterface(v.InstalledInventoryItemIds), types.String),
		"availableInventoryItemIds": llx.ArrayData(convert.SliceAnyToInterface(v.AvailableInventoryItemIds), types.String),
		"fixedCpeUris":              llx.ArrayData(fixedCpeUris, types.String),
		"upstreamFixes":             llx.ArrayData(upstreamFixes, types.String),
		"references":                llx.ArrayData(references, types.Dict),
		"updateTime":                llx.TimeDataPtr(parseTime(v.UpdateTime)),
	})
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectOsConfigService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_osconfig)
}
