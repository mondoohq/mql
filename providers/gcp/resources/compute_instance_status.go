// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/compute/v1"
)

// effectiveInstanceMetadataArgs maps the metadata values Compute Engine
// resolves for an instance (instance and project metadata merged) onto the
// instance's effective* fields. Every field is null when the API returned no
// effective metadata, so an absent block never reads as "disabled".
func effectiveInstanceMetadataArgs(rs *compute.ResourceStatus) map[string]*llx.RawData {
	var m *compute.ResourceStatusEffectiveInstanceMetadata
	if rs != nil {
		m = rs.EffectiveInstanceMetadata
	}
	if m == nil {
		return map[string]*llx.RawData{
			"effectiveOsLoginEnabled":           llx.NilData,
			"effectiveSerialPortEnabled":        llx.NilData,
			"effectiveSerialPortLoggingEnabled": llx.NilData,
			"effectiveBlockProjectSshKeys":      llx.NilData,
			"effectiveOsConfigEnabled":          llx.NilData,
			"effectiveOsInventoryEnabled":       llx.NilData,
			"effectiveGuestAttributesEnabled":   llx.NilData,
			"effectiveVmDnsSetting":             llx.NilData,
		}
	}
	return map[string]*llx.RawData{
		"effectiveOsLoginEnabled":           llx.BoolData(m.EnableOsloginMetadataValue),
		"effectiveSerialPortEnabled":        llx.BoolData(m.SerialPortEnableMetadataValue),
		"effectiveSerialPortLoggingEnabled": llx.BoolData(m.SerialPortLoggingEnableMetadataValue),
		"effectiveBlockProjectSshKeys":      llx.BoolData(m.BlockProjectSshKeysMetadataValue),
		"effectiveOsConfigEnabled":          llx.BoolData(m.EnableOsconfigMetadataValue),
		"effectiveOsInventoryEnabled":       llx.BoolData(m.EnableOsInventoryMetadataValue),
		"effectiveGuestAttributesEnabled":   llx.BoolData(m.EnableGuestAttributesMetadataValue),
		"effectiveVmDnsSetting":             llx.StringData(m.VmDnsSettingMetadataValue),
	}
}

// upcomingMaintenanceToDict returns the scheduled host maintenance of an
// instance, or nil when none is scheduled.
func upcomingMaintenanceToDict(rs *compute.ResourceStatus) map[string]any {
	if rs == nil || rs.UpcomingMaintenance == nil {
		return nil
	}
	um := rs.UpcomingMaintenance
	reasons := make([]any, 0, len(um.MaintenanceReasons))
	for _, r := range um.MaintenanceReasons {
		reasons = append(reasons, r)
	}
	return map[string]any{
		"type":                  um.Type,
		"maintenanceStatus":     um.MaintenanceStatus,
		"canReschedule":         um.CanReschedule,
		"windowStartTime":       um.WindowStartTime,
		"windowEndTime":         um.WindowEndTime,
		"latestWindowStartTime": um.LatestWindowStartTime,
		"maintenanceOnShutdown": um.MaintenanceOnShutdown,
		"maintenanceReasons":    reasons,
	}
}

func (g *mqlGcpProjectComputeServiceInstance) machineImage() (*mqlGcpProjectComputeServiceMachineImage, error) {
	mi, err := getMachineImageByUrl(g.cacheSourceMachineImageUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if mi == nil {
		g.MachineImage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mi, nil
}

// globalComputeResourceRef splits a global Compute Engine reference such as
// https://www.googleapis.com/compute/v1/projects/p/global/machineImages/n
// (or the same path without the host) into its project and name. kind is the
// collection segment, for example "machineImages" or "images". It returns
// empty strings when the reference does not name that collection.
func globalComputeResourceRef(ref, kind string) (project, name string) {
	ref = strings.TrimPrefix(ref, "https://www.googleapis.com/compute/v1/")
	ref = strings.TrimPrefix(ref, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(ref, "/")
	if len(parts) != 5 || parts[0] != "projects" || parts[2] != "global" || parts[3] != kind {
		return "", ""
	}
	if parts[1] == "" || parts[4] == "" {
		return "", ""
	}
	return parts[1], parts[4]
}

// getMachineImageByUrl resolves a machine image reference against the
// machine images listed for its project. Returns nil when the URL is empty,
// malformed, or names a machine image that no longer exists.
func getMachineImageByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceMachineImage, error) {
	project, name := globalComputeResourceRef(url, "machineImages")
	if project == "" {
		return nil, nil
	}
	obj, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(project),
	})
	if err != nil {
		return nil, err
	}
	list := obj.(*mqlGcpProjectComputeService).GetMachineImages()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, m := range list.Data {
		mi := m.(*mqlGcpProjectComputeServiceMachineImage)
		if mi.Name.Data == name {
			return mi, nil
		}
	}
	return nil, nil
}

type imageDeprecationInfo struct {
	state       string
	deprecated  string
	obsolete    string
	deleted     string
	replacement string
}

func imageDeprecation(d *compute.DeprecationStatus) imageDeprecationInfo {
	if d == nil {
		return imageDeprecationInfo{}
	}
	return imageDeprecationInfo{
		state:       d.State,
		deprecated:  d.Deprecated,
		obsolete:    d.Obsolete,
		deleted:     d.Deleted,
		replacement: d.Replacement,
	}
}

func guestOsFeatureTypes(features []*compute.GuestOsFeature) []any {
	res := make([]any, 0, len(features))
	for _, f := range features {
		if f == nil || f.Type == "" {
			continue
		}
		res = append(res, f.Type)
	}
	return res
}

func int64sToInterface(in []int64) []any {
	res := make([]any, 0, len(in))
	for _, v := range in {
		res = append(res, v)
	}
	return res
}

func (g *mqlGcpProjectComputeServiceImage) replacement() (*mqlGcpProjectComputeServiceImage, error) {
	project, name := globalComputeResourceRef(g.cacheReplacementUrl, "images")
	if project == "" {
		g.Replacement.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	obj, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(project),
	})
	if err != nil {
		return nil, err
	}
	images := obj.(*mqlGcpProjectComputeService).GetImages()
	if images.Error != nil {
		return nil, images.Error
	}
	for _, i := range images.Data {
		img := i.(*mqlGcpProjectComputeServiceImage)
		if img.Name.Data == name {
			return img, nil
		}
	}
	g.Replacement.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
