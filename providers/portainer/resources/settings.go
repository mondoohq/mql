// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

// initPortainerSettings populates the resource when it is queried directly as
// `portainer.settings`. That dotted form is both a field on `portainer` and a
// registered resource name; MQL resolves the resource name and would otherwise
// instantiate an empty husk (every field erroring with "cannot convert
// primitive with NO type information"). Delegating to the parent's settings()
// accessor fills it in. When the resource is created normally (with an __id),
// this is a no-op.
func initPortainerSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	portainer, err := CreateResource(runtime, "portainer", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	settings := portainer.(*mqlPortainer).GetSettings()
	if settings.Error != nil {
		return nil, nil, settings.Error
	}
	return args, settings.Data, nil
}

func (r *mqlPortainer) settings() (*mqlPortainerSettings, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	settings, err := conn.Client().GetSettings()
	if err != nil {
		return nil, err
	}
	if settings == nil {
		return nil, errors.New("Portainer returned no settings")
	}

	var requiredPasswordLength int64
	if settings.InternalAuthSettings != nil {
		requiredPasswordLength = settings.InternalAuthSettings.RequiredPasswordLength
	}

	res, err := CreateResource(r.MqlRuntime, "portainer.settings", map[string]*llx.RawData{
		"__id":                                      llx.StringData("portainer.settings"),
		"authenticationMethod":                      llx.StringData(connection.AuthenticationMethod(settings.AuthenticationMethod)),
		"requiredPasswordLength":                    llx.IntData(requiredPasswordLength),
		"userSessionTimeout":                        llx.StringData(settings.UserSessionTimeout),
		"enableTelemetry":                           llx.BoolData(settings.EnableTelemetry),
		"trustOnFirstConnect":                       llx.BoolData(settings.TrustOnFirstConnect),
		"enableEdgeComputeFeatures":                 llx.BoolData(settings.EnableEdgeComputeFeatures),
		"allowPrivilegedModeForRegularUsers":        llx.BoolData(settings.AllowPrivilegedModeForRegularUsers),
		"allowBindMountsForRegularUsers":            llx.BoolData(settings.AllowBindMountsForRegularUsers),
		"allowDeviceMappingForRegularUsers":         llx.BoolData(settings.AllowDeviceMappingForRegularUsers),
		"allowHostNamespaceForRegularUsers":         llx.BoolData(settings.AllowHostNamespaceForRegularUsers),
		"allowContainerCapabilitiesForRegularUsers": llx.BoolData(settings.AllowContainerCapabilitiesForRegularUsers),
		"allowStackManagementForRegularUsers":       llx.BoolData(settings.AllowStackManagementForRegularUsers),
		"allowVolumeBrowserForRegularUsers":         llx.BoolData(settings.AllowVolumeBrowserForRegularUsers),
		"disableKubeShell":                          llx.BoolData(settings.DisableKubeShell),
		"disableKubeconfigDownload":                 llx.BoolData(settings.DisableKubeconfigDownload),
		"disableKubeRolesSync":                      llx.BoolData(settings.DisableKubeRolesSync),
		"kubectlShellImage":                         llx.StringData(settings.KubectlShellImage),
		"kubeconfigExpiry":                          llx.StringData(settings.KubeconfigExpiry),
		"helmRepositoryUrl":                         llx.StringData(settings.HelmRepositoryURL),
		"snapshotInterval":                          llx.StringData(settings.SnapshotInterval),
		"edgePortainerUrl":                          llx.StringData(settings.EdgePortainerURL),
		"edgeAgentCheckinInterval":                  llx.IntData(settings.EdgeAgentCheckinInterval),
		"enforceEdgeId":                             llx.BoolData(settings.EnforceEdgeID),
		"customLoginBanner":                         llx.StringData(settings.CustomLoginBanner),
		"logoUrl":                                   llx.StringData(settings.LogoURL),
		"displayExternalContributors":               llx.BoolData(settings.DisplayExternalContributors),
		"isDockerDesktopExtension":                  llx.BoolData(settings.IsDockerDesktopExtension),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPortainerSettings), nil
}
