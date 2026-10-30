// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jamf/connection"
)

// packageToArgs maps a Jamf Pro package into the MQL resource fields. It is
// shared by the list creator and the by-id init function so both paths
// populate the resource identically.
func packageToArgs(c jamfpro.ResourcePackage) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                   llx.StringData(c.ID),
		"name":                 llx.StringData(c.PackageName),
		"fileName":             llx.StringData(c.FileName),
		"osInstall":            llx.BoolDataPtr(c.OSInstall),
		"categoryId":           llx.StringData(c.CategoryID),
		"priority":             llx.IntData(c.Priority),
		"suppressUpdates":      llx.BoolDataPtr(c.SuppressUpdates),
		"suppressRegistration": llx.BoolDataPtr(c.SuppressRegistration),
		"sha256":               llx.StringData(c.SHA256),
		"size":                 llx.StringData(c.Size),
		"format":               llx.StringData(c.Format),
		"info":                 llx.StringData(c.Info),
		"notes":                llx.StringData(c.Notes),
		"osRequirements":       llx.StringData(c.OSRequirements),
		"installLanguage":      llx.StringData(c.InstallLanguage),
		"serialNumber":         llx.StringData(c.SerialNumber),
		"basePath":             llx.StringData(c.BasePath),
		"osInstallerVersion":   llx.StringData(c.OSInstallerVersion),
		"manifest":             llx.StringData(c.Manifest),
		"manifestFileName":     llx.StringData(c.ManifestFileName),
		"fillUserTemplate":     llx.BoolDataPtr(c.FillUserTemplate),
		"fillExistingUsers":    llx.BoolDataPtr(c.FillExistingUsers),
		"indexed":              llx.BoolDataPtr(c.Indexed),
		"swu":                  llx.BoolDataPtr(c.SWU),
		"rebootRequired":       llx.BoolDataPtr(c.RebootRequired),
		"selfHealNotify":       llx.BoolDataPtr(c.SelfHealNotify),
		"selfHealingAction":    llx.StringData(c.SelfHealingAction),
		"ignoreConflicts":      llx.BoolDataPtr(c.IgnoreConflicts),
		"suppressFromDock":     llx.BoolDataPtr(c.SuppressFromDock),
		"suppressEula":         llx.BoolDataPtr(c.SuppressEula),
		"cloudTransferStatus":  llx.StringData(c.CloudTransferStatus),
		"parentPackageId":      llx.StringData(c.ParentPackageID),
	}
}

func (r *mqlJamf) packages() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	// GetPackages paginates through every page internally and returns the
	// full set of results, so a single call here is the complete inventory.
	inventory, err := client.GetPackages("id:asc", "")
	if err != nil {
		return nil, err
	}

	var res []any
	for _, c := range inventory.Results {
		item, err := CreateResource(r.MqlRuntime, "jamf.package", packageToArgs(c))
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}

	return res, nil
}

// initJamfPackage resolves a package referenced only by id (e.g. via a
// parentPackage traversal or a direct jamf.package(id:) query) by fetching its
// full definition. When the resource already carries its fields (the list
// path), the args are returned unchanged.
func initJamfPackage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.JamfConnection)
	pkg, err := conn.Client.GetPackageByID(id)
	if err != nil {
		return nil, nil, err
	}

	return packageToArgs(*pkg), nil, nil
}

func (c *mqlJamfPackage) id() (string, error) {
	return "jamf.package/" + c.Id.Data, nil
}

func (c *mqlJamfPackage) parentPackage() (*mqlJamfPackage, error) {
	parentID := c.ParentPackageId.Data
	// "", "-1", and "0" all indicate the package has no parent.
	if parentID == "" || parentID == "-1" || parentID == "0" {
		c.ParentPackage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(c.MqlRuntime, "jamf.package", map[string]*llx.RawData{
		"id": llx.StringData(parentID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJamfPackage), nil
}
