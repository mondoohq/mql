// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// ---- typed VM and scale set extensions ----

// extensionFields holds the extension properties shared by VM and scale set
// extensions, already converted for the resource args.
type extensionFields struct {
	publisher                   *string
	extensionType               *string
	typeHandlerVersion          *string
	autoUpgradeMinorVersion     *bool
	enableAutomaticUpgrade      *bool
	suppressFailures            *bool
	provisioningState           *string
	forceUpdateTag              *string
	settings                    map[string]any
	protectedSettingsInKeyVault bool
	provisionAfterExtensions    []any
}

func (f extensionFields) args() map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"publisher":                   llx.StringDataPtr(f.publisher),
		"extensionType":               llx.StringDataPtr(f.extensionType),
		"typeHandlerVersion":          llx.StringDataPtr(f.typeHandlerVersion),
		"autoUpgradeMinorVersion":     llx.BoolDataPtr(f.autoUpgradeMinorVersion),
		"enableAutomaticUpgrade":      llx.BoolDataPtr(f.enableAutomaticUpgrade),
		"suppressFailures":            llx.BoolDataPtr(f.suppressFailures),
		"provisioningState":           llx.StringDataPtr(f.provisioningState),
		"forceUpdateTag":              llx.StringDataPtr(f.forceUpdateTag),
		"settings":                    llx.DictData(f.settings),
		"protectedSettingsInKeyVault": llx.BoolData(f.protectedSettingsInKeyVault),
		"provisionAfterExtensions":    llx.ArrayData(f.provisionAfterExtensions, types.String),
	}
}

func vmExtensionFields(p *compute.VirtualMachineExtensionProperties) (extensionFields, error) {
	f := extensionFields{provisionAfterExtensions: []any{}}
	if p == nil {
		return f, nil
	}
	settings, err := convert.JsonToDict(p.Settings)
	if err != nil {
		return f, err
	}
	f.publisher = p.Publisher
	f.extensionType = p.Type
	f.typeHandlerVersion = p.TypeHandlerVersion
	f.autoUpgradeMinorVersion = p.AutoUpgradeMinorVersion
	f.enableAutomaticUpgrade = p.EnableAutomaticUpgrade
	f.suppressFailures = p.SuppressFailures
	f.provisioningState = p.ProvisioningState
	f.forceUpdateTag = p.ForceUpdateTag
	f.settings = redactSettingsDict(settings)
	f.protectedSettingsInKeyVault = p.ProtectedSettingsFromKeyVault != nil
	f.provisionAfterExtensions = strPtrsToAny(p.ProvisionAfterExtensions)
	return f, nil
}

func vmssExtensionFields(p *compute.VirtualMachineScaleSetExtensionProperties) (extensionFields, error) {
	f := extensionFields{provisionAfterExtensions: []any{}}
	if p == nil {
		return f, nil
	}
	settings, err := convert.JsonToDict(p.Settings)
	if err != nil {
		return f, err
	}
	f.publisher = p.Publisher
	f.extensionType = p.Type
	f.typeHandlerVersion = p.TypeHandlerVersion
	f.autoUpgradeMinorVersion = p.AutoUpgradeMinorVersion
	f.enableAutomaticUpgrade = p.EnableAutomaticUpgrade
	f.suppressFailures = p.SuppressFailures
	f.provisioningState = p.ProvisioningState
	f.forceUpdateTag = p.ForceUpdateTag
	f.settings = redactSettingsDict(settings)
	f.protectedSettingsInKeyVault = p.ProtectedSettingsFromKeyVault != nil
	f.provisionAfterExtensions = strPtrsToAny(p.ProvisionAfterExtensions)
	return f, nil
}

// childResourceID returns the child's own ARM id, or builds one from the parent
// id, the child collection, and the child name when the API left it out.
func childResourceID(id *string, parentID, collection string, name *string) string {
	if id != nil && *id != "" {
		return *id
	}
	if name == nil || *name == "" {
		return ""
	}
	return parentID + "/" + collection + "/" + *name
}

func (a *mqlAzureSubscriptionComputeServiceVm) installedExtensions() ([]any, error) {
	list, err := a.fetchExtensions()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(list))
	for _, ext := range list {
		if ext == nil {
			continue
		}
		id := childResourceID(ext.ID, a.Id.Data, "extensions", ext.Name)
		if id == "" {
			continue
		}
		fields, err := vmExtensionFields(ext.Properties)
		if err != nil {
			return nil, err
		}
		args := fields.args()
		args["id"] = llx.StringData(id)
		args["name"] = llx.StringDataPtr(ext.Name)
		args["location"] = llx.StringDataPtr(ext.Location)
		args["tags"] = llx.MapData(convert.PtrMapStrToInterface(ext.Tags), types.String)
		mqlExt, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionComputeServiceVmExtension, args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlExt)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmExtension) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) installedExtensions() ([]any, error) {
	list, err := a.fetchExtensions()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(list))
	for _, ext := range list {
		if ext == nil {
			continue
		}
		id := childResourceID(ext.ID, a.Id.Data, "extensions", ext.Name)
		if id == "" {
			continue
		}
		fields, err := vmssExtensionFields(ext.Properties)
		if err != nil {
			return nil, err
		}
		args := fields.args()
		args["id"] = llx.StringData(id)
		args["name"] = llx.StringDataPtr(ext.Name)
		mqlExt, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionComputeServiceVmScaleSetExtension, args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlExt)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSetExtension) id() (string, error) {
	return a.Id.Data, nil
}

// ---- patch assessment ----

// vmPatchAssessmentMode returns the patch assessment mode from whichever OS
// configuration the VM carries, or nil when it reports none.
func vmPatchAssessmentMode(props *compute.VirtualMachineProperties) *string {
	if props == nil || props.OSProfile == nil {
		return nil
	}
	if lc := props.OSProfile.LinuxConfiguration; lc != nil && lc.PatchSettings != nil && lc.PatchSettings.AssessmentMode != nil {
		return stringEnumPtr(lc.PatchSettings.AssessmentMode)
	}
	if wc := props.OSProfile.WindowsConfiguration; wc != nil && wc.PatchSettings != nil && wc.PatchSettings.AssessmentMode != nil {
		return stringEnumPtr(wc.PatchSettings.AssessmentMode)
	}
	return nil
}

// availablePatchSummary returns the result of the VM's latest patch
// assessment, or nil when the VM has never reported one.
func availablePatchSummary(view *compute.VirtualMachineInstanceView) *compute.AvailablePatchSummary {
	if view == nil || view.PatchStatus == nil {
		return nil
	}
	return view.PatchStatus.AvailablePatchSummary
}

func (a *mqlAzureSubscriptionComputeServiceVm) patchSummary() (*compute.AvailablePatchSummary, error) {
	view, err := a.fetchInstanceView()
	if err != nil {
		return nil, err
	}
	return availablePatchSummary(view), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) patchAssessmentStatus() (string, error) {
	s, err := a.patchSummary()
	if err != nil {
		return "", err
	}
	if s == nil || s.Status == nil {
		a.PatchAssessmentStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(*s.Status), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) patchAssessmentTime() (*time.Time, error) {
	s, err := a.patchSummary()
	if err != nil {
		return nil, err
	}
	if s == nil || s.LastModifiedTime == nil {
		a.PatchAssessmentTime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return s.LastModifiedTime, nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) pendingCriticalAndSecurityPatchCount() (int64, error) {
	s, err := a.patchSummary()
	if err != nil {
		return 0, err
	}
	if s == nil || s.CriticalAndSecurityPatchCount == nil {
		a.PendingCriticalAndSecurityPatchCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*s.CriticalAndSecurityPatchCount), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) pendingOtherPatchCount() (int64, error) {
	s, err := a.patchSummary()
	if err != nil {
		return 0, err
	}
	if s == nil || s.OtherPatchCount == nil {
		a.PendingOtherPatchCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*s.OtherPatchCount), nil
}

func (a *mqlAzureSubscriptionComputeServiceVm) rebootPending() (bool, error) {
	s, err := a.patchSummary()
	if err != nil {
		return false, err
	}
	if s == nil || s.RebootPending == nil {
		a.RebootPending.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.RebootPending, nil
}

// ---- run commands ----

// Values reported by runCommand.scriptSource.
const (
	runCommandSourceInline    = "inlineScript"
	runCommandSourceURI       = "scriptUri"
	runCommandSourceCommandID = "commandId"
	runCommandSourceGallery   = "galleryScript"
)

// runCommandScriptSource names which of the mutually exclusive script sources
// a run command uses, or "" when none is set.
func runCommandScriptSource(src *compute.VirtualMachineRunCommandScriptSource) string {
	if src == nil {
		return ""
	}
	switch {
	case src.Script != nil && *src.Script != "":
		return runCommandSourceInline
	case src.ScriptURI != nil && *src.ScriptURI != "":
		return runCommandSourceURI
	case src.CommandID != nil && *src.CommandID != "":
		return runCommandSourceCommandID
	case src.GalleryScriptReferenceID != nil && *src.GalleryScriptReferenceID != "":
		return runCommandSourceGallery
	}
	return ""
}

// runCommandArgs builds the resource args for a run command. It never copies
// the script, its parameters, its output, the run-as password, or a SAS
// token.
func runCommandArgs(rc *compute.VirtualMachineRunCommand) map[string]*llx.RawData {
	var (
		scriptSource, scriptURI                         string
		hasInlineScript, scriptURIHasSAS                bool
		commandID, galleryScriptID, scriptShell         *string
		runAsUser, provisioningState                    *string
		timeout                                         *int64
		asyncExecution, treatFailureAsDeploymentFailure *bool
		outputBlobConfigured, errorBlobConfigured       bool
	)
	if p := rc.Properties; p != nil {
		if src := p.Source; src != nil {
			scriptSource = runCommandScriptSource(src)
			hasInlineScript = src.Script != nil && *src.Script != ""
			if src.ScriptURI != nil {
				scriptURIHasSAS = urlHasSASToken(*src.ScriptURI)
				scriptURI, _ = stripURLCredentials(*src.ScriptURI)
			}
			commandID = src.CommandID
			galleryScriptID = src.GalleryScriptReferenceID
			scriptShell = stringEnumPtr(src.ScriptShell)
		}
		runAsUser = p.RunAsUser
		provisioningState = p.ProvisioningState
		if p.TimeoutInSeconds != nil {
			timeout = to.Ptr(int64(*p.TimeoutInSeconds))
		}
		asyncExecution = p.AsyncExecution
		treatFailureAsDeploymentFailure = p.TreatFailureAsDeploymentFailure
		outputBlobConfigured = p.OutputBlobURI != nil && *p.OutputBlobURI != ""
		errorBlobConfigured = p.ErrorBlobURI != nil && *p.ErrorBlobURI != ""
	}
	return map[string]*llx.RawData{
		"id":                              llx.StringDataPtr(rc.ID),
		"name":                            llx.StringDataPtr(rc.Name),
		"location":                        llx.StringDataPtr(rc.Location),
		"tags":                            llx.MapData(convert.PtrMapStrToInterface(rc.Tags), types.String),
		"scriptSource":                    llx.StringData(scriptSource),
		"hasInlineScript":                 llx.BoolData(hasInlineScript),
		"scriptUri":                       llx.StringData(scriptURI),
		"scriptUriHasSasToken":            llx.BoolData(scriptURIHasSAS),
		"commandId":                       llx.StringDataPtr(commandID),
		"galleryScriptId":                 llx.StringDataPtr(galleryScriptID),
		"scriptShell":                     llx.StringDataPtr(scriptShell),
		"runAsUser":                       llx.StringDataPtr(runAsUser),
		"timeoutInSeconds":                llx.IntDataPtr(timeout),
		"asyncExecution":                  llx.BoolDataPtr(asyncExecution),
		"treatFailureAsDeploymentFailure": llx.BoolDataPtr(treatFailureAsDeploymentFailure),
		"outputBlobConfigured":            llx.BoolData(outputBlobConfigured),
		"errorBlobConfigured":             llx.BoolData(errorBlobConfigured),
		"provisioningState":               llx.StringDataPtr(provisioningState),
	}
}

// runCommandExecution is the outcome of a run command's last execution. Each
// field is nil when Azure reports no value, so a run command that never ran
// reads as null rather than as a zero exit code that looks like success.
type runCommandExecution struct {
	state     *string
	exitCode  *int64
	startTime *time.Time
	endTime   *time.Time
}

// runCommandExecutionFrom reads the execution outcome from an instance view.
// The script output and error text are never copied.
func runCommandExecutionFrom(iv *compute.VirtualMachineRunCommandInstanceView) runCommandExecution {
	var e runCommandExecution
	if iv == nil {
		return e
	}
	e.state = stringEnumPtr(iv.ExecutionState)
	if iv.ExitCode != nil {
		e.exitCode = to.Ptr(int64(*iv.ExitCode))
	}
	e.startTime = iv.StartTime
	e.endTime = iv.EndTime
	return e
}

func (a *mqlAzureSubscriptionComputeServiceVm) runCommands() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	vmName, err := resourceID.Component("virtualMachines")
	if err != nil {
		return nil, err
	}
	client, err := compute.NewVirtualMachineRunCommandsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// ARM ignores the expand on this list call today; if it ever honors it,
	// the instance views seed fetchExecution and save one GET per command.
	pager := client.NewListByVirtualMachinePager(resourceID.ResourceGroup, vmName, &compute.VirtualMachineRunCommandsClientListByVirtualMachineOptions{
		Expand: to.Ptr("instanceView"),
	})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.Compute/virtualMachines/runCommands/read")
		}
		for _, rc := range page.Value {
			if rc == nil || rc.ID == nil {
				continue
			}
			mqlRc, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionComputeServiceVmRunCommand, runCommandArgs(rc))
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(rc.SystemData)
			if err != nil {
				return nil, err
			}
			typed := mqlRc.(*mqlAzureSubscriptionComputeServiceVmRunCommand)
			typed.cacheSystemData = sysData
			if rc.Properties != nil {
				typed.cacheInstanceView = rc.Properties.InstanceView
			}
			res = append(res, mqlRc)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionComputeServiceVmRunCommandInternal struct {
	cacheSystemData   any
	cacheInstanceView *compute.VirtualMachineRunCommandInstanceView

	executionOnce sync.Once
	execution     runCommandExecution
	executionErr  error
}

// fetchExecution reads the outcome of the run command's last execution. The
// run command list leaves out the instance view even when asked to expand it,
// so it takes a GET of the single run command. Every execution field shares
// this one call.
func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) fetchExecution() (runCommandExecution, error) {
	a.executionOnce.Do(func() {
		iv := a.cacheInstanceView
		if iv == nil {
			iv, a.executionErr = a.loadInstanceView()
		}
		a.execution = runCommandExecutionFrom(iv)
	})
	return a.execution, a.executionErr
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) loadInstanceView() (*compute.VirtualMachineRunCommandInstanceView, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	vmName, err := resourceID.Component("virtualMachines")
	if err != nil {
		return nil, err
	}
	name, err := resourceID.Component("runCommands")
	if err != nil {
		return nil, err
	}
	client, err := compute.NewVirtualMachineRunCommandsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := client.GetByVirtualMachine(context.Background(), resourceID.ResourceGroup, vmName, name,
		&compute.VirtualMachineRunCommandsClientGetByVirtualMachineOptions{Expand: to.Ptr("instanceView")})
	if err != nil {
		return nil, classifyAzureRefusal(err, "Microsoft.Compute/virtualMachines/runCommands/read")
	}
	if resp.Properties == nil {
		return nil, nil
	}
	return resp.Properties.InstanceView, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) executionState() (string, error) {
	e, err := a.fetchExecution()
	if err != nil {
		return "", err
	}
	if e.state == nil {
		a.ExecutionState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *e.state, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) exitCode() (int64, error) {
	e, err := a.fetchExecution()
	if err != nil {
		return 0, err
	}
	if e.exitCode == nil {
		a.ExitCode.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *e.exitCode, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) startTime() (*time.Time, error) {
	e, err := a.fetchExecution()
	if err != nil {
		return nil, err
	}
	if e.startTime == nil {
		a.StartTime.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return e.startTime, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) endTime() (*time.Time, error) {
	e, err := a.fetchExecution()
	if err != nil {
		return nil, err
	}
	if e.endTime == nil {
		a.EndTime.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return e.endTime, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmRunCommand) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
