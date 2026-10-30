// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/apiaccesscontrol"
	"github.com/oracle/oci-go-sdk/v65/delegateaccesscontrol"
	"github.com/oracle/oci-go-sdk/v65/lockbox"
	"github.com/oracle/oci-go-sdk/v65/operatoraccesscontrol"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// Who outside the tenancy can reach the data inside it.
//
// Four separate OCI services answer one question that no other cloud in this
// catalog forces you to ask. Operator access control gates Oracle's own staff
// on the managed database and Cloud@Customer platforms. Delegate access
// control gates third-party managed service providers. Privileged API control
// gates individual API operations behind approval. Lockbox is the Managed
// Access approval workflow.
//
// Each carries both a control object and a request history, and both are
// modeled, because the two answer different questions. The control says what
// is permitted; the history says what was actually asked for and granted. A
// control nobody has tested and a control that has never denied anything are
// indistinguishable until the requests are read.

// ----- operator access control -----

func (o *mqlOciOperatorAccessControl) id() (string, error) {
	return "oci.operatorAccessControl", nil
}

type mqlOciOperatorAccessControlControlInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciOperatorAccessControl) controls() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.OperatorControlClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]operatoraccesscontrol.OperatorControlSummary, *string, error) {
				resp, err := svc.ListOperatorControls(ctx, operatoraccesscontrol.ListOperatorControlsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.OperatorControlCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				control := items[i]

				mqlControl, err := CreateResource(o.MqlRuntime, "oci.operatorAccessControl.control", map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(control.Id),
					"name":               llx.StringDataPtr(control.OperatorControlName),
					"isFullyPreApproved": llx.BoolDataPtr(control.IsFullyPreApproved),
					"numberOfApprovers":  ociOptionalInt(control.NumberOfApprovers),
					"resourceType":       llx.StringData(string(control.ResourceType)),
					"state":              llx.StringData(string(control.LifecycleState)),
					"created":            sdkTimeData(control.TimeOfCreation),
					"timeOfModification": sdkTimeData(control.TimeOfModification),
					"freeformTags":       llx.MapData(strMapToAny(control.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(control.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlControl.(*mqlOciOperatorAccessControlControl)
				typed.cacheCompartmentID = stringValue(control.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciOperatorAccessControlControl) id() (string, error) {
	return "oci.operatorAccessControl.control/" + o.Id.Data, nil
}

func (o *mqlOciOperatorAccessControlControl) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

type mqlOciOperatorAccessControlControlAssignmentInternal struct {
	cacheCompartmentID     string
	cacheOperatorControlID string
}

func (o *mqlOciOperatorAccessControl) controlAssignments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.OperatorControlAssignmentClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]operatoraccesscontrol.OperatorControlAssignmentSummary, *string, error) {
				resp, err := svc.ListOperatorControlAssignments(ctx, operatoraccesscontrol.ListOperatorControlAssignmentsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.OperatorControlAssignmentCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				assignment := items[i]

				mqlAssignment, err := CreateResource(o.MqlRuntime, "oci.operatorAccessControl.controlAssignment", map[string]*llx.RawData{
					"id":                        llx.StringDataPtr(assignment.Id),
					"operatorControlName":       llx.StringDataPtr(assignment.OpControlName),
					"resourceId":                llx.StringDataPtr(assignment.ResourceId),
					"resourceName":              llx.StringDataPtr(assignment.ResourceName),
					"resourceType":              llx.StringData(string(assignment.ResourceType)),
					"isEnforcedAlways":          llx.BoolDataPtr(assignment.IsEnforcedAlways),
					"timeAssignmentFrom":        sdkTimeData(assignment.TimeAssignmentFrom),
					"timeAssignmentTo":          sdkTimeData(assignment.TimeAssignmentTo),
					"isLogForwarded":            llx.BoolDataPtr(assignment.IsLogForwarded),
					"remoteSyslogServerAddress": llx.StringDataPtr(assignment.RemoteSyslogServerAddress),
					"remoteSyslogServerPort":    ociOptionalInt(assignment.RemoteSyslogServerPort),
					"isHypervisorLogForwarded":  llx.BoolDataPtr(assignment.IsHypervisorLogForwarded),
					"state":                     llx.StringData(string(assignment.LifecycleState)),
					"lifecycleDetails":          llx.StringDataPtr(assignment.LifecycleDetails),
					"timeOfAssignment":          sdkTimeData(assignment.TimeOfAssignment),
					"freeformTags":              llx.MapData(strMapToAny(assignment.FreeformTags), types.String),
					"definedTags":               llx.MapData(definedTagsToAny(assignment.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlAssignment.(*mqlOciOperatorAccessControlControlAssignment)
				typed.cacheCompartmentID = stringValue(assignment.CompartmentId)
				typed.cacheOperatorControlID = stringValue(assignment.OperatorControlId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciOperatorAccessControlControlAssignment) id() (string, error) {
	return "oci.operatorAccessControl.controlAssignment/" + o.Id.Data, nil
}

func (o *mqlOciOperatorAccessControlControlAssignment) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciOperatorAccessControlControlAssignment) operatorControl() (*mqlOciOperatorAccessControlControl, error) {
	return resolveRef(o.MqlRuntime, "oci.operatorAccessControl.control",
		ocidOrEmpty(o.cacheOperatorControlID), &o.OperatorControl)
}

type mqlOciOperatorAccessControlAccessRequestInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciOperatorAccessControl) accessRequests() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.OperatorAccessRequestsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]operatoraccesscontrol.AccessRequestSummary, *string, error) {
				resp, err := svc.ListAccessRequests(ctx, operatoraccesscontrol.ListAccessRequestsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.AccessRequestCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				request := items[i]

				mqlRequest, err := CreateResource(o.MqlRuntime, "oci.operatorAccessControl.accessRequest", map[string]*llx.RawData{
					"id":                           llx.StringDataPtr(request.Id),
					"requestId":                    llx.StringDataPtr(request.RequestId),
					"accessReasonSummary":          llx.StringDataPtr(request.AccessReasonSummary),
					"resourceId":                   llx.StringDataPtr(request.ResourceId),
					"resourceName":                 llx.StringDataPtr(request.ResourceName),
					"resourceType":                 llx.StringData(string(request.ResourceType)),
					"subResources":                 llx.ArrayData(stringsToAny(request.SubResourceList), types.String),
					"actionRequests":               llx.ArrayData(stringsToAny(request.ActionRequestsList), types.String),
					"isAutoApproved":               llx.BoolDataPtr(request.IsAutoApproved),
					"severity":                     llx.StringData(string(request.Severity)),
					"duration":                     ociOptionalInt(request.Duration),
					"extendDuration":               ociOptionalInt(request.ExtendDuration),
					"state":                        llx.StringData(string(request.LifecycleState)),
					"lifecycleDetails":             llx.StringDataPtr(request.LifecycleDetails),
					"timeRequestedForFutureAccess": sdkTimeData(request.TimeRequestedForFutureAccess),
					"created":                      sdkTimeData(request.TimeOfCreation),
					"timeOfModification":           sdkTimeData(request.TimeOfModification),
					"freeformTags":                 llx.MapData(strMapToAny(request.FreeformTags), types.String),
					"definedTags":                  llx.MapData(definedTagsToAny(request.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlRequest.(*mqlOciOperatorAccessControlAccessRequest)
				typed.cacheCompartmentID = stringValue(request.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciOperatorAccessControlAccessRequest) id() (string, error) {
	return "oci.operatorAccessControl.accessRequest/" + o.Id.Data, nil
}

func (o *mqlOciOperatorAccessControlAccessRequest) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

type mqlOciOperatorAccessControlActionInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciOperatorAccessControl) actions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.OperatorActionsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]operatoraccesscontrol.OperatorActionSummary, *string, error) {
				resp, err := svc.ListOperatorActions(ctx, operatoraccesscontrol.ListOperatorActionsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.OperatorActionCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				action := items[i]

				mqlAction, err := CreateResource(o.MqlRuntime, "oci.operatorAccessControl.action", map[string]*llx.RawData{
					"id":           llx.StringDataPtr(action.Id),
					"name":         llx.StringDataPtr(action.Name),
					"description":  llx.StringDataPtr(action.Description),
					"component":    llx.StringDataPtr(action.Component),
					"resourceType": llx.StringData(string(action.ResourceType)),
					"state":        llx.StringData(string(action.LifecycleState)),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlAction.(*mqlOciOperatorAccessControlAction)
				typed.cacheCompartmentID = stringValue(action.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciOperatorAccessControlAction) id() (string, error) {
	return "oci.operatorAccessControl.action/" + o.Id.Data, nil
}

func (o *mqlOciOperatorAccessControlAction) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// ----- delegate access control -----

func (o *mqlOciDelegateAccessControl) id() (string, error) {
	return "oci.delegateAccessControl", nil
}

type mqlOciDelegateAccessControlDelegationControlInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciDelegateAccessControl) delegationControls() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.DelegateAccessControlClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]delegateaccesscontrol.DelegationControlSummary, *string, error) {
				resp, err := svc.ListDelegationControls(ctx, delegateaccesscontrol.ListDelegationControlsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.DelegationControlSummaryCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				control := items[i]

				mqlControl, err := CreateResource(o.MqlRuntime, "oci.delegateAccessControl.delegationControl", map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(control.Id),
					"name":                  llx.StringDataPtr(control.DisplayName),
					"resourceType":          llx.StringData(string(control.ResourceType)),
					"state":                 llx.StringData(string(control.LifecycleState)),
					"lifecycleStateDetails": llx.StringDataPtr(control.LifecycleStateDetails),
					"created":               sdkTimeData(control.TimeCreated),
					"timeUpdated":           sdkTimeData(control.TimeUpdated),
					"freeformTags":          llx.MapData(strMapToAny(control.FreeformTags), types.String),
					"definedTags":           llx.MapData(definedTagsToAny(control.DefinedTags), types.Any),
					"systemTags":            llx.MapData(definedTagsToAny(control.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlControl.(*mqlOciDelegateAccessControlDelegationControl)
				typed.cacheCompartmentID = stringValue(control.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciDelegateAccessControlDelegationControl) id() (string, error) {
	return "oci.delegateAccessControl.delegationControl/" + o.Id.Data, nil
}

func (o *mqlOciDelegateAccessControlDelegationControl) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

type mqlOciDelegateAccessControlDelegationSubscriptionInternal struct {
	cacheCompartmentID     string
	cacheServiceProviderID string
}

func (o *mqlOciDelegateAccessControl) delegationSubscriptions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.DelegateAccessControlClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]delegateaccesscontrol.DelegationSubscriptionSummary, *string, error) {
				resp, err := svc.ListDelegationSubscriptions(ctx, delegateaccesscontrol.ListDelegationSubscriptionsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.DelegationSubscriptionSummaryCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				subscription := items[i]

				mqlSubscription, err := CreateResource(o.MqlRuntime, "oci.delegateAccessControl.delegationSubscription", map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(subscription.Id),
					"name":                  llx.StringDataPtr(subscription.DisplayName),
					"subscribedServiceType": llx.StringData(string(subscription.SubscribedServiceType)),
					"state":                 llx.StringData(string(subscription.LifecycleState)),
					"lifecycleStateDetails": llx.StringDataPtr(subscription.LifecycleStateDetails),
					"created":               sdkTimeData(subscription.TimeCreated),
					"timeUpdated":           sdkTimeData(subscription.TimeUpdated),
					"freeformTags":          llx.MapData(strMapToAny(subscription.FreeformTags), types.String),
					"definedTags":           llx.MapData(definedTagsToAny(subscription.DefinedTags), types.Any),
					"systemTags":            llx.MapData(definedTagsToAny(subscription.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlSubscription.(*mqlOciDelegateAccessControlDelegationSubscription)
				typed.cacheCompartmentID = stringValue(subscription.CompartmentId)
				typed.cacheServiceProviderID = stringValue(subscription.ServiceProviderId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciDelegateAccessControlDelegationSubscription) id() (string, error) {
	return "oci.delegateAccessControl.delegationSubscription/" + o.Id.Data, nil
}

func (o *mqlOciDelegateAccessControlDelegationSubscription) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDelegateAccessControlDelegationSubscription) serviceProvider() (*mqlOciDelegateAccessControlServiceProvider, error) {
	return resolveRef(o.MqlRuntime, "oci.delegateAccessControl.serviceProvider",
		ocidOrEmpty(o.cacheServiceProviderID), &o.ServiceProvider)
}

type mqlOciDelegateAccessControlAccessRequestInternal struct {
	cacheCompartmentID       string
	cacheDelegationControlID string
}

func (o *mqlOciDelegateAccessControl) accessRequests() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.DelegateAccessControlClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]delegateaccesscontrol.DelegatedResourceAccessRequestSummary, *string, error) {
				resp, err := svc.ListDelegatedResourceAccessRequests(ctx, delegateaccesscontrol.ListDelegatedResourceAccessRequestsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.DelegatedResourceAccessRequestSummaryCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				request := items[i]

				mqlRequest, err := CreateResource(o.MqlRuntime, "oci.delegateAccessControl.accessRequest", map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(request.Id),
					"name":                  llx.StringDataPtr(request.DisplayName),
					"reasonForRequest":      llx.StringDataPtr(request.ReasonForRequest),
					"resourceId":            llx.StringDataPtr(request.ResourceId),
					"resourceName":          llx.StringDataPtr(request.ResourceName),
					"resourceType":          llx.StringData(string(request.ResourceType)),
					"ticketNumbers":         llx.ArrayData(stringsToAny(request.TicketNumbers), types.String),
					"requestedActionNames":  llx.ArrayData(stringsToAny(request.RequestedActionNames), types.String),
					"requesterType":         llx.StringData(string(request.RequesterType)),
					"severity":              llx.StringData(string(request.Severity)),
					"durationInHours":       ociOptionalInt(request.DurationInHours),
					"extendDurationInHours": ociOptionalInt(request.ExtendDurationInHours),
					"isAutoApproved":        llx.BoolDataPtr(request.IsAutoApproved),
					"requestStatus":         llx.StringData(string(request.RequestStatus)),
					"state":                 llx.StringData(string(request.LifecycleState)),
					"lifecycleStateDetails": llx.StringDataPtr(request.LifecycleStateDetails),
					"timeAccessRequested":   sdkTimeData(request.TimeAccessRequested),
					"created":               sdkTimeData(request.TimeCreated),
					"timeUpdated":           sdkTimeData(request.TimeUpdated),
					"freeformTags":          llx.MapData(strMapToAny(request.FreeformTags), types.String),
					"definedTags":           llx.MapData(definedTagsToAny(request.DefinedTags), types.Any),
					"systemTags":            llx.MapData(definedTagsToAny(request.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlRequest.(*mqlOciDelegateAccessControlAccessRequest)
				typed.cacheCompartmentID = stringValue(request.CompartmentId)
				typed.cacheDelegationControlID = stringValue(request.DelegationControlId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciDelegateAccessControlAccessRequest) id() (string, error) {
	return "oci.delegateAccessControl.accessRequest/" + o.Id.Data, nil
}

func (o *mqlOciDelegateAccessControlAccessRequest) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciDelegateAccessControlAccessRequest) delegationControl() (*mqlOciDelegateAccessControlDelegationControl, error) {
	return resolveRef(o.MqlRuntime, "oci.delegateAccessControl.delegationControl",
		ocidOrEmpty(o.cacheDelegationControlID), &o.DelegationControl)
}

type mqlOciDelegateAccessControlServiceProviderInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciDelegateAccessControl) serviceProviders() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.DelegateAccessControlClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]delegateaccesscontrol.ServiceProviderSummary, *string, error) {
				resp, err := svc.ListServiceProviders(ctx, delegateaccesscontrol.ListServiceProvidersRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.ServiceProviderSummaryCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				provider := items[i]

				mqlProvider, err := CreateResource(o.MqlRuntime, "oci.delegateAccessControl.serviceProvider", map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(provider.Id),
					"name":                   llx.StringDataPtr(provider.Name),
					"serviceProviderType":    llx.StringData(string(provider.ServiceProviderType)),
					"serviceTypes":           llx.ArrayData(stringsToAny(ociServiceTypeStrings(provider.ServiceTypes)), types.String),
					"supportedResourceTypes": llx.ArrayData(stringsToAny(ociDelegationResourceTypeStrings(provider.SupportedResourceTypes)), types.String),
					"state":                  llx.StringData(string(provider.LifecycleState)),
					"lifecycleStateDetails":  llx.StringDataPtr(provider.LifecycleStateDetails),
					"created":                sdkTimeData(provider.TimeCreated),
					"timeUpdated":            sdkTimeData(provider.TimeUpdated),
					"freeformTags":           llx.MapData(strMapToAny(provider.FreeformTags), types.String),
					"definedTags":            llx.MapData(definedTagsToAny(provider.DefinedTags), types.Any),
					"systemTags":             llx.MapData(definedTagsToAny(provider.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlProvider.(*mqlOciDelegateAccessControlServiceProvider)
				typed.cacheCompartmentID = stringValue(provider.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciDelegateAccessControlServiceProvider) id() (string, error) {
	return "oci.delegateAccessControl.serviceProvider/" + o.Id.Data, nil
}

func (o *mqlOciDelegateAccessControlServiceProvider) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// ociServiceTypeStrings renders the classes of service a provider offers.
func ociServiceTypeStrings(values []delegateaccesscontrol.ServiceProviderServiceTypeEnum) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

// ociDelegationResourceTypeStrings renders the resource kinds a provider can be
// engaged on.
func ociDelegationResourceTypeStrings(values []delegateaccesscontrol.DelegationControlResourceTypeEnum) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

// ----- privileged API control -----

func (o *mqlOciApiAccessControl) id() (string, error) {
	return "oci.apiAccessControl", nil
}

type mqlOciApiAccessControlPrivilegedApiControlInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciApiAccessControl) privilegedApiControls() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.PrivilegedApiControlClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]apiaccesscontrol.PrivilegedApiControlSummary, *string, error) {
				resp, err := svc.ListPrivilegedApiControls(ctx, apiaccesscontrol.ListPrivilegedApiControlsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.PrivilegedApiControlCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				control := items[i]

				mqlControl, err := CreateResource(o.MqlRuntime, "oci.apiAccessControl.privilegedApiControl", map[string]*llx.RawData{
					"id":                llx.StringDataPtr(control.Id),
					"name":              llx.StringDataPtr(control.DisplayName),
					"resourceType":      llx.StringDataPtr(control.ResourceType),
					"numberOfApprovers": ociOptionalInt(control.NumberOfApprovers),
					"state":             llx.StringData(string(control.LifecycleState)),
					"lifecycleDetails":  llx.StringDataPtr(control.LifecycleDetails),
					"created":           sdkTimeData(control.TimeCreated),
					"timeUpdated":       sdkTimeData(control.TimeUpdated),
					"freeformTags":      llx.MapData(strMapToAny(control.FreeformTags), types.String),
					"definedTags":       llx.MapData(definedTagsToAny(control.DefinedTags), types.Any),
					"systemTags":        llx.MapData(definedTagsToAny(control.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlControl.(*mqlOciApiAccessControlPrivilegedApiControl)
				typed.cacheCompartmentID = stringValue(control.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciApiAccessControlPrivilegedApiControl) id() (string, error) {
	return "oci.apiAccessControl.privilegedApiControl/" + o.Id.Data, nil
}

func (o *mqlOciApiAccessControlPrivilegedApiControl) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

type mqlOciApiAccessControlPrivilegedApiRequestInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciApiAccessControl) privilegedApiRequests() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.PrivilegedApiRequestsClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]apiaccesscontrol.PrivilegedApiRequestSummary, *string, error) {
				resp, err := svc.ListPrivilegedApiRequests(ctx, apiaccesscontrol.ListPrivilegedApiRequestsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.PrivilegedApiRequestCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				request := items[i]

				operations, err := dictSlice(request.PrivilegedOperationList)
				if err != nil {
					return nil, err
				}

				mqlRequest, err := CreateResource(o.MqlRuntime, "oci.apiAccessControl.privilegedApiRequest", map[string]*llx.RawData{
					"id":                           llx.StringDataPtr(request.Id),
					"name":                         llx.StringDataPtr(request.DisplayName),
					"requestId":                    llx.StringDataPtr(request.RequestId),
					"reasonSummary":                llx.StringDataPtr(request.ReasonSummary),
					"resourceId":                   llx.StringDataPtr(request.ResourceId),
					"resourceName":                 llx.StringDataPtr(request.ResourceName),
					"resourceType":                 llx.StringDataPtr(request.ResourceType),
					"subResourceNames":             llx.ArrayData(stringsToAny(request.SubResourceNameList), types.String),
					"privilegedOperations":         llx.ArrayData(operations, types.Dict),
					"requestState":                 llx.StringData(string(request.State)),
					"state":                        llx.StringData(string(request.LifecycleState)),
					"lifecycleDetails":             llx.StringDataPtr(request.LifecycleDetails),
					"severity":                     llx.StringData(string(request.Severity)),
					"durationInHours":              ociOptionalInt(request.DurationInHrs),
					"timeRequestedForFutureAccess": sdkTimeData(request.TimeRequestedForFutureAccess),
					"created":                      sdkTimeData(request.TimeCreated),
					"timeUpdated":                  sdkTimeData(request.TimeUpdated),
					"freeformTags":                 llx.MapData(strMapToAny(request.FreeformTags), types.String),
					"definedTags":                  llx.MapData(definedTagsToAny(request.DefinedTags), types.Any),
					"systemTags":                   llx.MapData(definedTagsToAny(request.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlRequest.(*mqlOciApiAccessControlPrivilegedApiRequest)
				typed.cacheCompartmentID = stringValue(request.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciApiAccessControlPrivilegedApiRequest) id() (string, error) {
	return "oci.apiAccessControl.privilegedApiRequest/" + o.Id.Data, nil
}

func (o *mqlOciApiAccessControlPrivilegedApiRequest) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// ----- lockbox -----

func (o *mqlOciLockbox) id() (string, error) {
	return "oci.lockbox", nil
}

type mqlOciLockboxLockboxInternal struct {
	cacheCompartmentID      string
	cacheApprovalTemplateID string
	cacheRegion             string
}

func (o *mqlOciLockbox) lockboxes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.LockboxClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]lockbox.LockboxSummary, *string, error) {
				resp, err := svc.ListLockboxes(ctx, lockbox.ListLockboxesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.LockboxCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				box := items[i]

				mqlLockbox, err := CreateResource(o.MqlRuntime, "oci.lockbox.lockbox", map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(box.Id),
					"name":                 llx.StringDataPtr(box.DisplayName),
					"resourceId":           llx.StringDataPtr(box.ResourceId),
					"lockboxPartner":       llx.StringData(string(box.LockboxPartner)),
					"partnerId":            llx.StringDataPtr(box.PartnerId),
					"partnerCompartmentId": llx.StringDataPtr(box.PartnerCompartmentId),
					"maxAccessDuration":    llx.StringDataPtr(box.MaxAccessDuration),
					"state":                llx.StringData(string(box.LifecycleState)),
					"lifecycleDetails":     llx.StringDataPtr(box.LifecycleDetails),
					"created":              sdkTimeData(box.TimeCreated),
					"timeUpdated":          sdkTimeData(box.TimeUpdated),
					"freeformTags":         llx.MapData(strMapToAny(box.FreeformTags), types.String),
					"definedTags":          llx.MapData(definedTagsToAny(box.DefinedTags), types.Any),
					"systemTags":           llx.MapData(definedTagsToAny(box.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlLockbox.(*mqlOciLockboxLockbox)
				typed.cacheCompartmentID = stringValue(box.CompartmentId)
				typed.cacheApprovalTemplateID = stringValue(box.ApprovalTemplateId)
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

func (o *mqlOciLockboxLockbox) id() (string, error) {
	return "oci.lockbox.lockbox/" + o.Id.Data, nil
}

func (o *mqlOciLockboxLockbox) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciLockboxLockbox) approvalTemplate() (*mqlOciLockboxApprovalTemplate, error) {
	return resolveRef(o.MqlRuntime, "oci.lockbox.approvalTemplate",
		ocidOrEmpty(o.cacheApprovalTemplateID), &o.ApprovalTemplate)
}

// accessRequests lists the requests raised against this lockbox.
//
// Scoped to the lockbox because that is the only scope the API offers:
// ListAccessRequests takes a lockbox rather than a compartment, so unlike the
// other request histories here there is no tenancy-wide listing to filter.
func (o *mqlOciLockboxLockbox) accessRequests() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.LockboxClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]lockbox.AccessRequestSummary, *string, error) {
		resp, err := svc.ListAccessRequests(ctx, lockbox.ListAccessRequestsRequest{
			LockboxId: new(o.Id.Data),
			Page:      page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.AccessRequestCollection.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		request := items[i]

		mqlRequest, err := CreateResource(o.MqlRuntime, "oci.lockbox.accessRequest", map[string]*llx.RawData{
			"id":                llx.StringDataPtr(request.Id),
			"name":              llx.StringDataPtr(request.DisplayName),
			"description":       llx.StringDataPtr(request.Description),
			"requestorId":       llx.StringDataPtr(request.RequestorId),
			"requestorLocation": llx.StringDataPtr(request.RequestorLocation),
			"accessDuration":    llx.StringDataPtr(request.AccessDuration),
			"ticketNumber":      llx.StringDataPtr(request.TicketNumber),
			"state":             llx.StringData(string(request.LifecycleState)),
			"created":           sdkTimeData(request.TimeCreated),
			"timeUpdated":       sdkTimeData(request.TimeUpdated),
			"timeExpired":       sdkTimeData(request.TimeExpired),
			"freeformTags":      llx.MapData(strMapToAny(request.FreeformTags), types.String),
			"definedTags":       llx.MapData(definedTagsToAny(request.DefinedTags), types.Any),
			"systemTags":        llx.MapData(definedTagsToAny(request.SystemTags), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlRequest.(*mqlOciLockboxAccessRequest)
		typed.cacheLockboxID = stringValue(request.LockboxId)
		res = append(res, typed)
	}
	return res, nil
}

type mqlOciLockboxApprovalTemplateInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciLockbox) approvalTemplates() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.LockboxClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]lockbox.ApprovalTemplateSummary, *string, error) {
				resp, err := svc.ListApprovalTemplates(ctx, lockbox.ListApprovalTemplatesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return resp.ApprovalTemplateCollection.Items, resp.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				template := items[i]

				mqlTemplate, err := CreateResource(o.MqlRuntime, "oci.lockbox.approvalTemplate", map[string]*llx.RawData{
					"id":                llx.StringDataPtr(template.Id),
					"name":              llx.StringDataPtr(template.DisplayName),
					"autoApprovalState": llx.StringData(string(template.AutoApprovalState)),
					"approverLevels":    llx.ArrayData(ociApproverLevels(template.ApproverLevels), types.Dict),
					"state":             llx.StringData(string(template.LifecycleState)),
					"created":           sdkTimeData(template.TimeCreated),
					"timeUpdated":       sdkTimeData(template.TimeUpdated),
					"freeformTags":      llx.MapData(strMapToAny(template.FreeformTags), types.String),
					"definedTags":       llx.MapData(definedTagsToAny(template.DefinedTags), types.Any),
					"systemTags":        llx.MapData(definedTagsToAny(template.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlTemplate.(*mqlOciLockboxApprovalTemplate)
				typed.cacheCompartmentID = stringValue(template.CompartmentId)
				res = append(res, typed)
			}
			return res, nil
		})
}

// ociApproverLevels flattens the approval chain into an ordered list.
//
// The API models the chain as three named optional slots rather than a list,
// which makes the one question worth asking - how many people have to agree -
// awkward to reach and easy to get wrong. Flattening to a list in level order
// makes it `approverLevels.length`, and dropping the unset slots means that
// count is the number of approvals actually required rather than three.
//
// A gap in the middle is not closed up: level 3 set with level 2 unset keeps
// its `level` of 3, because the number identifies which slot the approver
// sits in and renumbering it would report a different chain than the one
// configured.
func ociApproverLevels(levels *lockbox.ApproverLevels) []any {
	if levels == nil {
		return []any{}
	}

	res := []any{}
	for _, entry := range []struct {
		level int64
		info  *lockbox.ApproverInfo
	}{
		{1, levels.Level1},
		{2, levels.Level2},
		{3, levels.Level3},
	} {
		if entry.info == nil {
			continue
		}
		res = append(res, map[string]any{
			"level":        entry.level,
			"approverType": string(entry.info.ApproverType),
			"approverId":   stringValue(entry.info.ApproverId),
			"domainId":     stringValue(entry.info.DomainId),
		})
	}
	return res
}

func (o *mqlOciLockboxApprovalTemplate) id() (string, error) {
	return "oci.lockbox.approvalTemplate/" + o.Id.Data, nil
}

func (o *mqlOciLockboxApprovalTemplate) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

type mqlOciLockboxAccessRequestInternal struct {
	cacheLockboxID string
}

func (o *mqlOciLockboxAccessRequest) id() (string, error) {
	return "oci.lockbox.accessRequest/" + o.Id.Data, nil
}

func (o *mqlOciLockboxAccessRequest) lockbox() (*mqlOciLockboxLockbox, error) {
	return resolveRef(o.MqlRuntime, "oci.lockbox.lockbox", ocidOrEmpty(o.cacheLockboxID), &o.Lockbox)
}
