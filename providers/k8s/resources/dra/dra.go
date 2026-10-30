// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dra decodes Kubernetes Dynamic Resource Allocation objects.
//
// The API server serves resource.k8s.io in several versions (v1beta1, v1beta2
// and v1). The k8s provider's client scheme does not register any of them, so
// the objects arrive as unstructured maps. Decoding through JSON keeps the
// reader independent of the served version, because the field names that carry
// the allocation state are identical across those versions.
package dra

import (
	"encoding/json"
	"sort"
	"strconv"
)

// ResourceSlice is the published device inventory of one driver pool.
type ResourceSlice struct {
	Spec ResourceSliceSpec `json:"spec"`
}

// ResourceSliceSpec holds the pool, the node selection and the devices.
type ResourceSliceSpec struct {
	Driver                 string         `json:"driver"`
	Pool                   ResourcePool   `json:"pool"`
	NodeName               string         `json:"nodeName"`
	NodeSelector           map[string]any `json:"nodeSelector"`
	AllNodes               bool           `json:"allNodes"`
	PerDeviceNodeSelection bool           `json:"perDeviceNodeSelection"`
	Devices                []Device       `json:"devices"`
}

// ResourcePool identifies the pool a slice belongs to.
type ResourcePool struct {
	Name               string `json:"name"`
	Generation         int64  `json:"generation"`
	ResourceSliceCount int64  `json:"resourceSliceCount"`
}

// Device is one allocatable device inside a pool.
type Device struct {
	Name                     string                    `json:"name"`
	Attributes               map[string]DeviceAttr     `json:"attributes"`
	Capacity                 map[string]DeviceCapacity `json:"capacity"`
	AllowMultipleAllocations bool                      `json:"allowMultipleAllocations"`
	NodeName                 string                    `json:"nodeName"`
	AllNodes                 bool                      `json:"allNodes"`
	Taints                   []map[string]any          `json:"taints"`
	BindingConditions        []string                  `json:"bindingConditions"`
}

// DeviceAttr is a device attribute. Exactly one member carries the value.
type DeviceAttr struct {
	Int     *int64  `json:"int"`
	Bool    *bool   `json:"bool"`
	String  *string `json:"string"`
	Version *string `json:"version"`
}

// Value returns the attribute value as a string, and false when no member is
// set. A false result marks an attribute the reader does not understand, so
// callers can drop it rather than report an empty value as fact.
func (a DeviceAttr) Value() (string, bool) {
	switch {
	case a.Int != nil:
		return strconv.FormatInt(*a.Int, 10), true
	case a.Bool != nil:
		return strconv.FormatBool(*a.Bool), true
	case a.String != nil:
		return *a.String, true
	case a.Version != nil:
		return *a.Version, true
	default:
		return "", false
	}
}

// DeviceCapacity is a quantity a device provides.
type DeviceCapacity struct {
	Value Quantity `json:"value"`
}

// Quantity is a Kubernetes resource quantity such as "8" or "1Gi".
//
// The API server serialises a quantity as a string. A number is accepted as
// well, so a driver that publishes a bare JSON number does not fail the decode
// of the whole slice.
type Quantity string

// UnmarshalJSON reads a quantity from a JSON string or number.
func (q *Quantity) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*q = Quantity(text)
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	*q = Quantity(number.String())
	return nil
}

// ResourceClaim is a request for devices plus its allocation state.
type ResourceClaim struct {
	Spec   ResourceClaimSpec   `json:"spec"`
	Status ResourceClaimStatus `json:"status"`
}

// ResourceClaimSpec describes what the claim requests.
type ResourceClaimSpec struct {
	Devices DeviceClaim `json:"devices"`
}

// DeviceClaim holds the requests, constraints and config of a claim.
type DeviceClaim struct {
	Requests    []map[string]any `json:"requests"`
	Constraints []map[string]any `json:"constraints"`
	Config      []map[string]any `json:"config"`
}

// ResourceClaimStatus reports the allocation and the consumers.
type ResourceClaimStatus struct {
	Allocation  *AllocationResult    `json:"allocation"`
	ReservedFor []ConsumerRef        `json:"reservedFor"`
	Devices     []AllocatedDevStatus `json:"devices"`
}

// AllocationResult is the scheduler's allocation decision.
type AllocationResult struct {
	Devices      DeviceAllocationResult `json:"devices"`
	NodeSelector map[string]any         `json:"nodeSelector"`
}

// DeviceAllocationResult lists the allocated devices.
type DeviceAllocationResult struct {
	Results []DeviceRequestAllocationResult `json:"results"`
	Config  []map[string]any                `json:"config"`
}

// DeviceRequestAllocationResult is one allocated device.
type DeviceRequestAllocationResult struct {
	Request           string           `json:"request"`
	Driver            string           `json:"driver"`
	Pool              string           `json:"pool"`
	Device            string           `json:"device"`
	AdminAccess       *bool            `json:"adminAccess"`
	Tolerations       []map[string]any `json:"tolerations"`
	BindingConditions []string         `json:"bindingConditions"`
}

// ConsumerRef names an object that reserved the claim.
type ConsumerRef struct {
	APIGroup string `json:"apiGroup"`
	Resource string `json:"resource"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
}

// AllocatedDevStatus is the driver's report about a prepared device.
type AllocatedDevStatus struct {
	Driver      string             `json:"driver"`
	Pool        string             `json:"pool"`
	Device      string             `json:"device"`
	ShareID     string             `json:"shareID"`
	Conditions  []map[string]any   `json:"conditions"`
	NetworkData *NetworkDeviceData `json:"networkData"`
}

// NetworkDeviceData is the realised network state of a prepared device.
type NetworkDeviceData struct {
	InterfaceName   string   `json:"interfaceName"`
	IPs             []string `json:"ips"`
	HardwareAddress string   `json:"hardwareAddress"`
}

// DeviceClass constrains which devices a claim may select.
type DeviceClass struct {
	Spec DeviceClassSpec `json:"spec"`
}

// DeviceClassSpec holds the selectors, the config and the extended resource name.
type DeviceClassSpec struct {
	Selectors            []map[string]any `json:"selectors"`
	Config               []map[string]any `json:"config"`
	ExtendedResourceName string           `json:"extendedResourceName"`
}

// ResourceClaimTemplate produces a ResourceClaim per pod.
type ResourceClaimTemplate struct {
	Spec ResourceClaimTemplateSpec `json:"spec"`
}

// ResourceClaimTemplateSpec is the claim template body.
type ResourceClaimTemplateSpec struct {
	Metadata ObjectMeta        `json:"metadata"`
	Spec     ResourceClaimSpec `json:"spec"`
}

// ObjectMeta is the subset of the template metadata the provider reports.
type ObjectMeta struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// Decode reads a Kubernetes object into one of the types above.
//
// The input is anything the k8s connection returns, typed or unstructured. It
// is marshalled to JSON first so the same reader serves every served version.
func Decode[T any](object any) (*T, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	out := new(T)
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeviceNames returns the device names of a slice in the published order.
func (s ResourceSliceSpec) DeviceNames() []string {
	names := make([]string, 0, len(s.Devices))
	for _, device := range s.Devices {
		names = append(names, device.Name)
	}
	return names
}

// StringAttributes returns the device attributes as strings, keyed by name.
//
// Attributes with no recognised value member are dropped, so an unreadable
// attribute is absent rather than reported as an empty string.
func (d Device) StringAttributes() map[string]string {
	if len(d.Attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(d.Attributes))
	for name, attr := range d.Attributes {
		value, ok := attr.Value()
		if !ok {
			continue
		}
		out[name] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Capacities returns the device capacities as strings, keyed by capacity name.
func (d Device) Capacities() map[string]string {
	if len(d.Capacity) == 0 {
		return nil
	}
	out := make(map[string]string, len(d.Capacity))
	for name, capacity := range d.Capacity {
		out[name] = string(capacity.Value)
	}
	return out
}

// Allocated reports whether the scheduler allocated the claim.
func (s ResourceClaimStatus) Allocated() bool {
	return s.Allocation != nil
}

// AllocatedDevices returns the allocated devices of a claim.
func (s ResourceClaimStatus) AllocatedDevices() []DeviceRequestAllocationResult {
	if s.Allocation == nil {
		return nil
	}
	return s.Allocation.Devices.Results
}

// UsesAdminAccess reports whether any allocated device carries admin access.
//
// Admin access grants the workload an unfiltered view of the device, so it is
// the privileged mode of a claim.
func (s ResourceClaimStatus) UsesAdminAccess() bool {
	for _, result := range s.AllocatedDevices() {
		if result.AdminAccess != nil && *result.AdminAccess {
			return true
		}
	}
	return false
}

// ReservedPodNames returns the names of the pods that reserved the claim.
//
// Only consumers in the core API group and the pods resource are returned, so
// a claim reserved by another object kind yields no pod names.
func (s ResourceClaimStatus) ReservedPodNames() []string {
	names := []string{}
	for _, ref := range s.ReservedFor {
		if ref.APIGroup != "" || ref.Resource != "pods" || ref.Name == "" {
			continue
		}
		names = append(names, ref.Name)
	}
	sort.Strings(names)
	return names
}

// DeviceRequestNames returns the request names of a claim in declared order.
func (c DeviceClaim) DeviceRequestNames() []string {
	names := make([]string, 0, len(c.Requests))
	for _, request := range c.Requests {
		name, _ := request["name"].(string)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}

// DeviceClassNames returns the device classes a claim's requests select.
//
// Both the exactly form and every subrequest of the firstAvailable form are
// read, and the result is deduplicated and sorted.
func (c DeviceClaim) DeviceClassNames() []string {
	seen := map[string]struct{}{}
	for _, request := range c.Requests {
		for _, name := range requestDeviceClassNames(request) {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// UsesAdminAccess reports whether any request asks for administrative access.
//
// Admin access lifts the driver's isolation for the device, so a claim
// template that sets it grants every pod using it an unfiltered view.
func (c DeviceClaim) UsesAdminAccess() bool {
	for _, request := range c.Requests {
		for _, body := range requestBodies(request) {
			if admin, ok := body["adminAccess"].(bool); ok && admin {
				return true
			}
		}
	}
	return false
}

func requestDeviceClassNames(request map[string]any) []string {
	names := []string{}
	for _, body := range requestBodies(request) {
		if name, ok := body["deviceClassName"].(string); ok && name != "" {
			names = append(names, name)
		}
	}
	return names
}

// requestBodies returns every place a request carries its device selection.
//
// A request holds the selection in an exactly object, or once per subrequest
// in a firstAvailable list. The request map itself is always returned as a
// body as well, because a request written before that split carries
// deviceClassName and adminAccess directly on the request. A reader of the
// result therefore matches all three shapes.
func requestBodies(request map[string]any) []map[string]any {
	bodies := []map[string]any{request}
	if exactly, ok := request["exactly"].(map[string]any); ok {
		bodies = append(bodies, exactly)
	}
	subrequests, ok := request["firstAvailable"].([]any)
	if !ok {
		return bodies
	}
	for _, raw := range subrequests {
		if subrequest, ok := raw.(map[string]any); ok {
			bodies = append(bodies, subrequest)
		}
	}
	return bodies
}
