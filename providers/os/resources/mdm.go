// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

type mqlMdmInternal struct {
	lock    sync.Mutex
	fetched bool
}

func (m *mqlMdm) id() (string, error) {
	return "mdm", nil
}

// mdmVendorHosts maps an MDM server's host, or the domain it sits under, to
// the vendor that runs it. Self-hosted servers have no fixed host and are not
// recognized.
var mdmVendorHosts = []struct {
	suffix string
	vendor string
}{
	{"manage.microsoft.com", "intune"},
	{"jamfcloud.com", "jamf"},
	{"kandji.io", "kandji"},
	{"mosyle.com", "mosyle"},
	{"awmdm.com", "workspaceone"},
	{"simplemdm.com", "simplemdm"},
	{"addigy.com", "addigy"},
	{"hexnodemdm.com", "hexnode"},
	{"jumpcloud.com", "jumpcloud"},
}

// mdmVendor recognizes the vendor from the server URL, or returns "" when the
// host is not in the catalog. A suffix only matches on a label boundary, so
// notjamfcloud.com is not jamf.
func mdmVendor(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	for _, h := range mdmVendorHosts {
		if host == h.suffix || strings.HasSuffix(host, "."+h.suffix) {
			return h.vendor
		}
	}
	return ""
}

// mdmResult is what every platform reduces to before it is set on the fields.
// An empty string is null: a device that is not enrolled has no server, vendor
// or method, and reporting "" would let a check compare against a value
// nobody read.
type mdmResult struct {
	enrolled  bool
	serverURL string
	method    string
	identity  detwin.DeviceIdentity
}

func (r mdmResult) set(m *mqlMdm) error {
	vendor := mdmVendor(r.serverURL)
	m.Enrolled = plugin.TValue[bool]{Data: r.enrolled, State: plugin.StateIsSet}
	m.ServerUrl = mdmStringField(r.serverURL)
	m.Vendor = mdmStringField(vendor)
	m.Method = mdmStringField(r.method)

	// The Intune details describe the MDM enrollment, so they are only reported
	// while the device is enrolled in Intune: a certificate left behind by an
	// earlier enrollment must not pass as the current one.
	if !r.enrolled || vendor != "intune" {
		m.DeviceId = mdmStringField("")
		m.Intune = plugin.TValue[*mqlMdmIntune]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil
	}
	m.DeviceId = mdmStringField(r.identity.IntuneDeviceID)
	raw, err := CreateResource(m.MqlRuntime, "mdm.intune", map[string]*llx.RawData{
		"__id":     llx.StringData("mdm.intune"),
		"deviceId": mdmStringData(r.identity.IntuneDeviceID),
		"tenantId": mdmStringData(r.identity.EntraTenantID),
	})
	if err != nil {
		return err
	}
	m.Intune = plugin.TValue[*mqlMdmIntune]{Data: raw.(*mqlMdmIntune), State: plugin.StateIsSet}
	return nil
}

// mdmStringData is mdmStringField for resource arguments: an empty string is
// null.
func mdmStringData(v string) *llx.RawData {
	if v == "" {
		return llx.NilData
	}
	return llx.StringData(v)
}

func mdmStringField(v string) plugin.TValue[string] {
	if v == "" {
		return plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	return plugin.TValue[string]{Data: v, State: plugin.StateIsSet}
}

// macosMdmResult reduces `profiles status -type enrollment` to the shared
// result. Automated Device Enrollment is the only enrollment the device cannot
// start by itself, so anything else was started by a user.
func macosMdmResult(e mdmEnrollment) mdmResult {
	if !e.enrolled {
		return mdmResult{}
	}
	method := "user"
	if e.dep {
		method = "automated"
	}
	return mdmResult{enrolled: true, serverURL: e.serverUrl, method: method}
}

// windowsMdmResult reduces the registry state to the shared result.
func windowsMdmResult(s *windows.MdmState) (mdmResult, error) {
	e, err := s.ActiveEnrollment()
	if err != nil || e == nil {
		return mdmResult{}, err
	}
	return mdmResult{enrolled: true, serverURL: e.URL(), method: s.Method()}, nil
}

// populate reads the platform's enrollment state once and sets every field,
// so every accessor shares one command and one error path.
func (m *mqlMdm) populate() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.fetched {
		return nil
	}

	conn, ok := m.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("mdm is not supported on this connection")
	}
	platform := conn.Asset().Platform

	var res mdmResult
	switch {
	case platform != nil && platform.IsFamily(inventory.FAMILY_DARWIN):
		e, err := m.readMacos()
		if err != nil {
			return err
		}
		res = macosMdmResult(e)
	case platform != nil && platform.IsFamily(inventory.FAMILY_WINDOWS):
		s, err := readWindowsMdm(conn)
		if err != nil {
			return err
		}
		res, err = windowsMdmResult(s)
		if err != nil {
			return err
		}
		// The device identity is detected once, with the platform, from the
		// device certificates; reading it back from the platform labels keeps
		// these fields and the labels from ever disagreeing.
		res.identity = detwin.DeviceIdentityFromLabels(platform)
	}

	if err := res.set(m); err != nil {
		return err
	}
	m.fetched = true
	return nil
}

func (m *mqlMdm) readMacos() (mdmEnrollment, error) {
	o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("profiles status -type enrollment"),
	})
	if err != nil {
		return mdmEnrollment{}, err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return mdmEnrollment{}, exit.Error
	} else if exit.Data != 0 {
		return mdmEnrollment{}, errors.New("profiles status failed: " + cmd.GetStderr().Data)
	}
	return parseMdmEnrollment(cmd.GetStdout().Data), nil
}

func readWindowsMdm(conn shared.Connection) (*windows.MdmState, error) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("mdm on Windows requires a connection that can run commands")
	}
	executed, err := conn.RunCommand(powershell.Encode(windows.PSGetMdmState))
	if err != nil {
		return nil, err
	}
	if executed.ExitStatus != 0 {
		stderr, err := io.ReadAll(executed.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to read MDM enrollment state: " + string(stderr))
	}
	return windows.ParseMdmState(executed.Stdout)
}

func (m *mqlMdm) enrolled() (bool, error)    { return false, m.populate() }
func (m *mqlMdm) vendor() (string, error)    { return "", m.populate() }
func (m *mqlMdm) serverUrl() (string, error) { return "", m.populate() }
func (m *mqlMdm) method() (string, error)    { return "", m.populate() }
func (m *mqlMdm) deviceId() (string, error)  { return "", m.populate() }
func (m *mqlMdm) intune() (*mqlMdmIntune, error) {
	return nil, m.populate()
}

// initMdmIntune makes mdm.intune reachable by its own path. The resource
// shares its name with the mdm field that returns it, so a query for
// mdm.intune resolves to the resource; without this it would be built from
// empty arguments and report null for every field.
func initMdmIntune(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "mdm", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := parent.(*mqlMdm).GetIntune()
	if v.Error != nil {
		return nil, nil, v.Error
	}
	if v.IsNull() {
		return nil, nil, errors.New("cannot read mdm.intune: the device is not enrolled in Microsoft Intune")
	}
	return args, v.Data, nil
}
