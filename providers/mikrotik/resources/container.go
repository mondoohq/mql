// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- container ---

type mqlMikrotikContainerInternal struct {
	cacheInterface string
}

func containerArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData(rowID("mikrotik.container/", row, row["name"], row["tag"])),
		"name":        llx.StringData(row["name"]),
		"tag":         llx.StringData(row["tag"]),
		"os":          llx.StringData(row["os"]),
		"arch":        llx.StringData(row["arch"]),
		"rootDir":     llx.StringData(row["root-dir"]),
		"mounts":      listField(row, "mounts"),
		"dns":         llx.StringData(row["dns"]),
		"cmd":         llx.StringData(row["cmd"]),
		"entrypoint":  llx.StringData(row["entrypoint"]),
		"hostname":    llx.StringData(row["hostname"]),
		"workdir":     llx.StringData(row["workdir"]),
		"status":      llx.StringData(row["status"]),
		"logging":     boolField(row, "logging"),
		"startOnBoot": boolField(row, "start-on-boot"),
		"comment":     llx.StringData(row["comment"]),
	}
}

func newMikrotikContainer(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.container", containerArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikContainer).cacheInterface = row["interface"]
	return res, nil
}

func (r *mqlMikrotik) containers() ([]any, error) {
	// /container only exists on RouterOS 7.4 and later with the container package
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/container")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikContainer)
}

func (r *mqlMikrotikContainer) compute_interface() (*mqlMikrotikInterface, error) {
	if r.cacheInterface == "" {
		r.Interface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheInterface)
}

// --- container.config ---

func containerConfigArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData("mikrotik.container.config"),
		"registryUrl": llx.StringData(row["registry-url"]),
		// the registry user name and password are never read; only whether
		// credentials are configured at all
		"hasRegistryCredentials": presenceField(row, "password"),
		"layerDir":               llx.StringData(row["layer-dir"]),
		"tmpdir":                 llx.StringData(row["tmpdir"]),
		"ramHigh":                llx.StringData(row["ram-high"]),
	}
}

func (r *mqlMikrotik) containerConfig() (*mqlMikrotikContainerConfig, error) {
	res, ok, err := singletonAccessor[*mqlMikrotikContainerConfig](
		r.MqlRuntime, "/container/config", "mikrotik.container.config", containerConfigArgs)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.ContainerConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func initMikrotikContainerConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return singletonInit(runtime, "/container/config", args, containerConfigArgs)
}

// --- radius.client ---

type mqlMikrotikRadiusClientInternal struct {
	cacheCertificate string
}

func radiusClientArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData(rowID("mikrotik.radius.client/", row, row["address"], row["service"])),
		"services":           listField(row, "service"),
		"address":            llx.StringData(row["address"]),
		"protocol":           llx.StringData(row["protocol"]),
		"requireMessageAuth": llx.StringData(row["require-message-auth"]),
		// the shared secret is never read; only whether one is configured
		"hasSecret":          presenceField(row, "secret"),
		"authenticationPort": intField(row, "authentication-port"),
		"accountingPort":     intField(row, "accounting-port"),
		"timeout":            llx.StringData(row["timeout"]),
		"accountingBackup":   boolField(row, "accounting-backup"),
		"domain":             llx.StringData(row["domain"]),
		"realm":              llx.StringData(row["realm"]),
		"srcAddress":         llx.StringData(row["src-address"]),
		"calledId":           llx.StringData(row["called-id"]),
		"disabled":           boolField(row, "disabled"),
		"comment":            llx.StringData(row["comment"]),
	}
}

func newMikrotikRadiusClient(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.radius.client", radiusClientArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikRadiusClient).cacheCertificate = certificateRefName(row["certificate"])
	return res, nil
}

// certificate resolves the certificate the client presents for RADIUS over
// TLS against the already-cached /certificate listing, so a device with
// several RADIUS servers configured costs one read of /certificate rather than
// one per server.
func (r *mqlMikrotikRadiusClient) certificate() (*mqlMikrotikCertificate, error) {
	if r.cacheCertificate == "" {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheCertificate)
}

func (r *mqlMikrotik) radiusClients() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/radius")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikRadiusClient)
}

// --- user.aaa ---

func userAaaArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":          llx.StringData("mikrotik.user.aaa"),
		"useRadius":     boolField(row, "use-radius"),
		"defaultGroup":  llx.StringData(row["default-group"]),
		"accounting":    boolField(row, "accounting"),
		"interimUpdate": llx.StringData(row["interim-update"]),
		"excludeGroups": listField(row, "exclude-groups"),
	}
}

func (r *mqlMikrotik) userAaa() (*mqlMikrotikUserAaa, error) {
	res, ok, err := singletonAccessor[*mqlMikrotikUserAaa](
		r.MqlRuntime, "/user/aaa", "mikrotik.user.aaa", userAaaArgs)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.UserAaa.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func initMikrotikUserAaa(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return singletonInit(runtime, "/user/aaa", args, userAaaArgs)
}
