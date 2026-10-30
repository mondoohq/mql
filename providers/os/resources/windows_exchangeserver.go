// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
	"go.mondoo.com/mql/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	exchangeSetupKey = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup`
	exchangeV15Key   = `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15`
)

// exchangeRoleKeys are the keys Exchange setup writes under v15 for each role
// it installs. ClientAccess and HubTransport are Exchange 2013 roles that
// 2016 and later fold into Mailbox.
var exchangeRoleKeys = []struct{ key, role string }{
	{"MailboxRole", "Mailbox"},
	{"EdgeTransportRole", "EdgeTransport"},
	{"ClientAccessRole", "ClientAccess"},
	{"HubTransportRole", "HubTransport"},
}

// exchangeScript names one collection script and caches what it returned.
type exchangeScript struct {
	lock    sync.Mutex
	fetched bool
	data    *windows.ExchangeCollection
	err     error
}

// mqlWindowsExchangeServerInternal caches the three collection scripts, so a
// policy that reads twenty fields still loads the Exchange snap-in at most
// three times.
type mqlWindowsExchangeServerInternal struct {
	organization exchangeScript
	clients      exchangeScript
	transport    exchangeScript

	setupLock    sync.Mutex
	setupFetched bool
	setupItems   map[string]registry.RegistryKeyItem
	setupFound   bool
}

func (w *mqlWindowsExchangeServer) id() (string, error) {
	return "windows.exchangeServer", nil
}

// collect runs a collection script once and keeps its result, the error
// included, so a host without the Exchange Management Shell is asked once and
// not once per field.
func (w *mqlWindowsExchangeServer) collect(s *exchangeScript, script string) (*windows.ExchangeCollection, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.fetched {
		return s.data, s.err
	}
	s.data, s.err = w.runExchangeScript(script)
	s.fetched = true
	return s.data, s.err
}

// runExchangeScript errors when the snap-in cannot be loaded rather than
// reporting empty values: a host that is not an Exchange server is not one
// whose connectors are compliant, and an empty connector list would let
// `receiveConnectors.all(...)` pass on it.
func (w *mqlWindowsExchangeServer) runExchangeScript(script string) (*windows.ExchangeCollection, error) {
	conn, ok := w.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("windows.exchangeServer is not supported on this connection")
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, errors.New("windows.exchangeServer requires a connection that can run commands")
	}

	cmd, err := conn.RunCommand(powershell.Encode(script))
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(cmd.Stderr)
		if err != nil {
			return nil, err
		}
		// Left unclassified: the same exit is a host without Exchange and an
		// Exchange server whose management tools are broken, and only the
		// first is "not applicable".
		return nil, fmt.Errorf("cannot read the Exchange Server configuration, Exchange Server may not be installed on this host (see windows.exchangeServer.installed): %s", strings.TrimSpace(string(stderr)))
	}
	return windows.ParseExchangeCollection(cmd.Stdout)
}

func (w *mqlWindowsExchangeServer) organizationData() (*windows.ExchangeCollection, error) {
	return w.collect(&w.organization, windows.EXCHANGE_ORGANIZATION)
}

func (w *mqlWindowsExchangeServer) clientsData() (*windows.ExchangeCollection, error) {
	return w.collect(&w.clients, windows.EXCHANGE_CLIENTS)
}

func (w *mqlWindowsExchangeServer) transportData() (*windows.ExchangeCollection, error) {
	return w.collect(&w.transport, windows.EXCHANGE_TRANSPORT)
}

// setup reads the key Exchange setup writes. A missing key means Exchange is
// not installed; a registry that cannot be read is an error, not "not
// installed".
func (w *mqlWindowsExchangeServer) setup() (map[string]registry.RegistryKeyItem, bool, error) {
	w.setupLock.Lock()
	defer w.setupLock.Unlock()
	if w.setupFetched {
		return w.setupItems, w.setupFound, nil
	}

	items, found, err := readExchangeRegistryKey(w.MqlRuntime, exchangeSetupKey)
	if err != nil {
		return nil, false, err
	}
	w.setupItems, w.setupFound, w.setupFetched = items, found, true
	return items, found, nil
}

func readExchangeRegistryKey(runtime *plugin.Runtime, path string) (map[string]registry.RegistryKeyItem, bool, error) {
	o, err := CreateResource(runtime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, false, err
	}
	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, false, nil
		}
		return nil, false, err
	}
	items := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		items[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return items, true, nil
}

func (w *mqlWindowsExchangeServer) installed() (bool, error) {
	items, found, err := w.setup()
	if err != nil {
		return false, err
	}
	return found && regString(items, "MsiInstallPath") != "", nil
}

func (w *mqlWindowsExchangeServer) installPath() (string, error) {
	items, _, err := w.setup()
	if err != nil {
		return "", err
	}
	return exchangeInstallPath(items), nil
}

func (w *mqlWindowsExchangeServer) version() (string, error) {
	items, _, err := w.setup()
	if err != nil {
		return "", err
	}
	return exchangeVersion(items), nil
}

func (w *mqlWindowsExchangeServer) roles() ([]any, error) {
	installed, err := w.installed()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if !installed {
		return res, nil
	}
	for _, r := range exchangeRoleKeys {
		_, found, err := readExchangeRegistryKey(w.MqlRuntime, exchangeV15Key+`\`+r.key)
		if err != nil {
			return nil, err
		}
		if found {
			res = append(res, r.role)
		}
	}
	return res, nil
}

// exchangeInstallPath returns the install directory without a trailing
// separator, as setup writes it with one.
func exchangeInstallPath(items map[string]registry.RegistryKeyItem) string {
	return strings.TrimRight(regString(items, "MsiInstallPath"), `\`)
}

// exchangeVersion assembles the build number from the four DWORDs setup
// writes, the form Microsoft's build number table uses (15.2.1544.4). Empty
// when Exchange is not installed, and when setup was interrupted before it
// wrote all four: a partial build such as 15.2.0.0 would compare as an old,
// unpatched release.
func exchangeVersion(items map[string]registry.RegistryKeyItem) string {
	for _, name := range []string{"MsiProductMajor", "MsiProductMinor", "MsiBuildMajor", "MsiBuildMinor"} {
		if !regHas(items, name) {
			return ""
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		regInt(items, "MsiProductMajor"),
		regInt(items, "MsiProductMinor"),
		regInt(items, "MsiBuildMajor"),
		regInt(items, "MsiBuildMinor"))
}

// The singular settings resources are reachable by a dotted path that is also
// their own resource name, so `windows.exchangeServer.transportConfig`
// instantiates the child without running the parent's accessor. Delegating to
// the parent fills it in, as windows.dnsServer does for its settings.
func initWindowsExchangeServerChild[T plugin.Resource](
	runtime *plugin.Runtime,
	args map[string]*llx.RawData,
	get func(*mqlWindowsExchangeServer) *plugin.TValue[T],
) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	parent, err := CreateResource(runtime, "windows.exchangeServer", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	v := get(parent.(*mqlWindowsExchangeServer))
	if v.Error != nil {
		return nil, nil, v.Error
	}
	return args, v.Data, nil
}

func initWindowsExchangeServerOrganizationConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetOrganizationConfig)
}

func initWindowsExchangeServerTransportConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetTransportConfig)
}

func initWindowsExchangeServerAdminAuditLogConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetAdminAuditLogConfig)
}

func initWindowsExchangeServerContentFilterConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetContentFilterConfig)
}

func initWindowsExchangeServerSenderFilterConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetSenderFilterConfig)
}

func initWindowsExchangeServerSenderIdConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetSenderIdConfig)
}

func initWindowsExchangeServerSenderReputationConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetSenderReputationConfig)
}

func initWindowsExchangeServerRecipientFilterConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initWindowsExchangeServerChild(runtime, args, (*mqlWindowsExchangeServer).GetRecipientFilterConfig)
}

// exchangeSingle builds a singular settings resource from the one record of an
// organization-wide cmdlet.
func (w *mqlWindowsExchangeServer) exchangeSingle(section, resource string, build func(*windows.ExchangeRecordReader) map[string]*llx.RawData) (plugin.Resource, error) {
	data, err := w.organizationData()
	if err != nil {
		return nil, err
	}
	rec, err := data.Single(section)
	if err != nil {
		return nil, err
	}
	x := &windows.ExchangeRecordReader{Record: rec}
	args := build(x)
	if x.Err != nil {
		return nil, llx.MalformedData(fmt.Errorf("%s: %w", section, x.Err))
	}
	args["__id"] = llx.StringData(resource)
	return CreateResource(w.MqlRuntime, resource, args)
}

// exchangeList builds one resource per record of a cmdlet. ids are built
// from the record's identity, which Exchange keeps unique within its kind.
func (w *mqlWindowsExchangeServer) exchangeList(
	collect func() (*windows.ExchangeCollection, error),
	section, resource string,
	build func(*windows.ExchangeRecordReader) (string, map[string]*llx.RawData),
) ([]any, error) {
	data, err := collect()
	if err != nil {
		return nil, err
	}
	records, err := data.Section(section)
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(records))
	for i := range records {
		x := &windows.ExchangeRecordReader{Record: records[i]}
		key, args := build(x)
		if x.Err != nil {
			return nil, llx.MalformedData(fmt.Errorf("%s: %w", section, x.Err))
		}
		if key == "" {
			// Every record Exchange returns has an identity; a record without
			// one cannot be told apart from the next, and would collide in the
			// resource cache.
			return nil, llx.MalformedData(fmt.Errorf("%s: a record has no identity", section))
		}
		args["__id"] = llx.StringData(resource + "/" + key)
		r, err := CreateResource(w.MqlRuntime, resource, args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (w *mqlWindowsExchangeServer) organizationConfig() (*mqlWindowsExchangeServerOrganizationConfig, error) {
	r, err := w.exchangeSingle("OrganizationConfig", "windows.exchangeServer.organizationConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"name":                       llx.StringDataPtr(x.String("Name")),
			"customerFeedbackEnabled":    llx.BoolDataPtr(x.Bool("CustomerFeedbackEnabled")),
			"oAuth2ClientProfileEnabled": llx.BoolDataPtr(x.Bool("OAuth2ClientProfileEnabled")),
			"mapiHttpEnabled":            llx.BoolDataPtr(x.Bool("MapiHttpEnabled")),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerOrganizationConfig), nil
}

func (w *mqlWindowsExchangeServer) transportConfig() (*mqlWindowsExchangeServerTransportConfig, error) {
	r, err := w.exchangeSingle("TransportConfig", "windows.exchangeServer.transportConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"maxReceiveSizeBytes":       llx.IntDataPtr(x.Bytes("MaxReceiveSize")),
			"maxSendSizeBytes":          llx.IntDataPtr(x.Bytes("MaxSendSize")),
			"maxRecipientEnvelopeLimit": llx.IntDataPtr(x.Int("MaxRecipientEnvelopeLimit")),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerTransportConfig), nil
}

func (w *mqlWindowsExchangeServer) adminAuditLogConfig() (*mqlWindowsExchangeServerAdminAuditLogConfig, error) {
	r, err := w.exchangeSingle("AdminAuditLogConfig", "windows.exchangeServer.adminAuditLogConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"adminAuditLogEnabled":         llx.BoolDataPtr(x.Bool("AdminAuditLogEnabled")),
			"adminAuditLogCmdlets":         llx.ArrayData(strSliceToAny(x.Strings("AdminAuditLogCmdlets")), types.String),
			"adminAuditLogParameters":      llx.ArrayData(strSliceToAny(x.Strings("AdminAuditLogParameters")), types.String),
			"adminAuditLogExcludedCmdlets": llx.ArrayData(strSliceToAny(x.Strings("AdminAuditLogExcludedCmdlets")), types.String),
			"adminAuditLogAgeLimitSeconds": llx.IntDataPtr(x.Seconds("AdminAuditLogAgeLimit")),
			"logLevel":                     llx.StringDataPtr(x.String("LogLevel")),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerAdminAuditLogConfig), nil
}

func (w *mqlWindowsExchangeServer) contentFilterConfig() (*mqlWindowsExchangeServerContentFilterConfig, error) {
	r, err := w.exchangeSingle("ContentFilterConfig", "windows.exchangeServer.contentFilterConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"enabled":                llx.BoolDataPtr(x.Bool("Enabled")),
			"sclQuarantineEnabled":   llx.BoolDataPtr(x.Bool("SCLQuarantineEnabled")),
			"sclQuarantineThreshold": llx.IntDataPtr(x.Int("SCLQuarantineThreshold")),
			"sclRejectEnabled":       llx.BoolDataPtr(x.Bool("SCLRejectEnabled")),
			"sclDeleteEnabled":       llx.BoolDataPtr(x.Bool("SCLDeleteEnabled")),
			"quarantineMailbox":      llx.StringDataPtr(x.String("QuarantineMailbox")),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerContentFilterConfig), nil
}

func (w *mqlWindowsExchangeServer) senderFilterConfig() (*mqlWindowsExchangeServerSenderFilterConfig, error) {
	r, err := w.exchangeSingle("SenderFilterConfig", "windows.exchangeServer.senderFilterConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"enabled":                    llx.BoolDataPtr(x.Bool("Enabled")),
			"action":                     llx.StringDataPtr(x.String("Action")),
			"blankSenderBlockingEnabled": llx.BoolDataPtr(x.Bool("BlankSenderBlockingEnabled")),
			"blockedSenders":             llx.ArrayData(strSliceToAny(x.Strings("BlockedSenders")), types.String),
			"blockedDomains":             llx.ArrayData(strSliceToAny(x.Strings("BlockedDomains")), types.String),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerSenderFilterConfig), nil
}

func (w *mqlWindowsExchangeServer) senderIdConfig() (*mqlWindowsExchangeServerSenderIdConfig, error) {
	r, err := w.exchangeSingle("SenderIdConfig", "windows.exchangeServer.senderIdConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"enabled":             llx.BoolDataPtr(x.Bool("Enabled")),
			"spoofedDomainAction": llx.StringDataPtr(x.String("SpoofedDomainAction")),
			"tempErrorAction":     llx.StringDataPtr(x.String("TempErrorAction")),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerSenderIdConfig), nil
}

func (w *mqlWindowsExchangeServer) senderReputationConfig() (*mqlWindowsExchangeServerSenderReputationConfig, error) {
	r, err := w.exchangeSingle("SenderReputationConfig", "windows.exchangeServer.senderReputationConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"enabled":                   llx.BoolDataPtr(x.Bool("Enabled")),
			"senderBlockingEnabled":     llx.BoolDataPtr(x.Bool("SenderBlockingEnabled")),
			"openProxyDetectionEnabled": llx.BoolDataPtr(x.Bool("OpenProxyDetectionEnabled")),
			"srlBlockThreshold":         llx.IntDataPtr(x.Int("SrlBlockThreshold")),
			"senderBlockingPeriodHours": llx.IntDataPtr(x.Int("SenderBlockingPeriod")),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerSenderReputationConfig), nil
}

func (w *mqlWindowsExchangeServer) recipientFilterConfig() (*mqlWindowsExchangeServerRecipientFilterConfig, error) {
	r, err := w.exchangeSingle("RecipientFilterConfig", "windows.exchangeServer.recipientFilterConfig", func(x *windows.ExchangeRecordReader) map[string]*llx.RawData {
		return map[string]*llx.RawData{
			"enabled":                    llx.BoolDataPtr(x.Bool("Enabled")),
			"recipientValidationEnabled": llx.BoolDataPtr(x.Bool("RecipientValidationEnabled")),
			"blockListEnabled":           llx.BoolDataPtr(x.Bool("BlockListEnabled")),
			"blockedRecipients":          llx.ArrayData(strSliceToAny(x.Strings("BlockedRecipients")), types.String),
		}
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlWindowsExchangeServerRecipientFilterConfig), nil
}

func (w *mqlWindowsExchangeServer) mobileDeviceMailboxPolicies() ([]any, error) {
	return w.exchangeList(w.clientsData, "MobileDeviceMailboxPolicies", "windows.exchangeServer.mobileDeviceMailboxPolicy", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		return strOrEmpty(x.String("Identity")), map[string]*llx.RawData{
			"name":                               llx.StringDataPtr(x.String("Name")),
			"isDefault":                          llx.BoolDataPtr(x.Bool("IsDefault")),
			"passwordEnabled":                    llx.BoolDataPtr(x.Bool("PasswordEnabled")),
			"allowSimplePassword":                llx.BoolDataPtr(x.Bool("AllowSimplePassword")),
			"alphanumericPasswordRequired":       llx.BoolDataPtr(x.Bool("AlphanumericPasswordRequired")),
			"minPasswordLength":                  llx.IntDataPtr(x.Int("MinPasswordLength")),
			"minPasswordComplexCharacters":       llx.IntDataPtr(x.Int("MinPasswordComplexCharacters")),
			"passwordHistory":                    llx.IntDataPtr(x.Int("PasswordHistory")),
			"passwordExpirationSeconds":          llx.IntDataPtr(x.Seconds("PasswordExpiration")),
			"maxPasswordFailedAttempts":          llx.IntDataPtr(x.Int("MaxPasswordFailedAttempts")),
			"maxInactivityTimeLockSeconds":       llx.IntDataPtr(x.Seconds("MaxInactivityTimeLock")),
			"devicePolicyRefreshIntervalSeconds": llx.IntDataPtr(x.Seconds("DevicePolicyRefreshInterval")),
			"requireDeviceEncryption":            llx.BoolDataPtr(x.Bool("RequireDeviceEncryption")),
			"requireStorageCardEncryption":       llx.BoolDataPtr(x.Bool("RequireStorageCardEncryption")),
			"allowNonProvisionableDevices":       llx.BoolDataPtr(x.Bool("AllowNonProvisionableDevices")),
		}
	})
}

func (w *mqlWindowsExchangeServer) remoteDomains() ([]any, error) {
	return w.exchangeList(w.clientsData, "RemoteDomains", "windows.exchangeServer.remoteDomain", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		return strOrEmpty(x.String("Identity")), map[string]*llx.RawData{
			"name":                  llx.StringDataPtr(x.String("Name")),
			"domainName":            llx.StringDataPtr(x.String("DomainName")),
			"allowedOOFType":        llx.StringDataPtr(x.String("AllowedOOFType")),
			"autoForwardEnabled":    llx.BoolDataPtr(x.Bool("AutoForwardEnabled")),
			"autoReplyEnabled":      llx.BoolDataPtr(x.Bool("AutoReplyEnabled")),
			"ndrEnabled":            llx.BoolDataPtr(x.Bool("NDREnabled")),
			"deliveryReportEnabled": llx.BoolDataPtr(x.Bool("DeliveryReportEnabled")),
		}
	})
}

func (w *mqlWindowsExchangeServer) owaVirtualDirectories() ([]any, error) {
	return w.exchangeList(w.clientsData, "OwaVirtualDirectories", "windows.exchangeServer.owaVirtualDirectory", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		identity := x.String("Identity")
		return strOrEmpty(identity), map[string]*llx.RawData{
			"identity":            llx.StringDataPtr(identity),
			"server":              llx.StringDataPtr(x.String("Server")),
			"smimeEnabled":        llx.BoolDataPtr(x.Bool("SMimeEnabled")),
			"basicAuthentication": llx.BoolDataPtr(x.Bool("BasicAuthentication")),
			"formsAuthentication": llx.BoolDataPtr(x.Bool("FormsAuthentication")),
		}
	})
}

func (w *mqlWindowsExchangeServer) transportAgents() ([]any, error) {
	return w.exchangeList(w.clientsData, "TransportAgents", "windows.exchangeServer.transportAgent", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		identity := x.String("Identity")
		return strOrEmpty(identity), map[string]*llx.RawData{
			"identity": llx.StringDataPtr(identity),
			"enabled":  llx.BoolDataPtr(x.Bool("Enabled")),
			"priority": llx.IntDataPtr(x.Int("Priority")),
		}
	})
}

func (w *mqlWindowsExchangeServer) sendConnectors() ([]any, error) {
	return w.exchangeList(w.transportData, "SendConnectors", "windows.exchangeServer.sendConnector", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		identity := x.String("Identity")
		return strOrEmpty(identity), map[string]*llx.RawData{
			"identity":                           llx.StringDataPtr(identity),
			"name":                               llx.StringDataPtr(x.String("Name")),
			"enabled":                            llx.BoolDataPtr(x.Bool("Enabled")),
			"dnsRoutingEnabled":                  llx.BoolDataPtr(x.Bool("DNSRoutingEnabled")),
			"domainSecureEnabled":                llx.BoolDataPtr(x.Bool("DomainSecureEnabled")),
			"ignoreStartTls":                     llx.BoolDataPtr(x.Bool("IgnoreSTARTTLS")),
			"requireTls":                         llx.BoolDataPtr(x.Bool("RequireTLS")),
			"tlsAuthLevel":                       llx.StringDataPtr(x.String("TlsAuthLevel")),
			"maxMessageSizeBytes":                llx.IntDataPtr(x.Bytes("MaxMessageSize")),
			"protocolLoggingLevel":               llx.StringDataPtr(x.String("ProtocolLoggingLevel")),
			"connectionInactivityTimeoutSeconds": llx.IntDataPtr(x.Seconds("ConnectionInactivityTimeOut")),
			"addressSpaces":                      llx.ArrayData(strSliceToAny(x.Strings("AddressSpaces")), types.String),
			"smartHosts":                         llx.ArrayData(strSliceToAny(x.Strings("SmartHosts")), types.String),
		}
	})
}

func (w *mqlWindowsExchangeServer) receiveConnectors() ([]any, error) {
	return w.exchangeList(w.transportData, "ReceiveConnectors", "windows.exchangeServer.receiveConnector", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		identity := x.String("Identity")
		return strOrEmpty(identity), map[string]*llx.RawData{
			"identity":                 llx.StringDataPtr(identity),
			"name":                     llx.StringDataPtr(x.String("Name")),
			"server":                   llx.StringDataPtr(x.String("Server")),
			"enabled":                  llx.BoolDataPtr(x.Bool("Enabled")),
			"authMechanism":            llx.ArrayData(strSliceToAny(x.Flags("AuthMechanism")), types.String),
			"permissionGroups":         llx.ArrayData(strSliceToAny(x.Flags("PermissionGroups")), types.String),
			"banner":                   llx.StringDataPtr(x.String("Banner")),
			"connectionTimeoutSeconds": llx.IntDataPtr(x.Seconds("ConnectionTimeout")),
			"maxMessageSizeBytes":      llx.IntDataPtr(x.Bytes("MaxMessageSize")),
			"protocolLoggingLevel":     llx.StringDataPtr(x.String("ProtocolLoggingLevel")),
			"transportRole":            llx.StringDataPtr(x.String("TransportRole")),
			"bindings":                 llx.ArrayData(strSliceToAny(x.Strings("Bindings")), types.String),
			"remoteIpRanges":           llx.ArrayData(strSliceToAny(x.Strings("RemoteIPRanges")), types.String),
			"requireTls":               llx.BoolDataPtr(x.Bool("RequireTLS")),
		}
	})
}

func (w *mqlWindowsExchangeServer) transportServices() ([]any, error) {
	return w.exchangeList(w.transportData, "TransportServices", "windows.exchangeServer.transportService", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		return strOrEmpty(x.String("Identity")), map[string]*llx.RawData{
			"name":                      llx.StringDataPtr(x.String("Name")),
			"messageTrackingLogEnabled": llx.BoolDataPtr(x.Bool("MessageTrackingLogEnabled")),
			"connectivityLogEnabled":    llx.BoolDataPtr(x.Bool("ConnectivityLogEnabled")),
			"pickupDirectoryPath":       llx.StringDataPtr(x.String("PickupDirectoryPath")),
			"replayDirectoryPath":       llx.StringDataPtr(x.String("ReplayDirectoryPath")),
		}
	})
}

func (w *mqlWindowsExchangeServer) rpcClientAccessSettings() ([]any, error) {
	return w.exchangeList(w.transportData, "RpcClientAccess", "windows.exchangeServer.rpcClientAccess", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		return strOrEmpty(x.String("Identity")), map[string]*llx.RawData{
			"server":                llx.StringDataPtr(x.String("Server")),
			"encryptionRequired":    llx.BoolDataPtr(x.Bool("EncryptionRequired")),
			"blockedClientVersions": llx.StringDataPtr(x.String("BlockedClientVersions")),
		}
	})
}

func (w *mqlWindowsExchangeServer) mailboxDatabases() ([]any, error) {
	return w.exchangeList(w.transportData, "MailboxDatabases", "windows.exchangeServer.mailboxDatabase", func(x *windows.ExchangeRecordReader) (string, map[string]*llx.RawData) {
		return strOrEmpty(x.String("Identity")), map[string]*llx.RawData{
			"name":                          llx.StringDataPtr(x.String("Name")),
			"server":                        llx.StringDataPtr(x.String("Server")),
			"retainDeletedItemsUntilBackup": llx.BoolDataPtr(x.Bool("RetainDeletedItemsUntilBackup")),
			"deletedItemRetentionSeconds":   llx.IntDataPtr(x.Seconds("DeletedItemRetention")),
			"mailboxRetentionSeconds":       llx.IntDataPtr(x.Seconds("MailboxRetention")),
			"issueWarningQuotaBytes":        llx.IntDataPtr(x.Bytes("IssueWarningQuota")),
			"prohibitSendQuotaBytes":        llx.IntDataPtr(x.Bytes("ProhibitSendQuota")),
			"prohibitSendReceiveQuotaBytes": llx.IntDataPtr(x.Bytes("ProhibitSendReceiveQuota")),
			"circularLoggingEnabled":        llx.BoolDataPtr(x.Bool("CircularLoggingEnabled")),
		}
	})
}
