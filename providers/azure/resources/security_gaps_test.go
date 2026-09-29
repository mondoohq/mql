// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	apim "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement/v3"
	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v4"
	hybridcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute/v3"
	sql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// argsContain reports whether any string value in the args carries needle,
// so a test can prove a secret never reached the resource.
func argsContain(t *testing.T, args map[string]*llx.RawData, needle string) bool {
	t.Helper()
	for _, v := range args {
		if v == nil {
			continue
		}
		b, err := json.Marshal(v.Value)
		require.NoError(t, err)
		if strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

// withUserinfo builds an http URL carrying a user name and the PROXYLEAK
// marker as its password, so the fixtures hold no credential-shaped literal.
func withUserinfo(host, path, query string) string {
	u := url.URL{Scheme: "http", User: url.UserPassword("svc", "PROXYLEAK"), Host: host, Path: path, RawQuery: query}
	return u.String()
}

func TestStripURLCredentials(t *testing.T) {
	tests := []struct {
		in, want string
		hadQuery bool
	}{
		{"", "", false},
		{"https://acct.blob.core.windows.net/c/run.sh", "https://acct.blob.core.windows.net/c/run.sh", false},
		{"https://acct.blob.core.windows.net/c/run.sh?sv=2022&sig=abc%3D", "https://acct.blob.core.windows.net/c/run.sh", true},
		{withUserinfo("proxy.corp:3128", "", ""), "http://proxy.corp:3128", false},
		{withUserinfo("proxy.corp:3128", "/", "x=1") + "#frag", "http://proxy.corp:3128/", true},
		// Not parseable as a URL: still cut at the query.
		{"https://bad host/%zz?sig=secret", "https://bad host/%zz", true},
	}
	for _, tt := range tests {
		got, hadQuery := stripURLCredentials(tt.in)
		assert.Equal(t, tt.want, got, tt.in)
		assert.Equal(t, tt.hadQuery, hadQuery, tt.in)
	}
}

func TestURLHasSASToken(t *testing.T) {
	assert.True(t, urlHasSASToken("https://a.blob.core.windows.net/c/x.ps1?sv=2022-11-02&se=2026&sig=AbC%2F"))
	assert.True(t, urlHasSASToken("https://a.blob.core.windows.net/c/x.ps1?SIG=abc"))
	assert.False(t, urlHasSASToken("https://a.blob.core.windows.net/c/x.ps1?sv=2022"))
	assert.False(t, urlHasSASToken("https://raw.githubusercontent.com/org/repo/main/x.sh"))
	assert.False(t, urlHasSASToken("https://a/x.sh#sig=abc"))
	assert.False(t, urlHasSASToken(""))
}

func TestRedactSettings(t *testing.T) {
	in := map[string]any{
		"commandToExecute": "sh run.sh",
		"fileUris": []any{
			"https://acct.blob.core.windows.net/c/run.sh?sv=1&sig=SECRETSIG",
			"https://example.com/plain.sh",
		},
		"storageAccountKey": "SECRETKEY",
		"workspaceId":       "0000-1111",
		"nested": map[string]any{
			"adminPassword": "SECRETPW",
			"timeout":       float64(30),
			"key":           "SECRETBARE",
			"sasToken":      nil,
		},
		"enabled": true,
	}
	orig, err := json.Marshal(in)
	require.NoError(t, err)

	out := redactSettingsDict(in)
	b, err := json.Marshal(out)
	require.NoError(t, err)
	s := string(b)
	for _, secret := range []string{"SECRETSIG", "SECRETKEY", "SECRETPW", "SECRETBARE"} {
		assert.NotContains(t, s, secret)
	}

	assert.Equal(t, "sh run.sh", out["commandToExecute"])
	assert.Equal(t, "0000-1111", out["workspaceId"])
	assert.Equal(t, true, out["enabled"])
	assert.Equal(t, []any{"https://acct.blob.core.windows.net/c/run.sh", "https://example.com/plain.sh"}, out["fileUris"])
	assert.Equal(t, redactedValue, out["storageAccountKey"])
	nested := out["nested"].(map[string]any)
	assert.Equal(t, redactedValue, nested["adminPassword"])
	assert.Equal(t, float64(30), nested["timeout"])
	// An absent secret stays absent rather than looking configured.
	assert.Nil(t, nested["sasToken"])

	after, err := json.Marshal(in)
	require.NoError(t, err)
	assert.JSONEq(t, string(orig), string(after), "input must not be modified")

	assert.Nil(t, redactSettingsDict(nil))
}

func TestIsSecretSettingKey(t *testing.T) {
	for _, k := range []string{"password", "AdminPassword", "clientSecret", "sasToken", "storageAccountKey", "workspaceKey", "key", "ConnectionString"} {
		assert.True(t, isSecretSettingKey(k), k)
	}
	for _, k := range []string{"commandToExecute", "fileUris", "workspaceId", "keyVaultUri", "timestamp", "enableAutomaticUpgrade"} {
		assert.False(t, isSecretSettingKey(k), k)
	}
}

func TestClassifyAzureRefusalPassesThroughNonRefusals(t *testing.T) {
	assert.NoError(t, classifyAzureRefusal(nil))
	transport := errors.New("dial tcp: connection refused")
	assert.Same(t, transport, classifyAzureRefusal(transport, "x/read"))
	notFound := &azcore.ResponseError{StatusCode: http.StatusNotFound}
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyAzureRefusal(notFound, "x/read")))
}

func TestVmExtensionFields(t *testing.T) {
	f, err := vmExtensionFields(&compute.VirtualMachineExtensionProperties{
		Publisher:          to.Ptr("Microsoft.Compute"),
		Type:               to.Ptr("CustomScriptExtension"),
		TypeHandlerVersion: to.Ptr("1.10"),
		SuppressFailures:   to.Ptr(true),
		Settings: map[string]any{
			"fileUris":         []any{"https://a.blob.core.windows.net/c/s.ps1?sig=LEAK"},
			"commandToExecute": "powershell s.ps1",
		},
		ProtectedSettings: map[string]any{"storageAccountKey": "PROTECTEDLEAK"},
		ProtectedSettingsFromKeyVault: &compute.KeyVaultSecretReference{
			SecretURL: to.Ptr("https://kv.vault.azure.net/secrets/s/1"),
		},
		ProvisionAfterExtensions: []*string{to.Ptr("first"), nil},
	})
	require.NoError(t, err)
	args := f.args()
	assert.Equal(t, "CustomScriptExtension", args["extensionType"].Value)
	assert.Equal(t, true, args["suppressFailures"].Value)
	assert.Equal(t, true, args["protectedSettingsInKeyVault"].Value)
	assert.Equal(t, []any{"first"}, args["provisionAfterExtensions"].Value)
	assert.False(t, argsContain(t, args, "LEAK"))
	// Unset flags stay null rather than reading as false.
	assert.Nil(t, args["enableAutomaticUpgrade"].Value)

	empty, err := vmExtensionFields(nil)
	require.NoError(t, err)
	assert.Equal(t, false, empty.args()["protectedSettingsInKeyVault"].Value)
}

func TestVmssExtensionFields(t *testing.T) {
	f, err := vmssExtensionFields(&compute.VirtualMachineScaleSetExtensionProperties{
		Publisher: to.Ptr("Microsoft.Azure.Extensions"),
		Type:      to.Ptr("CustomScript"),
		Settings:  map[string]any{"script": "ZWNobw==", "password": "LEAK"},
	})
	require.NoError(t, err)
	args := f.args()
	assert.Equal(t, "CustomScript", args["extensionType"].Value)
	assert.Equal(t, false, args["protectedSettingsInKeyVault"].Value)
	assert.False(t, argsContain(t, args, "LEAK"))
}

func TestChildResourceID(t *testing.T) {
	parent := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/ss"
	assert.Equal(t, "/own/id", childResourceID(to.Ptr("/own/id"), parent, "extensions", to.Ptr("ext")))
	assert.Equal(t, parent+"/extensions/ext", childResourceID(nil, parent, "extensions", to.Ptr("ext")))
	assert.Equal(t, parent+"/extensions/ext", childResourceID(to.Ptr(""), parent, "extensions", to.Ptr("ext")))
	assert.Equal(t, "", childResourceID(nil, parent, "extensions", nil))
}

func TestVmPatchAssessmentMode(t *testing.T) {
	assert.Nil(t, vmPatchAssessmentMode(nil))
	assert.Nil(t, vmPatchAssessmentMode(&compute.VirtualMachineProperties{}))

	linux := &compute.VirtualMachineProperties{OSProfile: &compute.OSProfile{
		LinuxConfiguration: &compute.LinuxConfiguration{PatchSettings: &compute.LinuxPatchSettings{
			AssessmentMode: to.Ptr(compute.LinuxPatchAssessmentModeAutomaticByPlatform),
		}},
	}}
	require.NotNil(t, vmPatchAssessmentMode(linux))
	assert.Equal(t, "AutomaticByPlatform", *vmPatchAssessmentMode(linux))

	windows := &compute.VirtualMachineProperties{OSProfile: &compute.OSProfile{
		WindowsConfiguration: &compute.WindowsConfiguration{PatchSettings: &compute.PatchSettings{
			AssessmentMode: to.Ptr(compute.WindowsPatchAssessmentModeImageDefault),
		}},
	}}
	require.NotNil(t, vmPatchAssessmentMode(windows))
	assert.Equal(t, "ImageDefault", *vmPatchAssessmentMode(windows))

	// Patch settings present without an assessment mode is not a mode.
	noMode := &compute.VirtualMachineProperties{OSProfile: &compute.OSProfile{
		WindowsConfiguration: &compute.WindowsConfiguration{PatchSettings: &compute.PatchSettings{
			PatchMode: to.Ptr(compute.WindowsVMGuestPatchModeManual),
		}},
	}}
	assert.Nil(t, vmPatchAssessmentMode(noMode))
}

func TestAvailablePatchSummary(t *testing.T) {
	assert.Nil(t, availablePatchSummary(nil))
	assert.Nil(t, availablePatchSummary(&compute.VirtualMachineInstanceView{}))
	assert.Nil(t, availablePatchSummary(&compute.VirtualMachineInstanceView{PatchStatus: &compute.VirtualMachinePatchStatus{}}))

	summary := &compute.AvailablePatchSummary{CriticalAndSecurityPatchCount: to.Ptr[int32](3)}
	got := availablePatchSummary(&compute.VirtualMachineInstanceView{PatchStatus: &compute.VirtualMachinePatchStatus{AvailablePatchSummary: summary}})
	assert.Same(t, summary, got)
}

func TestRunCommandScriptSource(t *testing.T) {
	assert.Equal(t, "", runCommandScriptSource(nil))
	assert.Equal(t, "", runCommandScriptSource(&compute.VirtualMachineRunCommandScriptSource{Script: to.Ptr("")}))
	assert.Equal(t, runCommandSourceInline, runCommandScriptSource(&compute.VirtualMachineRunCommandScriptSource{Script: to.Ptr("id")}))
	assert.Equal(t, runCommandSourceURI, runCommandScriptSource(&compute.VirtualMachineRunCommandScriptSource{ScriptURI: to.Ptr("https://x/y.sh")}))
	assert.Equal(t, runCommandSourceCommandID, runCommandScriptSource(&compute.VirtualMachineRunCommandScriptSource{CommandID: to.Ptr("RunShellScript")}))
	assert.Equal(t, runCommandSourceGallery, runCommandScriptSource(&compute.VirtualMachineRunCommandScriptSource{GalleryScriptReferenceID: to.Ptr("/g/s/v")}))
}

func TestRunCommandArgsNeverCopySecrets(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	rc := &compute.VirtualMachineRunCommand{
		ID:       to.Ptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/runCommands/rc"),
		Name:     to.Ptr("rc"),
		Location: to.Ptr("westeurope"),
		Properties: &compute.VirtualMachineRunCommandProperties{
			Source: &compute.VirtualMachineRunCommandScriptSource{
				ScriptURI: to.Ptr("https://acct.blob.core.windows.net/c/run.sh?sv=1&sig=SASLEAK"),
			},
			RunAsUser:           to.Ptr("deploy"),
			RunAsPassword:       to.Ptr("PASSWORDLEAK"),
			Parameters:          []*compute.RunCommandInputParameter{{Name: to.Ptr("p"), Value: to.Ptr("PARAMLEAK")}},
			ProtectedParameters: []*compute.RunCommandInputParameter{{Name: to.Ptr("q"), Value: to.Ptr("PROTECTEDLEAK")}},
			OutputBlobURI:       to.Ptr("https://acct.blob.core.windows.net/out/o.txt?sig=OUTLEAK"),
			TimeoutInSeconds:    to.Ptr[int32](600),
			InstanceView: &compute.VirtualMachineRunCommandInstanceView{
				ExecutionState: to.Ptr(compute.ExecutionStateFailed),
				ExitCode:       to.Ptr[int32](2),
				Output:         to.Ptr("OUTPUTLEAK"),
				Error:          to.Ptr("ERRORLEAK"),
				StartTime:      &start,
			},
		},
	}
	args := runCommandArgs(rc)
	for _, leak := range []string{"SASLEAK", "PASSWORDLEAK", "PARAMLEAK", "PROTECTEDLEAK", "OUTLEAK", "OUTPUTLEAK", "ERRORLEAK"} {
		assert.False(t, argsContain(t, args, leak), leak)
	}
	assert.Equal(t, runCommandSourceURI, args["scriptSource"].Value)
	assert.Equal(t, "https://acct.blob.core.windows.net/c/run.sh", args["scriptUri"].Value)
	assert.Equal(t, true, args["scriptUriHasSasToken"].Value)
	assert.Equal(t, false, args["hasInlineScript"].Value)
	assert.Equal(t, "deploy", args["runAsUser"].Value)
	assert.Equal(t, true, args["outputBlobConfigured"].Value)
	assert.Equal(t, false, args["errorBlobConfigured"].Value)
	assert.Equal(t, int64(600), args["timeoutInSeconds"].Value)
	assert.Equal(t, "Failed", args["executionState"].Value)
	assert.Equal(t, int64(2), args["exitCode"].Value)
	assert.Nil(t, args["endTime"].Value)
}

func TestRunCommandArgsWithoutInstanceView(t *testing.T) {
	args := runCommandArgs(&compute.VirtualMachineRunCommand{
		ID:         to.Ptr("/x/runCommands/rc"),
		Properties: &compute.VirtualMachineRunCommandProperties{Source: &compute.VirtualMachineRunCommandScriptSource{Script: to.Ptr("whoami")}},
	})
	assert.Equal(t, runCommandSourceInline, args["scriptSource"].Value)
	assert.Equal(t, true, args["hasInlineScript"].Value)
	assert.False(t, argsContain(t, args, "whoami"))
	// No execution recorded: null, not a zero exit code that reads as success.
	assert.Nil(t, args["exitCode"].Value)
	assert.Nil(t, args["executionState"].Value)
}

func TestParseAgentBool(t *testing.T) {
	assert.Nil(t, parseAgentBool(nil))
	assert.Nil(t, parseAgentBool(to.Ptr("")))
	assert.Nil(t, parseAgentBool(to.Ptr("maybe")))
	require.NotNil(t, parseAgentBool(to.Ptr("True")))
	assert.True(t, *parseAgentBool(to.Ptr("True")))
	require.NotNil(t, parseAgentBool(to.Ptr(" false ")))
	assert.False(t, *parseAgentBool(to.Ptr(" false ")))
}

func TestHybridAgentConfigArgs(t *testing.T) {
	args := hybridAgentConfigArgs(&hybridcompute.AgentConfiguration{
		ExtensionsEnabled:         to.Ptr("false"),
		GuestConfigurationEnabled: to.Ptr("true"),
		ConfigMode:                to.Ptr(hybridcompute.AgentConfigurationModeMonitor),
		ProxyURL:                  to.Ptr(withUserinfo("proxy.corp:3128", "", "")),
		ProxyBypass:               []*string{to.Ptr("Arc"), nil},
		IncomingConnectionsPorts:  []*string{to.Ptr("22")},
		ExtensionsAllowList: []*hybridcompute.ConfigurationExtension{
			{Publisher: to.Ptr("Microsoft.Azure.Monitor"), Type: to.Ptr("AzureMonitorLinuxAgent")},
			{},
			nil,
		},
	})
	assert.Equal(t, false, args["extensionsEnabled"].Value)
	assert.Equal(t, true, args["guestConfigurationEnabled"].Value)
	assert.Equal(t, "monitor", args["agentConfigMode"].Value)
	assert.Equal(t, "http://proxy.corp:3128", args["proxyUrl"].Value)
	assert.Equal(t, []any{"Arc"}, args["proxyBypass"].Value)
	assert.Equal(t, []any{"22"}, args["incomingConnectionsPorts"].Value)
	assert.Equal(t, []any{"Microsoft.Azure.Monitor/AzureMonitorLinuxAgent"}, args["extensionsAllowList"].Value)
	assert.Equal(t, []any{}, args["extensionsBlockList"].Value)
	assert.False(t, argsContain(t, args, "PROXYLEAK"))

	none := hybridAgentConfigArgs(nil)
	assert.Nil(t, none["extensionsEnabled"].Value)
	assert.Nil(t, none["proxyUrl"].Value)
}

func TestManagedInstanceAdminArgs(t *testing.T) {
	none := managedInstanceAdminArgs(nil)
	assert.Nil(t, none["azureAdOnlyAuthentication"].Value)
	assert.Nil(t, none["azureAdAdminLogin"].Value)

	args := managedInstanceAdminArgs(&sql.ManagedInstanceExternalAdministrator{
		AzureADOnlyAuthentication: to.Ptr(true),
		Login:                     to.Ptr("sql-admins"),
		PrincipalType:             to.Ptr(sql.PrincipalTypeGroup),
		AdministratorType:         to.Ptr(sql.AdministratorTypeActiveDirectory),
	})
	assert.Equal(t, true, args["azureAdOnlyAuthentication"].Value)
	assert.Equal(t, "sql-admins", args["azureAdAdminLogin"].Value)
	assert.Equal(t, "Group", args["azureAdAdminPrincipalType"].Value)
	assert.Equal(t, "ActiveDirectory", args["azureAdAdminType"].Value)
	assert.Nil(t, args["azureAdAdminSid"].Value)
}

func TestManagedInstancePolicyArgsDropStorageKeys(t *testing.T) {
	alert := managedInstanceSecurityAlertPolicyArgs(&sql.ManagedServerSecurityAlertPolicy{
		ID: to.Ptr("/mi/securityAlertPolicies/Default"),
		Properties: &sql.SecurityAlertsPolicyProperties{
			State:                   to.Ptr(sql.SecurityAlertsPolicyStateEnabled),
			StorageAccountAccessKey: to.Ptr("KEYLEAK"),
			DisabledAlerts:          []*string{to.Ptr("Sql_Injection")},
		},
	})
	assert.False(t, argsContain(t, alert, "KEYLEAK"))
	assert.Equal(t, "Enabled", alert["state"].Value)
	assert.Equal(t, []any{"Sql_Injection"}, alert["disabledAlerts"].Value)

	va := managedInstanceVulnerabilityAssessmentArgs(&sql.ManagedInstanceVulnerabilityAssessment{
		ID: to.Ptr("/mi/vulnerabilityAssessments/default"),
		Properties: &sql.ManagedInstanceVulnerabilityAssessmentProperties{
			StorageContainerPath:    to.Ptr("https://acct.blob.core.windows.net/va"),
			StorageAccountAccessKey: to.Ptr("KEYLEAK"),
			StorageContainerSasKey:  to.Ptr("SASLEAK"),
			RecurringScans:          &sql.VulnerabilityAssessmentRecurringScansProperties{IsEnabled: to.Ptr(true)},
		},
	})
	assert.False(t, argsContain(t, va, "KEYLEAK"))
	assert.False(t, argsContain(t, va, "SASLEAK"))
	assert.Equal(t, true, va["recurringScansEnabled"].Value)
	assert.Nil(t, va["emailSubscriptionAdmins"].Value)
}

func TestApimBackendArgs(t *testing.T) {
	args := apimBackendArgs(&apim.BackendContract{
		ID:   to.Ptr("/service/s/backends/b"),
		Name: to.Ptr("b"),
		Properties: &apim.BackendContractProperties{
			URL:      to.Ptr("https://logic.azure.com/workflows/w/triggers/manual/paths/invoke?sig=SIGLEAK"),
			Protocol: to.Ptr(apim.BackendProtocolHTTP),
			TLS:      &apim.BackendTLSProperties{ValidateCertificateChain: to.Ptr(false)},
			Credentials: &apim.BackendCredentialsContract{
				Authorization: &apim.BackendAuthorizationHeaderCredentials{Scheme: to.Ptr("Basic"), Parameter: to.Ptr("AUTHLEAK")},
				Header:        map[string][]*string{"x-key": {to.Ptr("HEADERLEAK")}},
			},
			Proxy: &apim.BackendProxyContract{URL: to.Ptr("http://proxy:8080"), Password: to.Ptr("PROXYLEAK")},
		},
	})
	for _, leak := range []string{"SIGLEAK", "AUTHLEAK", "HEADERLEAK", "PROXYLEAK"} {
		assert.False(t, argsContain(t, args, leak), leak)
	}
	assert.Equal(t, "https://logic.azure.com/workflows/w/triggers/manual/paths/invoke", args["url"].Value)
	assert.Equal(t, "http", args["protocol"].Value)
	assert.Equal(t, false, args["validateCertificateChain"].Value)
	assert.Nil(t, args["validateCertificateName"].Value)
	assert.Equal(t, true, args["authorizationHeaderConfigured"].Value)
	assert.Equal(t, true, args["credentialHeadersConfigured"].Value)
	assert.Equal(t, false, args["credentialQueryConfigured"].Value)
	assert.Equal(t, false, args["clientCertificateConfigured"].Value)
	assert.Equal(t, "http://proxy:8080", args["proxyUrl"].Value)
	assert.Equal(t, true, args["proxyCredentialsConfigured"].Value)

	bare := apimBackendArgs(&apim.BackendContract{ID: to.Ptr("/x"), Properties: &apim.BackendContractProperties{URL: to.Ptr("https://api")}})
	assert.Nil(t, bare["validateCertificateChain"].Value)
	assert.Equal(t, false, bare["authorizationHeaderConfigured"].Value)
	assert.Equal(t, false, bare["proxyCredentialsConfigured"].Value)
}

func TestWebhookArgsNeverCopyURI(t *testing.T) {
	expiry := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	args := webhookArgs(&armautomation.Webhook{
		ID:   to.Ptr("/aa/webhooks/w"),
		Name: to.Ptr("w"),
		Properties: &armautomation.WebhookProperties{
			URI:        to.Ptr("https://s1.webhook.azure-automation.net/webhooks?token=URILEAK"),
			Parameters: map[string]*string{"p": to.Ptr("PARAMLEAK")},
			IsEnabled:  to.Ptr(true),
			ExpiryTime: &expiry,
		},
	})
	assert.False(t, argsContain(t, args, "URILEAK"))
	assert.False(t, argsContain(t, args, "PARAMLEAK"))
	assert.Equal(t, true, args["isEnabled"].Value)
	assert.Equal(t, &expiry, args["expiryTime"].Value)
	assert.Nil(t, args["lastInvokedTime"].Value)
}

func TestRunbookArgs(t *testing.T) {
	args := runbookArgs(&armautomation.Runbook{
		ID: to.Ptr("/aa/runbooks/r"),
		Properties: &armautomation.RunbookProperties{
			RunbookType: to.Ptr(armautomation.RunbookTypeEnumPowerShell72),
			State:       to.Ptr(armautomation.RunbookStatePublished),
			LogVerbose:  to.Ptr(false),
		},
	})
	assert.Equal(t, "PowerShell72", args["runbookType"].Value)
	assert.Equal(t, "Published", args["state"].Value)
	assert.Equal(t, false, args["logVerbose"].Value)
	assert.Nil(t, args["logProgress"].Value)

	bare := runbookArgs(&armautomation.Runbook{ID: to.Ptr("/aa/runbooks/r")})
	assert.Nil(t, bare["runbookType"].Value)
}

func TestBackupPolicyRetentionRules(t *testing.T) {
	store := func(s armdataprotection.DataStoreTypes) *armdataprotection.DataStoreInfoBase {
		return &armdataprotection.DataStoreInfoBase{DataStoreType: &s}
	}
	rules := []armdataprotection.BasePolicyRuleClassification{
		&armdataprotection.AzureBackupRule{Name: to.Ptr("BackupDaily")},
		&armdataprotection.AzureRetentionRule{
			Name:      to.Ptr("Monthly"),
			IsDefault: to.Ptr(false),
			Lifecycles: []*armdataprotection.SourceLifeCycle{{
				SourceDataStore: store(armdataprotection.DataStoreTypesVaultStore),
				DeleteAfter:     &armdataprotection.AbsoluteDeleteOption{Duration: to.Ptr("P1Y")},
			}},
		},
		&armdataprotection.AzureRetentionRule{
			Name:      to.Ptr("Default"),
			IsDefault: to.Ptr(true),
			Lifecycles: []*armdataprotection.SourceLifeCycle{nil, {
				SourceDataStore: store(armdataprotection.DataStoreTypesOperationalStore),
				DeleteAfter:     &armdataprotection.AbsoluteDeleteOption{Duration: to.Ptr("P7D")},
			}},
		},
	}
	got, def := backupPolicyRetentionRules(rules)
	assert.Equal(t, "P7D", def)
	require.Len(t, got, 2)
	assert.Equal(t, map[string]any{"name": "Monthly", "isDefault": false, "dataStoreType": "VaultStore", "deleteAfter": "P1Y"}, got[0])
	assert.Equal(t, map[string]any{"name": "Default", "isDefault": true, "dataStoreType": "OperationalStore", "deleteAfter": "P7D"}, got[1])

	none, noDefault := backupPolicyRetentionRules(nil)
	assert.Empty(t, none)
	assert.Equal(t, "", noDefault)
}

func TestBackupDatasourceIs(t *testing.T) {
	assert.True(t, backupDatasourceIs("Microsoft.Compute/disks", "Microsoft.Compute/disks"))
	assert.True(t, backupDatasourceIs("microsoft.compute/DISKS", "Microsoft.Compute/disks"))
	assert.True(t, backupDatasourceIs("Microsoft.Storage/storageAccounts/blobServices", "Microsoft.Storage/storageAccounts"))
	assert.False(t, backupDatasourceIs("Microsoft.Compute/diskEncryptionSets", "Microsoft.Compute/disks"))
	assert.False(t, backupDatasourceIs("Microsoft.ContainerService/managedClusters", "Microsoft.Storage/storageAccounts"))
	assert.False(t, backupDatasourceIs("", "Microsoft.Compute/disks"))
}

func TestBackupInstanceArgs(t *testing.T) {
	args, policyID := backupInstanceArgs(&armdataprotection.BackupInstanceResource{
		ID: to.Ptr("/vault/backupInstances/bi"),
		Properties: &armdataprotection.BackupInstance{
			DataSourceInfo: &armdataprotection.Datasource{
				DatasourceType: to.Ptr("Microsoft.Compute/disks"),
				ResourceID:     to.Ptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/disks/d"),
			},
			PolicyInfo:             &armdataprotection.PolicyInfo{PolicyID: to.Ptr("/vault/backupPolicies/p")},
			ProtectionStatus:       &armdataprotection.ProtectionStatusDetails{Status: to.Ptr(armdataprotection.StatusProtectionStopped)},
			CurrentProtectionState: to.Ptr(armdataprotection.CurrentProtectionStateBackupSchedulesSuspended),
		},
	})
	assert.Equal(t, "/vault/backupPolicies/p", policyID)
	assert.Equal(t, "ProtectionStopped", args["protectionStatus"].Value)
	assert.Equal(t, "BackupSchedulesSuspended", args["currentProtectionState"].Value)
	assert.Equal(t, "Microsoft.Compute/disks", args["datasourceType"].Value)

	bare, none := backupInstanceArgs(&armdataprotection.BackupInstanceResource{ID: to.Ptr("/x")})
	assert.Equal(t, "", none)
	assert.Nil(t, bare["protectionStatus"].Value)
}

func TestVaultResourceGuardID(t *testing.T) {
	assert.Equal(t, "", vaultResourceGuardID(nil))
	guard := "/subscriptions/other/resourceGroups/sec/providers/Microsoft.DataProtection/resourceGuards/g"
	got := vaultResourceGuardID([]*armdataprotection.ResourceGuardProxyBaseResource{
		nil,
		{Properties: &armdataprotection.ResourceGuardProxyBase{}},
		{Properties: &armdataprotection.ResourceGuardProxyBase{ResourceGuardResourceID: to.Ptr(guard)}},
	})
	assert.Equal(t, guard, got)
}

func TestResourceGuardArgs(t *testing.T) {
	args := resourceGuardArgs(&armdataprotection.ResourceGuardResource{
		ID:       to.Ptr("/g"),
		Location: to.Ptr("westeurope"),
		Properties: &armdataprotection.ResourceGuard{
			AllowAutoApprovals: to.Ptr(false),
			ResourceGuardOperations: []*armdataprotection.ResourceGuardOperation{
				{VaultCriticalOperation: to.Ptr("Microsoft.DataProtection/backupVaults/delete")},
				{},
				nil,
			},
			VaultCriticalOperationExclusionList: []*string{to.Ptr("Microsoft.DataProtection/backupVaults/backupInstances/delete")},
		},
	})
	assert.Equal(t, false, args["allowAutoApprovals"].Value)
	assert.Equal(t, []any{"Microsoft.DataProtection/backupVaults/delete"}, args["protectedOperations"].Value)
	assert.Equal(t, []any{"Microsoft.DataProtection/backupVaults/backupInstances/delete"}, args["vaultCriticalOperationExclusionList"].Value)
}

func TestAppsitePlanAndEnvironmentIDs(t *testing.T) {
	plan := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan"
	env := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/hostingEnvironments/ase"
	props := map[string]any{
		"serverFarmId":              plan,
		"hostingEnvironmentProfile": map[string]any{"id": env, "name": "ase"},
	}
	assert.Equal(t, plan, appsiteServerFarmID(props))
	assert.Equal(t, env, appsiteHostingEnvironmentID(props))

	assert.Equal(t, "", appsiteServerFarmID(nil))
	assert.Equal(t, "", appsiteHostingEnvironmentID(nil))
	assert.Equal(t, "", appsiteHostingEnvironmentID(map[string]any{"hostingEnvironmentProfile": nil}))
	assert.Equal(t, "", appsiteServerFarmID(map[string]any{"serverFarmId": 42}))
}

// The keys the accessors read must be the ones the SDK writes when the site
// properties are turned into the raw dict the appsite carries.
func TestAppsitePropertyKeysMatchSDKJSON(t *testing.T) {
	props, err := convert.JsonToDict(&web.SiteProperties{
		ServerFarmID:              to.Ptr("/p"),
		HostingEnvironmentProfile: &web.HostingEnvironmentProfile{ID: to.Ptr("/e")},
	})
	require.NoError(t, err)
	assert.Equal(t, "/p", appsiteServerFarmID(props))
	assert.Equal(t, "/e", appsiteHostingEnvironmentID(props))
}
