// Trimmed from the generated SDK: only the request builders the tests read.
package armsecurity

func (client *AutoProvisioningSettingsClient) getCreateRequest(ctx context.Context, settingName string, _ *AutoProvisioningSettingsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings/{settingName}"
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}
