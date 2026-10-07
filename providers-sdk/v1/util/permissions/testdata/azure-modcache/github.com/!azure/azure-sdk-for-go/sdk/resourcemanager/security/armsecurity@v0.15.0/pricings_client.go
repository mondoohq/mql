// Trimmed from the generated SDK: only the request builders the tests read.
package armsecurity

func (client *PricingsClient) getCreateRequest(ctx context.Context, scopeID string, pricingName string, _ *PricingsClientGetOptions) (*policy.Request, error) {
	urlPath := "/{scopeId}/providers/Microsoft.Security/pricings/{pricingName}"
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}
