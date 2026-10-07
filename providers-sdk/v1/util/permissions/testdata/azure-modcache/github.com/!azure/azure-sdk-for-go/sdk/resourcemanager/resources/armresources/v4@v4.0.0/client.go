// Trimmed from the generated SDK: only the request builders the tests read.
package armresources

func (client *Client) listCreateRequest(ctx context.Context, _ *ClientListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resources"
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}
