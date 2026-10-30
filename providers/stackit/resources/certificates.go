// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	certificates "github.com/stackitcloud/stackit-sdk-go/services/certificates/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackit) certificates() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Certificates()
	if err != nil {
		return nil, err
	}
	out := []any{}
	pageId := ""
	for {
		req := client.DefaultAPI.ListCertificates(bgctx(), c.ProjectID(), c.Region())
		if pageId != "" {
			req = req.PageId(pageId)
		}
		resp, err := req.Execute()
		if err != nil {
			if isAccessDenied(err) {
				return deniedList(err)
			}
			return nil, err
		}
		items, _ := resp.GetItemsOk()
		for i := range items {
			res, err := buildCertificate(r.MqlRuntime, &items[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		next, ok := resp.GetNextPageIdOk()
		if !ok || next == nil || *next == "" {
			break
		}
		pageId = *next
	}
	return out, nil
}

func buildCertificate(runtime *plugin.Runtime, cert *certificates.GetCertificateResponse) (plugin.Resource, error) {
	labels := map[string]any{}
	for k, v := range cert.GetLabels() {
		labels[k] = v
	}

	data := cert.GetData()

	args := map[string]*llx.RawData{
		"id":                llx.StringData(cert.GetId()),
		"name":              llx.StringData(cert.GetName()),
		"region":            llx.StringData(cert.GetRegion()),
		"publicKey":         llx.StringData(cert.GetPublicKey()),
		"labels":            llx.MapData(labels, types.String),
		"dnsNames":          llx.StringData(data.GetDnsNames()),
		"extendedKeyUsage":  llx.StringData(data.GetExtendedKeyUsage()),
		"fingerprintSha1":   llx.StringData(data.GetFingerprintSha1()),
		"fingerprintSha256": llx.StringData(data.GetFingerprintSha256()),
		"subject":           llx.StringData(data.GetSubjectCn()),
		"issuer":            llx.StringData(data.GetIssuerCn()),
		"serialNumber":      llx.StringData(data.GetSerialNumber()),
		"keyAlgorithm":      llx.StringData(data.GetPublicKeyAlgorithm()),
		"keyStrength":       llx.StringData(data.GetKeyStrength()),
		"keyBitSize":        llx.IntDataPtr(parseKeyBitSize(data.GetKeyStrength())),
		"signingAlgorithm":  llx.StringData(data.GetSignatureAlgorithm()),
		"notBefore":         llx.TimeDataPtr(parseRFC3339(data.GetNotBefore())),
		"notAfter":          llx.TimeDataPtr(parseRFC3339(data.GetNotAfter())),
		"usage":             llx.ArrayData(certificateUsage(cert.GetUsage()), types.Dict),
		"organization":      llx.StringData(data.GetOrganization()),
		"isSelfSigned":      llx.BoolDataPtr(optBool(data.GetIsSelfSignedOk())),
		"isCa":              llx.BoolDataPtr(optBool(data.GetIsCaOk())),
	}
	return CreateResource(runtime, "stackit.certificate", args)
}

// certificateUsage flattens the certificate's load balancer usage into the
// dict form MQL expects: one entry per load balancer, each carrying the
// load balancer name and the listener names on it that use the certificate.
func certificateUsage(u certificates.Usage) []any {
	usage := []any{}
	for _, item := range u.GetItems() {
		listeners := []any{}
		for _, n := range item.GetListenerNames() {
			listeners = append(listeners, n)
		}
		usage = append(usage, map[string]any{
			"loadBalancerName": item.GetLoadBalancerName(),
			"listenerNames":    listeners,
		})
	}
	return usage
}

func (r *mqlStackitCertificate) id() (string, error) {
	return "stackit.certificate/" + r.Id.Data, nil
}

func initStackitCertificate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.Certificates()
	if err != nil {
		return nil, nil, err
	}
	cert, err := client.DefaultAPI.GetCertificate(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildCertificate(runtime, cert)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}
