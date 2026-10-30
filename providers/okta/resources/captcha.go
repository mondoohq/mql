// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

func (o *mqlOkta) captchas() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	instances, resp, err := client.CAPTCHAAPI.ListCaptchaInstances(ctx).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Captchas)
		}
		return nil, err
	}

	list := []any{}
	appendEntries := func(entries []okta.CAPTCHAInstance) error {
		for i := range entries {
			r, err := newMqlOktaCaptcha(o.MqlRuntime, &entries[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntries(instances); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.CAPTCHAInstance
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntries(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// oktaCaptchaArgs maps one CAPTCHA instance. The provider's secret key and site
// key are deliberately left out: the secret key performs the server-side
// validation and is standing credential material, and neither key says
// anything about whether the org is protected, which is what the enabled pages
// report. TestOktaCaptchaArgsCarriesNoKeyMaterial pins that.
func oktaCaptchaArgs(entry *okta.CAPTCHAInstance) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":   llx.StringData(oktaStr(entry.Id)),
		"name": llx.StringData(oktaStr(entry.Name)),
		"type": llx.StringData(oktaStr(entry.Type)),
	}
}

func newMqlOktaCaptcha(runtime *plugin.Runtime, entry *okta.CAPTCHAInstance) (*mqlOktaCaptcha, error) {
	r, err := CreateResource(runtime, "okta.captcha", oktaCaptchaArgs(entry))
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaCaptcha), nil
}

func (o *mqlOktaCaptcha) id() (string, error) {
	return "okta.captcha/" + o.Id.Data, o.Id.Error
}
