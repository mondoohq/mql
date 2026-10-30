// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"github.com/facebookincubator/nvdtools/wfn"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func initCpe(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	x, ok := args["uri"]
	if !ok {
		return nil, nil, errors.New("missing uri for cpe initialization")
	}

	value, ok := x.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'uri' in cpe initialization, it must be a string")
	}

	args["uri"] = llx.StringData(value)

	// ensure the value is a proper uuid
	_, err := wfn.Parse(value)
	if err != nil {
		return nil, nil, errors.New("invalid cpe: " + value)
	}

	// set attributes
	return args, nil, nil
}

func (c *mqlCpe) parse() error {
	x, err := wfn.Parse(c.Uri.Data)
	if err != nil {
		c.Part = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Vendor = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Product = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Version = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Update = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Edition = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Language = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.SwEdition = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.TargetSw = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.TargetHw = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		c.Other = plugin.TValue[string]{Error: err, State: plugin.StateIsSet}
		return err
	}

	c.Part = plugin.TValue[string]{Data: wfn.StripSlashes(x.Part), State: plugin.StateIsSet}
	c.Vendor = plugin.TValue[string]{Data: wfn.StripSlashes(x.Vendor), State: plugin.StateIsSet}
	c.Product = plugin.TValue[string]{Data: wfn.StripSlashes(x.Product), State: plugin.StateIsSet}
	c.Version = plugin.TValue[string]{Data: wfn.StripSlashes(x.Version), State: plugin.StateIsSet}
	c.Update = plugin.TValue[string]{Data: wfn.StripSlashes(x.Update), State: plugin.StateIsSet}
	c.Edition = plugin.TValue[string]{Data: wfn.StripSlashes(x.Edition), State: plugin.StateIsSet}
	c.Language = plugin.TValue[string]{Data: wfn.StripSlashes(x.Language), State: plugin.StateIsSet}
	c.SwEdition = plugin.TValue[string]{Data: wfn.StripSlashes(x.SWEdition), State: plugin.StateIsSet}
	c.TargetSw = plugin.TValue[string]{Data: wfn.StripSlashes(x.TargetSW), State: plugin.StateIsSet}
	c.TargetHw = plugin.TValue[string]{Data: wfn.StripSlashes(x.TargetHW), State: plugin.StateIsSet}
	c.Other = plugin.TValue[string]{Data: wfn.StripSlashes(x.Other), State: plugin.StateIsSet}
	return nil
}

func (c *mqlCpe) id() (string, error) {
	return c.Uri.Data, nil
}

func (c *mqlCpe) part() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) vendor() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) product() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) version() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) update() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) edition() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) language() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) swEdition() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) targetSw() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) targetHw() (string, error) {
	return "", c.parse()
}

func (c *mqlCpe) other() (string, error) {
	return "", c.parse()
}
