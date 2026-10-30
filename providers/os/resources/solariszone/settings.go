// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package solariszone

import (
	"fmt"
	"sort"
	"strconv"
)

// Settings are the security-relevant settings of a zone configuration. A nil
// pointer or a nil slice is a property the configuration does not carry at
// all, as the global zone's does not.
type Settings struct {
	Autoboot        *bool
	Bootargs        *string
	Limitpriv       []string
	FileMacProfile  *string
	FsAllowed       []string
	SchedulingClass *string
	Hostid          *string

	MemoryCapBytes       *int64
	SwapCapBytes         *int64
	LockedMemoryCapBytes *int64
	CPUCap               *float64
	DedicatedCPUs        string
	MaxLwps              *int64
	MaxProcesses         *int64

	Networks    []Network
	Filesystems []Filesystem
	Devices     []Device
	Datasets    []string
}

// Network is an anet or net resource.
type Network struct {
	// Type is anet or net.
	Type             string
	Name             string
	LowerLink        string
	Address          string
	AllowedAddresses []string
	Defrouter        []string
	LinkProtection   []string
	MacAddress       string
	VlanID           *int64
	// Properties holds every property with a value.
	Properties map[string]string
}

// Filesystem is an fs resource.
type Filesystem struct {
	Dir     string
	Special string
	Raw     string
	Type    string
	Options []string
}

// Device is a device resource.
type Device struct {
	Match          string
	AllowPartition bool
	AllowRawIO     bool
}

// Settings derives the zone's settings from its configuration.
func (c *Config) Settings() (*Settings, error) {
	s := &Settings{}
	p := c.Props

	if v, ok := p["autoboot"]; ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid autoboot value %q", v)
		}
		s.Autoboot = &b
	}
	s.Bootargs = optString(p, "bootargs")
	s.Limitpriv = optList(p, "limitpriv")
	s.FileMacProfile = optString(p, "file-mac-profile")
	s.FsAllowed = optList(p, "fs-allowed")
	s.SchedulingClass = optString(p, "scheduling-class")
	s.Hostid = optString(p, "hostid")

	var err error
	if s.MaxLwps, err = optInt(p, "max-lwps"); err != nil {
		return nil, err
	}
	if s.MaxProcesses, err = optInt(p, "max-processes"); err != nil {
		return nil, err
	}

	for _, r := range c.Resources {
		switch r.Type {
		case "capped-memory":
			if s.MemoryCapBytes, err = optSize(r.Props, "physical"); err != nil {
				return nil, err
			}
			if s.SwapCapBytes, err = optSize(r.Props, "swap"); err != nil {
				return nil, err
			}
			if s.LockedMemoryCapBytes, err = optSize(r.Props, "locked"); err != nil {
				return nil, err
			}
		case "capped-cpu":
			if v := r.Props["ncpus"]; v != "" {
				f, err := strconv.ParseFloat(v, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid capped-cpu ncpus %q", v)
				}
				s.CPUCap = &f
			}
		case "dedicated-cpu":
			s.DedicatedCPUs = r.Props["ncpus"]
		case "anet", "net":
			n, err := network(r)
			if err != nil {
				return nil, err
			}
			s.Networks = append(s.Networks, n)
		case "fs":
			s.Filesystems = append(s.Filesystems, Filesystem{
				Dir:     r.Props["dir"],
				Special: r.Props["special"],
				Raw:     r.Props["raw"],
				Type:    r.Props["type"],
				Options: List(r.Props["options"]),
			})
		case "device":
			d := Device{Match: r.Props["match"]}
			if d.AllowPartition, err = boolProp(r.Props, "allow-partition"); err != nil {
				return nil, err
			}
			if d.AllowRawIO, err = boolProp(r.Props, "allow-raw-io"); err != nil {
				return nil, err
			}
			s.Devices = append(s.Devices, d)
		case "dataset":
			if n := r.Props["name"]; n != "" {
				s.Datasets = append(s.Datasets, n)
			}
		}
	}
	return s, nil
}

func network(r Resource) (Network, error) {
	n := Network{
		Type:             r.Type,
		LowerLink:        r.Props["lower-link"],
		Address:          r.Props["address"],
		AllowedAddresses: List(r.Props["allowed-address"]),
		Defrouter:        List(r.Props["defrouter"]),
		LinkProtection:   List(r.Props["link-protection"]),
		MacAddress:       r.Props["mac-address"],
		Properties:       map[string]string{},
	}
	if r.Type == "anet" {
		n.Name = r.Props["linkname"]
	} else {
		n.Name = r.Props["physical"]
	}
	var err error
	if n.VlanID, err = optInt(r.Props, "vlan-id"); err != nil {
		return Network{}, err
	}
	keys := make([]string, 0, len(r.Props))
	for k := range r.Props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v := r.Props[k]; v != "" {
			n.Properties[k] = v
		}
	}
	return n, nil
}

func optString(p map[string]string, key string) *string {
	v, ok := p[key]
	if !ok {
		return nil
	}
	return &v
}

func optList(p map[string]string, key string) []string {
	v, ok := p[key]
	if !ok {
		return nil
	}
	return List(v)
}

func optInt(p map[string]string, key string) (*int64, error) {
	v := p[key]
	if v == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s value %q", key, v)
	}
	return &n, nil
}

func optSize(p map[string]string, key string) (*int64, error) {
	v := p[key]
	if v == "" {
		return nil, nil
	}
	n, err := ParseSize(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return &n, nil
}

// boolProp reads a true/false property, false when it has no value, which is
// the zonecfg default for the device properties it reads.
func boolProp(p map[string]string, key string) (bool, error) {
	v := p[key]
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q", key, v)
	}
	return b, nil
}
