// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsebs

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/id/hostname"
)

var winHostnameRE = regexp.MustCompile(`(?i)^hostname:\s*(.+)$`)

func (m *ebsMetadata) windowsMetadata() (any, error) {
	mdata := map[string]any{}

	instanceID, ok := m.getInstanceID()
	if ok {
		mdata["instance-id"] = instanceID
	}

	region, ok := m.getRegion()
	if ok {
		mdata["region"] = region
	}

	if privateHostname, ok := hostname.Hostname(m.conn, m.platform); ok {
		mdata["hostname"] = privateHostname
	} else {
		// we are looking for something similar to:
		//
		// Starting services...
		// Hostname: WIN-1234ABCD
		// Configuration done.
		//
		launchLogs, err := afero.ReadFile(m.conn.FileSystem(), `\ProgramData\Amazon\EC2Launch\log\agent.log`)
		scanner := bufio.NewScanner(bytes.NewReader(launchLogs))
		for scanner.Scan() {
			line := scanner.Text()
			if err == nil {
				if match := winHostnameRE.FindStringSubmatch(line); len(match) > 1 {
					mdata["hostname"] = match[1]
				}
			}
		}
	}

	if interfaces, ok := m.getWindowsNetworkInterfaces(); ok {
		mdata["network"] = map[string]any{"interfaces": interfaces}
	}

	return mdata, nil
}

var (
	winPublicRE  = regexp.MustCompile(`(?i)^Public IPv4 address:\s*([\d\.]+)`)
	winPrivateRE = regexp.MustCompile(`(?i)^Private IPv4 address:\s*([\d\.]+)`)
)

func (m *ebsMetadata) getWindowsNetworkInterfaces() (any, bool) {
	ec2AgentLogs, err := afero.ReadFile(m.conn.FileSystem(), `\ProgramData\Amazon\EC2Launch\log\agent.log`)
	if err != nil {
		log.Debug().Err(err).Msg("unable to read cloud-init log")
		return nil, false
	}

	// The above file has exactly what we need:
	//
	// 2024-11-10T12:03:26Z [INFO] Details to display on wallpaper:
	// Instance ID: i-0ab123456cdef7890
	// Hostname: EC2AMAZ-ABCD123
	// Private IPv4 address: 10.0.1.25
	// Public IPv4 address: 3.87.45.123
	// Availability Zone: us-west-2a
	// Instance size: t3.micro
	//
	publicIpv4 := ""
	privateIpv4 := ""
	scanner := bufio.NewScanner(bytes.NewReader(ec2AgentLogs))
	for scanner.Scan() {
		line := scanner.Text()

		if matches := winPrivateRE.FindStringSubmatch(line); len(matches) == 2 {
			privateIpv4 = matches[1]
		}
		if matches := winPublicRE.FindStringSubmatch(line); len(matches) == 2 {
			publicIpv4 = matches[1]
		}
		if privateIpv4 != "" && publicIpv4 != "" {
			break // Exit early if both found
		}

	}

	// The only thing I couldn't find was the actual MAC address, so we will use
	// the word 'unknown' until we can discover it (if we can)
	macs := map[string]*macDetails{
		"unknown": &macDetails{
			MAC:         "unknown",
			PublicIPv4s: publicIpv4,
			LocalIPv4s:  privateIpv4,
		},
	}
	return map[string]any{"macs": macs}, privateIpv4 != "" || publicIpv4 != ""
}
