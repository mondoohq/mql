// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

// Package wmiquery runs WMI queries for the local Windows fast paths without
// letting WMI take the scan down.
package wmiquery

import (
	"fmt"
	"runtime"
	"sync"

	cim "github.com/microsoft/wmi/pkg/wmiinstance"
)

// query runs the WMI query; tests replace it to simulate a failing library.
var query = queryNamespace

// lock serializes the queries: each one sets COM up on its own locked OS
// thread and tears it down again.
var lock sync.Mutex

// Query runs a WQL query against the local root\cimv2 namespace (see QueryNamespace for others) and returns,
// for every object, the properties named in props. Values are read as COM
// returns them and converted by the Row accessors, so a type WMI sends that a
// caller does not expect is an absent value, not a panic. The WMI library
// panics on some failures of its own (COM setup, a nil session); Query turns
// any panic into an error, so the caller can fall back to its PowerShell path.
func Query(q string, props ...string) ([]Row, error) {
	return QueryNamespace(`root\cimv2`, q, props...)
}

// QueryNamespace is Query against another local WMI namespace, e.g.
// root\Microsoft\Windows\DeviceGuard.
func QueryNamespace(namespace, q string, props ...string) (rows []Row, err error) {
	defer func() {
		if r := recover(); r != nil {
			rows = nil
			err = fmt.Errorf("WMI query %q in %s panicked: %v", q, namespace, r)
		}
	}()
	return query(namespace, q, props)
}

func queryNamespace(namespace, q string, props []string) ([]Row, error) {
	lock.Lock()
	defer lock.Unlock()
	// COM objects belong to the thread that created them.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	mgr := cim.NewWmiSessionManager()
	defer mgr.Close()

	session, err := mgr.GetLocalSession(namespace)
	if err != nil {
		return nil, err
	}
	if _, err := session.Connect(); err != nil {
		// Connect can fail after ConnectServer returned a session (setting
		// its security); Dispose would dereference a nil one.
		if session.RawSession != nil {
			session.RawSession.Clear()
		}
		return nil, err
	}
	defer session.Dispose()

	// PerformRawQuery, not QueryInstances: QueryInstances writes every query
	// to the standard logger.
	enum, err := session.PerformRawQuery(q)
	if err != nil {
		return nil, err
	}
	defer enum.Release()

	rows := []Row{}
	for item, n, err := enum.Next(1); n > 0; item, n, err = enum.Next(1) {
		if err != nil {
			return nil, err
		}
		instance, err := cim.CreateWmiInstance(&item, session)
		if err != nil {
			return nil, err
		}
		row, err := readRow(instance, props)
		instance.Close()
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func readRow(instance *cim.WmiInstance, props []string) (Row, error) {
	row := make(Row, len(props))
	for _, p := range props {
		v, err := instance.GetProperty(p)
		if err != nil {
			return nil, fmt.Errorf("could not read WMI property %s: %w", p, err)
		}
		row[p] = v
	}
	return row, nil
}
