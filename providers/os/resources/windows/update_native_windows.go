// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// comLock serializes the COM reads: each one sets COM up on its own locked OS
// thread and tears it down again.
var comLock sync.Mutex

// NativeWUAResults is WINDOWS_QUERY_WUA_RESULTS without PowerShell: the
// Windows Update Agent's results through COM and the newest scan events from
// the WindowsUpdateClient event log through wevtapi. A COM failure is an error;
// an event-log failure leaves the scan fields empty, like the script.
func NativeWUAResults() (res *WUAResults, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("reading Windows Update results panicked: %v", r)
		}
	}()

	search, install, err := readWUACOMDates()
	if err != nil {
		return nil, err
	}
	res = &WUAResults{LastSearchSuccess: search, LastInstallationSuccess: install}

	scan, fail, code, err := readWUAScanEvents()
	if err != nil {
		log.Debug().Err(err).Msg("could not read the Windows Update client event log, scan times stay empty")
		return res, nil
	}
	res.LastScanSuccess, res.LastScanFailure, res.LastScanFailureCode = scan, fail, code
	return res, nil
}

const (
	hresultSFalse          = 0x1
	hresultRPCEChangedMode = 0x80010106
	variantTypeEmpty       = 0
	variantTypeNull        = 1
	variantTypeDate        = 7
)

func readWUACOMDates() (search, install *time.Time, err error) {
	comLock.Lock()
	defer comLock.Unlock()
	// COM objects belong to the thread that created them.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if initErr := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); initErr != nil {
		var oerr *ole.OleError
		switch {
		case errors.As(initErr, &oerr) && oerr.Code() == hresultSFalse:
			// already initialized on this thread, balanced by the uninitialize
			defer ole.CoUninitialize()
		case errors.As(initErr, &oerr) && uint32(oerr.Code()) == hresultRPCEChangedMode:
			// the thread is in another apartment mode; COM is usable, do not uninitialize
		default:
			return nil, nil, fmt.Errorf("failed to initialize COM: %w", initErr)
		}
	} else {
		defer ole.CoUninitialize()
	}

	unknown, err := oleutil.CreateObject("Microsoft.Update.AutoUpdate")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Microsoft.Update.AutoUpdate: %w", err)
	}
	defer unknown.Release()
	autoUpdate, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query IDispatch: %w", err)
	}
	defer autoUpdate.Release()

	resultsVar, err := oleutil.GetProperty(autoUpdate, "Results")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read AutomaticUpdates.Results: %w", err)
	}
	defer resultsVar.Clear()
	results := resultsVar.ToIDispatch()
	if results == nil {
		return nil, nil, errors.New("AutomaticUpdates.Results is not an object")
	}

	search, err = readCOMDate(results, "LastSearchSuccessDate")
	if err != nil {
		return nil, nil, err
	}
	install, err = readCOMDate(results, "LastInstallationSuccessDate")
	if err != nil {
		return nil, nil, err
	}
	return search, install, nil
}

// readCOMDate reads one date property. A VT_DATE is decoded here instead of
// through Variant.Value, which returns the current time next to an error when
// the conversion fails.
func readCOMDate(obj *ole.IDispatch, name string) (*time.Time, error) {
	v, err := oleutil.GetProperty(obj, name)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", name, err)
	}
	defer v.Clear()
	switch v.VT {
	case variantTypeEmpty, variantTypeNull:
		return nil, nil
	case variantTypeDate:
		return wuaCOMDate(math.Float64frombits(uint64(v.Val)))
	}
	t, err := wuaCOMDate(v.Value())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return t, nil
}

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	evtNextTimeoutMs         = 30000

	errorNoMoreItems       = 259
	errorTimeout           = 1460
	errorEvtChannelMissing = 15007
)

var (
	wevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

func evtClose(h uintptr) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(h)
	}
}

// readWUAScanEvents returns the newest successful and failed scan of an OS
// update service. A missing log or no match is not an error; any other failure
// is, and the caller then drops all of it, as the script does.
func readWUAScanEvents() (scan, fail *time.Time, code string, err error) {
	if err := wevtapi.Load(); err != nil {
		return nil, nil, "", err
	}
	rendered, found, err := newestEventXML(wuaScanXPath(wuaScanSuccessEventID))
	if err != nil {
		return nil, nil, "", err
	}
	if found {
		t, _, err := parseWUAEvent(rendered)
		if err != nil {
			return nil, nil, "", err
		}
		scan = &t
	}
	rendered, found, err = newestEventXML(wuaScanXPath(wuaScanFailureEventID))
	if err != nil {
		return nil, nil, "", err
	}
	if found {
		t, c, err := parseWUAEvent(rendered)
		if err != nil {
			return nil, nil, "", err
		}
		fail, code = &t, c
	}
	return scan, fail, code, nil
}

// newestEventXML returns the rendered XML of the newest event matching the
// XPath query in the WindowsUpdateClient log. A wait of more than
// evtNextTimeoutMs for a match counts as no match.
func newestEventXML(query string) (string, bool, error) {
	path, err := windows.UTF16PtrFromString(wuaEventLog)
	if err != nil {
		return "", false, err
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return "", false, err
	}
	h, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(q)),
		uintptr(evtQueryChannelPath|evtQueryReverseDirection))
	if h == 0 {
		if errors.Is(callErr, windows.Errno(errorEvtChannelMissing)) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("EvtQuery: %w", callErr)
	}
	defer evtClose(h)

	var event uintptr
	var returned uint32
	r, _, callErr := procEvtNext.Call(h, 1, uintptr(unsafe.Pointer(&event)), evtNextTimeoutMs, 0,
		uintptr(unsafe.Pointer(&returned)))
	if r == 0 {
		if errors.Is(callErr, windows.Errno(errorNoMoreItems)) || errors.Is(callErr, windows.Errno(errorTimeout)) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("EvtNext: %w", callErr)
	}
	if returned == 0 {
		return "", false, nil
	}
	defer evtClose(event)

	s, err := renderEventXML(event)
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

func renderEventXML(event uintptr) (string, error) {
	buf := make([]uint16, 4096)
	for range 2 {
		var used, props uint32
		r, _, callErr := procEvtRender.Call(0, event, evtRenderEventXML,
			uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf), nil
		}
		if !errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", fmt.Errorf("EvtRender: %w", callErr)
		}
		buf = make([]uint16, used/2+1)
	}
	return "", errors.New("EvtRender: buffer still too small after resizing")
}
