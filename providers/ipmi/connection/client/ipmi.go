// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

// Specifications
// https://web.archive.org/web/20210423164216/https://www.intel.com/content/www/us/en/servers/ipmi/ipmi-technical-resources.html
//
// Commonly used commands
// https://web.archive.org/web/20241130020608/https://www.thomas-krenn.com/de/tkmag/wp-content/uploads/2017/08/ipmitool-cheat-sheet-v1.0.pdf
// https://web.archive.org/web/20191106135326/https://community.pivotal.io/s/article/How-to-work-on-IPMI-and-IPMITOOL

import (
	"errors"
	"fmt"

	ipmiTransport "github.com/vmware/goipmi"
)

// Connection properties for a Client
type Connection struct {
	Path      string
	Hostname  string
	Port      int32
	Username  string
	Password  string
	Interface string
}

type IpmiClient struct {
	*Connection
	*ipmiTransport.Client
}

// NewIpmiClient is a high-level api to access the data of a Ipmi instance
func NewIpmiClient(c *Connection) (*IpmiClient, error) {
	if c == nil {
		return nil, errors.New("no connection details provided")
	}

	pCfg := &ipmiTransport.Connection{
		Hostname:  c.Hostname,
		Path:      c.Path,
		Port:      int(c.Port),
		Username:  c.Username,
		Password:  c.Password,
		Interface: c.Interface,
	}

	p, err := ipmiTransport.NewClient(pCfg)
	if err != nil {
		return nil, err
	}

	return &IpmiClient{
		Connection: c,
		Client:     p,
	}, nil
}

type deviceIDReq struct{}

// 20.1 - Get Device IDCommand
type deviceIDResp struct {
	ipmiTransport.CompletionCode
	DeviceID                      uint8
	DeviceRevision                uint8
	FirmwareRevision1             uint8 // Major Firmware Revision, binary encoded
	FirmwareRevision2             uint8 // Minor Firmware Revision. BCD encoded.
	IPMIVersion                   uint8
	AdditionalDeviceSupport       uint8
	ManufacturerID1               uint16 // the number is 20 bit
	ManufacturerID2               uint8
	ProductID                     uint16
	AuxiliaryFirmwareInformation1 uint8 // optional Auxiliary Firmware Revision Information
	AuxiliaryFirmwareInformation2 uint8
	AuxiliaryFirmwareInformation3 uint8
	AuxiliaryFirmwareInformation4 uint8
}

type DeviceID struct {
	DeviceID                int64                   `json:"deviceID"`
	DeviceRevision          int64                   `json:"deviceRevision"`
	ProvidesDeviceSDRs      bool                    `json:"providesDeviceSDRs"`
	DeviceAvailable         bool                    `json:"deviceAvailable"`
	FirmwareRevision        string                  `json:"firmwareRevision"`
	IpmiVersion             string                  `json:"ipmiVersion"`
	ManufacturerID          int64                   `json:"manufacturerID"`
	ManufacturerName        string                  `json:"manufacturerName"`
	ProductID               int64                   `json:"productID"`
	ProductName             string                  `json:"productName"`
	AdditionalDeviceSupport AdditionalDeviceSupport `json:"additionalDeviceSupport"`
}

type AdditionalDeviceSupport struct {
	SensorDevice        bool `json:"sensorDevice"`
	SDRRepositoryDevice bool `json:"sdrRepositoryDevice"`
	SELDevice           bool `json:"selDevice"`
	FRUInventoryDevice  bool `json:"fruInventoryDevice"`
	IPMBEventReceiver   bool `json:"ipmbEventReciever"`
	IPMBEventGenerator  bool `json:"ipmbEventGenerator"`
	Bridge              bool `json:"bridge"`
	ChassisDevice       bool `json:"chassisDevice"`
}

const (
	SensorDevice        uint8 = 0x1
	SDRRepositoryDevice uint8 = 0x2
	SELDevice           uint8 = 0x4
	FRUInventoryDevice  uint8 = 0x8
	IPMBEventReceiver   uint8 = 0x10
	IPMBEventGenerator  uint8 = 0x20
	Bridge              uint8 = 0x40
	ChassisDevice       uint8 = 0x80
)

// DeviceID get the Device ID of the BMC
func (c *IpmiClient) DeviceID() (*DeviceID, error) {
	req := &ipmiTransport.Request{
		ipmiTransport.NetworkFunctionApp,
		ipmiTransport.CommandGetDeviceID,
		&deviceIDReq{},
	}
	res := &deviceIDResp{}
	err := c.Client.Send(req, res)
	if err != nil {
		return nil, err
	}

	manufactor := decodeManufacturerID(res.ManufacturerID1, res.ManufacturerID2)
	product := OemProductID(res.ProductID)

	return &DeviceID{
		DeviceID:           int64(res.DeviceID),
		DeviceRevision:     int64(res.DeviceRevision & 0x0F), // §20.1: revision is the low 4 bits
		ProvidesDeviceSDRs: res.DeviceRevision&0x80 != 0,
		DeviceAvailable:    res.FirmwareRevision1&0x80 == 0, // 0 - normal operation, 1 - firmware
		FirmwareRevision:   decodeFirmwareRevision(res.FirmwareRevision1, res.FirmwareRevision2),
		IpmiVersion:        decodeIPMIVersion(res.IPMIVersion),
		ManufacturerID:     int64(manufactor),
		ManufacturerName:   manufactor.String(),
		ProductID:          int64(product),
		ProductName:        product.String(),
		AdditionalDeviceSupport: AdditionalDeviceSupport{
			SensorDevice:        res.AdditionalDeviceSupport&SensorDevice != 0,
			SDRRepositoryDevice: res.AdditionalDeviceSupport&SDRRepositoryDevice != 0,
			SELDevice:           res.AdditionalDeviceSupport&SELDevice != 0,
			FRUInventoryDevice:  res.AdditionalDeviceSupport&FRUInventoryDevice != 0,
			IPMBEventReceiver:   res.AdditionalDeviceSupport&IPMBEventReceiver != 0,
			IPMBEventGenerator:  res.AdditionalDeviceSupport&IPMBEventGenerator != 0,
			Bridge:              res.AdditionalDeviceSupport&Bridge != 0,
			ChassisDevice:       res.AdditionalDeviceSupport&ChassisDevice != 0,
		},
	}, nil
}

// chassisStatusRequest per section 28.2
type chassisStatusRequest struct{}

// chassisStatusResponse per section 28.2
type chassisStatusResponse struct {
	ipmiTransport.CompletionCode
	PowerState     uint8
	LastPowerEvent uint8
	State          uint8
	// FrontControlPanel uint8
}

type ChassisStatus struct {
	SystemPower        bool                  `json:"systemPower"`
	PowerOverload      bool                  `json:"powerOverload"`
	PowerInterlock     bool                  `json:"powerInterlock"`
	MainPowerFault     bool                  `json:"mainPowerFault"`
	PowerControlFault  bool                  `json:"powerControlFault"`
	PowerRestorePolicy string                `json:"powerRestorePolicy"`
	LastPowerEvent     ChassisLastPowerEvent `json:"lastPowerEvent"`
	ChassisIntrusion   bool                  `json:"chassisIntrusion"`
	FrontPanelLockout  bool                  `json:"frontPanelLockout"`
	DriveFault         bool                  `json:"driveFault"`
	CoolingFanFault    bool                  `json:"coolingFanFault"`
}

type ChassisLastPowerEvent struct {
	AcFailed  bool `json:"ac-failed"`
	Overload  bool `json:"overload"`
	Interlock bool `json:"interlock"`
	Fault     bool `json:"fault"`
	Command   bool `json:"command"`
}

// ChassisStatus - 28.2 Get Chassis Status Command
func (c *IpmiClient) ChassisStatus() (*ChassisStatus, error) {
	req := &ipmiTransport.Request{
		ipmiTransport.NetworkFunctionChassis,
		ipmiTransport.CommandChassisStatus,
		&chassisStatusRequest{},
	}

	res := &chassisStatusResponse{}
	err := c.Client.Send(req, res)
	if err != nil {
		return nil, err
	}

	return &ChassisStatus{
		SystemPower:        res.PowerState&0x1 != 0,
		PowerOverload:      res.PowerState&0x2 != 0,
		PowerInterlock:     res.PowerState&0x4 != 0,
		MainPowerFault:     res.PowerState&0x8 != 0,
		PowerControlFault:  res.PowerState&0x10 != 0,
		PowerRestorePolicy: decodePowerRestorePolicy(res.PowerState),
		LastPowerEvent:     decodeLastPowerEvent(res.LastPowerEvent),
		ChassisIntrusion:   res.State&0x1 != 0,
		FrontPanelLockout:  res.State&0x2 != 0,
		DriveFault:         res.State&0x4 != 0,
		CoolingFanFault:    res.State&0x8 != 0,
	}, nil
}

type ChassisSystemBootOptions struct {
	ParameterVersion       int64                         `json:"parameterVersion"`
	ParameterValidUnlocked bool                          `json:"parameterValidUnlocked"`
	BootFlags              ChassisSystemBootOptionsFlags `json:"bootFlags"`
}

type ChassisSystemBootOptionsFlags struct {
	BootFlagsValid         bool   `json:"biosFlagsValid"`
	ApplyToNextBootOnly    bool   `json:"applyToNextBootOnly"`
	LegacyBootType         bool   `json:"legacyBootType"`
	BootDeviceSelector     string `json:"bootDeviceSelector"`
	CmosClear              bool   `json:"cmosClear"`
	LockKeyboard           bool   `json:"lockKeyboard"`
	ScreenBlank            bool   `json:"screenBlank"`
	LockOutResetButton     bool   `json:"lockOutResetButton"`
	LockOutPowerButton     bool   `json:"lockOutPowerButton"`
	LockOutSleepButton     bool   `json:"lockOutSleepButton"`
	UserPasswordBypass     bool   `json:"userPasswordBypass"`
	ForceProgressEventTrap bool   `json:"forceProgressEventTrap"`
	BIOSVerbosity          string `json:"biosVerbosity"`
	ConsoleRedirection     string `json:"consoleRedirection"`
	BIOSMuxControlOverride string `json:"biosMuxControlOverride"`
	BIOSSharedModeOverride bool   `json:"biosSharedModeOverride"`
}

// ChassisStatus - 28.13 Get System Boot Options Command
func (c *IpmiClient) ChassisSystemBootOptions() (*ChassisSystemBootOptions, error) {
	req := &ipmiTransport.Request{
		ipmiTransport.NetworkFunctionChassis,
		ipmiTransport.CommandGetSystemBootOptions,
		&ipmiTransport.SystemBootOptionsRequest{
			Param: ipmiTransport.BootParamBootFlags,
		},
	}

	res := &ipmiTransport.SystemBootOptionsResponse{}
	err := c.Client.Send(req, res)
	if err != nil {
		return nil, err
	}
	// The boot-flags parameter carries 5 data bytes (§28.13). The transport
	// does not enforce that length on the response, so a BMC that returns a
	// success completion code with a short payload would otherwise panic the
	// index accesses below (and BootDeviceSelector, which reads Data[1]).
	if len(res.Data) < 5 {
		return nil, fmt.Errorf("ipmi: short boot options response, expected 5 data bytes, got %d", len(res.Data))
	}
	return &ChassisSystemBootOptions{
		ParameterVersion:       int64(res.Version),
		ParameterValidUnlocked: res.Param&0x80 == 0,
		BootFlags: ChassisSystemBootOptionsFlags{
			BootFlagsValid:         res.Data[0]&0x80 != 0,
			ApplyToNextBootOnly:    res.Data[0]&0x40 == 0,
			LegacyBootType:         res.Data[0]&0x20 == 0,
			BootDeviceSelector:     res.BootDeviceSelector().String(),
			CmosClear:              res.Data[1]&0x80 != 0,
			LockKeyboard:           res.Data[1]&0x40 != 0,
			ScreenBlank:            res.Data[1]&0x2 != 0,
			LockOutResetButton:     res.Data[1]&0x1 != 0,
			ConsoleRedirection:     decodeConsoleRedirection(res.Data[2]),
			LockOutSleepButton:     res.Data[2]&0x4 != 0,
			UserPasswordBypass:     res.Data[2]&0x8 != 0,
			ForceProgressEventTrap: res.Data[2]&0x10 != 0,
			BIOSVerbosity:          decodeBIOSVerbosity(res.Data[2]),
			LockOutPowerButton:     res.Data[2]&0x80 != 0,
			BIOSMuxControlOverride: decodeBIOSMuxControlOverride(res.Data[3]),
			BIOSSharedModeOverride: res.Data[3]&0x8 != 0,
		},
	}, nil
}

const CommandGetUUID = ipmiTransport.Command(0x37)

type DeviceGuidRequest struct{}

type DeviceGuidResponse struct {
	ipmiTransport.CompletionCode
	Guid1        uint8
	Guid2        uint8
	Guid3        uint8
	Guid4        uint8
	Guid5        uint8
	Guid6        uint8
	ClockSeqLow  uint8
	ClockSeqHigh uint8
	TimeHigh     uint8
	TimeMid      uint8
	TimeLow      uint16
}

type DeviceGUID struct {
	GUID string
}

// Device GUID - 20.8 Get Device GUID Command
func (c *IpmiClient) DeviceGUID() (*DeviceGUID, error) {
	req := &ipmiTransport.Request{
		// NOTE we use the FunctionApp here
		ipmiTransport.NetworkFunctionApp,
		CommandGetUUID,
		&DeviceGuidRequest{},
	}

	res := &DeviceGuidResponse{}
	err := c.Client.Send(req, res)
	if err != nil {
		return nil, err
	}

	// guid dump mode
	// TODO: handle RFC4122 GUID, SMBIOS UUID
	// TODO: try to extract timestamp too
	guid := ""
	guid += fmt.Sprintf("%02X", res.Guid1)
	guid += fmt.Sprintf("%02X", res.Guid2)
	guid += fmt.Sprintf("%02X", res.Guid3)
	guid += fmt.Sprintf("%02X", res.Guid4)
	guid += fmt.Sprintf("%02X", res.Guid5)
	guid += fmt.Sprintf("%02X", res.Guid6)

	// use dump mode
	return &DeviceGUID{
		GUID: guid,
	}, nil
}
