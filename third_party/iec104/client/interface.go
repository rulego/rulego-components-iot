package client

import "github.com/rulego/rulego-components-iot/third_party/go-iecp5/asdu"

// ASDUCall  is the interface of client handler
type ASDUCall interface {
// OnInterrogation total interrogation response
	OnInterrogation(*asdu.ASDU) error
// OnCounterInterrogation counter interrogation response
	OnCounterInterrogation(*asdu.ASDU) error
// OnRead read setpoint response
	OnRead(*asdu.ASDU) error
// OnTestCommand test command response
	OnTestCommand(*asdu.ASDU) error
// OnClockSync clock synchronization response
	OnClockSync(*asdu.ASDU) error
// OnResetProcess process reset response
	OnResetProcess(*asdu.ASDU) error
// OnDelayAcquisition delayed acquisition response
	OnDelayAcquisition(*asdu.ASDU) error
// OnASDU data response or control response
	OnASDU(*asdu.ASDU) error
}
