package server

import (
	"time"

	"github.com/wendy512/go-iecp5/asdu"
)

type CommandHandler interface {
// OnInterrogation total interrogation request
	OnInterrogation(asdu.Connect, *asdu.ASDU, asdu.QualifierOfInterrogation) error
// OnCounterInterrogation counter interrogation request
	OnCounterInterrogation(asdu.Connect, *asdu.ASDU, asdu.QualifierCountCall) error
// OnRead read setpoint request
	OnRead(asdu.Connect, *asdu.ASDU, asdu.InfoObjAddr) error
// OnClockSync clock synchronization request
	OnClockSync(asdu.Connect, *asdu.ASDU, time.Time) error
// OnResetProcess process reset request
	OnResetProcess(asdu.Connect, *asdu.ASDU, asdu.QualifierOfResetProcessCmd) error
// OnDelayAcquisition delayed acquisition request
	OnDelayAcquisition(asdu.Connect, *asdu.ASDU, uint16) error
// OnTestCommand test command request
	OnTestCommand(asdu.Connect, *asdu.ASDU) error
// OnASDU control command request
	OnASDU(asdu.Connect, *asdu.ASDU) error
}
