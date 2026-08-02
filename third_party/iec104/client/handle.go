package client

import "github.com/wendy512/go-iecp5/asdu"

const (
	SinglePoint                            DataType = iota // Single point information
	DoublePoint                                            // Double point information
	MeasuredValueScaled                                    // Measured value, scaled value information
	MeasuredValueNormal                                    // Measured value, normalized value information
	StepPosition                                           // Step position information
	BitString32                                            // Bitstring information
	MeasuredValueFloat                                     // Measured value, short floating point information
	IntegratedTotals                                       // Integrated totals information
	EventOfProtectionEquipment                             // Protection equipment event information
	PackedStartEventsOfProtectionEquipment                 // Protection equipment event information
	PackedOutputCircuitInfo                                // Protection equipment packed output circuit information
	PackedSinglePointWithSCD                               // Packed single point with change detection
	SingleCommandInfo
	DoubleCommandInfo
	StepCommandInfo
	SetPointCommandNormalInfo
	SetPointCommandScaledInfo
	SetPointCommandFloatInfo
	BitsString32CommandInfo
	UNKNOWN // Unknown
)

type DataType int

type clientHandler struct {
	call ASDUCall
}

// InterrogationHandler total interrogation response
func (h *clientHandler) InterrogationHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnInterrogation(rxAsdu)
}

// CounterInterrogationHandler counter interrogation response
func (h *clientHandler) CounterInterrogationHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnCounterInterrogation(rxAsdu)
}

// ReadHandler read setpoint response
func (h *clientHandler) ReadHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnRead(rxAsdu)
}

// TestCommandHandler test command response
func (h *clientHandler) TestCommandHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnTestCommand(rxAsdu)
}

// ClockSyncHandler clock synchronization response
func (h *clientHandler) ClockSyncHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnClockSync(rxAsdu)
}

// ResetProcessHandler process reset response
func (h *clientHandler) ResetProcessHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnResetProcess(rxAsdu)
}

// DelayAcquisitionHandler delayed acquisition response
func (h *clientHandler) DelayAcquisitionHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnDelayAcquisition(rxAsdu)
}

// ASDUHandler ASDU upload, ASDU data
func (h *clientHandler) ASDUHandler(_ asdu.Connect, rxAsdu *asdu.ASDU) error {
	return h.call.OnASDU(rxAsdu)
}

func GetDataType(typeId asdu.TypeID) DataType {
	switch typeId {
	case asdu.M_SP_NA_1, asdu.M_SP_TA_1, asdu.M_SP_TB_1:
		return SinglePoint
	case asdu.M_DP_NA_1, asdu.M_DP_TA_1, asdu.M_DP_TB_1:
		return DoublePoint
	case asdu.M_ST_NA_1, asdu.M_ST_TA_1, asdu.M_ST_TB_1:
		return StepPosition
	case asdu.M_BO_NA_1, asdu.M_BO_TA_1, asdu.M_BO_TB_1:
		return BitString32
	case asdu.M_ME_NB_1, asdu.M_ME_TB_1, asdu.M_ME_TE_1:
		return MeasuredValueScaled
	case asdu.M_ME_NA_1, asdu.M_ME_TA_1, asdu.M_ME_TD_1, asdu.M_ME_ND_1:
		return MeasuredValueNormal
	case asdu.M_ME_NC_1, asdu.M_ME_TC_1, asdu.M_ME_TF_1:
		return MeasuredValueFloat
	case asdu.M_IT_NA_1, asdu.M_IT_TA_1, asdu.M_IT_TB_1:
		return IntegratedTotals
	case asdu.M_EP_TA_1, asdu.M_EP_TD_1:
		return EventOfProtectionEquipment
	case asdu.M_EP_TB_1, asdu.M_EP_TE_1:
		return PackedStartEventsOfProtectionEquipment
	case asdu.M_EP_TC_1, asdu.M_EP_TF_1:
		return PackedOutputCircuitInfo
	case asdu.M_PS_NA_1:
		return PackedSinglePointWithSCD
	case asdu.C_SC_NA_1, asdu.C_SC_TA_1:
		return SingleCommandInfo
	case asdu.C_DC_NA_1, asdu.C_DC_TA_1:
		return DoubleCommandInfo
	case asdu.C_RC_NA_1, asdu.C_RC_TA_1:
		return StepCommandInfo
	case asdu.C_SE_NA_1, asdu.C_SE_TA_1:
		return SetPointCommandNormalInfo
	case asdu.C_SE_NB_1, asdu.C_SE_TB_1:
		return SetPointCommandScaledInfo
	case asdu.C_SE_NC_1, asdu.C_SE_TC_1:
		return SetPointCommandFloatInfo
	case asdu.C_BO_NA_1, asdu.C_BO_TA_1:
		return BitsString32CommandInfo
	default:
		return UNKNOWN
	}
}
