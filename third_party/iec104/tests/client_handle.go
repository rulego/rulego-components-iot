package tests

import (
	"fmt"

	"github.com/rulego/rulego-components-iot/third_party/go-iecp5/asdu"
	"github.com/rulego/rulego-components-iot/third_party/iec104/client"
)

type clientCall struct {
}

// OnInterrogation total interrogation response
func (c *clientCall) OnInterrogation(packet *asdu.ASDU) error {
	addr, value := packet.GetInterrogationCmd()
	fmt.Printf("interrogation reply, addr: %d, value: %d\n", addr, value)
	return nil
}

// OnCounterInterrogation counter interrogation response
func (c *clientCall) OnCounterInterrogation(packet *asdu.ASDU) error {
	addr, value := packet.GetCounterInterrogationCmd()
	fmt.Printf("counter interrogation reply, addr: %d, request: 0x%02X, freeze: 0x%02X\n",
		addr, value.Request, value.Freeze)
	return nil
}

// OnRead read setpoint response
func (c *clientCall) OnRead(packet *asdu.ASDU) error {
	return c.OnASDU(packet)
}

// OnTestCommand test command response
func (c *clientCall) OnTestCommand(packet *asdu.ASDU) error {
	addr, value := packet.GetTestCommand()
	fmt.Printf("test cmd reply, addr: %d, value: %t\n", addr, value)
	return nil
}

// OnClockSync clock synchronization response
func (c *clientCall) OnClockSync(packet *asdu.ASDU) error {
	addr, value := packet.GetClockSynchronizationCmd()
	fmt.Printf("clock sync reply, addr: %d, value: %d\n", addr, value.UnixMilli())
	return nil
}

// OnResetProcess process reset response
func (c *clientCall) OnResetProcess(packet *asdu.ASDU) error {
	addr, value := packet.GetResetProcessCmd()
	fmt.Printf("reset process reply, addr: %d, value: 0x%02X\n", addr, value)
	return nil
}

// OnDelayAcquisition delayed acquisition response
func (c *clientCall) OnDelayAcquisition(packet *asdu.ASDU) error {
	addr, value := packet.GetDelayAcquireCommand()
	fmt.Printf("delay acquisition reply, addr: %d, value: %d\n", addr, value)
	return nil
}

// OnASDU data body
func (c *clientCall) OnASDU(packet *asdu.ASDU) error {
// Read device data
	switch client.GetDataType(packet.Type) {
	case client.SinglePoint:
		c.onSinglePoint(packet)
	case client.DoublePoint:
		c.onDoublePoint(packet)
	case client.MeasuredValueScaled:
		c.onMeasuredValueScaled(packet)
	case client.MeasuredValueNormal:
		c.onMeasuredValueNormal(packet)
	case client.StepPosition:
		c.onStepPosition(packet)
	case client.BitString32:
		c.onBitString32(packet)
	case client.MeasuredValueFloat:
		c.onMeasuredValueFloat(packet)
	case client.IntegratedTotals:
		c.onIntegratedTotals(packet)
	case client.EventOfProtectionEquipment:
		c.onEventOfProtectionEquipment(packet)
	case client.PackedStartEventsOfProtectionEquipment:
		c.onPackedStartEventsOfProtectionEquipment(packet)
	case client.PackedOutputCircuitInfo:
		c.onPackedOutputCircuitInfo(packet)
	case client.PackedSinglePointWithSCD:
		c.onPackedSinglePointWithSCD(packet)
	default:
		return nil
	}

	return nil
}

func (c *clientCall) onSinglePoint(packet *asdu.ASDU) {
// [M_SP_NA_1], [M_SP_TA_1] or [M_SP_TB_1] get single point information body collection
	for _, p := range packet.GetSinglePoint() {
		fmt.Printf("single point, ioa: %d, value: %v, qds: %d, time: %v\n", p.Ioa, p.Value, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onDoublePoint(packet *asdu.ASDU) {
// [M_DP_NA_1], [M_DP_TA_1] or [M_DP_TB_1] get double point information body collection
	for _, p := range packet.GetDoublePoint() {
		fmt.Printf("double point, ioa: %d, value: %v, qds: %d, time: %v\n", p.Ioa, p.Value, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onMeasuredValueScaled(packet *asdu.ASDU) {
// [M_ME_NB_1], [M_ME_TB_1] or [M_ME_TE_1] get measured value, scaled value information body collection
	for _, p := range packet.GetMeasuredValueScaled() {
		fmt.Printf("measured value scaled, ioa: %d, value: %v, qds: %d, time: %v\n", p.Ioa, p.Value, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onMeasuredValueNormal(packet *asdu.ASDU) {
// [M_ME_NA_1], [M_ME_TA_1],[ M_ME_TD_1] or [M_ME_ND_1] get measured value, normalized value information body collection
	for _, p := range packet.GetMeasuredValueNormal() {
		fmt.Printf("measured value normal, ioa: %d, value: %v, qds: %d, time: %v\n", p.Ioa, p.Value, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onStepPosition(packet *asdu.ASDU) {
// [M_ST_NA_1], [M_ST_TA_1] or [M_ST_TB_1] get step position information body collection
	for _, p := range packet.GetStepPosition() {
// state: false: device not in transient state, true: device in transient state
		fmt.Printf("step position, ioa: %d, state: %t, value: %d, qds: %d, time: %v\n", p.Ioa, p.Value.HasTransient, p.Value.Val, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onBitString32(packet *asdu.ASDU) {
// [M_BO_NA_1], [M_BO_TA_1] or [M_BO_TB_1]. get bitstring information body collection
	for _, p := range packet.GetBitString32() {
		fmt.Printf("bit string 32, ioa: %d, value: %v, qds: %d, time: %v\n", p.Ioa, p.Value, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onMeasuredValueFloat(packet *asdu.ASDU) {
// [M_ME_NC_1], [M_ME_TC_1] or [M_ME_TF_1]. get measured value, short floating point information body collection
	for _, p := range packet.GetMeasuredValueFloat() {
		fmt.Printf("measured value float, ioa: %d, value: %v, qds: %d, time: %v\n", p.Ioa, p.Value, p.Qds, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onIntegratedTotals(packet *asdu.ASDU) {
// [M_IT_NA_1], [M_IT_TA_1] or [M_IT_TB_1]. get integrated totals information body collection
	for _, p := range packet.GetIntegratedTotals() {
		fmt.Printf("integrated totals, ioa: %d, count: %d, SQ: 0x%02X, CY: %t, CA: %t, IV: %t, time: %v\n",
			p.Ioa, p.Value.CounterReading, p.Value.SeqNumber, p.Value.HasCarry, p.Value.IsAdjusted, p.Value.IsInvalid, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onEventOfProtectionEquipment(packet *asdu.ASDU) {
// [M_EP_TA_1] [M_EP_TD_1] get relay protection equipment event information body
	for _, p := range packet.GetEventOfProtectionEquipment() {
		fmt.Printf("event of protection equipment, ioa: %d, event: %d, qdp: %d, msec: %d, time: %v\n",
			p.Ioa, p.Event, p.Qdp, p.Msec, p.Time.Format("2006-01-02 15:04:05.000"))
	}
}

func (c *clientCall) onPackedStartEventsOfProtectionEquipment(packet *asdu.ASDU) {
// [M_EP_TB_1] [M_EP_TE_1] get relay protection equipment event information body
	p := packet.GetPackedStartEventsOfProtectionEquipment()
	fmt.Printf("packed start events of protection equipment, ioa: %d, event: %d, qdp: %d, msec: %d, time: %v\n",
		p.Ioa, p.Event, p.Qdp, p.Msec, p.Time.Format("2006-01-02 15:04:05.000"))
}

func (c *clientCall) onPackedOutputCircuitInfo(packet *asdu.ASDU) {
// [M_EP_TC_1] [M_EP_TF_1] get relay protection equipment grouped output circuit information body
	p := packet.GetPackedOutputCircuitInfo()
	fmt.Printf("packed output circuit, ioa: %d, qci: %d, qdp: %d, msec: %d, time: %v\n",
		p.Ioa, p.Oci, p.Qdp, p.Msec, p.Time.Format("2006-01-02 15:04:05.000"))
}

func (c *clientCall) onPackedSinglePointWithSCD(packet *asdu.ASDU) {
// [M_PS_NA_1]. get packed single point with change detection
	for _, p := range packet.GetPackedSinglePointWithSCD() {
		fmt.Printf("packed single point with SCD, ioa: %d, scd: %d, qds: %d\n", p.Ioa, p.Scd, p.Qds)
	}
}
