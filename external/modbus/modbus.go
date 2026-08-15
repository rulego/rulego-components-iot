/*
 * Copyright 2025 The RuleGo Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package modbus

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego-components-iot/pkg/iot_points"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/maps"
	"github.com/rulego/rulego/utils/str"
	"github.com/simonvetter/modbus"
)

const (
	DefaultServer                       = "tcp://127.0.0.1:502"
	DefaultSpeed      uint              = 19200
	DefaultDataBits   uint              = 8
	DefaultParity     Parity            = ParityNone
	DefaultStopBits   uint              = 2
	DefaultTimeout    time.Duration     = time.Second * 5
	DefaultEndianness modbus.Endianness = modbus.BIG_ENDIAN
	DefaultWordOrder  modbus.WordOrder  = modbus.HIGH_WORD_FIRST
	DefaultUnitId     uint8             = 1
)

// Custom error types
type UnknownCommandErr struct {
	Cmd string
}

func (e *UnknownCommandErr) Error() string {
	return fmt.Sprintf("unknown command: %s", e.Cmd)
}

type ModbusConnErr struct {
	Err error
}

func (e *ModbusConnErr) Error() string {
	return fmt.Sprintf("modbus connection error: %s", e.Err.Error())
}

func (e *ModbusConnErr) Unwrap() error {
	return e.Err
}

// Register node
func init() {
	_ = rulego.Registry.Register(&ModbusNode{})
}

// ModbusConfiguration node configuration
type ModbusConfiguration struct {
	// Server address
	Server string `json:"server" label:"Server" desc:"Modbus server address, format: tcp://host:port or rtu:///dev/ttyUSB0" required:"true" ref:"primary"`
	// Modbus method name
	Cmd string `json:"cmd" label:"Command" desc:"Modbus command: ReadCoils, ReadRegisters, WriteCoil, WriteRegister, etc."`
	// UnitId slave unit ID
	UnitId uint8 `json:"unitId" label:"Unit ID" desc:"Modbus slave unit ID"`
	// address register address supports ${} variables, e.g. 50 or 0x32
	Address string `json:"address" label:"Address" desc:"Register address, supports ${} variables, e.g. 50 or 0x32"`
	// quantity register count supports ${} variables
	Quantity string `json:"quantity" label:"Quantity" desc:"Number of registers, supports ${} variables"`
	// value register value supports ${} variables; not needed for read, comma-separated for multiple writes, e.g. 0x1,0x1 true 51,52
	Value string `json:"value" label:"Value" desc:"Register value for write, supports ${} variables, comma-separated for multiple"`
	// RegType register type supports ${} variables, 0=Holding (function code 0x3), 1=Input (function code 0x4)
	RegType        string         `json:"regType" label:"Register Type" desc:"Register type: 0=Holding, 1=Input"`
	TcpConfig      TcpConfig      `json:"tcpConfig" label:"TCP Config" desc:"TCP connection configuration"`
	RtuConfig      RtuConfig      `json:"rtuConfig" label:"RTU Config" desc:"RTU serial configuration"`
	EncodingConfig EncodingConfig `json:"encodingConfig" label:"Encoding Config" desc:"Data encoding configuration"`
}

type EncodingConfig struct {
	// Endianness register endianness 1=Big Endian 2=Little Endian
	Endianness uint `json:"endianness" label:"Endianness" desc:"Register endianness: 1=Big Endian, 2=Little Endian"`
	// WordOrder word ordering for 32-bit registers 1=High Word First 2=Low Word First
	WordOrder uint `json:"wordOrder" label:"Word Order" desc:"Word order for 32-bit registers: 1=High Word First, 2=Low Word First"`
}

type TcpConfig struct {
	// Timeout sets the request timeout value, unit seconds
	Timeout int64 `json:"timeout" label:"Timeout" desc:"Request timeout in seconds"`
	// CertFile TLS client certificate file
	CertFile string `json:"certFile" label:"Cert File" desc:"TLS client certificate file path"`
	// CertKeyFile TLS client private key file
	CertKeyFile string `json:"certKeyFile" label:"Cert Key File" desc:"TLS client private key file path"`
	// CAFile TLS CA certificate file
	CAFile string `json:"caFile" label:"CA File" desc:"TLS CA certificate file path"`
}

type RtuConfig struct {
	// Speed sets the serial link speed (in bps, rtu only)
	Speed uint `json:"speed" label:"Speed" desc:"Serial link speed in bps"`
	// DataBits sets the number of bits per serial character (rtu only)
	DataBits uint `json:"dataBits" label:"Data Bits" desc:"Bits per serial character: 5, 6, 7, 8"`
	// Parity sets the serial link parity mode (rtu only).
	// Wire form is the letter (N/O/E) as in "8E1"; 0/1/2 still parsed for compatibility.
	Parity Parity `json:"parity" label:"Parity" desc:"Parity mode: N=None, E=Even, O=Odd (0/1/2 also accepted)"`
	// StopBits sets the number of serial stop bits (rtu only)
	StopBits uint `json:"stopBits" label:"Stop Bits" desc:"Stop bits: 1, 2"`
}

// reconnectFunc callback function to re-establish connection
type reconnectFunc func(oldClient *modbus.ModbusClient, attempt int) (*modbus.ModbusClient, error)

// RetryableModbusClient Modbus client with retry logic
type RetryableModbusClient struct {
	client      *modbus.ModbusClient
	maxRetries  int
	logger      types.Logger
	reconnectFn reconnectFunc
	onStatus    func(types.NodeStatus, string)
	// Save runtime config (underlying lib has no getter, need to restore after reconnect)
	mu            sync.RWMutex
	currentUnitId uint8
	endianness    modbus.Endianness
	wordOrder     modbus.WordOrder
}

// NewRetryableModbusClient creates a new Modbus client with retry logic
func NewRetryableModbusClient(client *modbus.ModbusClient, maxRetries int, logger types.Logger, reconnectFn reconnectFunc, unitId uint8, endianness modbus.Endianness, wordOrder modbus.WordOrder, onStatus func(types.NodeStatus, string)) *RetryableModbusClient {
	return &RetryableModbusClient{
		client:        client,
		maxRetries:    maxRetries,
		logger:        logger,
		reconnectFn:   reconnectFn,
		currentUnitId: unitId,
		endianness:    endianness,
		wordOrder:     wordOrder,
		onStatus:      onStatus,
	}
}

// modbusOpLocks associates operation locks by underlying client, serializes SetUnitId+operation for shared connections.
var modbusOpLocks iot_points.OpLocks

// executeWithRetry executes operation and retries on connection errors
func (r *RetryableModbusClient) executeWithRetry(operation string, fn func() error) error {
	var err error
	for retry := 0; retry <= r.maxRetries; retry++ {
		opLock := modbusOpLocks.Lock(r.client)
		opLock.Lock()
		if r.client != nil {
			r.client.SetUnitId(r.currentUnitId)
		}
		err = fn()
		opLock.Unlock()
		if err == nil {
			if r.onStatus != nil {
				r.onStatus(types.StatusConnected, "")
			}
			return nil
		}

		// Check if connection error and retry limit not reached
		if retry < r.maxRetries {
			// Skip explicit non-network/retry-invalid protocol errors
			if err == modbus.ErrIllegalFunction ||
				err == modbus.ErrIllegalDataAddress ||
				err == modbus.ErrIllegalDataValue ||
				err == modbus.ErrConfigurationError {
				return err
			}

			r.warnf("Modbus %s error: %s, retry count: %d, trying to reconnect...", operation, err, retry)
			if r.onStatus != nil {
				r.onStatus(types.StatusReconnecting, err.Error())
			}

			// Rebuild connection via SharedNode mechanism
			if r.reconnectFn != nil {
				oldClient := r.client
				newClient, reconnectErr := r.reconnectFn(oldClient, retry)
				if reconnectErr != nil {
					r.warnf("Failed to reconnect: %s", reconnectErr)
					return &ModbusConnErr{Err: reconnectErr}
				}
				r.client = newClient
				modbusOpLocks.Delete(oldClient)
				// Restore runtime config to new connection
				r.applyRuntimeConfig()
			} else {
				// No reconnect callback, return error directly
				return &ModbusConnErr{Err: err}
			}

			continue
		}
	}
	return &ModbusConnErr{Err: err}
}

// warnf logs warning
func (r *RetryableModbusClient) warnf(format string, v ...interface{}) {
	if r.logger != nil {
		r.logger.Warnf("[Modbus] "+format, v...)
	}
}

// ReadCoil reads single coil status
func (r *RetryableModbusClient) ReadCoil(address uint16) (bool, error) {
	var result bool
	var err error
	fn := func() error {
		result, err = r.client.ReadCoil(address)
		return err
	}
	err = r.executeWithRetry("ReadCoil", fn)
	return result, err
}

// ReadCoils reads multiple coil status
func (r *RetryableModbusClient) ReadCoils(address uint16, quantity uint16) ([]bool, error) {
	var result []bool
	var err error
	fn := func() error {
		result, err = r.client.ReadCoils(address, quantity)
		return err
	}
	err = r.executeWithRetry("ReadCoils", fn)
	return result, err
}

// ReadDiscreteInput reads single discrete input status
func (r *RetryableModbusClient) ReadDiscreteInput(address uint16) (bool, error) {
	var result bool
	var err error
	fn := func() error {
		result, err = r.client.ReadDiscreteInput(address)
		return err
	}
	err = r.executeWithRetry("ReadDiscreteInput", fn)
	return result, err
}

// ReadDiscreteInputs reads multiple discrete input status
func (r *RetryableModbusClient) ReadDiscreteInputs(address uint16, quantity uint16) ([]bool, error) {
	var result []bool
	var err error
	fn := func() error {
		result, err = r.client.ReadDiscreteInputs(address, quantity)
		return err
	}
	err = r.executeWithRetry("ReadDiscreteInputs", fn)
	return result, err
}

// ReadRegister reads single register
func (r *RetryableModbusClient) ReadRegister(address uint16, regType modbus.RegType) (uint16, error) {
	var result uint16
	var err error
	fn := func() error {
		result, err = r.client.ReadRegister(address, regType)
		return err
	}
	err = r.executeWithRetry("ReadRegister", fn)
	return result, err
}

// ReadRegisters reads multiple registers
func (r *RetryableModbusClient) ReadRegisters(address uint16, quantity uint16, regType modbus.RegType) ([]uint16, error) {
	var result []uint16
	var err error
	fn := func() error {
		result, err = r.client.ReadRegisters(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadRegisters", fn)
	return result, err
}

// ReadUint32 reads single 32-bit unsigned integer
func (r *RetryableModbusClient) ReadUint32(address uint16, regType modbus.RegType) (uint32, error) {
	var result uint32
	var err error
	fn := func() error {
		result, err = r.client.ReadUint32(address, regType)
		return err
	}
	err = r.executeWithRetry("ReadUint32", fn)
	return result, err
}

// ReadUint32s reads multiple 32-bit unsigned integers
func (r *RetryableModbusClient) ReadUint32s(address uint16, quantity uint16, regType modbus.RegType) ([]uint32, error) {
	var result []uint32
	var err error
	fn := func() error {
		result, err = r.client.ReadUint32s(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadUint32s", fn)
	return result, err
}

// ReadFloat32 reads single 32-bit float
func (r *RetryableModbusClient) ReadFloat32(address uint16, regType modbus.RegType) (float32, error) {
	var result float32
	var err error
	fn := func() error {
		result, err = r.client.ReadFloat32(address, regType)
		return err
	}
	err = r.executeWithRetry("ReadFloat32", fn)
	return result, err
}

// ReadFloat32s reads multiple 32-bit floats
func (r *RetryableModbusClient) ReadFloat32s(address uint16, quantity uint16, regType modbus.RegType) ([]float32, error) {
	var result []float32
	var err error
	fn := func() error {
		result, err = r.client.ReadFloat32s(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadFloat32s", fn)
	return result, err
}

// ReadUint64 reads single 64-bit unsigned integer
func (r *RetryableModbusClient) ReadUint64(address uint16, regType modbus.RegType) (uint64, error) {
	var result uint64
	var err error
	fn := func() error {
		result, err = r.client.ReadUint64(address, regType)
		return err
	}
	err = r.executeWithRetry("ReadUint64", fn)
	return result, err
}

// ReadUint64s reads multiple 64-bit unsigned integers
func (r *RetryableModbusClient) ReadUint64s(address uint16, quantity uint16, regType modbus.RegType) ([]uint64, error) {
	var result []uint64
	var err error
	fn := func() error {
		result, err = r.client.ReadUint64s(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadUint64s", fn)
	return result, err
}

// ReadFloat64 reads single 64-bit float
func (r *RetryableModbusClient) ReadFloat64(address uint16, regType modbus.RegType) (float64, error) {
	var result float64
	var err error
	fn := func() error {
		result, err = r.client.ReadFloat64(address, regType)
		return err
	}
	err = r.executeWithRetry("ReadFloat64", fn)
	return result, err
}

// ReadFloat64s reads multiple 64-bit floats
func (r *RetryableModbusClient) ReadFloat64s(address uint16, quantity uint16, regType modbus.RegType) ([]float64, error) {
	var result []float64
	var err error
	fn := func() error {
		result, err = r.client.ReadFloat64s(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadFloat64s", fn)
	return result, err
}

// ReadBytes reads byte array
func (r *RetryableModbusClient) ReadBytes(address uint16, quantity uint16, regType modbus.RegType) ([]byte, error) {
	var result []byte
	var err error
	fn := func() error {
		result, err = r.client.ReadBytes(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadBytes", fn)
	return result, err
}

// ReadRawBytes reads raw byte array
func (r *RetryableModbusClient) ReadRawBytes(address uint16, quantity uint16, regType modbus.RegType) ([]byte, error) {
	var result []byte
	var err error
	fn := func() error {
		result, err = r.client.ReadRawBytes(address, quantity, regType)
		return err
	}
	err = r.executeWithRetry("ReadRawBytes", fn)
	return result, err
}

// WriteCoil writes single coil status
func (r *RetryableModbusClient) WriteCoil(address uint16, value bool) error {
	fn := func() error {
		return r.client.WriteCoil(address, value)
	}
	return r.executeWithRetry("WriteCoil", fn)
}

// WriteCoils writes multiple coil status
func (r *RetryableModbusClient) WriteCoils(address uint16, values []bool) error {
	fn := func() error {
		return r.client.WriteCoils(address, values)
	}
	return r.executeWithRetry("WriteCoils", fn)
}

// WriteRegister writes single register
func (r *RetryableModbusClient) WriteRegister(address uint16, value uint16) error {
	fn := func() error {
		return r.client.WriteRegister(address, value)
	}
	return r.executeWithRetry("WriteRegister", fn)
}

// WriteRegisters writes multiple registers
func (r *RetryableModbusClient) WriteRegisters(address uint16, values []uint16) error {
	fn := func() error {
		return r.client.WriteRegisters(address, values)
	}
	return r.executeWithRetry("WriteRegisters", fn)
}

// WriteUint32 writes single 32-bit unsigned integer
func (r *RetryableModbusClient) WriteUint32(address uint16, value uint32) error {
	fn := func() error {
		return r.client.WriteUint32(address, value)
	}
	return r.executeWithRetry("WriteUint32", fn)
}

// WriteUint32s writes multiple 32-bit unsigned integers
func (r *RetryableModbusClient) WriteUint32s(address uint16, values []uint32) error {
	fn := func() error {
		return r.client.WriteUint32s(address, values)
	}
	return r.executeWithRetry("WriteUint32s", fn)
}

// WriteFloat32 writes single 32-bit float
func (r *RetryableModbusClient) WriteFloat32(address uint16, value float32) error {
	fn := func() error {
		return r.client.WriteFloat32(address, value)
	}
	return r.executeWithRetry("WriteFloat32", fn)
}

// WriteFloat32s writes multiple 32-bit floats
func (r *RetryableModbusClient) WriteFloat32s(address uint16, values []float32) error {
	fn := func() error {
		return r.client.WriteFloat32s(address, values)
	}
	return r.executeWithRetry("WriteFloat32s", fn)
}

// WriteUint64 writes single 64-bit unsigned integer
func (r *RetryableModbusClient) WriteUint64(address uint16, value uint64) error {
	fn := func() error {
		return r.client.WriteUint64(address, value)
	}
	return r.executeWithRetry("WriteUint64", fn)
}

// WriteUint64s writes multiple 64-bit unsigned integers
func (r *RetryableModbusClient) WriteUint64s(address uint16, values []uint64) error {
	fn := func() error {
		return r.client.WriteUint64s(address, values)
	}
	return r.executeWithRetry("WriteUint64s", fn)
}

// WriteFloat64 writes single 64-bit float
func (r *RetryableModbusClient) WriteFloat64(address uint16, value float64) error {
	fn := func() error {
		return r.client.WriteFloat64(address, value)
	}
	return r.executeWithRetry("WriteFloat64", fn)
}

// WriteFloat64s writes multiple 64-bit floats
func (r *RetryableModbusClient) WriteFloat64s(address uint16, values []float64) error {
	fn := func() error {
		return r.client.WriteFloat64s(address, values)
	}
	return r.executeWithRetry("WriteFloat64s", fn)
}

// WriteBytes writes byte array
func (r *RetryableModbusClient) WriteBytes(address uint16, values []byte) error {
	fn := func() error {
		return r.client.WriteBytes(address, values)
	}
	return r.executeWithRetry("WriteBytes", fn)
}

// WriteRawBytes writes raw byte array
func (r *RetryableModbusClient) WriteRawBytes(address uint16, values []byte) error {
	fn := func() error {
		return r.client.WriteRawBytes(address, values)
	}
	return r.executeWithRetry("WriteRawBytes", fn)
}

// SetUnitId sets slave unit ID
func (r *RetryableModbusClient) SetUnitId(unitId uint8) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentUnitId = unitId
	if r.client != nil {
		r.client.SetUnitId(unitId)
	}
}

// SetEncoding sets encoding
func (r *RetryableModbusClient) SetEncoding(endianness modbus.Endianness, wordOrder modbus.WordOrder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endianness = endianness
	r.wordOrder = wordOrder
	if r.client != nil {
		r.client.SetEncoding(endianness, wordOrder)
	}
}

// applyRuntimeConfig restores runtime config to current connection
func (r *RetryableModbusClient) applyRuntimeConfig() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.client != nil {
		if r.currentUnitId != 0 {
			r.client.SetUnitId(r.currentUnitId)
		}
		r.client.SetEncoding(r.endianness, r.wordOrder)
	}
}

// ModbusNode imperative modbus node (single point Cmd/Address/Quantity).
// Deprecated: use x/modbusRead / x/modbusWrite (point table + Modicon address, unified iot_points contract).
// Success: route to Success chain, result stored in msg.Data
// Failure: route to Failure chain
type ModbusNode struct {
	base.SharedNode[*modbus.ModbusClient]
	// Node configuration
	Config           ModbusConfiguration
	addressTemplate  str.Template
	quantityTemplate str.Template
	valueTemplate    str.Template
	regTypeTemplate  str.Template
	reconnectLocker  sync.Mutex
	// Record current UnitId
	currentUnitId   uint8
	currentUnitIdMu sync.RWMutex
}

type Params struct {
	Cmd      string         `json:"cmd" `
	Address  uint16         `json:"address" `
	Quantity uint16         `json:"quantity" `
	Value    string         `json:"value" `
	RegType  modbus.RegType `json:"regType" `
}

// Type returns component type

func (x *ModbusNode) getCurrentUnitId() uint8 {
	x.currentUnitIdMu.RLock()
	defer x.currentUnitIdMu.RUnlock()
	return x.currentUnitId
}

func (x *ModbusNode) setUnitId(client *modbus.ModbusClient, unitId uint8) {
	x.currentUnitIdMu.Lock()
	defer x.currentUnitIdMu.Unlock()
	x.currentUnitId = unitId
	if client != nil {
		client.SetUnitId(unitId)
	}
}
func (x *ModbusNode) Type() string {
	return "x/modbus"
}

// New default parameters
func (x *ModbusNode) New() types.Node {
	return &ModbusNode{
		Config: ModbusConfiguration{
			Server:   DefaultServer,
			Cmd:      "ReadCoils",
			UnitId:   DefaultUnitId,
			Address:  "50",
			Quantity: "1",
			Value:    "1",
			RegType:  "0",
			TcpConfig: TcpConfig{
				Timeout: 5,
			},
			EncodingConfig: EncodingConfig{
				Endianness: uint(DefaultEndianness),
				WordOrder:  uint(DefaultWordOrder),
			},
			RtuConfig: RtuConfig{
				Speed:    DefaultSpeed,
				DataBits: DefaultDataBits,
				Parity:   DefaultParity,
				StopBits: 2,
			},
		},
	}
}

// Init initializes component
func (x *ModbusNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	if err == nil {
		// Initialize current UnitId
		x.setUnitId(nil, x.Config.UnitId)

		// Initialize client. Soft-fail keeps a dead device from failing chain load;
		// the shared node records the cooldown and retries on the next message.
		_ = x.SharedNode.InitWithCloseSoftFail(ruleConfig, x.Type(), x.Config.Server, ruleConfig.NodeClientInitNow, func() (*modbus.ModbusClient, error) {
			return x.initClient()
		}, func(client *modbus.ModbusClient) error {
			if client != nil {
				return client.Close()
			}
			return nil
		})
	}
	// Initialize templates
	x.addressTemplate = str.NewTemplate(x.Config.Address)
	x.quantityTemplate = str.NewTemplate(x.Config.Quantity)
	x.valueTemplate = str.NewTemplate(x.Config.Value)
	x.regTypeTemplate = str.NewTemplate(x.Config.RegType)
	// Enable same-chain connection pool
	x.SharedNode.BindChain(configuration)
	return err
}

func readModbusValues[T bool | uint16 | uint32 | uint64 | float32 | float64 | byte](data []T, initAddr uint16, step uint16, unitId uint8) []iot_points.Data {
	addVals := make([]iot_points.Data, 0, len(data))
	now := time.Now().UnixNano()
	elemType := reflect.ValueOf(data).Type().Elem()
	if elemType == reflect.TypeOf(byte(0)) {
		step = 1
		for i := range data {
			if i%2 == 0 {
				addVals = append(addVals, iot_points.Data{
					Name:      strconv.Itoa(int(initAddr) + i*int(step)),
					Value:     data[i : i+1],
					Timestamp: now,
				})
			}
		}

	} else {
		for i, v := range data {
			addVals = append(addVals, iot_points.Data{
				Name:      strconv.Itoa(int(initAddr) + i*int(step)),
				Value:     v,
				Timestamp: now,
			})
		}
	}
	return addVals
}

// reconnect safely rebuilds connection through SharedNode mechanism.
func (x *ModbusNode) reconnect(oldClient *modbus.ModbusClient, attempt int) (*modbus.ModbusClient, error) {
	// ref:// borrower: connection owned by source node, borrower does not rebuild.
	if x.SharedNode.IsFromPool() {
		// NodePool mode: delegate to source node in pool
		if x.RuleConfig.NodePool != nil {
			if nodeCtx, ok := x.RuleConfig.NodePool.Get(x.SharedNode.InstanceId); ok {
				if sourceNode, ok := nodeCtx.GetNode().(*ModbusNode); ok {
					return sourceNode.reconnect(oldClient, attempt)
				}
			}
		}
		// Same-chain mode: return error for upper layer to handle
		return nil, fmt.Errorf("modbus ref://%s borrower does not own the connection", x.SharedNode.InstanceId)
	}

	x.reconnectLocker.Lock()
	defer x.reconnectLocker.Unlock()

	// Check if connection already rebuilt by other goroutine
	currentClient, err := x.SharedNode.GetSafely()
	if err != nil {
		// Get or init failed
		return nil, err
	}
	if currentClient != oldClient {
		// Already rebuilt by other goroutine, return new connection directly
		return currentClient, nil
	}

	// Close old connection and wait for gateway to release resources
	if oldClient != nil {
		_ = oldClient.Close()
		modbusOpLocks.Delete(oldClient) // Clean up old connection operation lock
		time.Sleep(iot_points.BackoffFor(attempt))
	}

	// Build new connection, Refresh updates holder
	newClient, err := x.initClient()
	if err != nil {
		return nil, err
	}
	x.SharedNode.Refresh(newClient)
	return newClient, nil
}

// OnMsg processes message
func (x *ModbusNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	var (
		err    error
		params *Params
		data   []iot_points.Data = make([]iot_points.Data, 0)
	)

	conn, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	// Create temporary retryableClient for this request, pass reconnect callback and runtime config
	retryableClient := NewRetryableModbusClient(
		conn, 3, x.RuleConfig.Logger, x.reconnect,
		x.getCurrentUnitId(),
		modbus.Endianness(x.Config.EncodingConfig.Endianness),
		modbus.WordOrder(x.Config.EncodingConfig.WordOrder),
		x.SharedNode.SetStatus,
	)

	params, err = x.getParams(ctx, msg)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	// Use client with retry capability to execute operation
	err, data = x.executeModbusCommand(params, retryableClient)

	if err != nil {
		ctx.TellFailure(msg, err)
	} else {
		if len(data) > 0 {
			bytes, err := json.Marshal(data)
			if err != nil {
				ctx.TellFailure(msg, err)
				return
			}
			msg.SetDataType(types.JSON)
			msg.SetData(str.ToString(bytes))
		}
		ctx.TellSuccess(msg)
	}
}

// executeModbusCommand executes Modbus command
func (x *ModbusNode) executeModbusCommand(params *Params, retryableClient *RetryableModbusClient) (error, []iot_points.Data) {
	var (
		err      error
		boolVals []bool
		boolVal  bool
		ui16     uint16
		ui32     uint32
		ui64     uint64
		f32      float32
		f64      float64
		ui16s    []uint16
		ui32s    []uint32
		ui64s    []uint64
		f32s     []float32
		f64s     []float64
		bts      []byte
		data     []iot_points.Data = make([]iot_points.Data, 0)
	)

	switch params.Cmd {
	case "ReadCoils":
		boolVals, err = retryableClient.ReadCoils(params.Address, params.Quantity)
		if err == nil {
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadCoil":
		boolVal, err = retryableClient.ReadCoil(params.Address)
		if err == nil {
			boolVals = append(boolVals, boolVal)
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadDiscreteInputs":
		boolVals, err = retryableClient.ReadDiscreteInputs(params.Address, params.Quantity)
		if err == nil {
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadDiscreteInput":
		boolVal, err = retryableClient.ReadDiscreteInput(params.Address)
		if err == nil {
			boolVals = append(boolVals, boolVal)
			data = readModbusValues(boolVals, params.Address, 1, x.Config.UnitId)
		}
	case "ReadRegisters":
		ui16s, err = retryableClient.ReadRegisters(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(ui16s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadRegister":
		ui16, err = retryableClient.ReadRegister(params.Address, params.RegType)
		if err == nil {
			ui16s = append(ui16s, ui16)
			data = readModbusValues(ui16s, params.Address, 1, x.Config.UnitId)
		}
	case "ReadUint32s":
		ui32s, err = retryableClient.ReadUint32s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(ui32s, params.Address, 2, x.Config.UnitId)
		}
	case "ReadUint32":
		ui32, err = retryableClient.ReadUint32(params.Address, params.RegType)
		if err == nil {
			ui32s = append(ui32s, ui32)
			data = readModbusValues(ui32s, params.Address, 2, x.Config.UnitId)
		}
	case "ReadFloat32s":
		f32s, err = retryableClient.ReadFloat32s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(f32s, params.Address, 2, x.Config.UnitId)
		}
	case "ReadFloat32":
		f32, err = retryableClient.ReadFloat32(params.Address, params.RegType)
		if err == nil {
			f32s = append(f32s, f32)
			data = readModbusValues(f32s, params.Address, 2, x.Config.UnitId)
		}
	case "ReadUint64s":
		ui64s, err = retryableClient.ReadUint64s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(ui64s, params.Address, 4, x.Config.UnitId)
		}
	case "ReadUint64":
		ui64, err = retryableClient.ReadUint64(params.Address, params.RegType)
		if err == nil {
			ui64s = append(ui64s, ui64)
			data = readModbusValues(ui64s, params.Address, 4, x.Config.UnitId)
		}
	case "ReadFloat64s":
		f64s, err = retryableClient.ReadFloat64s(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(f64s, params.Address, 4, x.Config.UnitId)
		}
	case "ReadFloat64":
		f64, err = retryableClient.ReadFloat64(params.Address, params.RegType)
		if err == nil {
			f64s = append(f64s, f64)
			data = readModbusValues(f64s, params.Address, 4, x.Config.UnitId)
		}
	case "ReadBytes":
		bts, err = retryableClient.ReadBytes(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(bts, params.Address, 1, x.Config.UnitId)
		}
	case "ReadRawBytes":
		bts, err = retryableClient.ReadRawBytes(params.Address, params.Quantity, params.RegType)
		if err == nil {
			data = readModbusValues(bts, params.Address, 1, x.Config.UnitId)
		}
	case "WriteCoil":
		boolVal, err = byteToBool(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteCoil(params.Address, boolVal)
		}
	case "WriteCoils":
		boolVals, err = byteToBools(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteCoils(params.Address, boolVals)
		}
	case "WriteRegister":
		ui16, err = byteToUint16(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteRegister(params.Address, ui16)
		}
	case "WriteRegisters":
		ui16s, err = byteToUint16s(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteRegisters(params.Address, ui16s)
		}
	case "WriteUint32":
		ui32, err = byteToUint32(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteUint32(params.Address, ui32)
		}
	case "WriteUint32s":
		ui32s, err = byteToUint32s(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteUint32s(params.Address, ui32s)
		}
	case "WriteFloat32":
		f32, err = byteToFloat32(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteFloat32(params.Address, f32)
		}
	case "WriteFloat32s":
		f32s, err = byteToFloat32s(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteFloat32s(params.Address, f32s)
		}
	case "WriteUint64":
		ui64, err = byteToUint64(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteUint64(params.Address, ui64)
		}
	case "WriteUint64s":
		ui64s, err = byteToUint64s(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteUint64s(params.Address, ui64s)
		}
	case "WriteFloat64":
		f64, err = byteToFloat64(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteFloat64(params.Address, f64)
		}
	case "WriteFloat64s":
		f64s, err = byteToFloat64s(params.Value)
		if err != nil {
			x.errorf("convert value error:%s", err)
		} else {
			err = retryableClient.WriteFloat64s(params.Address, f64s)
		}
	case "WriteBytes":
		err = retryableClient.WriteBytes(params.Address, []byte(params.Value))
	case "WriteRawBytes":
		err = retryableClient.WriteRawBytes(params.Address, []byte(params.Value))
	default:
		return &UnknownCommandErr{Cmd: params.Cmd}, data
	}

	return err, data
}

// getParams gets parameters
func (x *ModbusNode) getParams(ctx types.RuleContext, msg types.RuleMsg) (*Params, error) {
	var (
		err       error
		tmp       uint64
		address   uint16
		quanitity uint16
		val       string
		regType   modbus.RegType = modbus.HOLDING_REGISTER
		params                   = Params{}
	)
	evn := base.NodeUtils.GetEvnAndMetadata(ctx, msg)
	// Get address
	if strings.TrimSpace(x.addressTemplate.Execute(evn)) != "" {
		tmp, err = strconv.ParseUint(x.addressTemplate.Execute(evn), 0, 64)
		if err != nil {
			return nil, err
		}
		address = uint16(tmp)
	}
	// Get quantity
	if strings.TrimSpace(x.quantityTemplate.Execute(evn)) != "" {
		tmp, err = strconv.ParseUint(x.quantityTemplate.Execute(evn), 0, 64)
		if err != nil {
			return nil, err
		}
		quanitity = uint16(tmp)
	}

	// Get regType
	if strings.TrimSpace(x.regTypeTemplate.Execute(evn)) != "" {
		tmp, err = strconv.ParseUint(x.regTypeTemplate.Execute(evn), 0, 64)
		if err != nil {
			return nil, err
		}
		regType = modbus.RegType(tmp)
	}
	val = x.valueTemplate.Execute(evn)
	// Update parameters
	params.Cmd = x.Config.Cmd
	params.Address = address
	params.Quantity = quanitity
	params.Value = val
	params.RegType = regType

	// Validate required params: only when address template renders empty counts as unset; protocol address 0 is valid (first register in each area, e.g. holding 40001)
	if strings.TrimSpace(x.addressTemplate.Execute(evn)) == "" {
		return nil, fmt.Errorf("modbus address cannot be empty")
	}
	// Write operation requires value parameter
	if strings.HasPrefix(params.Cmd, "Write") && strings.TrimSpace(val) == "" {
		return nil, fmt.Errorf("modbus value cannot be empty for write command: %s", params.Cmd)
	}

	return &params, nil
}

// Destroy destroys component
func (x *ModbusNode) Destroy() {
	if !x.SharedNode.IsFromPool() { // Only owner cleans up operation lock
		if c, err := x.SharedNode.GetSafely(); err == nil && c != nil {
			modbusOpLocks.Delete(c)
		}
	}
	_ = x.SharedNode.Close()
}

// Desc returns the component description
func (x *ModbusNode) Desc() string {
	return "Modbus client for reading/writing registers. Supports TCP and RTU. Routes to Success/Failure"
}

// Printf prints log
// Deprecated: use debugf/infof/warnf/errorf instead
func (x *ModbusNode) Printf(format string, v ...interface{}) {
	x.infof(format, v...)
}

func (x *ModbusNode) debugf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Debugf("[Modbus] "+format, v...)
	}
}

func (x *ModbusNode) infof(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Infof("[Modbus] "+format, v...)
	}
}

func (x *ModbusNode) warnf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Warnf("[Modbus] "+format, v...)
	}
}

func (x *ModbusNode) errorf(format string, v ...interface{}) {
	if x.RuleConfig.Logger != nil {
		x.RuleConfig.Logger.Errorf("[Modbus] "+format, v...)
	}
}

// Initialize connection
func (x *ModbusNode) initClient() (*modbus.ModbusClient, error) {
	config := &modbus.ClientConfiguration{
		URL:      x.Config.Server,
		Speed:    x.Config.RtuConfig.Speed,
		DataBits: x.Config.RtuConfig.DataBits,
		StopBits: x.Config.RtuConfig.StopBits,
		Timeout:  time.Duration(x.Config.TcpConfig.Timeout) * time.Second,
		Parity:   uint(x.Config.RtuConfig.Parity),
	}
	x.debugf("Initializing Modbus connection to %s with timeout=%ds, unitId=%d",
		x.Config.Server, x.Config.TcpConfig.Timeout, x.Config.UnitId)
	// handle TLS options
	if strings.HasPrefix(x.Config.Server, "tcp+tls://") {
		clientKeyPair, err := tls.LoadX509KeyPair(x.Config.TcpConfig.CertFile, x.Config.TcpConfig.CertKeyFile)
		if err != nil {
			x.errorf("failed to load client tls key pair: %v", err)
			return nil, err
		}
		config.TLSClientCert = &clientKeyPair

		config.TLSRootCAs, err = modbus.LoadCertPool(x.Config.TcpConfig.CAFile)
		if err != nil {
			x.errorf("failed to load tls CA/server certificate: %v", err)
			return nil, err
		}
	}

	conn, err := modbus.NewClient(config)
	if err != nil {
		x.errorf("Failed to create Modbus client: %v", err)
		return nil, err
	}
	conn.SetEncoding(modbus.Endianness(x.Config.EncodingConfig.Endianness), modbus.WordOrder(x.Config.EncodingConfig.WordOrder))
	conn.SetUnitId(x.Config.UnitId)

	err = conn.Open()
	if err != nil {
		x.errorf("Failed to open Modbus connection: %v", err)
		return nil, err
	}
	x.debugf("Modbus connection established successfully to %s", x.Config.Server)
	return conn, err
}

// byteToBool converts string to bool, supports ,01,true,false
func byteToBool(data string) (bool, error) {
	switch strings.ToLower(data) {
	case "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	default:
		return false, errors.New("invalid boolean value")
	}
}

// byteToBools converts string to bool list, supports "[0,1]","[true,false]","true,false"
func byteToBools(data string) ([]bool, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	bools := make([]bool, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if b, err := byteToBool(part); err == nil {
			bools = append(bools, b)
		} else {
			return nil, err
		}
	}
	return bools, nil
}

// byteToUint64 converts string to uint64, supports "0x32","50"
func byteToUint64(data string) (uint64, error) {
	return strconv.ParseUint(data, 0, 64)
}

// byteToUint64s converts string to uint64 list, supports "[0x32,50]","[32,50]","32,50"
func byteToUint64s(data string) ([]uint64, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	u64s := make([]uint64, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if u64, err := byteToUint64(part); err == nil {
			u64s = append(u64s, u64)
		} else {
			return nil, err
		}
	}
	return u64s, nil
}

// byteToUint32 converts string to uint32, supports "0x32","50"
func byteToUint32(data string) (uint32, error) {
	if temp, err := strconv.ParseUint(data, 0, 32); err == nil {
		return uint32(temp), nil
	} else {
		return 0, err
	}
}

// byteToUint32s converts string to uint32 list, supports "[0x32,50]","[32,50]","32,50"
func byteToUint32s(data string) ([]uint32, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	u32s := make([]uint32, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if u32, err := byteToUint32(part); err == nil {
			u32s = append(u32s, u32)
		} else {
			return nil, err
		}
	}
	return u32s, nil
}

// byteToUint16 converts string to uint16, supports "0x32","50"
func byteToUint16(data string) (uint16, error) {
	if temp, err := strconv.ParseUint(data, 0, 16); err == nil {
		return uint16(temp), nil
	} else {
		return 0, err
	}
}

// byteToUint16s converts string to uint16 list, supports "[0x32,50]","[32,50]","32,50"
func byteToUint16s(data string) ([]uint16, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	u16s := make([]uint16, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if u16, err := byteToUint16(part); err == nil {
			u16s = append(u16s, u16)
		} else {
			return nil, err
		}
	}
	return u16s, nil
}

// byteToFloat32 converts string to float32
func byteToFloat32(data string) (float32, error) {
	f64, err := strconv.ParseFloat(data, 32)
	return float32(f64), err
}

// byteToFloat32s converts string to float32 list, supports "[1.2,3.4]","1.2,3.4"
func byteToFloat32s(data string) ([]float32, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	f32s := make([]float32, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if f32, err := byteToFloat32(part); err == nil {
			f32s = append(f32s, f32)
		} else {
			return nil, err
		}
	}
	return f32s, nil
}

// byteToFloat64 converts string to float64
func byteToFloat64(data string) (float64, error) {
	return strconv.ParseFloat(data, 64)
}

// byteToFloat64s converts string to float64 list, supports "[1.2,3.4]","1.2,3.4"
func byteToFloat64s(data string) ([]float64, error) {
	data = strings.Trim(data, "[]")
	parts := strings.Split(data, ",")
	f64s := make([]float64, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if f64, err := byteToFloat64(part); err == nil {
			f64s = append(f64s, f64)
		} else {
			return nil, err
		}
	}
	return f64s, nil
}
