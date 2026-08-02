package serial

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/components/base"
	"github.com/rulego/rulego/utils/el"
	"github.com/rulego/rulego/utils/maps"
	"go.bug.st/serial"
)

const (
	// DataTypeText text type
	// String type
	DataTypeText = "text"
	// DataTypeBinary binary type
	// Binary type
	DataTypeBinary = "binary"
	// DataTypeHex hex string type
	// Hex string type
	DataTypeHex = "hex"
	// DataTypeBase64 base64 string type
	// Base64 string type
	DataTypeBase64 = "base64"

	// SplitTypeChar split by char
	// Split by character
	SplitTypeChar = "char"
	// SplitTypeTimeout split by timeout
	// Split by timeout
	SplitTypeTimeout = "timeout"
	// SplitTypeFixed split by fixed length
	// Split by fixed length
	SplitTypeFixed = "fixed"

	// ParityNone no parity
	// No parity
	ParityNone = "N"
	// ParityOdd odd parity
	// Odd parity
	ParityOdd = "O"
	// ParityEven even parity
	// Even parity
	ParityEven = "E"
	// ParityMark mark parity
	// Mark parity
	ParityMark = "M"
	// ParitySpace space parity
	// Space parity
	ParitySpace = "S"

	// StopBits1 1 stop bit
	// 1 stop bit
	StopBits1 = "1"
	// StopBits1_5 1.5 stop bits
	// 1.5 stop bits
	StopBits1_5 = "1.5"
	// StopBits2 2 stop bits
	// 2 stop bits
	StopBits2 = "2"

	// ActionOpen open port
	// Open serial port
	ActionOpen = "open"
	// ActionClose close port
	// Close serial port
	ActionClose = "close"
	// ActionDTRHigh set DTR high
	// Set DTR to high level
	ActionDTRHigh = "dtr=1"
	// ActionDTRLow set DTR low
	// Set DTR to low level
	ActionDTRLow = "dtr=0"
	// ActionRTSHigh set RTS high
	// Set RTS to high level
	ActionRTSHigh = "rts=1"
	// ActionRTSLow set RTS low
	// Set RTS to low level
	ActionRTSLow = "rts=0"
	// ActionFlush flush both buffers
	// Flush input and output buffers
	ActionFlush = "flush"
	// ActionFlushIn flush input buffer
	// Flush input buffer
	ActionFlushIn = "flush_in"
	// ActionFlushOut flush output buffer
	// Flush output buffer
	ActionFlushOut = "flush_out"
)

// Register nodes
func init() {
	_ = rulego.Registry.Register(&SerialInNode{})
	_ = rulego.Registry.Register(&SerialOutNode{})
	_ = rulego.Registry.Register(&SerialRequestNode{})
	_ = rulego.Registry.Register(&SerialControlNode{})
}

// ISerialPort Serial port interface, convenient for test Mock
// ISerialPort defines the serial port interface for easy test mocking
type ISerialPort interface {
	io.ReadWriteCloser
	SetReadTimeout(t time.Duration) error
	SetDTR(dtr bool) error
	SetRTS(rts bool) error
	ResetInputBuffer() error
	ResetOutputBuffer() error
}

// SharedSerialConfig Shared serial connection configuration
// SharedSerialConfig is the shared serial port connection configuration
type SharedSerialConfig struct {
	Port     string `json:"port" label:"Port" desc:"Serial port name, e.g. COM1, /dev/ttyUSB0" required:"true" ref:"primary"`
	BaudRate int    `json:"baudRate" label:"Baud Rate" desc:"Serial baud rate, e.g. 9600, 115200"`
	DataBits int    `json:"dataBits" label:"Data Bits" desc:"Data bits per character: 5, 6, 7, 8"`
	StopBits string `json:"stopBits" label:"Stop Bits" desc:"Stop bits: 1, 1.5, 2"`
	Parity   string `json:"parity" label:"Parity" desc:"Parity: N=None, O=Odd, E=Even, M=Mark, S=Space"`
	DTR      bool   `json:"dtr" label:"DTR" desc:"Data Terminal Ready signal"`
	RTS      bool   `json:"rts" label:"RTS" desc:"Request To Send signal"`
}

// ReadConfig Read configuration
// ReadConfig reads configuration
type ReadConfig struct {
	StartChar    string `json:"startChar" label:"Start Char" desc:"Optional start character"`
	SplitType    string `json:"splitType" label:"Split Type" desc:"Split mode: char, timeout, fixed"`
	SplitKey     string `json:"splitKey" label:"Split Key" desc:"Split char (e.g. \\n) or length"`
	SplitTimeout int64  `json:"splitTimeout" label:"Split Timeout" desc:"Read split timeout in ms"`
	DataType     string `json:"dataType" label:"Data Type" desc:"Output data type: text, binary, hex, base64"`
}

// SerialInConfig Serial input node configuration
// SerialInConfig is the configuration for the serial port read node
type SerialInConfig struct {
	SharedSerialConfig `json:",squash"`
	ReadConfig         `json:",squash"`
}

// SerialOutConfig Serial output node configuration
// SerialOutConfig is the configuration for the serial port write node
type SerialOutConfig struct {
	SharedSerialConfig `json:",squash"`
	// Data content to send, supports dynamic variable replacement (e.g. ${data}). If empty, use msg.Data
	// Data is the content to send, supports dynamic variable replacement (e.g., ${data}). If empty, uses msg.Data
	Data string `json:"data" label:"Data" desc:"Data to send, supports ${xx} variables, empty uses msg.Data"`
	// (e.g. \r\n)
	AddChar  string `json:"addChar" label:"Add Char" desc:"Character appended when sending, e.g. \\r\\n"`
	DataType string `json:"dataType" label:"Data Type" desc:"Data type: text, hex, base64"`
}

// SerialRequestConfig Serial request node configuration
// SerialRequestConfig is the configuration for the serial port request node
type SerialRequestConfig struct {
	SharedSerialConfig `json:",squash"`
	// Data content to send, supports dynamic variable replacement (e.g. ${data}). If empty, use msg.Data
	// Data is the content to send, supports dynamic variable replacement (e.g., ${data}). If empty, uses msg.Data
	Data string `json:"data" label:"Data" desc:"Data to send, supports ${xx} variables, empty uses msg.Data"`
	// Output settings
	// (e.g. \r\n)
	AddChar  string `json:"addChar" label:"Add Char" desc:"Character appended when sending, e.g. \\r\\n"`
	DataType string `json:"dataType" label:"Data Type" desc:"Data type: text, hex, base64"`
	// Input settings for response
	ReadConfig `json:",squash"`
	// Request specific
	RequestTimeout int64 `json:"requestTimeout" label:"Request Timeout" desc:"Request total timeout in ms"`
}

// SerialControlConfig Serial control node configuration
// SerialControlConfig is the configuration for the serial port control node
type SerialControlConfig struct {
	SharedSerialConfig `json:",squash"`
	// Action Control instruction, supports dynamic variable replacement (e.g. ${msg.action}). If empty, use msg.Data as instruction
	// Action is the control command, supports dynamic variable replacement (e.g., ${msg.action}). If empty, uses msg.Data as the command
	Action string `json:"action" label:"Action" desc:"Control action, supports ${xx} variables, e.g. open, close, dtr=1"`
}

// SafeSerialPort Thread-safe serial port wrapper
// SafeSerialPort is a thread-safe serial port wrapper
type SafeSerialPort struct {
	Port   ISerialPort
	Config SharedSerialConfig
	isOpen bool
	sync.Mutex
}

// Write writes data to the serial port.
// Write writes data to the serial port.
func (s *SafeSerialPort) Write(b []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			return 0, err
		}
	}
	n, err = s.Port.Write(b)
	if err != nil {
		// Close port on error to allow reopen
		_ = s.Port.Close()
		s.Port = nil
		s.isOpen = false
	}
	return n, err
}

// Read reads data from the serial port.
// Read reads data from the serial port.
func (s *SafeSerialPort) Read(b []byte) (n int, err error) {
	s.Lock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			s.Unlock()
			return 0, err
		}
	}
	// Capture the port under the lock: s.Port may be set to nil by another goroutine
	// (Close or error cleanup) while Read blocks unlocked.
	port := s.Port
	s.Unlock()
	n, err = port.Read(b)
	if err != nil {
		// Close port on error to allow reopen, but only if it is still the same instance.
		s.Lock()
		if s.isOpen && s.Port == port {
			_ = s.Port.Close()
			s.Port = nil
			s.isOpen = false
		}
		s.Unlock()
	}
	return n, err
}

// Close closes the serial port.
// Close closes the serial port.
func (s *SafeSerialPort) Close() error {
	s.Lock()
	defer s.Unlock()
	if s.Port != nil {
		err := s.Port.Close()
		s.Port = nil
		s.isOpen = false
		return err
	}
	return nil
}

// SetDTR sets the modem control signal DTR.
func (s *SafeSerialPort) SetDTR(dtr bool) error {
	s.Lock()
	defer s.Unlock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			return err
		}
	}
	err := s.Port.SetDTR(dtr)
	if err != nil {
		_ = s.Port.Close()
		s.Port = nil
		s.isOpen = false
	}
	return err
}

// SetRTS sets the modem control signal RTS.
func (s *SafeSerialPort) SetRTS(rts bool) error {
	s.Lock()
	defer s.Unlock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			return err
		}
	}
	err := s.Port.SetRTS(rts)
	if err != nil {
		_ = s.Port.Close()
		s.Port = nil
		s.isOpen = false
	}
	return err
}

// SetReadTimeout sets the read timeout.
func (s *SafeSerialPort) SetReadTimeout(t time.Duration) error {
	s.Lock()
	defer s.Unlock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			return err
		}
	}
	err := s.Port.SetReadTimeout(t)
	if err != nil {
		_ = s.Port.Close()
		s.Port = nil
		s.isOpen = false
	}
	return err
}

// ResetInputBuffer resets the input buffer.
func (s *SafeSerialPort) ResetInputBuffer() error {
	s.Lock()
	defer s.Unlock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			return err
		}
	}
	err := s.Port.ResetInputBuffer()
	if err != nil {
		_ = s.Port.Close()
		s.Port = nil
		s.isOpen = false
	}
	return err
}

// ResetOutputBuffer resets the output buffer.
func (s *SafeSerialPort) ResetOutputBuffer() error {
	s.Lock()
	defer s.Unlock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			return err
		}
	}
	err := s.Port.ResetOutputBuffer()
	if err != nil {
		_ = s.Port.Close()
		s.Port = nil
		s.isOpen = false
	}
	return err
}

func (s *SafeSerialPort) reopen() error {
	mode := &serial.Mode{
		BaudRate: s.Config.BaudRate,
		DataBits: s.Config.DataBits,
	}

	switch s.Config.Parity {
	case ParityOdd:
		mode.Parity = serial.OddParity
	case ParityEven:
		mode.Parity = serial.EvenParity
	case ParityMark:
		mode.Parity = serial.MarkParity
	case ParitySpace:
		mode.Parity = serial.SpaceParity
	default:
		mode.Parity = serial.NoParity
	}

	switch s.Config.StopBits {
	case StopBits1_5:
		mode.StopBits = serial.OnePointFiveStopBits
	case StopBits2:
		mode.StopBits = serial.TwoStopBits
	default:
		mode.StopBits = serial.OneStopBit
	}

	port, err := serialOpener(s.Config.Port, mode)
	if err != nil {
		return err
	}

	// Handle DTR/RTS control
	if err := port.SetDTR(s.Config.DTR); err != nil {
		_ = port.Close()
		return err
	}
	if err := port.SetRTS(s.Config.RTS); err != nil {
		_ = port.Close()
		return err
	}

	s.Port = port
	s.isOpen = true
	return nil
}

// Allow test coverage
// Allows test override
var serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
	return serial.Open(name, mode)
}

// SetSerialOpener sets the serial port opener function.
// SetSerialOpener sets the serial port opening function.
func SetSerialOpener(opener func(name string, mode *serial.Mode) (ISerialPort, error)) {
	serialOpener = opener
}

// Allow test coverage
// Allows test override
var portsLister = func() ([]string, error) {
	return serial.GetPortsList()
}

// SetPortsLister sets the serial ports lister function.
// SetPortsLister sets the serial port list retrieval function.
func SetPortsLister(lister func() ([]string, error)) {
	portsLister = lister
}

// GetPortsList Get list of all available serial ports in the system
// GetPortsList gets all available serial ports in the system
func GetPortsList() ([]string, error) {
	return portsLister()
}

// baseSerialNode Base serial node
// baseSerialNode is the base serial port node
type baseSerialNode struct {
	base.SharedNode[*SafeSerialPort]
	Config SharedSerialConfig
}

func (x *baseSerialNode) initClient(config SharedSerialConfig) (*SafeSerialPort, error) {
	client := &SafeSerialPort{Config: config}
	err := client.reopen()
	if err != nil {
		return nil, err
	}
	return client, nil
}

// ------------------------------------------------------------------------------------------------
// SerialInNode
// ------------------------------------------------------------------------------------------------

type SerialInNode struct {
	baseSerialNode
	Config SerialInConfig
}

// Type returns the node type.
// Type returns the node type.
func (x *SerialInNode) Type() string {
	return "x/serialIn"
}

// New creates a new instance of SerialInNode.
// New creates a new instance of SerialInNode.
func (x *SerialInNode) New() types.Node {
	return &SerialInNode{
		Config: SerialInConfig{
			SharedSerialConfig: SharedSerialConfig{
				BaudRate: 115200, DataBits: 8, StopBits: StopBits1, Parity: ParityNone, DTR: true, RTS: false,
			},
			ReadConfig: ReadConfig{
				SplitType: SplitTypeTimeout, SplitTimeout: 100, DataType: DataTypeText,
			},
		},
	}
}

// Init initializes the node with the provided configuration.
// Init initializes the node with the provided configuration.
func (x *SerialInNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	if err == nil {
		err = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Port, ruleConfig.NodeClientInitNow, func() (*SafeSerialPort, error) {
			return x.initClient(x.Config.SharedSerialConfig)
		}, func(client *SafeSerialPort) error {
			if client != nil {
				return client.Close()
			}
			return nil
		})
	}
	return err
}

// OnMsg handles the incoming message and reads data from the serial port.
// OnMsg processes the input message and reads data from the serial port.
func (x *SerialInNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	data, err := readData(client, x.Config.ReadConfig)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	if len(data) > 0 {
		dataType := x.Config.DataType
		if dataType == DataTypeBinary {
			msg.SetDataType(types.BINARY)
			msg.SetBytes(data)
		} else if dataType == DataTypeHex {
			msg.SetDataType(types.TEXT)
			msg.SetData(hex.EncodeToString(data))
		} else if dataType == DataTypeBase64 {
			msg.SetDataType(types.TEXT)
			msg.SetData(base64.StdEncoding.EncodeToString(data))
		} else {
			msg.SetDataType(types.TEXT)
			msg.SetData(string(data))
		}
		ctx.TellSuccess(msg)
	} else {
		// No data read
		ctx.TellSuccess(msg)
	}
}

// Destroy cleans up the node resources.
// Destroy cleans up node resources.
func (x *SerialInNode) Destroy() {
	_ = x.SharedNode.Close()
}

// ------------------------------------------------------------------------------------------------
// SerialOutNode
// ------------------------------------------------------------------------------------------------

type SerialOutNode struct {
	baseSerialNode
	Config       SerialOutConfig
	dataTemplate el.Template
}

// Type returns the node type.
// Type returns the node type.
func (x *SerialOutNode) Type() string {
	return "x/serialOut"
}

// New creates a new instance of SerialOutNode.
// New creates a new instance of SerialOutNode.
func (x *SerialOutNode) New() types.Node {
	return &SerialOutNode{
		Config: SerialOutConfig{
			SharedSerialConfig: SharedSerialConfig{
				BaudRate: 115200, DataBits: 8, StopBits: StopBits1, Parity: ParityNone, DTR: true, RTS: false,
			},
			DataType: DataTypeText,
			AddChar:  "\r\n",
		},
	}
}

// Init initializes the node with the provided configuration.
// Init initializes the node with the provided configuration.
func (x *SerialOutNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	if err == nil {
		err = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Port, ruleConfig.NodeClientInitNow, func() (*SafeSerialPort, error) {
			return x.initClient(x.Config.SharedSerialConfig)
		}, func(client *SafeSerialPort) error {
			if client != nil {
				return client.Close()
			}
			return nil
		})
	}
	if err != nil {
		return err
	}
	// Initialize data template
	if x.Config.Data != "" {
		x.dataTemplate, err = el.NewTemplate(x.Config.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

// OnMsg handles the incoming message and writes data to the serial port.
// OnMsg processes the input message and writes data to the serial port.
func (x *SerialOutNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	var data []byte
	if x.dataTemplate != nil {
		data = []byte(x.dataTemplate.ExecuteAsString(ctx.GetEnv(msg, true)))
	} else {
		data = msg.GetBytes()
	}

	if x.Config.DataType == DataTypeHex {
		decoded, err := hex.DecodeString(string(data))
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
		data = decoded
	} else if x.Config.DataType == DataTypeBase64 {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
		data = decoded
	}

	if x.Config.AddChar != "" {
		data = append(data, []byte(x.Config.AddChar)...)
	}

	if len(data) > 0 {
		_, err = client.Write(data)
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
	}
	ctx.TellSuccess(msg)
}

// Destroy cleans up the node resources.
// Destroy cleans up node resources.
func (x *SerialOutNode) Destroy() {
	_ = x.SharedNode.Close()
}

// ------------------------------------------------------------------------------------------------
// SerialRequestNode
// ------------------------------------------------------------------------------------------------

type SerialRequestNode struct {
	baseSerialNode
	Config       SerialRequestConfig
	dataTemplate el.Template
}

// Type returns the node type.
// Type returns the node type.
func (x *SerialRequestNode) Type() string {
	return "x/serialRequest"
}

// New creates a new instance of SerialRequestNode.
// New creates a new instance of SerialRequestNode.
func (x *SerialRequestNode) New() types.Node {
	return &SerialRequestNode{
		Config: SerialRequestConfig{
			SharedSerialConfig: SharedSerialConfig{
				BaudRate: 115200, DataBits: 8, StopBits: StopBits1, Parity: ParityNone, DTR: true, RTS: false,
			},
			ReadConfig: ReadConfig{
				SplitType: SplitTypeTimeout, SplitTimeout: 100, DataType: DataTypeText,
			},
			DataType:       DataTypeText,
			RequestTimeout: 10000,
		},
	}
}

// Init initializes the node with the provided configuration.
// Init initializes the node with the provided configuration.
func (x *SerialRequestNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	if err == nil {
		err = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Port, ruleConfig.NodeClientInitNow, func() (*SafeSerialPort, error) {
			return x.initClient(x.Config.SharedSerialConfig)
		}, func(client *SafeSerialPort) error {
			if client != nil {
				return client.Close()
			}
			return nil
		})
	}
	if err != nil {
		return err
	}
	// Initialize data template
	if x.Config.Data != "" {
		x.dataTemplate, err = el.NewTemplate(x.Config.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

// OnMsg handles the incoming message, writes to serial port and waits for response.
// OnMsg processes the input message, writes to the serial port and waits for response.
func (x *SerialRequestNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	// Write data
	var data []byte
	if x.dataTemplate != nil {
		data = []byte(x.dataTemplate.ExecuteAsString(ctx.GetEnv(msg, false)))
	} else {
		data = msg.GetBytes()
	}

	if x.Config.DataType == DataTypeHex {
		decoded, err := hex.DecodeString(string(data))
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
		data = decoded
	} else if x.Config.DataType == DataTypeBase64 {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
		data = decoded
	}

	if x.Config.AddChar != "" {
		data = append(data, []byte(x.Config.AddChar)...)
	}
	if len(data) > 0 {
		_, err = client.Write(data)
		if err != nil {
			ctx.TellFailure(msg, err)
			return
		}
	}

	// Read with total timeout
	respData, err := readData(client, x.Config.ReadConfig)
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	dataType := x.Config.ReadConfig.DataType
	if dataType == DataTypeBinary {
		msg.DataType = types.BINARY
		msg.SetBytes(respData)
	} else if dataType == DataTypeHex {
		msg.DataType = types.TEXT
		msg.SetData(hex.EncodeToString(respData))
	} else if dataType == DataTypeBase64 {
		msg.DataType = types.TEXT
		msg.SetData(base64.StdEncoding.EncodeToString(respData))
	} else {
		msg.DataType = types.TEXT
		msg.SetData(string(respData))
	}
	ctx.TellSuccess(msg)
}

// Destroy cleans up the node resources.
// Destroy cleans up node resources.
func (x *SerialRequestNode) Destroy() {
	_ = x.SharedNode.Close()
}

// ------------------------------------------------------------------------------------------------
// SerialControlNode
// ------------------------------------------------------------------------------------------------

type SerialControlNode struct {
	baseSerialNode
	Config         SerialControlConfig
	actionTemplate el.Template
}

// Type returns the node type.
// Type returns the node type.
func (x *SerialControlNode) Type() string {
	return "x/serialControl"
}

// New creates a new instance of SerialControlNode.
// New creates a new instance of SerialControlNode.
func (x *SerialControlNode) New() types.Node {
	return &SerialControlNode{
		Config: SerialControlConfig{
			SharedSerialConfig: SharedSerialConfig{
				BaudRate: 115200, DataBits: 8, StopBits: StopBits1, Parity: ParityNone, DTR: true, RTS: false,
			},
			Action: ActionClose,
		},
	}
}

// Init initializes the node with the provided configuration.
// Init initializes the node with the provided configuration.
func (x *SerialControlNode) Init(ruleConfig types.Config, configuration types.Configuration) error {
	err := maps.Map2Struct(configuration, &x.Config)
	if err == nil {
		err = x.SharedNode.InitWithClose(ruleConfig, x.Type(), x.Config.Port, ruleConfig.NodeClientInitNow, func() (*SafeSerialPort, error) {
			return x.initClient(x.Config.SharedSerialConfig)
		}, func(client *SafeSerialPort) error {
			if client != nil {
				return client.Close()
			}
			return nil
		})
	}
	if err != nil {
		return err
	}
	// Initialize action template
	if x.Config.Action != "" {
		x.actionTemplate, err = el.NewTemplate(x.Config.Action)
		if err != nil {
			return err
		}
	}
	return nil
}

// OnMsg handles the incoming message and controls the serial port.
// OnMsg processes the input message and controls the serial port.
func (x *SerialControlNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	var action string
	if x.actionTemplate != nil {
		// Use configured action expression
		action = x.actionTemplate.ExecuteAsString(ctx.GetEnv(msg, true))
	} else {
		action = msg.GetData()
	}

	switch strings.ToLower(action) {
	case ActionOpen:
		// SafeSerialPort will reopen if needed when calling any operation.
		// For ActionOpen, we can just trigger a DTR set or similar to ensure it's open.
		_ = client.SetDTR(x.Config.DTR)
	case ActionClose:
		_ = client.Close()
	case ActionDTRHigh:
		_ = client.SetDTR(true)
	case ActionDTRLow:
		_ = client.SetDTR(false)
	case ActionRTSHigh:
		_ = client.SetRTS(true)
	case ActionRTSLow:
		_ = client.SetRTS(false)
	case ActionFlush:
		_ = client.ResetInputBuffer()
		_ = client.ResetOutputBuffer()
	case ActionFlushIn:
		_ = client.ResetInputBuffer()
	case ActionFlushOut:
		_ = client.ResetOutputBuffer()
	}
	ctx.TellSuccess(msg)
}

// Destroy cleans up the node resources.
// Destroy cleans up node resources.
func (x *SerialControlNode) Destroy() {
	_ = x.SharedNode.Close()
}

// ------------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------------

// readData reads data from the serial port based on the provided configuration.
// readData reads data from the serial port according to the provided configuration.
func readData(port io.Reader, config ReadConfig) ([]byte, error) {
	// Set initial read timeout
	if p, ok := port.(ISerialPort); ok {
		timeout := config.SplitTimeout
		if timeout <= 0 {
			timeout = 10
		}
		_ = p.SetReadTimeout(time.Duration(timeout) * time.Millisecond)
	}

	var buf bytes.Buffer
	// Use a small buffer for reading to control granularity, especially for StartChar and SplitTypeChar
	temp := make([]byte, 128)

	// 1. Start Char Logic
	if config.StartChar != "" {
		startBytes := []byte(config.StartChar)
		if len(startBytes) > 0 {
			matched := 0
			// Read byte by byte until match
			for {
				n, err := port.Read(temp[:1])
				if err != nil {
					return nil, err
				}
				if n == 0 {
					return nil, nil // Timeout before start char found
				}
				if temp[0] == startBytes[matched] {
					matched++
					if matched == len(startBytes) {
						break // Found start sequence
					}
				} else {
					matched = 0
					// Check if the current char starts the sequence again
					if temp[0] == startBytes[0] {
						matched = 1
					}
				}
			}
		}
	}

	// 2. Read Loop based on SplitType
	switch config.SplitType {
	case SplitTypeFixed:
		// Read specific length
		length, _ := strconv.Atoi(config.SplitKey)
		if length <= 0 {
			length = 1
		}
		result := make([]byte, length)
		totalRead := 0
		for totalRead < length {
			readLen := min(len(temp), length-totalRead)
			n, err := port.Read(temp[:readLen])
			if err != nil {
				return result[:totalRead], err
			}
			if n == 0 {
				break // Timeout
			}
			copy(result[totalRead:], temp[:n])
			totalRead += n
		}
		return result[:totalRead], nil

	case SplitTypeChar:
		// Read until delimiter
		splitKey := config.SplitKey
		if splitKey == "" {
			splitKey = "\n"
		}
		splitBytes := []byte(splitKey)

		for {
			n, err := port.Read(temp[:1])
			if err != nil {
				return buf.Bytes(), err
			}
			if n == 0 {
				break // Timeout
			}
			buf.WriteByte(temp[0])

			if bytes.HasSuffix(buf.Bytes(), splitBytes) {
				return buf.Bytes(), nil
			}
		}
		return buf.Bytes(), nil

	default:
		// SplitTypeTimeout (Default): Read until silence/timeout
		for {
			n, err := port.Read(temp)
			if err != nil {
				return buf.Bytes(), err
			}
			if n == 0 {
				break // Timeout reached
			}
			buf.Write(temp[:n])
		}
		return buf.Bytes(), nil
	}
}

// min returns the minimum of two integers.
// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
