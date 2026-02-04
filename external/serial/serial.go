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
	// 字符串类型
	DataTypeText = "text"
	// DataTypeBinary binary type
	// 二进制类型
	DataTypeBinary = "binary"
	// DataTypeHex hex string type
	// 十六进制字符串类型
	DataTypeHex = "hex"
	// DataTypeBase64 base64 string type
	// base64字符串类型
	DataTypeBase64 = "base64"

	// SplitTypeChar split by char
	// 按字符拆分
	SplitTypeChar = "char"
	// SplitTypeTimeout split by timeout
	// 按超时拆分
	SplitTypeTimeout = "timeout"
	// SplitTypeFixed split by fixed length
	// 按固定长度拆分
	SplitTypeFixed = "fixed"

	// ParityNone no parity
	// 无校验
	ParityNone = "N"
	// ParityOdd odd parity
	// 奇校验
	ParityOdd = "O"
	// ParityEven even parity
	// 偶校验
	ParityEven = "E"
	// ParityMark mark parity
	// 标志校验
	ParityMark = "M"
	// ParitySpace space parity
	// 空格校验
	ParitySpace = "S"

	// StopBits1 1 stop bit
	// 1位停止位
	StopBits1 = "1"
	// StopBits1_5 1.5 stop bits
	// 1.5位停止位
	StopBits1_5 = "1.5"
	// StopBits2 2 stop bits
	// 2位停止位
	StopBits2 = "2"

	// ActionOpen open port
	// 打开串口
	ActionOpen = "open"
	// ActionClose close port
	// 关闭串口
	ActionClose = "close"
	// ActionDTRHigh set DTR high
	// 设置 DTR 为高电平
	ActionDTRHigh = "dtr=1"
	// ActionDTRLow set DTR low
	// 设置 DTR 为低电平
	ActionDTRLow = "dtr=0"
	// ActionRTSHigh set RTS high
	// 设置 RTS 为高电平
	ActionRTSHigh = "rts=1"
	// ActionRTSLow set RTS low
	// 设置 RTS 为低电平
	ActionRTSLow = "rts=0"
	// ActionFlush flush both buffers
	// 刷新输入输出缓冲区
	ActionFlush = "flush"
	// ActionFlushIn flush input buffer
	// 刷新输入缓冲区
	ActionFlushIn = "flush_in"
	// ActionFlushOut flush output buffer
	// 刷新输出缓冲区
	ActionFlushOut = "flush_out"
)

// 注册节点
func init() {
	_ = rulego.Registry.Register(&SerialInNode{})
	_ = rulego.Registry.Register(&SerialOutNode{})
	_ = rulego.Registry.Register(&SerialRequestNode{})
	_ = rulego.Registry.Register(&SerialControlNode{})
}

// ISerialPort Serial port interface, convenient for test Mock
// ISerialPort 定义串口接口，方便测试Mock
type ISerialPort interface {
	io.ReadWriteCloser
	SetReadTimeout(t time.Duration) error
	SetDTR(dtr bool) error
	SetRTS(rts bool) error
	ResetInputBuffer() error
	ResetOutputBuffer() error
}

// SharedSerialConfig Shared serial connection configuration
// SharedSerialConfig 共享的串口连接配置
type SharedSerialConfig struct {
	Port     string `json:"port"`
	BaudRate int    `json:"baudRate"`
	DataBits int    `json:"dataBits"`
	StopBits string `json:"stopBits"` // "1", "1.5", "2"
	Parity   string `json:"parity"`   // "N", "O", "E", "M", "S"
	DTR      bool   `json:"dtr"`      // true, false
	RTS      bool   `json:"rts"`      // true, false
}

// ReadConfig Read configuration
// ReadConfig 读取配置
type ReadConfig struct {
	StartChar    string `json:"startChar"`    // Optional: start character. 可选：起始字符
	SplitType    string `json:"splitType"`    // "char", "timeout", "fixed"
	SplitKey     string `json:"splitKey"`     // Split char (e.g. \n) or length. 拆分字符(如\n) 或 长度
	SplitTimeout int64  `json:"splitTimeout"` // Read split timeout (ms). 读取分段超时(ms)
	DataType     string `json:"dataType"`     // "text", "binary", "hex", "base64"
}

// SerialInConfig Serial input node configuration
// SerialInConfig 串口读取节点配置
type SerialInConfig struct {
	SharedSerialConfig `json:",squash"`
	ReadConfig         `json:",squash"`
}

// SerialOutConfig Serial output node configuration
// SerialOutConfig 串口写入节点配置
type SerialOutConfig struct {
	SharedSerialConfig `json:",squash"`
	// Data content to send, supports dynamic variable replacement (e.g. ${data}). If empty, use msg.Data
	// Data 发送内容，支持动态变量替换（如 ${data}）。如果为空，则使用 msg.Data
	Data string `json:"data"`
	// (e.g. \r\n)
	AddChar  string `json:"addChar"`  // Character appended when sending. 发送时追加的字符
	DataType string `json:"dataType"` // "text", "hex", "base64"
}

// SerialRequestConfig Serial request node configuration
// SerialRequestConfig 串口请求节点配置
type SerialRequestConfig struct {
	SharedSerialConfig `json:",squash"`
	// Data content to send, supports dynamic variable replacement (e.g. ${data}). If empty, use msg.Data
	// Data 发送内容，支持动态变量替换（如 ${data}）。如果为空，则使用 msg.Data
	Data string `json:"data"`
	// Output settings
	// (e.g. \r\n)
	AddChar  string `json:"addChar"`
	DataType string `json:"dataType"` // "text", "hex", "base64"
	// Input settings for response
	ReadConfig `json:",squash"`
	// Request specific
	RequestTimeout int64 `json:"requestTimeout"` // Request total timeout (ms). 请求总超时时间(ms)
}

// SerialControlConfig Serial control node configuration
// SerialControlConfig 串口控制节点配置
type SerialControlConfig struct {
	SharedSerialConfig `json:",squash"`
	// Action Control instruction, supports dynamic variable replacement (e.g. ${msg.action}). If empty, use msg.Data as instruction
	// Action 控制指令，支持动态变量替换（如 ${msg.action}）。如果为空，则使用 msg.Data 作为指令
	Action string `json:"action"`
}

// SafeSerialPort Thread-safe serial port wrapper
// SafeSerialPort 线程安全的串口封装
type SafeSerialPort struct {
	Port   ISerialPort
	Config SharedSerialConfig
	isOpen bool
	sync.Mutex
}

// Write writes data to the serial port.
// Write 向串口写入数据。
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
// Read 从串口读取数据。
func (s *SafeSerialPort) Read(b []byte) (n int, err error) {
	s.Lock()
	if !s.isOpen || s.Port == nil {
		if err := s.reopen(); err != nil {
			s.Unlock()
			return 0, err
		}
	}
	s.Unlock()
	n, err = s.Port.Read(b)
	if err != nil {
		// Close port on error to allow reopen
		s.Lock()
		if s.isOpen {
			if s.Port != nil {
				_ = s.Port.Close()
				s.Port = nil
			}
			s.isOpen = false
		}
		s.Unlock()
	}
	return n, err
}

// Close closes the serial port.
// Close 关闭串口。
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

	// Handle DTR/RTS / 处理 DTR/RTS
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
// 允许测试覆盖
var serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
	return serial.Open(name, mode)
}

// SetSerialOpener sets the serial port opener function.
// SetSerialOpener 设置串口打开函数。
func SetSerialOpener(opener func(name string, mode *serial.Mode) (ISerialPort, error)) {
	serialOpener = opener
}

// Allow test coverage
// 允许测试覆盖
var portsLister = func() ([]string, error) {
	return serial.GetPortsList()
}

// SetPortsLister sets the serial ports lister function.
// SetPortsLister 设置串口列表获取函数。
func SetPortsLister(lister func() ([]string, error)) {
	portsLister = lister
}

// GetPortsList Get list of all available serial ports in the system
// GetPortsList 获取系统中所有可用的串口列表
func GetPortsList() ([]string, error) {
	return portsLister()
}

// baseSerialNode Base serial node
// baseSerialNode 基础串口节点
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
// Type 返回节点类型。
func (x *SerialInNode) Type() string {
	return "x/serialIn"
}

// New creates a new instance of SerialInNode.
// New 创建 SerialInNode 的新实例。
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
// Init 使用提供的配置初始化节点。
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
// OnMsg 处理输入消息并从串口读取数据。
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
		// No data read / 未读取到数据
		ctx.TellSuccess(msg)
	}
}

// Destroy cleans up the node resources.
// Destroy 清理节点资源。
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
// Type 返回节点类型。
func (x *SerialOutNode) Type() string {
	return "x/serialOut"
}

// New creates a new instance of SerialOutNode.
// New 创建 SerialOutNode 的新实例。
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
// Init 使用提供的配置初始化节点。
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
	// Initialize data template / 初始化 data 模板
	if x.Config.Data != "" {
		x.dataTemplate, err = el.NewTemplate(x.Config.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

// OnMsg handles the incoming message and writes data to the serial port.
// OnMsg 处理输入消息并向串口写入数据。
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
// Destroy 清理节点资源。
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
// Type 返回节点类型。
func (x *SerialRequestNode) Type() string {
	return "x/serialRequest"
}

// New creates a new instance of SerialRequestNode.
// New 创建 SerialRequestNode 的新实例。
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
// Init 使用提供的配置初始化节点。
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
	// Initialize data template / 初始化 data 模板
	if x.Config.Data != "" {
		x.dataTemplate, err = el.NewTemplate(x.Config.Data)
		if err != nil {
			return err
		}
	}
	return nil
}

// OnMsg handles the incoming message, writes to serial port and waits for response.
// OnMsg 处理输入消息，向串口写入并等待响应。
func (x *SerialRequestNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	// Write / 写入
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
// Destroy 清理节点资源。
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
// Type 返回节点类型。
func (x *SerialControlNode) Type() string {
	return "x/serialControl"
}

// New creates a new instance of SerialControlNode.
// New 创建 SerialControlNode 的新实例。
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
// Init 使用提供的配置初始化节点。
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
	// Initialize action template / 初始化 action 模板
	if x.Config.Action != "" {
		x.actionTemplate, err = el.NewTemplate(x.Config.Action)
		if err != nil {
			return err
		}
	}
	return nil
}

// OnMsg handles the incoming message and controls the serial port.
// OnMsg 处理输入消息并控制串口。
func (x *SerialControlNode) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	client, err := x.SharedNode.GetSafely()
	if err != nil {
		ctx.TellFailure(msg, err)
		return
	}

	var action string
	if x.actionTemplate != nil {
		// Use configured action expression / 使用配置的 action 表达式
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
// Destroy 清理节点资源。
func (x *SerialControlNode) Destroy() {
	_ = x.SharedNode.Close()
}

// ------------------------------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------------------------------

// readData reads data from the serial port based on the provided configuration.
// readData 根据提供的配置从串口读取数据。
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
// min 返回两个整数中的较小值。
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
