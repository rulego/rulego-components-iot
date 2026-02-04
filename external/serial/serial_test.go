package serial

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/test"
	"github.com/rulego/rulego/test/assert"
	"go.bug.st/serial"
)

// MockSerialPort mocks the serial port
type MockSerialPort struct {
	RxBuffer *bytes.Buffer // Data ready to be Read by the node
	TxBuffer *bytes.Buffer // Data Written by the node
	DTR      bool
	RTS      bool
	Flushed  bool
	Closed   bool
}

func (m *MockSerialPort) Read(p []byte) (n int, err error) {
	if m.Closed {
		return 0, fmt.Errorf("port closed")
	}
	if m.RxBuffer.Len() == 0 {
		return 0, nil // Simulate timeout/no data
	}
	return m.RxBuffer.Read(p)
}

func (m *MockSerialPort) Write(p []byte) (n int, err error) {
	if m.Closed {
		return 0, fmt.Errorf("port closed")
	}
	return m.TxBuffer.Write(p)
}

func (m *MockSerialPort) Close() error {
	m.Closed = true
	return nil
}

func (m *MockSerialPort) SetReadTimeout(t time.Duration) error {
	return nil
}

func (m *MockSerialPort) SetDTR(dtr bool) error {
	m.DTR = dtr
	return nil
}

func (m *MockSerialPort) SetRTS(rts bool) error {
	m.RTS = rts
	return nil
}

func (m *MockSerialPort) ResetInputBuffer() error {
	m.Flushed = true
	return nil
}

func (m *MockSerialPort) ResetOutputBuffer() error {
	m.Flushed = true
	return nil
}

func TestGetPortsList(t *testing.T) {
	originalLister := portsLister
	defer func() { portsLister = originalLister }()

	portsLister = func() ([]string, error) {
		return []string{"COM1", "COM2"}, nil
	}

	list, err := GetPortsList()
	assert.Nil(t, err)
	assert.Equal(t, 2, len(list))
	assert.Equal(t, "COM1", list[0])
	assert.Equal(t, "COM2", list[1])
}

func TestSerialNodes(t *testing.T) {
	originalOpener := serialOpener
	serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
		return &MockSerialPort{
			RxBuffer: bytes.NewBuffer(nil),
			TxBuffer: bytes.NewBuffer(nil),
		}, nil
	}
	defer func() { serialOpener = originalOpener }()

	// Helper to create config map
	createConfig := func(port string) types.Configuration {
		return types.Configuration{
			"port":     port,
			"baudRate": 9600,
		}
	}

	t.Run("SerialOutNode", func(t *testing.T) {
		mockPort := &MockSerialPort{
			RxBuffer: bytes.NewBuffer(nil),
			TxBuffer: bytes.NewBuffer(nil),
		}
		serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
			return mockPort, nil
		}

		node := &SerialOutNode{}
		config := createConfig("COM_OUT")
		config["addChar"] = "\n"

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
		})

		msg := types.NewMsg(0, "TEST", types.TEXT, nil, "Hello")
		node.OnMsg(ctx, msg)

		// Check TxBuffer
		assert.Equal(t, "Hello\n", mockPort.TxBuffer.String())
		node.Destroy()
	})

	t.Run("SerialInNode", func(t *testing.T) {
		mockPort := &MockSerialPort{
			RxBuffer: bytes.NewBuffer(nil),
			TxBuffer: bytes.NewBuffer(nil),
		}
		serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
			return mockPort, nil
		}

		node := &SerialInNode{}
		config := createConfig("COM_IN")
		config["splitType"] = "char"
		config["splitKey"] = "\n"

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		// Pre-fill RxBuffer
		mockPort.RxBuffer.WriteString("World\n")

		var resultData string
		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			resultData = msg.GetData()
		})

		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, ""))
		assert.Equal(t, "World\n", resultData)
		node.Destroy()
	})

	t.Run("SerialRequestNode", func(t *testing.T) {
		mockPort := &MockSerialPort{
			RxBuffer: bytes.NewBuffer(nil),
			TxBuffer: bytes.NewBuffer(nil),
		}
		serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
			return mockPort, nil
		}

		node := &SerialRequestNode{}
		config := createConfig("COM_REQ")
		config["addChar"] = "?"
		config["splitType"] = "char"
		config["splitKey"] = "!"

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		// Prepare response in RxBuffer
		mockPort.RxBuffer.WriteString("Status OK!")

		var resultData string
		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			resultData = msg.GetData()
		})

		msg := types.NewMsg(0, "TEST", types.TEXT, nil, "Query")
		node.OnMsg(ctx, msg)

		// Check Write
		assert.Equal(t, "Query?", mockPort.TxBuffer.String())
		// Check Read Result
		assert.Equal(t, "Status OK!", resultData)
		node.Destroy()
	})

	t.Run("SerialControlNode", func(t *testing.T) {
		mockPort := &MockSerialPort{
			RxBuffer: bytes.NewBuffer(nil),
			TxBuffer: bytes.NewBuffer(nil),
		}
		serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
			return mockPort, nil
		}

		node := &SerialControlNode{}
		config := createConfig("COM_CTRL")

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
		})

		// Test "open"
		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, "open"))
		assert.Equal(t, false, mockPort.Closed)

		// Test "dtr=1"
		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, "dtr=1"))
		assert.Equal(t, true, mockPort.DTR)

		// Test "rts=1"
		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, "rts=1"))
		assert.Equal(t, true, mockPort.RTS)

		// Test "flush"
		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, "flush"))
		assert.Equal(t, true, mockPort.Flushed)

		// Test "close"
		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, "close"))
		assert.Equal(t, true, mockPort.Closed)

		node.Destroy()
	})
}

func TestSerialHexDelivery(t *testing.T) {
	// Setup Mock Opener
	mockPort := &MockSerialPort{
		RxBuffer: bytes.NewBuffer(nil),
		TxBuffer: bytes.NewBuffer(nil),
	}

	originalOpener := serialOpener
	serialOpener = func(name string, mode *serial.Mode) (ISerialPort, error) {
		return mockPort, nil
	}
	defer func() { serialOpener = originalOpener }()

	t.Run("SerialInNode_Hex", func(t *testing.T) {
		mockPort.Closed = false
		mockPort.RxBuffer.Reset()
		mockPort.TxBuffer.Reset()

		node := &SerialInNode{}
		config := types.Configuration{
			"port":     "COM_HEX",
			"dataType": "hex",
		}

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		// Prepare binary data: 0x01 0x02 0x0A 0xFF
		mockPort.RxBuffer.Write([]byte{0x01, 0x02, 0x0A, 0xFF})

		var resultData string
		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			resultData = msg.GetData()
		})

		node.OnMsg(ctx, types.NewMsg(0, "TEST", types.TEXT, nil, ""))

		// Expected: "01020aff"
		assert.Equal(t, "01020aff", resultData)
		node.Destroy()
	})

	t.Run("SerialRequestNode_Hex", func(t *testing.T) {
		mockPort.Closed = false
		mockPort.RxBuffer.Reset()
		mockPort.TxBuffer.Reset()

		node := &SerialRequestNode{}
		config := types.Configuration{
			"port":     "COM_REQ_HEX",
			"dataType": "hex",
		}

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		// Prepare response: 0xAB 0xCD
		mockPort.RxBuffer.Write([]byte{0xAB, 0xCD})

		var resultData string
		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			resultData = msg.GetData()
		})

		msg := types.NewMsg(0, "TEST", types.TEXT, nil, "5175657279") // "Query" in hex
		node.OnMsg(ctx, msg)

		assert.Equal(t, "abcd", resultData)
		node.Destroy()
	})

	t.Run("SerialOutNode_Hex", func(t *testing.T) {
		mockPort.Closed = false
		mockPort.TxBuffer.Reset()

		node := &SerialOutNode{}
		config := types.Configuration{
			"port":     "COM_OUT_HEX",
			"dataType": "hex",
		}

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
		})

		// Send hex string "01020A"
		msg := types.NewMsg(0, "TEST", types.TEXT, nil, "01020A")
		node.OnMsg(ctx, msg)

		// Expect bytes 0x01, 0x02, 0x0A
		expected := []byte{0x01, 0x02, 0x0A}
		assert.Equal(t, expected, mockPort.TxBuffer.Bytes())
		node.Destroy()
	})

	t.Run("SerialRequestNode_Hex_Input", func(t *testing.T) {
		mockPort.Closed = false
		mockPort.TxBuffer.Reset()
		mockPort.RxBuffer.Reset()

		node := &SerialRequestNode{}
		config := types.Configuration{
			"port":     "COM_REQ_HEX_IN",
			"dataType": "hex",
		}

		err := node.Init(types.NewConfig(), config)
		assert.Nil(t, err)

		// Prepare response
		mockPort.RxBuffer.WriteString("OK")

		ctx := test.NewRuleContext(types.NewConfig(), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
		})

		// Send hex string "0102"
		msg := types.NewMsg(0, "TEST", types.TEXT, nil, "0102")
		node.OnMsg(ctx, msg)

		// Expect bytes 0x01, 0x02
		expected := []byte{0x01, 0x02}
		assert.Equal(t, expected, mockPort.TxBuffer.Bytes())
		node.Destroy()
	})
}
