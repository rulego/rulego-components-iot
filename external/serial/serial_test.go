package serial

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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

// serialNodeOnMsg sends one message to a node and waits for the callback.
func serialNodeOnMsg(t *testing.T, node types.Node, msg types.RuleMsg, callback func(types.RuleMsg, string, error)) {
	t.Helper()
	done := make(chan struct{}, 1)
	test.NodeOnMsg(t, node, []test.Msg{{
		DataType: msg.GetDataType(),
		MsgType:  msg.Type,
		MetaData: msg.Metadata,
		Data:     msg.GetData(),
	}}, func(outMsg types.RuleMsg, relationType string, err error) {
		callback(outMsg, relationType, err)
		done <- struct{}{}
	})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for serial node callback")
	}
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

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "Hello"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})

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

		mockPort.RxBuffer.WriteString("World\n")

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, ""), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.Equal(t, "World\n", msg.GetData())
		})
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

		mockPort.RxBuffer.WriteString("Status OK!")

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "Query"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.Equal(t, "Status OK!", msg.GetData())
		})

		assert.Equal(t, "Query?", mockPort.TxBuffer.String())
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

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "open"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})
		assert.Equal(t, false, mockPort.Closed)

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "dtr=1"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})
		assert.Equal(t, true, mockPort.DTR)

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "rts=1"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})
		assert.Equal(t, true, mockPort.RTS)

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "flush"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})
		assert.Equal(t, true, mockPort.Flushed)

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "close"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})
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

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, ""), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.Equal(t, "01020aff", msg.GetData())
		})
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

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "5175657279"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
			assert.Equal(t, "abcd", msg.GetData())
		})
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

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "01020A"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})

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

		serialNodeOnMsg(t, node, types.NewMsg(0, "TEST", types.TEXT, nil, "0102"), func(msg types.RuleMsg, relationType string, err error) {
			assert.Nil(t, err)
			assert.Equal(t, types.Success, relationType)
		})

		// Expect bytes 0x01, 0x02
		expected := []byte{0x01, 0x02}
		assert.Equal(t, expected, mockPort.TxBuffer.Bytes())
		node.Destroy()
	})
}

// TestSafeSerialPort_TransactSerializes: 并发 Transact 必须互斥执行,
// 防止半双工串口上 B 的写入落在 A 的写与读响应之间。
func TestSafeSerialPort_TransactSerializes(t *testing.T) {
	p := &SafeSerialPort{}
	var inside int32
	var maxInside int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Transact(func() error {
				cur := atomic.AddInt32(&inside, 1)
				if cur > atomic.LoadInt32(&maxInside) {
					atomic.StoreInt32(&maxInside, cur)
				}
				time.Sleep(5 * time.Millisecond)
				atomic.AddInt32(&inside, -1)
				return nil
			})
		}()
	}
	wg.Wait()
	assert.True(t, atomic.LoadInt32(&maxInside) == 1, "Transact 未互斥: 并发进入 %d 次", maxInside)
}

// TestSafeSerialPort_TransactPropagatesError: 事务内错误必须原样返回。
func TestSafeSerialPort_TransactPropagatesError(t *testing.T) {
	p := &SafeSerialPort{}
	wantErr := errors.New("boom")
	err := p.Transact(func() error { return wantErr })
	assert.True(t, err == wantErr)
	// 出错后锁必须释放,后续事务可继续
	assert.Nil(t, p.Transact(func() error { return nil }))
}
