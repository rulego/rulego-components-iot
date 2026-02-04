package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/node_pool"

	// Register serial component
	_ "github.com/rulego/rulego-components-iot/external/serial"
	"go.bug.st/serial"
)

func main() {
	// 1. Get Serial Port
	ports, err := serial.GetPortsList()
	if err != nil || len(ports) == 0 {
		log.Fatal("未发现真实串口设备，请连接设备后重试")
	}
	portName := ports[0] // Use first available
	fmt.Printf("使用真实串口: %s\n", portName)

	config := rulego.NewConfig()
	// Use shared node pool
	pool := node_pool.NewNodePool(config)
	config.NodePool = pool

	// 1.5 Register shared serial instance to NodePool
	// Using "serial_master" as the shared ID
	masterNodeDsl := fmt.Sprintf(`{
	  "id": "serial_master",
	  "type": "x/serialIn",
	  "name": "Serial Master",
	  "configuration": {
		"port": "%s",
		"baudRate": 115200,
		"dataBits": 8,
		"stopBits": "1",
		"parity": "N"
	  }
	}`, portName)

	nodeDef, err := config.Parser.DecodeRuleNode([]byte(masterNodeDsl))
	if err != nil {
		log.Fatalf("解析 master 节点失败: %v", err)
	}
	// Add master node to pool
	_, err = pool.NewFromRuleNode(nodeDef)
	if err != nil {
		log.Fatalf("注册 master 节点到 NodePool 失败: %v", err)
	}

	// 2. Define Rule Chain DSL
	// Tests:
	// 1. Shared instance usage (ref://serial_master)
	// 2. Control (DTR)
	// 3. Write & Read (Text)
	// 4. Request (Hex output)
	// 5. Close & Auto Reconnect
	dsl := `{
	  "ruleChain": {
		"name": "Serial Ref Test"
	  },
	  "metadata": {
		"nodes": [
		  {
			"id": "c1",
			"type": "x/serialControl",
			"name": "Set DTR High",
			"configuration": {
			  "port": "ref://serial_master",
			  "action": "dtr=1"
			}
		  },
		  {
			"id": "out1",
			"type": "x/serialOut",
			"name": "Send AT Command",
			"configuration": {
			  "port": "ref://serial_master",
			  "data": "AT+VERSION?\r\n"
			}
		  },
		  {
			"id": "in1",
			"type": "x/serialIn",
			"name": "Read Response (Text)",
			"configuration": {
			  "port": "ref://serial_master",
			  "splitType": "timeout",
			  "splitTimeout": 500,
			  "dataType": "text"
			}
		  },
		  {
			"id": "log_text",
			"type": "log",
			"name": "Log Text Response",
			"configuration": {
			  "jsScript": "return 'Step 1 (Text): ' + msg;"
			}
		  },
		  {
			"id": "transform_hex",
			"type": "jsTransform",
			"name": "Prepare Hex Command",
			"configuration": {
			  "jsScript": "msg = '41540D0A'; return {'msg': msg, 'metadata': metadata, 'msgType': msgType};"
			}
		  },
		  {
			"id": "req1",
			"type": "x/serialRequest",
			"name": "Serial Request (Hex)",
			"configuration": {
			  "port": "ref://serial_master",
			  "addChar": "",
			  "splitType": "timeout",
			  "splitTimeout": 500,
			  "requestTimeout": 3000,
			  "dataType": "hex"
			}
		  },
		  {
			"id": "log_hex",
			"type": "log",
			"name": "Log Hex Response",
			"configuration": {
			  "jsScript": "return 'Step 2 (Hex): ' + msg;"
			}
		  },
		  {
			"id": "c2",
			"type": "x/serialControl",
			"name": "Close Port",
			"configuration": {
			  "port": "ref://serial_master",
			  "action": "close"
			}
		  },
		  {
			"id": "log_closed",
			"type": "log",
			"name": "Log Closed",
			"configuration": {
			  "jsScript": "return 'Step 3: Port Closed. Attempting send to trigger auto-reconnect...';"
			}
		  },
		  {
			"id": "out2",
			"type": "x/serialOut",
			"name": "Send Again (Auto Reopen)",
			"configuration": {
			  "port": "ref://serial_master",
			  "data": "AT\r\n"
			}
		  },
		  {
			"id": "log_final",
			"type": "log",
			"name": "Log Final",
			"configuration": {
			  "jsScript": "return 'Step 4: Auto-reconnect & Send Success!';"
			}
		  }
		],
		"connections": [
		  { "fromId": "c1", "toId": "out1", "type": "Success" },
		  { "fromId": "out1", "toId": "in1", "type": "Success" },
		  { "fromId": "in1", "toId": "log_text", "type": "Success" },
		  { "fromId": "log_text", "toId": "transform_hex", "type": "Success" },
		  { "fromId": "transform_hex", "toId": "req1", "type": "Success" },
		  { "fromId": "req1", "toId": "log_hex", "type": "Success" },
		  { "fromId": "log_hex", "toId": "c2", "type": "Success" },
		  { "fromId": "c2", "toId": "log_closed", "type": "Success" },
		  { "fromId": "log_closed", "toId": "out2", "type": "Success" },
		  { "fromId": "out2", "toId": "log_final", "type": "Success" }
		]
	  }
	}`

	// 3. Initialize Engine
	engine, err := rulego.New("serial_test_comp", []byte(dsl), rulego.WithConfig(config))
	if err != nil {
		log.Fatalf("规则引擎初始化失败: %v", err)
	}

	// 4. Start Test
	fmt.Println("开始执行综合读写控制测试 (Shared Instance, Auto-Reconnect, Hex/Text)...")

	meta := types.NewMetadata()
	meta.PutValue("step", "start")
	msg := types.NewMsg(0, "TEST_MSG", types.TEXT, meta, "AT+VERSION?")

	engine.OnMsg(msg, types.WithOnEnd(func(ctx types.RuleContext, msg types.RuleMsg, err error, relationType string) {
		if err != nil {
			fmt.Printf("执行过程中出错: %v\n", err)
		} else {
			fmt.Printf("测试链执行完成.\n")
		}
	}))

	// Wait for execution
	time.Sleep(5 * time.Second)
	fmt.Println("测试结束")
}
