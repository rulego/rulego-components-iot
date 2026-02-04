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
	// Register schedule endpoint
	_ "github.com/rulego/rulego/endpoint/schedule"
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

	// 2. Configure RuleGo
	config := rulego.NewConfig()
	// Enable Endpoint module to load endpoints from DSL
	config.EndpointEnabled = true

	// Use OnDebug to capture the output since we cannot attach OnEnd to DSL-defined routers directly
	config.OnDebug = func(chainId, flowType string, nodeId string, msg types.RuleMsg, relationType string, err error) {
		if err != nil {
			fmt.Printf("执行出错 (Node: %s): %v\n", nodeId, err)
			return
		}
		// Capture the output of the 'in1' node (SerialIn) when it successfully executes
		if nodeId == "in1" && flowType == types.Out {
			data := msg.GetData()
			if data != "" {
				fmt.Printf("[%s] 读取到数据: %s\n", time.Now().Format("15:04:05"), data)
			}
		}
	}

	// Use shared node pool
	pool := node_pool.NewNodePool(config)
	config.NodePool = pool

	// 1.5 Register shared serial instance to NodePool
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

	// 3. Define Rule Chain DSL with Endpoint
	chainID := "serial_schedule_chain"
	dsl := fmt.Sprintf(`{
	  "ruleChain": {
		"id": "%s",
		"name": "Serial Schedule Test",
		"root": true,
		"debugMode": true
	  },
	  "metadata": {
		"endpoints": [
		  {
			"id": "schedule_ep",
			"type": "endpoint/schedule",
			"name": "Schedule Endpoint",
			"routers": [
			  {
				"from": {
				  "path": "*/2 * * * * *"
				},
				"to": {
				  "path": "%s:in1"
				}
			  }
			]
		  }
		],
		"nodes": [
		  {
			"id": "in1",
			"type": "x/serialIn",
			"name": "Read Serial",
			"debugMode": true,
			"configuration": {
			  "port": "ref://serial_master",
			  "splitType": "timeout",
			  "splitTimeout": 100,
			  "dataType": "text"
			}
		  }
		],
		"connections": [] 
	  }
	}`, chainID, chainID)

	// 4. Initialize Engine
	// rulego.New will parse the DSL and, because EndpointEnabled is true,
	// it should automatically start the defined endpoints.
	engine, err := rulego.New(chainID, []byte(dsl), rulego.WithConfig(config))
	if err != nil {
		log.Fatalf("规则引擎初始化失败: %v", err)
	}

	// Wait for endpoint to start (it starts asynchronously)
	time.Sleep(100 * time.Millisecond)

	fmt.Println("规则引擎已启动 (Endpoint enabled)，每 2 秒读取一次串口数据...")
	fmt.Println("按 Ctrl+C 退出")

	// Block forever
	select {}

	// Keep engine alive (though select{} handles it, using engine variable avoids unused error)
	_ = engine
}
