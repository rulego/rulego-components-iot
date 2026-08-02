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
		log.Fatal("No real serial device found, please connect device and retry")
	}
	portName := ports[0] // Use first available
	fmt.Printf("Using real serial port: %s\n", portName)

	// 2. Configure RuleGo
	config := rulego.NewConfig()
	// Enable Endpoint module to load endpoints from DSL
	config.EndpointEnabled = true

	// Use OnDebug to capture the output since we cannot attach OnEnd to DSL-defined routers directly
	config.OnDebug = func(chainId, flowType string, nodeId string, msg types.RuleMsg, relationType string, err error) {
		if err != nil {
			fmt.Printf("Execution error (Node: %s): %v\n", nodeId, err)
			return
		}
		// Capture the output of the 'in1' node (SerialIn) when it successfully executes
		if nodeId == "in1" && flowType == types.Out {
			data := msg.GetData()
			if data != "" {
				fmt.Printf("[%s] Data read: %s\n", time.Now().Format("15:04:05"), data)
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
		log.Fatalf("Failed to parse master node: %v", err)
	}
	// Add master node to pool
	_, err = pool.NewFromRuleNode(nodeDef)
	if err != nil {
		log.Fatalf("Failed to register master node to NodePool: %v", err)
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
		log.Fatalf("Failed to initialize rule engine: %v", err)
	}

	// Wait for endpoint to start (it starts asynchronously)
	time.Sleep(100 * time.Millisecond)

	_ = engine // keep engine reference; rule chain + endpoint run in the background
	fmt.Println("Rule engine started (Endpoint enabled), reading serial data every 2 seconds...")
	fmt.Println("Press Ctrl+C to exit")

	// Block forever
	select {}
}
