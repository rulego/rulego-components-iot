# rulego-components-iot

[![Test](https://github.com/rulego/rulego-components-iot/actions/workflows/test.yml/badge.svg)](https://github.com/rulego/rulego-components-iot/actions/workflows/test.yml)

[RuleGo](https://github.com/rulego/rulego) 的 IoT 协议组件库 — 统一采集（读/写）、时序落盘与软 PLC 式逻辑控制，覆盖 9 种工业协议和 5 种时序数据库。

## 架构

```
┌───────────────────────────────────────────────────────────────────────┐
│  通用节点: x/iotRead · x/iotWrite · x/tsdbWrite · x/tsdbQuery          │
└────────────┬──────────────────────────────┬───────────────────────────┘
             │  driver=modbus/s7/eip/...    │  driver=opengemini/influxdb/...
┌────────────▼────────────┐   ┌─────────────▼─────────────┐
│  协议读写节点            │   │  时序写入/查询节点          │
│  x/s7Read  x/s7Write    │   │  x/opengeminiWrite         │
│  x/eipRead x/eipWrite   │   │  x/influxdbWrite           │
│  x/modbusRead/Write ... │   │  x/tdengineWrite           │
│  x/opcuaRead/Write      │   │  x/timescaledbWrite        │
│  x/snmpRead/Write       │   │  x/promremoteWrite         │
│  x/mcRead  x/mcWrite    │   └────────────────────────────┘
│  x/finsRead x/finsWrite │
│  x/dlt645Read/Write     │   ┌────────────────────────────┐
│  x/iec104Read/Write     │   │  端点（被动接收）            │
└─────────────────────────┘   │  endpoint/opcua (轮询)     │
                              │  endpoint/snmp (Trap)      │
┌─────────────────────────┐   │  endpoint/hj212 (TCP)      │
│  pkg/ (协议客户端封装)    │   │  endpoint/modbusServer     │
│  iot_points · tsdb      │   └────────────────────────────┘
│  s7_client · eip_client │
│  snmp_client · opcua    │   ┌────────────────────────────┐
│  fins_client · mc (Hsl) │   │  转换                       │
│  iec104_client          │   │  x/iotToSeries             │
└─────────────────────────┘   └────────────────────────────┘
┌─────────────────────────┐
│  逻辑控制                │
│  x/control/timer        │
│  x/control/watchdog     │
└─────────────────────────┘
```

## 支持的协议

| 协议 | 读 | 写 | 端点 | 地址格式 |
|------|---|---|------|----------|
| Modbus TCP/RTU | ✅ | ✅ | ✅ (从站) | Modicon: 40001, 30001, 00001, 10001 |
| S7 (西门子) | ✅ | ✅ | — | DB1.DBD0, MW0, M0.1, IW0 |
| EtherNet/IP (CIP) | ✅ | ✅ | — | 标签名: MyDB.Temperature |
| OPC UA | ✅ | ✅ | ✅ (轮询) | ns=2;s=Temperature |
| SNMP | ✅ | ✅ | ✅ (Trap) | OID: 1.3.6.1.2.1.1.3.0 |
| MC (三菱) | ✅ | ✅ | — | D100, M10.1, W200, X1A0 |
| FINS (欧姆龙) | ✅ | ✅ | — | DM100, CIO10.0, WR200 |
| DL/T 645 | ✅ | ✅ | — | DI: 00-01-00-00 |
| IEC 60870-5-104 | ✅ | ✅ | — | IOA: 100, 16385 |
| HJ 212 | — | — | ✅ (TCP) | 环保数采协议 |

## 时序数据库

| 驱动 | 写入 | 查询 | 说明 |
|------|------|------|------|
| OpenGemini | ✅ | ✅ | Line protocol |
| InfluxDB 2.x | ✅ | ✅ | Flux 查询 |
| TDengine | ✅ | ✅ | taosRestful (纯 Go) |
| TimescaleDB | ✅ | ✅ | PostgreSQL |
| Prometheus Remote Write | ✅ | — | 仅写入 |

## 逻辑控制组件

协议无关的软 PLC 式逻辑控制节点，与 `x/iotRead` / `x/iotWrite` 串接即可实现延时动作与失联保护：

| 节点 | 说明 |
|------|------|
| `x/control/timer` | 定时器（TON 延时接通 / TOF 延时断开），可取消、可重触发；输出布尔写入 `metadata[out]`（默认 `q`） |
| `x/control/watchdog` | 看门狗：每条消息透传并重新武装，超时未收到消息则下发故障安全 JSON |

> 判断、计数、窗口时序、模式（CEP）等能力请复用 RuleGo 的 `exprFilter` / `x/streamAggregator` / `cache` / `endpoint/schedule`；本包只补「需要定时自发」的定时与看门狗两类。

## 快速开始

```go
import (
    _ "github.com/rulego/rulego-components-iot/external/deviceio" // x/iotRead + x/iotWrite
    _ "github.com/rulego/rulego-components-iot/external/tsdb" // x/tsdbWrite + x/tsdbQuery
    _ "github.com/rulego/rulego-components-iot/action/control"    // x/control/timer + x/control/watchdog
    // 或按需导入具体协议：
    _ "github.com/rulego/rulego-components-iot/external/modbus"
    _ "github.com/rulego/rulego-components-iot/external/s7"
)
```

## 统一数据契约

**采集输出**（`x/iotRead` → msg.Data）：
```json
[{"name":"温度","value":25.3,"timestamp":1721900000000000000}]
```

**时序输入**（`x/tsdbWrite` ← msg.Data）：
```json
[{"measurement":"device1","tags":{"site":"A"},"fields":{"temp":25.3},"timestamp":0}]
```

使用 `x/iotToSeries` 衔接采集输出 → 时序写入。

### 统一结构的优势

| 优势 | 说明 |
|------|------|
| **下游协议无关** | 9 种协议输出完全相同的 `[{name, value, timestamp, error}]` 格式——下游转换/过滤/落盘节点无需关心数据来自哪个协议 |
| **一套拓扑换任意后端** | 只改 `driver` 字段即可切换协议或 TSDB，规则链连线不变 |
| **逐点容错** | 单点失败标 `error` 继续采集，一个坏点不拖垮整批 |
| **模板驱动** | 所有点位字段支持 `${msg.xx}` / `${metadata.xx}`，动态采集/写入无需改拓扑 |
| **点位模板复用** | 统一的 `name/addr/type` 结构跨协议通用（`scale`/`offset` 支持 Modbus/MC/FINS/DL/T645，`endian` 仅 Modbus），导入一次到处使用 |
| **字节序感知** | Modbus 点位级 Endian（ABCD/CDAB/BADC/DCBA）解码多寄存器类型，无需外部转换 |

## 规则链 DSL 示例

### 采集 → 时序落盘

```json
{
  "ruleChain": {"name": "iot-pipeline", "root": true},
  "metadata": {
    "nodes": [
      {"id": "n1", "type": "x/iotRead", "configuration": {
        "driver": "modbus", "server": "tcp://192.168.1.100:502",
        "points": [
          {"name": "电压", "addr": "40001", "type": "FLOAT32", "scale": 0.1},
          {"name": "电流", "addr": "40003", "type": "FLOAT32", "scale": 0.001}
        ]
      }},
      {"id": "n2", "type": "x/iotToSeries", "configuration": {
        "measurement": "power_meter",
        "tags": {"deviceId": "${metadata.deviceId}"}
      }},
      {"id": "n3", "type": "x/tsdbWrite", "configuration": {
        "driver": "timescaledb", "dsn": "postgres://user:pass@localhost:5432/iot?sslmode=disable"
      }}
    ],
    "connections": [
      {"fromId": "n1", "toId": "n2", "type": "Success"},
      {"fromId": "n2", "toId": "n3", "type": "Success"}
    ]
  }
}
```

> 换协议只改 n1 的 `driver`（s7/opcua/snmp/fins/mc/iec104...），n2/n3 不变。

### 遥控写入

```json
{
  "ruleChain": {"name": "iot-control", "root": false},
  "metadata": {
    "nodes": [
      {"id": "w1", "type": "x/iotWrite", "configuration": {
        "driver": "iec104", "server": "192.168.1.20:2404", "commonAddr": 1,
        "points": [
          {"name": "断路器", "addr": "100", "type": "C_SC_NA_1", "value": "${msg.action}"}
        ]
      }}
    ],
    "connections": []
  }
}
```

### Modbus 从站端点（写触发）

```json
{
  "ruleChain": {"name": "modbus-bridge", "root": true},
  "metadata": {
    "nodes": [
      {"id": "e1", "type": "endpoint/modbusServer", "configuration": {
        "listen": "tcp://:5020", "unitId": 1
      }},
      {"id": "p1", "type": "log", "configuration": {"jsScript": "return msg;"}},
      {"id": "w1", "type": "x/tsdbWrite", "configuration": {
        "driver": "influxdb", "url": "http://localhost:8086",
        "token": "my-token", "org": "rulego", "bucket": "iot"
      }}
    ],
    "connections": [
      {"fromId": "e1", "toId": "p1", "type": "ip"},
      {"fromId": "p1", "toId": "w1", "type": "Success"}
    ]
  }
}
```

### 看门狗失联保护

```json
{
  "ruleChain": {"name": "watchdog-guard", "root": true},
  "metadata": {
    "nodes": [
      {"id": "e1", "type": "endpoint/modbusServer", "configuration": {
        "listen": "tcp://:5020", "unitId": 1
      }},
      {"id": "wd", "type": "x/control/watchdog", "configuration": {
        "timeout": "10s", "failsafe": "{\"valve\":0,\"motor\":0}"
      }},
      {"id": "w1", "type": "x/iotWrite", "configuration": {
        "driver": "modbus", "server": "tcp://192.168.1.100:502",
        "points": [
          {"name": "阀", "addr": "40001", "type": "UINT16", "value": "${msg.valve}"},
          {"name": "电机", "addr": "40002", "type": "UINT16", "value": "${msg.motor}"}
        ]
      }}
    ],
    "connections": [
      {"fromId": "e1", "toId": "wd", "type": "ip"},
      {"fromId": "wd", "toId": "w1", "type": "Success"}
    ]
  }
}
```

> 心跳正常时 watchdog 透传设定值；10 秒无消息则下发 `failsafe`（阀关、电机停）。延时启动可用 `x/control/timer`（TON）。

## 构建标签

- 默认编译：**零 IoT 依赖**（组件不注册）
- `with_iot` 或 `with_all`：注册所有 IoT 组件

## 测试

```bash
GOTOOLCHAIN=go1.24.7 go test -p 1 ./...
```

CI 在 Go 1.24.7 + 1.25.x 上运行，含真实 TimescaleDB/InfluxDB/TDengine/VictoriaMetrics 服务。

## 许可证

Apache 2.0
