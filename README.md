# rulego-components-iot

[![Test](https://github.com/rulego/rulego-components-iot/actions/workflows/test.yml/badge.svg)](https://github.com/rulego/rulego-components-iot/actions/workflows/test.yml)

IoT protocol components for [RuleGo](https://github.com/rulego/rulego) — unified acquisition (read/write), time-series storage, and soft-PLC logic control across 9 industrial protocols and 5 TSDB backends.

[Doc](https://rulego.cc/en/pages/iot-overview/)

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│  Universal Nodes: x/iotRead · x/iotWrite · x/tsdbWrite · x/tsdbQuery  │
└────────────┬──────────────────────────────┬───────────────────────────┘
             │  driver=modbus/s7/eip/...    │  driver=opengemini/influxdb/...
┌────────────▼────────────┐   ┌─────────────▼─────────────┐
│  Protocol Read/Write    │   │  TSDB Write/Query          │
│  x/s7Read  x/s7Write    │   │  x/opengeminiWrite         │
│  x/eipRead x/eipWrite   │   │  x/influxdbWrite           │
│  x/modbusRead/Write ... │   │  x/tdengineWrite           │
│  x/opcuaRead/Write      │   │  x/timescaledbWrite        │
│  x/snmpRead/Write       │   │  x/promremoteWrite         │
│  x/mcRead  x/mcWrite    │   └────────────────────────────┘
│  x/finsRead x/finsWrite │
│  x/dlt645Read/Write     │   ┌────────────────────────────┐
│  x/iec104Read/Write     │   │  Endpoints (passive)       │
└─────────────────────────┘   │  endpoint/opcua (poll)     │
                              │  endpoint/snmp (trap)      │
┌─────────────────────────┐   │  endpoint/hj212 (TCP)      │
│  pkg/ (protocol clients)│   │  endpoint/modbusServer     │
│  iot_points · tsdb      │   └────────────────────────────┘
│  s7_client · eip_client │
│  snmp_client · opcua    │   ┌────────────────────────────┐
│  fins_client · mc (Hsl) │   │  Transform                 │
│  iec104_client          │   │  x/iotToSeries             │
└─────────────────────────┘   └────────────────────────────┘
┌─────────────────────────┐
│  Logic Control          │
│  x/control/timer        │
│  x/control/watchdog     │
└─────────────────────────┘
```

## Supported Protocols

| Protocol | Read | Write | Endpoint | Address Format |
|----------|------|-------|----------|----------------|
| Modbus TCP/RTU | ✅ | ✅ | ✅ (slave) | Modicon: 40001, 30001, 00001, 10001 |
| S7 (Siemens) | ✅ | ✅ | — | DB1.DBD0, MW0, M0.1, IW0 |
| EtherNet/IP (CIP) | ✅ | ✅ | — | Tag name: MyDB.Temperature |
| OPC UA | ✅ | ✅ | ✅ (poll) | ns=2;s=Temperature |
| SNMP | ✅ | ✅ | ✅ (trap) | OID: 1.3.6.1.2.1.1.3.0 |
| MC (Mitsubishi) | ✅ | ✅ | — | D100, M10.1, W200, X1A0 |
| FINS (Omron) | ✅ | ✅ | — | DM100, CIO10.0, WR200 |
| DL/T 645 | ✅ | ✅ | — | DI: 00-01-00-00 |
| IEC 60870-5-104 | ✅ | ✅ | — | IOA: 100, 16385 |
| HJ 212 | — | — | ✅ (TCP) | 环保数采协议 |

## TSDB Backends

| Driver | Write | Query | Notes |
|--------|-------|-------|-------|
| OpenGemini | ✅ | ✅ | Line protocol |
| InfluxDB 2.x | ✅ | ✅ | Flux query |
| TDengine | ✅ | ✅ | taosRestful (pure Go) |
| TimescaleDB | ✅ | ✅ | PostgreSQL |
| Prometheus Remote Write | ✅ | — | Write-only |

## Logic Control Components

Protocol-agnostic soft-PLC logic control nodes; wire them with `x/iotRead` / `x/iotWrite` for delayed actions and link-loss protection:

| Node | Description |
|------|-------------|
| `x/control/timer` | Timer (TON on-delay / TOF off-delay), cancellable and retriggerable; writes the boolean output to `metadata[out]` (default `q`) |
| `x/control/watchdog` | Watchdog: forwards each message and re-arms; emits the failsafe JSON if no message arrives within the timeout |

> For filtering, counting, windowed timing, and CEP patterns, reuse RuleGo's `exprFilter` / `x/streamAggregator` / `cache` / `endpoint/schedule`; this package only adds the two "fires on its own timer" primitives — timer and watchdog.

## Quick Start

```go
import (
    _ "github.com/rulego/rulego-components-iot/external/deviceio" // x/iotRead + x/iotWrite
    _ "github.com/rulego/rulego-components-iot/external/tsdb" // x/tsdbWrite + x/tsdbQuery
    _ "github.com/rulego/rulego-components-iot/action/control"    // x/control/timer + x/control/watchdog
    // Or import specific protocols:
    _ "github.com/rulego/rulego-components-iot/external/modbus"
    _ "github.com/rulego/rulego-components-iot/external/s7"
)
```

## Unified Data Contract

**Acquisition output** (`x/iotRead` → msg.Data):
```json
[{"name":"temperature","value":25.3,"timestamp":1721900000000000000}]
```

**TSDB input** (`x/tsdbWrite` ← msg.Data):
```json
[{"measurement":"device1","tags":{"site":"A"},"fields":{"temp":25.3},"timestamp":0}]
```

Use `x/iotToSeries` to bridge acquisition output → TSDB input.

### Why Unified?

| Advantage | Description |
|-----------|-------------|
| **Protocol-agnostic downstream** | All 9 protocols output identical `[{name, value, timestamp, error}]` — downstream nodes (transform/filter/TSDB) never care which protocol produced the data |
| **One topology, any backend** | Change `driver` field to swap protocol or TSDB — rule chain wiring stays the same |
| **Point-level fault tolerance** | Single point failure marks `error` and continues; one bad point doesn't abort the batch |
| **Template-driven** | Every point field supports `${msg.xx}` / `${metadata.xx}` — dynamic acquisition/writing without topology changes |
| **Reusable point templates** | Same `name/addr/type` schema across all protocols (`scale`/`offset` on Modbus/MC/FINS/DL/T645, `endian` on Modbus only); import once, use everywhere |
| **Endian-aware decoding** | Modbus per-point byte order (ABCD/CDAB/BADC/DCBA) for multi-register types, no external conversion needed |

## Rule Chain DSL Examples

### Acquisition → TSDB Pipeline

```json
{
  "ruleChain": {"name": "iot-pipeline", "root": true},
  "metadata": {
    "nodes": [
      {"id": "n1", "type": "x/iotRead", "configuration": {
        "driver": "modbus", "server": "tcp://192.168.1.100:502",
        "points": [
          {"name": "voltage", "addr": "40001", "type": "FLOAT32", "scale": 0.1},
          {"name": "current", "addr": "40003", "type": "FLOAT32", "scale": 0.001}
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

### Remote Control (Write)

```json
{
  "ruleChain": {"name": "iot-control", "root": false},
  "metadata": {
    "nodes": [
      {"id": "w1", "type": "x/iotWrite", "configuration": {
        "driver": "iec104", "server": "192.168.1.20:2404", "commonAddr": 1,
        "points": [
          {"name": "breaker", "addr": "100", "type": "C_SC_NA_1", "value": "${msg.action}"}
        ]
      }}
    ],
    "connections": []
  }
}
```

### Modbus Server Endpoint (Write-Triggered)

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

### Watchdog Link-Loss Protection

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
          {"name": "valve", "addr": "40001", "type": "UINT16", "value": "${msg.valve}"},
          {"name": "motor", "addr": "40002", "type": "UINT16", "value": "${msg.motor}"}
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

> While heartbeats arrive, the watchdog forwards the setpoints; after 10s of silence it emits the `failsafe` (close valve, stop motor). For delayed start, use `x/control/timer` (TON).

## Build Tags

- Default build: **zero IoT dependency** (components not registered)
- `with_iot` or `with_all`: registers all IoT components

## Testing

```bash
GOTOOLCHAIN=go1.24.7 go test -p 1 ./...
```

CI runs on Go 1.24.7 + 1.25.x with real TimescaleDB/InfluxDB/TDengine/VictoriaMetrics services.

## License

Apache 2.0
