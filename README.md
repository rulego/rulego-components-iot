# rulego-components-iot

[![Test](https://github.com/rulego/rulego-components-iot/actions/workflows/test.yml/badge.svg)](https://github.com/rulego/rulego-components-iot/actions/workflows/test.yml)

IoT protocol components for [RuleGo](https://github.com/rulego/rulego) — unified acquisition (read/write), time-series storage, and soft-PLC logic control across 10 industrial protocols and 5 TSDB backends. **Compatible with 10+ industrial IoT protocols under one unified data format**: all protocols share the same point configuration structure and acquisition output format; switching protocols only requires changing the `driver` field.

[Doc](https://rulego.cc/en/pages/iot-overview/)

## Supported Protocols

| Protocol | Read | Write | Endpoint | Address Format |
|----------|------|-------|----------|----------------|
| Modbus TCP/RTU | ✅ | ✅ | ✅ (slave) | Modicon: 40001, 30001, 00001, 10001 |
| S7 (Siemens) | ✅ | ✅ | — | DB1.DBD0, MW0, M0.1, IW0 |
| EtherNet/IP (CIP) | ✅ | ✅ | — | Tag name: MyDB.Temperature |
| OPC UA | ✅ | ✅ | ✅ (poll) | ns=2;s=Temperature |
| SNMP | ✅ | ✅ | ✅ (trap) | OID: 1.3.6.1.2.1.1.3.0 |
| MC (Mitsubishi) | ✅ | ✅ | — | D100, M10.1, W200, X1A0 |
| FINS (Omron) | ✅ | ✅ | — | DM100, CIO10.0, D100:20 |
| DL/T 645 | ✅ | ✅ | — | DI: 00-01-00-00 |
| IEC 60870-5-104 | ✅ | ✅ | — | IOA: 100, 16385 |
| BACnet/IP | ✅ | ✅ | — | analog-input:0, ai:1, device:100:object-name |
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

> For filtering, counting, windowed timing, and CEP patterns, reuse RuleGo's `exprFilter` / [`x/streamAggregator`](https://rulego.cc/en/pages/x-stream-aggregator/) / `cache` / `endpoint/schedule`; this package only adds the two "fires on its own timer" primitives — timer and watchdog.

## Stream Aggregation (rulego-components)

For window aggregation, change detection, and CEP pattern recognition in acquisition pipelines, use the stream-processing components from [rulego-components](https://github.com/rulego/rulego-components) (built on the [StreamSQL](https://rulego.cc/en/pages/streamsql-overview/) engine):

| Node | Description |
|------|-------------|
| `x/streamTransform` | Stream transform: per-row SQL filter/compute/change detection, results travel on the `Success` chain |
| `x/streamAggregator` | Stream aggregator: windowed aggregation (tumbling/sliding/count/session) and CEP pattern recognition, results travel on the `stream_event` chain |

```go
import _ "github.com/rulego/rulego-components/stats/streamsql"
```

Typical downsampling pipeline (the acquisition point array connects directly to the aggregator — no transform node needed):

```
x/iotRead → x/streamAggregator(window) → x/tsdbWrite
```

Use `GROUP BY name` in the aggregation SQL for per-point stats; set `inputFormat: columns` for cross-point calculations. Full rule chain DSL in [IoT Scenarios](https://rulego.cc/en/pages/iot-scenarios/).

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

With `measurement` set on `x/tsdbWrite`, the acquisition array flows in directly — no bridge node needed.

### Why Unified?

| Advantage | Description |
|-----------|-------------|
| **Protocol-agnostic downstream** | All 10 protocols output identical `[{name, value, timestamp, error}]` — downstream nodes (transform/filter/TSDB) never care which protocol produced the data |
| **One topology, any backend** | Change `driver` field to swap protocol or TSDB — rule chain wiring stays the same |
| **Point-level fault tolerance** | Single point failure marks `error` and continues; one bad point doesn't abort the batch |
| **Template-driven** | Every point field supports `${msg.xx}` / `${metadata.xx}` — dynamic acquisition/writing without topology changes |
| **Reusable point templates** | Same `name/addr/type` schema across all protocols (`scale`/`offset` on Modbus/MC/FINS/DL/T645, `endian` on Modbus/FINS); import once, use everywhere |
| **Endian-aware decoding** | Modbus/FINS per-point byte order (ABCD/CDAB/BADC/DCBA) for multi-register types, no external conversion needed |

## Rule Chain DSL Examples

### Acquisition → TSDB Pipeline

`x/tsdbWrite` ingests the acquisition array directly when `measurement` is set; `fields` omitted expands every point as a field.

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
      {"id": "n2", "type": "x/tsdbWrite", "configuration": {
        "driver": "timescaledb", "dsn": "postgres://user:pass@localhost:5432/iot?sslmode=disable",
        "measurement": "power_meter",
        "tags": [{"key": "deviceId", "value": "${metadata.deviceId}"}]
      }}
    ],
    "connections": [
      {"fromId": "n1", "toId": "n2", "type": "Success"}
    ]
  }
}
```

### Acquisition -> Window Aggregation -> Downsampled Store

High-frequency acquisition windowed into per-minute averages before storage - storage volume reduced to 1/60. The acquisition point array connects **directly** to the aggregator - no transform node needed.

```json
{
  "ruleChain": {"name": "iot-downsample", "root": true},
  "metadata": {
    "nodes": [
      {"id": "n1", "type": "x/iotRead", "configuration": {
        "driver": "modbus", "server": "tcp://192.168.1.100:502",
        "points": [
          {"name": "voltage", "addr": "40001", "type": "FLOAT32", "scale": 0.1},
          {"name": "current", "addr": "40003", "type": "FLOAT32", "scale": 0.001}
        ]
      }},
      {"id": "n2", "type": "x/streamAggregator", "configuration": {
        "sql": "SELECT name, AVG(value) AS value FROM stream WHERE error IS NULL GROUP BY name, TumblingWindow('1m')"
      }},
      {"id": "n3", "type": "x/tsdbWrite", "configuration": {
        "driver": "timescaledb", "dsn": "postgres://user:pass@localhost:5432/iot?sslmode=disable",
        "measurement": "power_meter_1m"
      }}
    ],
    "connections": [
      {"fromId": "n1", "toId": "n2", "type": "Success"},
      {"fromId": "n2", "toId": "n3", "type": "stream_event"}
    ]
  }
}
```

> - Requires additionally importing `_ "github.com/rulego/rulego-components/stats/streamsql"`.
> - Default long format: the SQL uses `GROUP BY name` for per-point stats; the result `[{name,value}]` is pivoted by `x/tsdbWrite` (with `measurement` set) into a single time-series record.
> - For cross-point calculations (e.g. `voltage * current`), set `"inputFormat": "columns"` on n2: the point array is pivoted into a wide row, the SQL reads `SELECT AVG(voltage) * AVG(current) AS power ...`, and the whole output map becomes the fields of one record.
> - Storage timestamp is automatic: aggregation results carry the window-end timestamp (injected from `window_id`), so `x/tsdbWrite` stores at the window time without needing `window_end() AS timestamp`; to window by data time add `WITH (TIMESTAMP='timestamp', TIMEUNIT='ns')`.
> - Aggregation results travel on the `stream_event` relation; `Success` passes the original message through - to store raw data as well, wire another `x/tsdbWrite` from n1.

### Watchdog Link-Loss Protection

```json
{
  "ruleChain": {"name": "watchdog-guard", "root": true},
  "metadata": {
    "nodes": [
      {"id": "e1", "type": "endpoint/modbusServer", "configuration": {
        "server": "tcp://:5020", "unitId": 1
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

## License

Apache 2.0
