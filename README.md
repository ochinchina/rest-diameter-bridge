# rest-diameter-bridge

A high-performance REST-to-Diameter protocol bridge written in Rust. It translates between RESTful HTTP/JSON APIs and the Diameter protocol (RFC 6733), enabling HTTP clients to send and receive Diameter messages via a JSON REST interface.

## Features

- **REST-to-Diameter bridging** — Accept JSON HTTP requests and convert them to Diameter binary protocol messages
- **Diameter-to-REST forwarding** — Forward incoming Diameter requests to HTTP backend processors
- **Configurable load balancing** — RoundRobin, FailOver, and Random strategies, composable/nestable
- **Routing** — Route Diameter messages by realm or host with flexible routing rules
- **Transport** — TCP and SCTP (Linux) with optional TLS (rustls)
- **Prometheus metrics** — Requests received, responses, retries, REST requests, processed requests
- **Alarm management** — SQLite-backed alarms with severity levels and HTTP forwarding to external alarm managers
- **Hot-reloadable configuration** — File change monitoring for live config updates
- **Multiple stacks** — Run multiple independent Diameter stacks in a single process

## Building

```bash
cargo build --release
```

## Usage

```bash
rest-diameter-bridge --config-file <path-to-config.yaml> [OPTIONS]
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--config-file` | Path to the YAML stack configuration file (required) |
| `--log-file` | Log output file path |
| `--log-level` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `--log-format` | Log format: `text` (default) or `json` |

### Example

```bash
./target/release/rest-diameter-bridge \
  --config-file server-1.yaml \
  --log-level info \
  --log-format json
```

## Configuration

Configuration is defined in YAML files. A config file contains one or more Diameter stacks:

```yaml
stacks:
- name: hss
  realm: example.com
  host: server-1
  request-timeout: 5000
  connection-request-timeout: 5000

  # TCP/SCTP listeners
  listen:
  - address: "tcp://127.0.0.1:3868?tls=false"

  # REST API listener
  rest-listen:
  - address: "127.0.0.1:8080"
    path: "/diameter"

  # Peer connections with load balancing
  peers:
  - host: peer@example.com
    connection-url: "RoundRobin(tcp://host1:3868;FailOver(tcp://host2:3868;tcp://host3:3868))"

  # Routing policy
  routing:
    policy: "REALM"
    default: "RoundRobin(peer1;FailOver(peer2;peer3))"

  # Diameter capabilities
  capability:
    vendor-id: 10415
    product-name: "Diameter Bridge"
    supported-vendor-ids: [10415]
    auth-application-ids: [16777216]

  # Forward incoming Diameter requests to HTTP backends
  my-request-processors:
  - urls: ["http://localhost:8088/diameter"]

  # Alarm management
  alarm-management:
    alarm-manager-url: "http://localhost:8088/alarms"
    alarm-db:
      path: "alarms.db"
    alarm-rest-path: "/alarms"

  # AVP and command definitions
  avp-files: ["avps.yaml"]
  command-files: ["commands.yaml"]
```

### Load Balancing Strategies

Strategies can be nested for complex topologies:

- `RoundRobin(peer1;peer2;peer3)` — Distribute requests evenly
- `FailOver(primary;secondary;tertiary)` — Use primary, fall back on failure
- `Random(peer1;peer2;peer3)` — Random selection
- Nested: `RoundRobin(tcp://host1:3868;FailOver(tcp://host2:3868;tcp://host3:3868))`

### AVP Definitions

AVPs are defined in external YAML files:

```yaml
avps:
- name: "Origin-Host"
  code: 264
  type: "DiameterIdentity"
  mandatory: true
  vendor_id: 0
  vendor_specific: false
```

### Command Definitions

Diameter commands (request/answer pairs) are defined in external YAML files:

```yaml
commands:
- long-name: "User-Data-Request"
  short-name: "UDR"
  code: 306
  application-id: 16777216
  request: true
  avps: ["Session-Id", "Origin-Host", "Origin-Realm"]
```

## Architecture

| Module | Responsibility |
|--------|---------------|
| `stack.rs` | Diameter stack lifecycle, connection orchestration, routing |
| `transport/` | Connection abstractions, TCP/SCTP transports, load-balancing strategies |
| `http_rest_listener.rs` | Axum HTTP server for REST API, metrics, and alarm endpoints |
| `config.rs` | YAML configuration parsing and validation |
| `avp.rs` | AVP encoding/decoding and definition loading |
| `command.rs` | Diameter command/message parsing, JSON ↔ binary conversion |
| `alarm.rs` | Alarm management with SQLite persistence |
| `metrics.rs` | Prometheus metrics collection |
| `filechange_monitor.rs` | Configuration file hot-reload |

## Testing

```bash
cargo test
```

Test coverage includes AVP encoding/decoding, command serialization, connection iteration, failover behavior, round-robin load balancing, routing decisions, hop-by-hop ID mapping, and stack lifecycle.

## License

See [Cargo.toml](Cargo.toml) for license information.
