# rest-diameter-bridge

A high-performance REST-to-Diameter protocol bridge written in Rust. It translates between RESTful HTTP/JSON APIs and the Diameter protocol (RFC 6733), enabling HTTP clients to send and receive Diameter messages via a JSON REST interface.

## Why This Project?

The Diameter protocol (RFC 6733) uses a binary format over TCP/SCTP, making it difficult to integrate with modern web services. Developing Diameter applications traditionally requires deep knowledge of the binary encoding, AVP structures, and transport-level details.

**rest-diameter-bridge** solves this by:

1. **Simple REST/JSON interface** — Any HTTP client (curl, Python, Node.js, etc.) can send and receive Diameter messages as JSON. No binary protocol knowledge needed.
2. **Easy message processing** — Backend services receive Diameter requests as JSON via HTTP POST and reply with JSON. You can write your Diameter application logic in any language.
3. **Protocol gateway** — Acts as a bridge between the JSON/HTTP world and the Diameter binary world, handling encoding/decoding, connection management, CER/CEA handshake, DWR/DWA keepalive, and failover automatically.
4. **Flexible deployment** — Multiple gateways can be chained: one accepts JSON from web clients, another forwards binary Diameter to peers, and a third delivers to backend HTTP processors.

## Features

- **REST-to-Diameter bridging** — Accept JSON HTTP requests and convert them to Diameter binary protocol messages
- **Diameter-to-REST forwarding** — Forward incoming Diameter requests to HTTP backend processors
- **Configurable load balancing** — RoundRobin, FailOver, and Random strategies, composable/nestable
- **Routing** — Route Diameter messages by realm or host with flexible routing rules
- **Transport** — TCP and SCTP (Linux) with optional TLS/DTLS
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

---

## Example: 3-Gateway Diameter Deployment

This example demonstrates a common deployment pattern with three Diameter gateways:

```
                    Binary Diameter            Binary Diameter            HTTP/JSON
 HTTP/JSON  ┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
 ──────────►│   Gateway A          │────►│   Gateway B          │────►│   Gateway C          │──────────►  Python
   (curl)   │   (REST ingress)     │     │   (Diameter proxy)   │     │   (REST egress)      │            Web Server
            └──────────────────────┘     └──────────────────────┘     └──────────────────────┘
```

- **Gateway A** — Accepts Diameter messages in JSON format via REST API, converts to binary, and sends to Gateway B.
- **Gateway B** — Receives binary Diameter messages and forwards (proxies) them to Gateway C based on routing rules.
- **Gateway C** — Receives binary Diameter messages, determines the message is destined for it, converts to JSON, and forwards to a backend Python web server for processing.

### Gateway A Configuration (`gateway-a.yaml`)

```yaml
stacks:
- name: gateway-a
  realm: gateway-a.example.com
  host: gateway-a

  # Timeouts (milliseconds)
  request-timeout: 10000
  connection-request-timeout: 5000
  cer-timeout: 5000

  # AVP and command definition files
  avp-files: ["avps.yaml"]
  command-files: ["commands.yaml"]

  # REST API listener - accepts JSON Diameter messages from HTTP clients
  rest-listen:
  - address: "0.0.0.0:8080"
    path: "/diameter"

  # Connect to Gateway B as a Diameter peer
  peers:
  - host: gateway-b@gateway-b.example.com
    connection-url: "tcp://gateway-b-host:3868"

  # Route all messages to Gateway B
  routing:
    policy: "REALM"
    default: gateway-b@gateway-b.example.com

  # Diameter capabilities exchanged during CER/CEA
  capability:
    vendor-id: 10415
    host-ips: ["127.0.0.1"]
    product-name: "Gateway-A"
    auth-application-ids: [16777217]
    inband-security-ids: [0]
    firmware-revision: 1
    vendor-specific-application-ids:
    - vendor-id: 10415
      auth-application-id: 16777217
      acct-application-id: 16777217
```

**Configuration field explanation:**

| Field | Description |
|-------|-------------|
| `name` | Identifier for this stack instance |
| `realm` | Diameter realm of this node (used in Origin-Realm AVP) |
| `host` | Diameter host identity (used in Origin-Host AVP) |
| `request-timeout` | Total timeout (ms) for a Diameter request across all retry attempts |
| `connection-request-timeout` | Timeout (ms) for a single connection attempt before trying next |
| `cer-timeout` | Timeout (seconds) to wait for CEA after sending CER |
| `avp-files` | List of YAML files defining AVP codec information |
| `command-files` | List of YAML files defining Diameter command structures |
| `rest-listen` | HTTP listeners that accept JSON Diameter messages |
| `rest-listen[].address` | Bind address and port for the REST listener |
| `rest-listen[].path` | URL path prefix for Diameter requests |
| `peers` | List of Diameter peers to connect to |
| `peers[].host` | Peer identity in format `host@realm` |
| `peers[].connection-url` | Connection URL with protocol, address, and load balancing strategy |
| `routing` | Message routing configuration |
| `routing.policy` | Routing policy (`REALM` routes by Destination-Realm) |
| `routing.default` | Default route when no specific rule matches |
| `capability` | Diameter capabilities advertised in CER/CEA |
| `capability.vendor-id` | IANA vendor ID |
| `capability.product-name` | Product name string |
| `capability.auth-application-ids` | Supported auth application IDs |

### Gateway B Configuration (`gateway-b.yaml`)

```yaml
stacks:
- name: gateway-b
  realm: gateway-b.example.com
  host: gateway-b

  request-timeout: 10000
  connection-request-timeout: 5000
  cer-timeout: 5000

  avp-files: ["avps.yaml"]
  command-files: ["commands.yaml"]

  # Listen for incoming Diameter connections from Gateway A
  listen:
  - address: "tcp://0.0.0.0:3868"

  # Connect to Gateway C as a Diameter peer
  peers:
  - host: gateway-c@gateway-c.example.com
    connection-url: "tcp://gateway-c-host:3868"

  # Route messages destined for gateway-c.example.com realm to Gateway C
  routing:
    policy: "REALM"
    default: gateway-c@gateway-c.example.com
    items:
    - host-realms:
      - gateway-c.example.com
      route: gateway-c@gateway-c.example.com

  capability:
    vendor-id: 10415
    host-ips: ["127.0.0.1"]
    product-name: "Gateway-B"
    auth-application-ids: [16777217]
    inband-security-ids: [0]
    firmware-revision: 1
    vendor-specific-application-ids:
    - vendor-id: 10415
      auth-application-id: 16777217
      acct-application-id: 16777217
```

**Additional fields:**

| Field | Description |
|-------|-------------|
| `listen` | Diameter protocol listeners (accept incoming peer connections) |
| `listen[].address` | Listen URL: `tcp://host:port` or `sctp://host1,host2:port` |
| `listen[].cert-file` | TLS/DTLS certificate file (enables encryption if set) |
| `listen[].key-file` | TLS/DTLS private key file |
| `listen[].ca-cert-file` | CA certificate for client verification (enables mTLS) |
| `routing.items` | Specific routing rules evaluated before the default |
| `routing.items[].host-realms` | Match messages destined for these realms |
| `routing.items[].route` | Target peer(s) with optional load balancing |

### Gateway C Configuration (`gateway-c.yaml`)

```yaml
stacks:
- name: gateway-c
  realm: gateway-c.example.com
  host: gateway-c

  request-timeout: 10000
  connection-request-timeout: 5000
  cer-timeout: 5000

  avp-files: ["avps.yaml"]
  command-files: ["commands.yaml"]

  # Listen for incoming Diameter connections from Gateway B
  listen:
  - address: "tcp://0.0.0.0:3868"

  # Forward received Diameter requests to backend HTTP server as JSON
  my-request-processors:
  - command-codes: [306]
    application-ids: [16777217]
    urls: ["http://localhost:9090/diameter"]
    timeout: 5000

  capability:
    vendor-id: 10415
    host-ips: ["127.0.0.1"]
    product-name: "Gateway-C"
    auth-application-ids: [16777217]
    inband-security-ids: [0]
    firmware-revision: 1
    vendor-specific-application-ids:
    - vendor-id: 10415
      auth-application-id: 16777217
      acct-application-id: 16777217
```

**Additional fields:**

| Field | Description |
|-------|-------------|
| `my-request-processors` | Rules for forwarding received Diameter requests to HTTP backends |
| `my-request-processors[].command-codes` | Match requests with these command codes (empty = match all) |
| `my-request-processors[].application-ids` | Match requests with these app IDs (empty = match all) |
| `my-request-processors[].urls` | Backend HTTP URLs to POST the JSON message to (tried in order) |
| `my-request-processors[].timeout` | Timeout (ms) for the HTTP request to the backend |

### Sending a JSON Diameter Message to Gateway A

Send a UDR (User-Data-Request) via REST API:

```bash
curl -X POST http://localhost:8080/diameter \
  -H "Content-Type: application/json" \
  -d '{
    "name": "UDR",
    "Session-Id": "gateway-a.example.com;1234;5678",
    "Destination-Realm": "gateway-c.example.com",
    "Destination-Host": "gateway-c",
    "User-Name": "user@example.com",
    "Vendor-Specific-Application-Id": {
        "Vendor-Id": 10415,
        "Auth-Application-Id": 16777217
    },
    "Data-Reference": 0
}'
```

The JSON message fields:

| Field | Description |
|-------|-------------|
| `name` | Command short name (matches `short-name` in `commands.yaml`) |
| `Session-Id` | Diameter Session-Id AVP value |
| `Destination-Realm` | Target realm for routing |
| `Destination-Host` | Target host identity |
| Other fields | AVP names as keys, values matching their type |

Gateway A automatically adds `Origin-Host`, `Origin-Realm`, `hop-by-hop-id`, and `end-to-end-id`, encodes the message to binary, and sends it to Gateway B, which forwards it to Gateway C.

### Python Backend Web Server for Gateway C

Gateway C forwards the received Diameter request as a JSON POST to `http://localhost:9090/diameter`. Here is a simple Python web server that processes the UDR and returns a UDA response:

```python
#!/usr/bin/env python3
"""
Simple Diameter message processor for Gateway C.
Receives UDR requests as JSON, processes them, and returns UDA responses.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json


class DiameterHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the incoming JSON Diameter request
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        request = json.loads(body)

        print(f"Received Diameter request: {json.dumps(request, indent=2)}")

        command_name = request.get("name", "")
        
        if command_name == "UDR":
            # Process User-Data-Request and build User-Data-Answer
            response = self.handle_udr(request)
        else:
            # Unknown command - return DIAMETER_UNABLE_TO_COMPLY
            response = {
                "name": request.get("name", "Unknown"),
                "Session-Id": request.get("Session-Id", ""),
                "Result-Code": 5012,
                "Origin-Host": "gateway-c",
                "Origin-Realm": "gateway-c.example.com",
            }

        # Send the JSON response back
        response_body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
        print(f"Sent Diameter response: {json.dumps(response, indent=2)}")

    def handle_udr(self, request):
        """Process a User-Data-Request and return a User-Data-Answer."""
        user_name = request.get("User-Name", "unknown")
        session_id = request.get("Session-Id", "")

        print(f"Processing UDR for user: {user_name}")

        # Simulate fetching user data
        user_data = f"<UserData><PublicIdentity>{user_name}</PublicIdentity></UserData>"

        # Build UDA response
        return {
            "name": "UDA",
            "Session-Id": session_id,
            "Result-Code": 2001,  # DIAMETER_SUCCESS
            "Origin-Host": "gateway-c",
            "Origin-Realm": "gateway-c.example.com",
            "Vendor-Specific-Application-Id": {
                "Vendor-Id": 10415,
                "Auth-Application-Id": 16777217,
            },
            "User-Data": user_data,
        }

    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9090), DiameterHandler)
    print("Diameter processor listening on http://0.0.0.0:9090")
    print("Waiting for requests from Gateway C...")
    server.serve_forever()
```

Run the Python server:

```bash
python3 diameter_processor.py
```

### End-to-End Flow

1. HTTP client sends JSON UDR to Gateway A (`POST http://gateway-a:8080/diameter`)
2. Gateway A encodes JSON → binary Diameter and sends to Gateway B over TCP
3. Gateway B routes the binary message to Gateway C based on Destination-Realm
4. Gateway C receives the binary message, sees it is destined for itself, converts binary → JSON, and POSTs to the Python backend
5. Python backend processes the UDR, returns a JSON UDA response
6. Gateway C encodes the UDA response to binary and sends back to Gateway B
7. Gateway B forwards the binary response back to Gateway A
8. Gateway A decodes binary → JSON and returns the JSON UDA to the HTTP client

---

## Custom Diameter Messages and AVPs

The bridge supports any Diameter application, including vendor-specific messages not defined in the base RFC. You define custom AVPs and commands in YAML files.

### Defining Custom AVPs (`avps.yaml`)

AVPs defined in RFC 6733 (such as Session-Id, Origin-Host, Origin-Realm, Destination-Host, Destination-Realm, Result-Code, Vendor-Id, Auth-Application-Id, Vendor-Specific-Application-Id, User-Name, Experimental-Result, etc.) are already built into the application. You only need to define vendor-specific or application-specific AVPs that are not in the base RFC.

Here is an example defining 3GPP HSS-related AVPs for the Sh interface (TS 29.329):

```yaml
avps:
# --- 3GPP Sh Interface AVPs (TS 29.329) ---
- name: "User-Data"
  code: 702
  type: "OctetString"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Data-Reference"
  code: 703
  type: "Enumerated"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Service-Indication"
  code: 704
  type: "OctetString"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Subs-Req-Type"
  code: 705
  type: "Enumerated"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Requested-Domain"
  code: 706
  type: "Enumerated"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Current-Location"
  code: 707
  type: "Enumerated"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "MSISDN"
  code: 701
  type: "OctetString"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Server-Name"
  code: 602
  type: "UTF8String"
  mandatory: true
  vendor_id: 10415
  vendor_specific: true

- name: "Wildcarded-Public-Identity"
  code: 634
  type: "UTF8String"
  mandatory: false
  vendor_id: 10415
  vendor_specific: true

- name: "DSA-Flags"
  code: 710
  type: "Unsigned32"
  mandatory: false
  vendor_id: 10415
  vendor_specific: true
```

**AVP field explanation:**

| Field | Description |
|-------|-------------|
| `name` | AVP name (used as JSON key in messages) |
| `code` | AVP code number from the specification |
| `type` | Data type: `UTF8String`, `OctetString`, `Unsigned32`, `Integer32`, `Enumerated`, `Address`, `DiameterIdentity`, `Grouped`. Note: `OctetString` values are encoded as Base64 in JSON messages. |
| `mandatory` | Whether the M-bit is set in the AVP flags |
| `vendor_id` | Vendor ID (0 for standard AVPs, 10415 for 3GPP) |
| `vendor_specific` | Whether the V-bit is set (true if vendor_id != 0) |
| `items` | For `Grouped` AVPs, list of child AVP names |

### Defining Custom Commands (`commands.yaml`)

Define the 3GPP Sh interface UDR/UDA commands:

```yaml
commands:
- long-name: "User-Data-Request"
  short-name: "UDR"
  code: 306
  application-id: 16777217
  request: true
  proxiable: true
  error: false
  retransmit: false
  avps:
  - "Session-Id"
  - "Vendor-Specific-Application-Id"
  - "Origin-Host"
  - "Origin-Realm"
  - "Destination-Host"
  - "Destination-Realm"
  - "User-Name"
  - "Data-Reference"
  - "Service-Indication"
  - "Server-Name"
  - "Wildcarded-Public-Identity"
  - "MSISDN"
  - "DSA-Flags"
  - "Current-Location"

- long-name: "User-Data-Answer"
  short-name: "UDA"
  code: 306
  application-id: 16777217
  request: false
  proxiable: true
  error: false
  retransmit: false
  avps:
  - "Session-Id"
  - "Vendor-Specific-Application-Id"
  - "Result-Code"
  - "Experimental-Result"
  - "Origin-Host"
  - "Origin-Realm"
  - "User-Data"
```

**Command field explanation:**

| Field | Description |
|-------|-------------|
| `long-name` | Full command name |
| `short-name` | Abbreviated name (used as `"name"` in JSON messages) |
| `code` | Diameter command code (306 for UDR/UDA on the Sh interface) |
| `application-id` | Diameter application ID (16777217 = 3GPP Sh) |
| `request` | `true` for request, `false` for answer |
| `proxiable` | Whether the P-bit is set (message can be proxied) |
| `error` | Whether the E-bit is set |
| `retransmit` | Whether the T-bit is set |
| `avps` | Ordered list of AVP names that may appear in this command |

### Sending a Custom UDR as JSON

```bash
curl -X POST http://localhost:8080/diameter \
  -H "Content-Type: application/json" \
  -d '{
    "name": "UDR",
    "Session-Id": "gateway-a.example.com;1690000000;1",
    "Destination-Realm": "gateway-c.example.com",
    "Destination-Host": "gateway-c",
    "Vendor-Specific-Application-Id": {
        "Vendor-Id": 10415,
        "Auth-Application-Id": 16777217
    },
    "User-Name": "sip:user@example.com",
    "Data-Reference": 0,
    "Service-Indication": "MMTEL-Services",
    "Server-Name": "sip:scscf@example.com",
    "MSISDN": "1234567890"
}'
```

The bridge converts this JSON to a binary Diameter UDR with:
- Command code 306, Application-Id 16777217
- Request bit set, Proxiable bit set
- All AVPs encoded with proper vendor-specific flags and padding

---

## Configuration Reference

### Full Stack Configuration

```yaml
stacks:
- name: <string>                          # Stack identifier
  realm: <string>                         # Diameter realm (Origin-Realm)
  host: <string>                          # Diameter host (Origin-Host)
  request-timeout: <ms>                   # Total request timeout
  connection-request-timeout: <ms>        # Per-connection attempt timeout
  cer-timeout: <seconds>                  # CER/CEA handshake timeout
  request-retry-result-codes: [<u32>...]  # Result codes that trigger retry

  avp-files: [<path>...]                  # AVP definition YAML files
  command-files: [<path>...]              # Command definition YAML files

  listen:                                 # Diameter protocol listeners
  - address: "<proto>://<hosts>:<port>"   # tcp:// or sctp://
    cert-file: <path>                     # TLS cert (optional, enables TLS)
    key-file: <path>                      # TLS key
    ca-cert-file: <path>                  # CA cert (enables mTLS)

  rest-listen:                            # REST API listeners
  - address: "<host>:<port>"
    path: "<url-path>"
    cert-file: <path>                     # HTTPS cert (optional)
    key-file: <path>
    ca-cert-file: <path>

  peers:                                  # Outbound peer connections
  - host: "<host>@<realm>"
    connection-url: "<strategy-or-url>"
    cert-file: <path>
    key-file: <path>
    ca-cert-file: <path>

  routing:                                # Message routing
    policy: "REALM"
    default: "<strategy>"
    items:
    - host-realms: [<realm>...]
      application-ids: [<u32>...]
      route: "<strategy>"

  my-request-processors:                  # Forward requests to HTTP backends
  - command-codes: [<u32>...]
    application-ids: [<u32>...]
    urls: [<url>...]
    timeout: <ms>

  capability:                             # CER/CEA capabilities
    vendor-id: <u32>
    product-name: <string>
    supported-vendor-ids: [<u32>...]
    auth-application-ids: [<u32>...]
    acct-application-ids: [<u32>...]
    vendor-specific-application-ids:
    - vendor-id: <u32>
      auth-application-id: <u32>

  alarm-management:                       # Alarm configuration
    alarm-manager-url: <url>
    alarm-db:
      path: <path>
    alarm-rest-path: <url-path>
    cert-file: <path>
    key-file: <path>
    ca-cert-file: <path>
```

### Load Balancing Strategies

Strategies can be nested for complex topologies:

- `RoundRobin(peer1;peer2;peer3)` — Distribute requests evenly
- `FailOver(primary;secondary;tertiary)` — Use primary, fall back on failure
- `Random(peer1;peer2;peer3)` — Random selection
- Nested: `RoundRobin(tcp://host1:3868;FailOver(tcp://host2:3868;tcp://host3:3868))`

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

Test coverage includes AVP encoding/decoding, command serialization, connection iteration, failover behavior, round-robin load balancing, routing decisions, hop-by-hop ID mapping, TCP transport integration, and stack lifecycle.

## License

See [Cargo.toml](Cargo.toml) for license information.
