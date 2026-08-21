 # TCP three-node example

This example starts three Diameter bridge instances and sends a User-Data-Request (UDR) through them:

```text
HTTP client -> Gateway A -> Gateway B -> Gateway C -> HTTP application
				 :3867       :3868       :3869       :9090
```

Gateway A exposes the REST API. Gateway B proxies the Diameter message. Gateway C sends the UDR to an HTTP application, receives a User-Data-Answer (UDA), and returns it through B and A to the original REST client.

## Prerequisites

- Linux, macOS, or Windows with a TCP-capable build of the bridge
- Rust and Cargo
- Python 3 for the small HTTP application used by Gateway C

Build the bridge from the repository root:

```bash
cargo build
```

## Start the example

Open four terminals. Run the commands from `examples/tcp`, or use the corresponding paths from the repository root.

### 1. Start the HTTP application

Gateway C posts decoded UDR messages to `http://127.0.0.1:9090/diameter`. The application must return JSON for the answer. For a quick test, create `diameter_processor.py` with the following content:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Handler(BaseHTTPRequestHandler):
	def do_POST(self):
		length = int(self.headers.get("Content-Length", 0))
		request = json.loads(self.rfile.read(length))
		print("Received:", json.dumps(request, indent=2))

		response = {
			"name": "UDA",
			"Session-Id": request.get("Session-Id", ""),
			"Result-Code": 2001,
			"Origin-Host": "gateway-c",
			"Origin-Realm": "gateway-c.example.com",
			"Vendor-Specific-Application-Id": {
				"Vendor-Id": 10415,
				"Auth-Application-Id": 16777217,
			},
			"User-Data": "<UserData><PublicIdentity>sip:user@example.com</PublicIdentity></UserData>",
		}
		body = json.dumps(response).encode()
		self.send_response(200)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, format, *args):
		print("HTTP:", args[0])


HTTPServer(("127.0.0.1", 9090), Handler).serve_forever()
```

Start it:

```bash
python3 diameter_processor.py
```

### 2. Start Gateway C, B, and A

Start Gateway C first, then B, then A. This allows each peer to accept connections as the preceding process starts.

```bash
../../target/debug/rest-diameter-bridge --config-file tcp-diameter-3.yaml --log-level info
```

```bash
../../target/debug/rest-diameter-bridge --config-file tcp-diameter-2.yaml --log-level info
```

```bash
../../target/debug/rest-diameter-bridge --config-file tcp-diameter-1.yaml --log-level info
```

The three checked-in configuration files use these local endpoints:

| Instance | Role | Endpoint |
|---|---|---|
| Gateway A | REST ingress and Diameter client | `http://127.0.0.1:8080/diameter`, Diameter `3867` |
| Gateway B | Diameter proxy | Diameter `3868` |
| Gateway C | REST egress and Diameter server | Diameter `3869`, backend `http://127.0.0.1:9090/diameter` |

The shared `avps.yaml` and `commands.yaml` files define the UDR/UDA command and AVPs used by all three gateways.

## Send the UDR

With all four processes running, send the checked-in request through Gateway A:

```bash
curl --fail-with-body -X POST http://127.0.0.1:8080/diameter \
  -H 'Content-Type: application/json' \
  --data-binary @udr.json
```

The HTTP response is the UDA returned by the Python application. It should contain `"name": "UDA"` and `"Result-Code": 2001` (`DIAMETER_SUCCESS`). The same request and response can be observed in the Gateway C and Python application logs.

## Message flow

1. Gateway A receives `udr.json`, adds its origin and transaction identifiers, and encodes the UDR as Diameter.
2. Gateway A sends the message to Gateway B over TCP port `3868`.
3. Gateway B routes `Destination-Realm: gateway-c.example.com` to Gateway C.
4. Gateway C decodes the UDR and posts it to the backend on port `9090`.
5. The backend returns a JSON UDA.
6. Gateway C encodes the UDA and the response travels back through B to A.
7. Gateway A decodes the answer and returns it to `curl`.

## Troubleshooting

- Start the backend before Gateway C, and start the gateways in the order C, B, A.
- Ensure ports `8080`, `3867`, `3868`, `3869`, and `9090` are available.
- Run the commands from this directory so the relative `avps.yaml` and `commands.yaml` paths resolve correctly.
- If using a release build, replace `target/debug` with `target/release` after running `cargo build --release`.
