#!/usr/bin/env python3
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

