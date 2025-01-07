from mitmproxy import http
import json
import os
import socket
import threading
from datetime import datetime
from mitmproxy import ctx

class DelayedResponseAddon:
    def __init__(self):
        self.unlisted_file = "unlisted_domains.txt"
        self.logged_domains = set()
        self.pending_responses = {}
        self.server_running = True

        # Khởi động socket server
        thread = threading.Thread(target=self.run_socket_server, daemon=True)
        thread.start()

    def run_socket_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", 9999))
        sock.listen(5)
        ctx.log.info("Socket server running on 0.0.0.0:9999")

        while self.server_running:
            conn, addr = sock.accept()
            data = conn.recv(1024).decode("utf-8")
            if data:
                command, _, request_id = data.partition(" ")
                request_id = request_id.strip()

                if command.lower() == "allow" and request_id in self.pending_responses:
                    ctx.log.info(f"Allowing response for request ID {request_id}")
                    flow = self.pending_responses.pop(request_id)
                    flow.resume()  # Gửi response đến trình duyệt

                elif command.lower() == "block" and request_id in self.pending_responses:
                    ctx.log.info(f"Blocking response for request ID {request_id}")
                    flow = self.pending_responses.pop(request_id)
                    flow.response = http.Response.make(
                        200,
                        b"<html><body><h1>This page is blocked.</h1></body></html>",
                        {"Content-Type": "text/html"}
                    )

                    flow.resume()  # Trả response "blocked"

                else:
                    conn.sendall(b"Invalid command or request ID\n")
            conn.close()
    # def request(self, flow: http.HTTPFlow):
    #     host = flow.request.host
    #     request_id = str(flow.id)
        # self.log_unlisted_domain(host,request_id)

    def response(self, flow: http.HTTPFlow):

        request_id = str(flow.id)
        host = str(flow.request.host)
        url = flow.request.url
        ctx.log.info(f"Intercepting response for request ID {host} {request_id}")
        self.write_to_log(host,url, request_id)
        self.pending_responses[request_id] = flow


        flow.intercept()

    def done(self):

        self.server_running = False
        ctx.log.info("Shutting down socket server")

    def write_to_log(self, domain,url,log):
        now = datetime.now()
        log_entry = {
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "domain": domain,
            "url": url,
            "unlisted": True,
            "log":log
        }
        with open(self.unlisted_file, "a") as file:
            file.write(json.dumps(log_entry) + "\n")
        self.logged_domains.add(domain)
        ctx.log.info(f"{log_entry['time']} Domain {domain} logged into {self.unlisted_file}")

addons = [
    DelayedResponseAddon()
]
