#!/usr/bin/env python3
"""Legacy receiver for scenario s53: a plain SOCK_DGRAM socket without any RFC 9868 support.

Binds the given port, filters on the campaign source port, and emits one JSONL row per datagram
in the same shape as udpopt-recv --json (subset), so p0-eval.py can join on the embedded
sequence number. A legacy receiver can only ever see the UDP user data; the surplus area is
invisible to it by construction, which is exactly what the scenario measures.

Usage: p0-legacy-recv.py <port> <src-port>
"""

import json
import socket
import sys


def main():
    port, src_port = int(sys.argv[1]), int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        data, peer = sock.recvfrom(65535)
        if peer[1] != src_port:
            continue
        print(
            json.dumps(
                {
                    "delivery": "payload",
                    "payload_len": len(data),
                    "payload_hex": data[:8].hex(),
                    "option_bearing": False,
                    "options": "",
                    "reports": "",
                    "ocs_reports": "legacy",
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
