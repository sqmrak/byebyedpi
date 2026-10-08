#!/usr/bin/env python3
"""a websocket server for test_wsconn: tls on 127.0.0.1, one thread a connection.

/echo     upgrade, ping the client, answer a pong with "got-pong", echo binary
          messages in two fragments, close on the message "close"
/refuse   a 404, as the gateway does when the binary subprotocol is missing
"""
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import threading

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def frame(opcode, payload, fin=True):
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    return head + payload


def read_frame(conn):
    b0, b1 = read_exact(conn, 2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", read_exact(conn, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", read_exact(conn, 8))[0]
    mask = read_exact(conn, 4) if b1 & 0x80 else b"\0\0\0\0"
    payload = bytearray(read_exact(conn, n))
    if not b1 & 0x80:
        raise ValueError("client frame not masked")
    for i in range(n):
        payload[i] ^= mask[i & 3]
    return b0 & 0x0F, bytes(payload)


def serve(conn):
    try:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk
        lines = request.decode("latin1").split("\r\n")
        path = lines[0].split(" ")[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if path != "/echo" or "binary" not in headers.get("sec-websocket-protocol", ""):
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return
        accept = base64.b64encode(
            hashlib.sha1(headers["sec-websocket-key"].encode() + GUID).digest())
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n"
                     b"Upgrade: websocket\r\nSec-WebSocket-Accept: " + accept +
                     b"\r\nSec-WebSocket-Protocol: binary\r\n\r\n" + frame(0x9, b"hi"))
        while True:
            opcode, payload = read_frame(conn)
            if opcode == 0xA:
                conn.sendall(frame(0x2, b"got-pong"))
            elif opcode == 0x9:
                conn.sendall(frame(0xA, payload))
            elif opcode == 0x8:
                return
            elif opcode == 0x2:
                if payload == b"close":
                    conn.sendall(frame(0x8, struct.pack(">H", 1000)))
                    return
                half = len(payload) // 2
                conn.sendall(frame(0x2, payload[:half], fin=False) + frame(0x0, payload[half:]))
    except (EOFError, ssl.SSLError, ConnectionError, ValueError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def exit_with_parent():
    # the test holds our stdin; when it ends or dies the pipe closes
    sys.stdin.buffer.read()
    os._exit(0)


def main():
    threading.Thread(target=exit_with_parent, daemon=True).start()
    cert, key = sys.argv[1], sys.argv[2]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    print("PORT %d" % sock.getsockname()[1], flush=True)
    while True:
        raw, _ = sock.accept()
        try:
            conn = context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            continue
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


main()
