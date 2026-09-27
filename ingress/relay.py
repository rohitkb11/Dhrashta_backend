"""Fixed-target ingress: management TCP relay and no-reply observation UDP.

No user-selected destinations, inference, capture, template queries or probes.
Only the management connection has a return path. UDP sender identity is
preserved in a private framing header for template scoping in the backend.
"""
import select
import socket
import threading

# Resolve only this fixed internal service when forwarding. Container recreation
# can change its address; a process-lifetime cached IP strands management/UDP.
TARGET = "api"
PREFIX = b"DRASHTA-PASSIVE-V1\x00"


def management(client):
    upstream = None
    try:
        upstream = socket.create_connection((TARGET, 8000), timeout=10)
        client.settimeout(None)
        upstream.settimeout(None)
        while True:
            readable, _, _ = select.select([client, upstream], [], [], 60)
            if not readable:
                continue
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (upstream if source is client else client).sendall(data)
    except OSError:
        pass
    finally:
        client.close()
        if upstream:
            upstream.close()


def tcp():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 8000))
        listener.listen(64)
        while True:
            client, _ = listener.accept()
            threading.Thread(target=management, args=(client,), daemon=True).start()


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward:
        listener.bind(("0.0.0.0", 2055))
        while True:
            data, sender = listener.recvfrom(65535)
            # Stay within the IPv4 UDP payload ceiling, including provenance.
            frame = PREFIX + f"{sender[0]}:{sender[1]}".encode() + b"\x00" + data
            if len(frame) > 65507:
                continue
            try:
                forward.sendto(frame, (TARGET, 2055))
            except OSError:
                pass
            # No recv on forward socket and no send on source-facing socket.


threading.Thread(target=tcp, daemon=True).start()
udp()
