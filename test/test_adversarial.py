#!/usr/bin/env python3
"""
Adversarial client suite for the baremetal S7 server.

Classic S7 has no authentication, so anyone who can reach port 102 can send
anything. The question this suite asks is not "does it work" but "what happens
when it is attacked" -- and the bar is not that every frame is answered, it is
that the DEVICE SURVIVES and keeps serving everyone else.

Two properties are checked after every case:
  1. the PLC is still scanning (a live counter keeps moving)
  2. a well-behaved client can still connect and read

    python3 s7adversarial.py 192.168.2.5
"""

import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.2.5"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 102

CR = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
passed = failed = 0


def result(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def frame(payload):
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def recv_frame(sock):
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        if not chunk:
            return None
        head += chunk
    total = struct.unpack(">H", head[2:4])[0]
    body = b""
    while len(head) + len(body) < total:
        chunk = sock.recv(total - len(head) - len(body))
        if not chunk:
            return None
        body += chunk
    return head + body


def connected_socket(timeout=5):
    """A socket that has completed COTP and Setup Communication."""
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(CR)
    recv_frame(s)
    pars = struct.pack(">BBHHH", 0xF0, 0x00, 1, 1, 480)
    hdr = struct.pack(">BBHHHH", 0x32, 0x01, 0, 1, len(pars), 0)
    s.sendall(frame(b"\x02\xf0\x80" + hdr + pars))
    recv_frame(s)
    return s


def read_mk(sock, seq=99, start_bit=0, count=2):
    params = struct.pack(
        ">BBBBBBHHBBBB",
        0x04, 0x01, 0x12, 0x0A, 0x10, 0x02,
        count, 0, 0x83,
        (start_bit >> 16) & 0xFF, (start_bit >> 8) & 0xFF, start_bit & 0xFF,
    )
    hdr = struct.pack(">BBHHHH", 0x32, 0x01, 0, seq, len(params), 0)
    sock.sendall(frame(b"\x02\xf0\x80" + hdr + params))
    return recv_frame(sock)


def still_alive():
    """The device answers a normal client, and the PLC is still scanning."""
    try:
        s = connected_socket()
        a = read_mk(s)
        time.sleep(0.6)
        b = read_mk(s, seq=100)
        s.close()
        if a is None or b is None:
            return False, "no answer"
        va = a[-2:]
        vb = b[-2:]
        return (va != vb), f"MW0 {va.hex()} -> {vb.hex()}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:50]


def case(name, body):
    """Run one attack, then prove the device survived it."""
    try:
        body()
    except Exception:  # noqa: BLE001 - the attack failing is fine; the device must not
        pass
    time.sleep(0.15)
    ok, detail = still_alive()
    result(name, ok, detail)


# --------------------------------------------------------------------------
# The attacks
# --------------------------------------------------------------------------

def raw(payload, wait=True):
    s = socket.create_connection((HOST, PORT), timeout=3)
    s.settimeout(3)
    s.sendall(payload)
    if wait:
        try:
            s.recv(512)
        except Exception:  # noqa: BLE001
            pass
    s.close()


def att_not_tpkt():
    raw(b"GET / HTTP/1.1\r\nHost: plc\r\n\r\n")


def att_tpkt_length_lies():
    bad = bytearray(CR)
    bad[2:4] = struct.pack(">H", 0xFFFF)
    raw(bytes(bad))


def att_tpkt_length_tiny():
    raw(bytes.fromhex("03000003"))


def att_cotp_li_overruns():
    bad = bytearray(CR)
    bad[4] = 0x7F
    raw(bytes(bad))


def att_unknown_cotp_type():
    raw(bytes.fromhex("0300000803990000"))


def att_s7_before_cotp():
    pars = struct.pack(">BBHHH", 0xF0, 0x00, 1, 1, 480)
    hdr = struct.pack(">BBHHHH", 0x32, 0x01, 0, 1, len(pars), 0)
    raw(frame(b"\x02\xf0\x80" + hdr + pars))


def att_s7_lengths_dont_add_up():
    s = socket.create_connection((HOST, PORT), timeout=3)
    s.settimeout(3)
    s.sendall(CR)
    recv_frame(s)
    hdr = struct.pack(">BBHHHH", 0x32, 0x01, 0, 1, 0xFFFF, 0xFFFF)
    s.sendall(frame(b"\x02\xf0\x80" + hdr + b"\xf0\x00"))
    try:
        s.recv(512)
    except Exception:  # noqa: BLE001
        pass
    s.close()


def att_oversize_pdu():
    # A frame far past the protocol ceiling. The server must refuse to wait
    # for bytes it has decided not to accept.
    raw(struct.pack(">BBH", 0x03, 0x00, 4000) + b"\x00" * 100, wait=False)


def att_item_count_lies():
    s = connected_socket()
    # 20 items declared, one item's worth of bytes delivered.
    params = bytearray(struct.pack(">BB", 0x04, 20))
    params += struct.pack(">BBBBHHBBBB", 0x12, 0x0A, 0x10, 0x02, 1, 0, 0x83, 0, 0, 0)
    hdr = struct.pack(">BBHHHH", 0x32, 0x01, 0, 2, len(params), 0)
    s.sendall(frame(b"\x02\xf0\x80" + hdr + bytes(params)))
    try:
        s.recv(1024)
    except Exception:  # noqa: BLE001
        pass
    s.close()


def att_read_enormous():
    s = connected_socket()
    # Ask for 65535 elements: far more than the PDU or the area can hold.
    read_mk(s, seq=3, count=0xFFFF)
    s.close()


def att_rst_mid_pdu():
    # Half a frame, then a hard RST. The server must not be left holding a
    # half-parsed connection.
    s = socket.create_connection((HOST, PORT), timeout=3)
    s.sendall(CR[:10])
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def att_half_open_flood():
    # Connect and say nothing. These are the connections that exhaust a slot
    # table if slots are never reclaimed.
    socks = []
    for _ in range(12):
        try:
            socks.append(socket.create_connection((HOST, PORT), timeout=2))
        except Exception:  # noqa: BLE001
            break
    time.sleep(0.5)
    for s in socks:
        s.close()


def att_connect_churn():
    for _ in range(40):
        try:
            s = socket.create_connection((HOST, PORT), timeout=2)
            s.close()
        except Exception:  # noqa: BLE001
            pass


def att_full_handshake_churn():
    for _ in range(15):
        try:
            connected_socket(timeout=3).close()
        except Exception:  # noqa: BLE001
            pass


def att_byte_at_a_time():
    # A valid request dribbled one byte at a time. A server that waits for the
    # rest inside the scan cycle stops the machine.
    s = socket.create_connection((HOST, PORT), timeout=3)
    for b in CR:
        s.sendall(bytes([b]))
        time.sleep(0.005)
    recv_frame(s)
    s.close()


def main():
    print(f"Adversarial suite against {HOST}:{PORT}\n")

    ok, detail = still_alive()
    result("baseline: the device is alive and scanning", ok, detail)
    if not ok:
        print("\nbaseline failed; not attacking a device that is already down")
        return 1

    case("a peer that is not speaking ISO-TCP at all", att_not_tpkt)
    case("a TPKT length that claims 65535 bytes", att_tpkt_length_lies)
    case("a TPKT length shorter than its own header", att_tpkt_length_tiny)
    case("a COTP header longer than the frame carrying it", att_cotp_li_overruns)
    case("an unknown COTP PDU type", att_unknown_cotp_type)
    case("S7 data before the COTP handshake", att_s7_before_cotp)
    case("S7 header lengths that do not add up", att_s7_lengths_dont_add_up)
    case("a frame past the protocol ceiling", att_oversize_pdu)
    case("an item count that lies about what follows", att_item_count_lies)
    case("a read of 65535 elements", att_read_enormous)
    case("RST in the middle of a PDU", att_rst_mid_pdu)
    case("12 half-open connections at once", att_half_open_flood)
    case("40 connect/disconnect cycles", att_connect_churn)
    case("15 full handshakes in a row", att_full_handshake_churn)
    case("a request dribbled one byte at a time", att_byte_at_a_time)

    print(f"\n{passed}/{passed + failed} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
