#!/usr/bin/env python3
"""
Interoperability check: a real S7 client against S7Server.

The unit tests ask "are the bytes what we intended". This asks the different
and more important question: "does a client written by someone else, against
a real Siemens CPU, agree?" python-snap7 wraps Snap7's own client, which is
the de-facto reference implementation of a protocol that has no published
standard -- so its opinion is as close to authoritative as this gets.

    # terminal 1
    g++ -std=c++11 -I.. ../S7Server.cpp harness.cpp -o harness && ./harness 1102
    # terminal 2
    python3 test_interop.py 127.0.0.1 1102

It also runs against a device: point it at the board's address and port 102.
"""

import sys
import snap7

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1102

results = []


def check(name, fn):
    try:
        detail = fn()
        results.append((True, name, detail))
        print(f"  PASS  {name}" + (f"  ({detail})" if detail else ""))
    except Exception as exc:  # noqa: BLE001 - a failed check is data, not a crash
        results.append((False, name, str(exc)))
        print(f"  FAIL  {name}  {exc}")


def main():
    print(f"python-snap7 -> {HOST}:{PORT}\n")

    client = snap7.client.Client()
    # Rack/slot go into the TSAPs; 0/2 is what an S7-300 uses and what every
    # client defaults to, so it is the case that has to work.
    check("connect (COTP handshake + Setup Communication)",
          lambda: client.connect(HOST, 0, 2, PORT) or "")

    if not client.get_connected():
        print("\nnot connected; nothing further to test")
        return 1

    check("negotiated PDU is a sane size",
          lambda: _pdu(client))

    # ---------------------------------------------------------------- reads
    check("read a DB (flat buffer)",
          lambda: _read_db(client))

    check("read the merker area (served by callbacks)",
          lambda: _read_area(client, snap7.type.Areas.MK, 0, 8))

    check("read several items in one request",
          lambda: _multi_read(client))

    # --------------------------------------------------------------- writes
    check("write a DB and read the value back",
          lambda: _write_roundtrip(client))

    check("write one bit without disturbing its neighbours",
          lambda: _write_bit_roundtrip(client))

    # ------------------------------------------------------- what it refuses
    check("reading past the end of an area is refused",
          lambda: _expect_refused(client, lambda: client.db_read(1, 250, 32)))

    check("reading a DB that does not exist is refused",
          lambda: _expect_refused(client, lambda: client.db_read(99, 0, 2)))

    check("writing a read-only area is refused",
          lambda: _expect_refused(
              client,
              lambda: client.write_area(snap7.type.Areas.PE, 0, 0, bytearray([1, 2]))))

    client.disconnect()
    check("disconnect is clean", lambda: "")

    # Last, and on its own connection: the harness serves one client at a time,
    # so this cannot run while the one above is still open.
    check("read a single bit (raw wire check)",
          lambda: _read_bit(HOST, PORT))

    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


def _pdu(client):
    size = client.get_pdu_length()
    if not (240 <= size <= 960):
        raise AssertionError(f"negotiated {size}, outside 240..960")
    return f"{size} bytes"


def _read_db(client):
    # The harness fills DB1 with 0,1,2,3..., so the bytes are self-checking:
    # an endianness or offset bug shows up as a wrong sequence, not as silence.
    data = client.db_read(1, 4, 8)
    expected = bytes(range(4, 12))
    if bytes(data) != expected:
        raise AssertionError(f"got {bytes(data).hex()}, expected {expected.hex()}")
    return f"DB1.DBB4..11 = {bytes(data).hex()}"


def _read_area(client, area, start, size):
    data = client.read_area(area, 0, start, size)
    if len(data) != size:
        raise AssertionError(f"asked for {size} bytes, got {len(data)}")
    return f"{size} bytes = {bytes(data).hex()}"


def _read_bit(host, port):
    """Read one bit and check the answer BYTE FOR BYTE, over a raw socket.

    Not driven through python-snap7, and deliberately. That library handles
    single-bit reads in two different and both-unhelpful ways: its single-item
    path divides every declared length by 8 regardless of transport size (so it
    reads nothing out of a correct answer), and its multi-item path does not
    honour a per-item Bit word length at all (so it reads bytes instead). The
    quirks are in the client; testing through them would test the client.

    The server sends the length Snap7's own server sends, which its C client
    expects and the Wireshark dissector documents: for TS_ResBit the length is
    1, and the payload is the one byte S7 always uses to carry a bit. Sending
    what the broken path wants -- 8 -- would make Snap7's C client memcpy eight
    bytes into the one-byte buffer it allocated. A client that reads nothing
    has a bug; a client that overruns its buffer has a vulnerability.

    DB1 byte 1 is 0x01 in the harness, so bit 0 is set and bits 1..7 are clear.
    A server that returns the whole byte rather than the masked bit passes a
    "is it non-zero" check and fails this one.
    """
    import socket
    import struct

    def frame(payload):
        return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload

    def read_bit_request(seq, db, bit_addr):
        params = struct.pack(
            ">BBBBBBHHBBBB",
            0x04, 0x01,                 # Read Var, 1 item
            0x12, 0x0A, 0x10, 0x01,     # spec, len, S7ANY, transport = BIT
            1,                          # element count
            db,
            0x84,                       # area = DB
            (bit_addr >> 16) & 0xFF, (bit_addr >> 8) & 0xFF, bit_addr & 0xFF,
        )
        header = struct.pack(">BBHHHH", 0x32, 0x01, 0, seq, len(params), 0)
        return frame(b"\x02\xf0\x80" + header + params)

    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    try:
        # COTP Connection Request, rack 0 slot 2. Byte for byte what
        # Settimino's own client sends (ISO_CR in Settimino.cpp).
        sock.sendall(bytes.fromhex(
            "03000016"          # TPKT, 22 bytes
            "11e00000000100"    # COTP CR, dst-ref 0, src-ref 1, class 0
            "c0010a"            # TPDU size
            "c1020100"          # source TSAP
            "c2020102"          # destination TSAP: rack 0, slot 2
        ))
        _recv_frame(sock)

        # Setup Communication.
        setup_params = struct.pack(">BBHHH", 0xF0, 0x00, 1, 1, 480)
        setup_header = struct.pack(">BBHHHH", 0x32, 0x01, 0, 1, len(setup_params), 0)
        sock.sendall(frame(b"\x02\xf0\x80" + setup_header + setup_params))
        _recv_frame(sock)

        results = []
        for bit in range(8):
            sock.sendall(read_bit_request(2 + bit, 1, 8 + bit))   # DB1.DBX1.bit
            answer = _recv_frame(sock)
            item = answer[7 + 12 + 2:]        # past ISO, AckData header, params
            if len(item) < 5:
                raise AssertionError(f"bit {bit}: answer too short: {answer.hex()}")
            rc, ts, length = item[0], item[1], struct.unpack(">H", item[2:4])[0]
            if rc != 0xFF:
                raise AssertionError(f"bit {bit}: return code {rc:#04x}")
            if ts != 0x03:
                raise AssertionError(f"bit {bit}: transport {ts:#04x}, expected 0x03 (TS_ResBit)")
            if length != 1:
                raise AssertionError(f"bit {bit}: length {length}, expected 1")
            results.append(item[4])

        if results != [1, 0, 0, 0, 0, 0, 0, 0]:
            raise AssertionError(f"bits of DB1.DBB1 (0x01) read back as {results}")
        return "DB1.DBX1.0 = 1, DB1.DBX1.1..7 = 0, each answered TS_ResBit len=1"
    finally:
        sock.close()


def _recv_frame(sock):
    import struct
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        if not chunk:
            raise AssertionError("connection closed mid-frame")
        head += chunk
    total = struct.unpack(">H", head[2:4])[0]
    body = b""
    while len(head) + len(body) < total:
        chunk = sock.recv(total - len(head) - len(body))
        if not chunk:
            raise AssertionError("connection closed mid-frame")
        body += chunk
    return head + body


def _multi_read(client):
    # Several items in one PDU exercises the per-item result headers and the
    # odd-byte padding between them -- a client that does not find item N+1
    # where it expects it reads the wrong variable rather than erroring.
    from snap7.type import Areas, S7DataItem, WordLen
    import ctypes

    items = (S7DataItem * 3)()
    for i, (start, amount) in enumerate(((0, 2), (4, 1), (8, 4))):
        items[i].Area = ctypes.c_int32(Areas.DB.value)
        items[i].WordLen = ctypes.c_int32(WordLen.Byte.value)
        items[i].DBNumber = ctypes.c_int32(1)
        items[i].Start = ctypes.c_int32(start)
        items[i].Amount = ctypes.c_int32(amount)
        buf = (ctypes.c_uint8 * amount)()
        items[i].pData = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8))

    client.read_multi_vars(items)
    results = [bytes(bytearray(items[i].pData[: items[i].Amount])) for i in range(3)]
    expected = [bytes([0, 1]), bytes([4]), bytes([8, 9, 10, 11])]
    if results != expected:
        raise AssertionError(f"got {[r.hex() for r in results]}, expected {[e.hex() for e in expected]}")
    return "3 items, each with the right bytes"


def _write_roundtrip(client):
    payload = bytearray([0xDE, 0xAD, 0xBE, 0xEF])
    client.db_write(1, 100, payload)
    back = client.db_read(1, 100, 4)
    if bytes(back) != bytes(payload):
        raise AssertionError(f"wrote {payload.hex()}, read back {bytes(back).hex()}")
    return f"DB1.DBD100 = {bytes(back).hex()}"


def _write_bit_roundtrip(client):
    # The point of a bit write is that it leaves the other seven alone. Set a
    # known byte, flip one bit, and check the neighbours survived.
    client.db_write(1, 120, bytearray([0x00]))
    client.write_area(snap7.type.Areas.DB, 1, 120 * 8 + 3, bytearray([1]),
                      snap7.type.WordLen.Bit)
    back = client.db_read(1, 120, 1)
    if back[0] != 0x08:
        raise AssertionError(f"expected 0x08 after setting bit 3, got {back[0]:#04x}")

    client.db_write(1, 120, bytearray([0xFF]))
    client.write_area(snap7.type.Areas.DB, 1, 120 * 8 + 3, bytearray([0]),
                      snap7.type.WordLen.Bit)
    back = client.db_read(1, 120, 1)
    if back[0] != 0xF7:
        raise AssertionError(f"expected 0xF7 after clearing bit 3, got {back[0]:#04x}")
    return "set -> 0x08, clear from 0xFF -> 0xF7"


def _expect_refused(client, action):
    # Refused, and refused QUICKLY. An error and a timeout look the same to a
    # user and are completely different to diagnose.
    import time
    started = time.time()
    try:
        action()
    except Exception as exc:  # noqa: BLE001
        elapsed = time.time() - started
        if elapsed > 2.0:
            raise AssertionError(f"took {elapsed:.1f}s -- a timeout, not an answer") from exc
        return f"refused in {elapsed * 1000:.0f} ms"
    raise AssertionError("the server accepted something it should have refused")


if __name__ == "__main__":
    sys.exit(main())
