#!/usr/bin/env python3
"""
Three protocols at once, against one OpenPLC device, for as long as you ask.

OpenPLC-specific -- it drives S7, Modbus TCP and OPC-UA together -- and it lives
here because the question it answers is about this server: does S7 coexist with
the other two without any of them starving? That is the risk worth testing, and
it is not visible from a single-protocol test: two protocols each politely
taking "their" slack from one scan cycle will together overrun it.

Needs `asyncua` for the OPC-UA half. Drop that worker and it runs against any S7
device.

    python3 test_soak.py 120 192.168.2.5
"""
import asyncio, socket, struct, sys, threading, time
from asyncua import Client

HOST = sys.argv[2] if len(sys.argv) > 2 else "192.168.2.5"
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 120
stop = threading.Event()
res = {"mb": 0, "mb_err": 0, "ua": 0, "ua_err": 0, "s7": 0, "s7_err": 0,
       "s7_sess": 0, "ua_sess": 0}
lat = {"s7": [], "mb": []}


def frame(p):
    return struct.pack(">BBH", 3, 0, len(p) + 4) + p


def recv_frame(s):
    h = b""
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c:
            raise IOError("closed")
        h += c
    n = struct.unpack(">H", h[2:4])[0]
    b = b""
    while len(h) + len(b) < n:
        c = s.recv(n - len(h) - len(b))
        if not c:
            raise IOError("closed")
        b += c
    return h + b


def s7_worker():
    while not stop.is_set():
        try:
            s = socket.create_connection((HOST, 102), timeout=5)
            s.settimeout(5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.sendall(bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102"))
            recv_frame(s)
            pars = struct.pack(">BBHHH", 0xF0, 0, 1, 1, 480)
            s.sendall(frame(b"\x02\xf0\x80" + struct.pack(">BBHHHH", 0x32, 1, 0, 1, len(pars), 0) + pars))
            recv_frame(s)
            res["s7_sess"] += 1
            seq = 2
            for _ in range(400):
                if stop.is_set():
                    break
                params = struct.pack(">BBBBBBHHBBBB", 0x04, 0x01, 0x12, 0x0A, 0x10, 0x02,
                                     8, 0, 0x83, 0, 0, 0)
                t = time.time()
                s.sendall(frame(b"\x02\xf0\x80" +
                                struct.pack(">BBHHHH", 0x32, 1, 0, seq, len(params), 0) + params))
                recv_frame(s)
                lat["s7"].append((time.time() - t) * 1000)
                res["s7"] += 1
                seq = (seq + 1) & 0xFFFF
            s.close()
        except Exception:
            res["s7_err"] += 1
            time.sleep(0.2)


def modbus_worker():
    while not stop.is_set():
        try:
            s = socket.create_connection((HOST, 502), timeout=5)
            s.settimeout(5)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for i in range(200):
                if stop.is_set():
                    break
                t = time.time()
                s.sendall(struct.pack(">HHHB", i % 60000 + 1, 0, 6, 0) + bytes([3, 0, 0, 0, 1]))
                if not s.recv(256):
                    raise IOError("closed")
                lat["mb"].append((time.time() - t) * 1000)
                res["mb"] += 1
            s.close()
        except Exception:
            res["mb_err"] += 1
            time.sleep(0.2)


def ua_thread():
    async def go():
        while not stop.is_set():
            try:
                async with Client(url=f"opc.tcp://{HOST}:4840/openplc/opcua", timeout=20) as c:
                    res["ua_sess"] += 1
                    nodes = []
                    for k in await c.nodes.objects.get_children():
                        bn = await k.read_browse_name()
                        if bn.NamespaceIndex != 0:
                            nodes.append(k)
                    while not stop.is_set():
                        for n in nodes:
                            await n.read_value()
                            res["ua"] += 1
            except Exception:
                res["ua_err"] += 1
                await asyncio.sleep(0.3)
    asyncio.run(go())


def main():
    print(f"three protocols against {HOST} for {SECS}s\n")
    threads = [threading.Thread(target=w, daemon=True)
               for w in (s7_worker, modbus_worker, ua_thread)]
    for t in threads:
        t.start()

    t0 = time.time()
    while time.time() - t0 < SECS:
        time.sleep(15)
        e = int(time.time() - t0)
        print(f"  t={e:4d}s  s7={res['s7']:6d}(err {res['s7_err']})"
              f"  modbus={res['mb']:6d}(err {res['mb_err']})"
              f"  opcua={res['ua']:6d}(err {res['ua_err']})", flush=True)

    stop.set()
    time.sleep(1.5)

    def pct(v, p):
        if not v:
            return 0.0
        v = sorted(v)
        return v[min(int(len(v) * p), len(v) - 1)]

    print(f"\nTOTAL  s7={res['s7']} err={res['s7_err']} sessions={res['s7_sess']}")
    print(f"       modbus={res['mb']} err={res['mb_err']}")
    print(f"       opcua={res['ua']} err={res['ua_err']} sessions={res['ua_sess']}")
    print(f"\nS7     median {pct(lat['s7'], .5):.2f} ms   p95 {pct(lat['s7'], .95):.2f} ms"
          f"   p99 {pct(lat['s7'], .99):.2f} ms   max {max(lat['s7'] or [0]):.2f} ms")
    print(f"Modbus median {pct(lat['mb'], .5):.2f} ms   p95 {pct(lat['mb'], .95):.2f} ms"
          f"   p99 {pct(lat['mb'], .99):.2f} ms   max {max(lat['mb'] or [0]):.2f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
