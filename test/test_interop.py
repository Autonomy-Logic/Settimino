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

    # Phase 1 territory. Until Read Var is served, the SERVER MUST STILL ANSWER:
    # the client should report an S7 error, not a timeout. That distinction is
    # the whole reason errorAnswer() exists.
    check("an unserved function returns an error rather than timing out",
          lambda: _expect_s7_error(client))

    client.disconnect()
    check("disconnect is clean", lambda: "")

    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


def _pdu(client):
    size = client.get_pdu_length()
    if not (240 <= size <= 960):
        raise AssertionError(f"negotiated {size}, outside 240..960")
    return f"{size} bytes"


def _expect_s7_error(client):
    import time
    started = time.time()
    try:
        client.db_read(1, 0, 4)
    except Exception as exc:  # noqa: BLE001
        elapsed = time.time() - started
        if elapsed > 2.0:
            raise AssertionError(
                f"took {elapsed:.1f}s -- that is a timeout, not an answer") from exc
        return f"answered in {elapsed * 1000:.0f} ms: {exc}"
    return "served (Read Var is implemented)"


if __name__ == "__main__":
    sys.exit(main())
