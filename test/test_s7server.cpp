/*
  Host-side tests for S7Server.

  The server owns no socket, which is what makes this possible: the whole
  protocol engine can be driven from a PC with no network, no board and no
  PLC, and every answer inspected byte by byte. Run them before flashing
  anything.

      g++ -std=c++11 -Wall -Wextra -I.. ../S7Server.cpp test_s7server.cpp -o t && ./t

  There is also test_interop.py, which points a real python-snap7 client at a
  real device. These two answer different questions: this one asks "are the
  bytes right", that one asks "does a client that was not written against my
  assumptions agree".
*/

#include "../S7Server.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, ...) do {                                    \
    checks++;                                                    \
    if (!(cond)) {                                               \
        failures++;                                              \
        printf("  FAIL %s:%d  ", __FILE__, __LINE__);            \
        printf(__VA_ARGS__);                                     \
        printf("\n");                                            \
    }                                                            \
} while (0)

static void hexdump(const char* label, const uint8_t* p, uint16_t n)
{
    printf("  %s (%u):", label, n);
    for (uint16_t i = 0; i < n; i++) printf(" %02X", p[i]);
    printf("\n");
}

//-----------------------------------------------------------------------------
// Fixtures: real frames, as a client actually sends them.
//-----------------------------------------------------------------------------

// COTP Connection Request, rack 0 slot 2 -- byte for byte what Settimino's
// own client emits (ISO_CR in Settimino.cpp), which is what makes it a fair
// test: the client and the server in this library must agree.
static const uint8_t CR[] = {
    0x03, 0x00, 0x00, 0x16,
    0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
    0xC0, 0x01, 0x0A,
    0xC1, 0x02, 0x01, 0x00,
    0xC2, 0x02, 0x01, 0x02
};

// Setup Communication asking for 480 bytes.
static const uint8_t SETUP[] = {
    0x03, 0x00, 0x00, 0x19,
    0x02, 0xF0, 0x80,
    0x32, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x08, 0x00, 0x00,
    0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0
};

//-----------------------------------------------------------------------------
static void test_frame_length()
{
    printf("S7IsoFrameLength\n");

    uint8_t buf[8];
    memcpy(buf, CR, 8);

    CHECK(S7IsoFrameLength(buf, 0) == 0, "0 bytes should be 'not yet knowable'");
    CHECK(S7IsoFrameLength(buf, 3) == 0, "3 bytes should be 'not yet knowable'");
    CHECK(S7IsoFrameLength(buf, 4) == 0x16, "4 bytes is enough to know the length");
    CHECK(S7IsoFrameLength(buf, 8) == 0x16, "more bytes must not change the answer");

    // A peer that is not speaking ISO-TCP at all -- an HTTP GET, say, which is
    // what a browser sends when someone pastes the address into it.
    const uint8_t http[] = { 'G', 'E', 'T', ' ' };
    CHECK(S7IsoFrameLength(http, 4) == 0xFFFF, "non-TPKT must be rejected, not resynchronised");

    // Lengths that would make us wait forever or read out of bounds.
    const uint8_t tiny[]  = { 0x03, 0x00, 0x00, 0x03 };
    const uint8_t huge[]  = { 0x03, 0x00, 0xFF, 0xFF };
    CHECK(S7IsoFrameLength(tiny, 4) == 0xFFFF, "a frame shorter than the ISO header is nonsense");
    CHECK(S7IsoFrameLength(huge, 4) == 0xFFFF, "a frame past the ceiling is nonsense");
}

//-----------------------------------------------------------------------------
static void test_connect()
{
    printf("COTP Connection Request -> Confirm\n");

    S7Server srv;
    S7SrvSession s;
    srv.beginSession(s);

    uint8_t  resp[64];
    uint16_t n = 0;
    int r = srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);

    CHECK(r == S7SRV_REPLY, "a CR must be answered, got %d", r);
    CHECK(n == sizeof(CR), "the CC is the CR's length, got %u", n);
    CHECK(resp[5] == 0xD0, "PDU type must be CC (0xD0), got %02X", resp[5]);

    // DST-REF must be the client's SRC-REF or the client cannot match it.
    CHECK(resp[6] == CR[8] && resp[7] == CR[9], "DST-REF must echo the client's SRC-REF");
    CHECK(!(resp[8] == 0x00 && resp[9] == 0x00), "SRC-REF must be non-zero");

    // The variable part -- TSAPs and TPDU size -- is accepted by echoing it.
    CHECK(memcmp(resp + 11, CR + 11, sizeof(CR) - 11) == 0,
          "the variable part must come back unchanged");

    CHECK(s.isoConnected == 1, "the session must be marked connected");
    CHECK(s.pduSize == 0, "no PDU is negotiated yet at COTP time");

    if (failures) hexdump("CC", resp, n);
}

//-----------------------------------------------------------------------------
static void test_negotiate()
{
    printf("Setup Communication\n");

    S7Server srv;
    S7SrvSession s;
    srv.beginSession(s);

    uint8_t  resp[64];
    uint16_t n = 0;
    srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);

    int r = srv.handle(s, SETUP, sizeof(SETUP), resp, sizeof(resp), &n);
    CHECK(r == S7SRV_REPLY, "Setup Communication must be answered, got %d", r);
    CHECK(n == 7 + 12 + 8, "answer is ISO + 12-byte AckData header + 8 params, got %u", n);

    CHECK(resp[7] == 0x32, "protocol id");
    CHECK(resp[8] == 0x03, "must be AckData (3), got %02X", resp[8]);
    CHECK(resp[11] == SETUP[11] && resp[12] == SETUP[12],
          "the sequence number must be echoed or the client cannot match it");
    CHECK(resp[17] == 0x00 && resp[18] == 0x00, "error must be 0");
    CHECK(resp[19] == 0xF0, "parameter must be the negotiate function");

    // The client asked for 480 and the default cap is 240, so it gets 240.
    const uint16_t agreed = (uint16_t)(resp[25] << 8 | resp[26]);
    CHECK(agreed == 240, "default build must clamp 480 down to 240, got %u", agreed);
    CHECK(s.pduSize == agreed, "the session must remember what was agreed");

    // Raise the cap and the same request gets what it asked for.
    S7Server big;
    S7SrvSession s2;
    big.setMaxPduSize(960);
    big.beginSession(s2);
    big.handle(s2, CR, sizeof(CR), resp, sizeof(resp), &n);
    big.handle(s2, SETUP, sizeof(SETUP), resp, sizeof(resp), &n);
    const uint16_t agreed2 = (uint16_t)(resp[25] << 8 | resp[26]);
    CHECK(agreed2 == 480, "a 960-capable server must grant the 480 asked for, got %u", agreed2);

    if (failures) hexdump("negotiate", resp, n);
}

//-----------------------------------------------------------------------------
static void test_unimplemented_is_answered()
{
    printf("Unimplemented functions answer rather than go silent\n");

    S7Server srv;
    S7SrvSession s;
    srv.beginSession(s);

    uint8_t  resp[64];
    uint16_t n = 0;
    srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);
    srv.handle(s, SETUP, sizeof(SETUP), resp, sizeof(resp), &n);

    // Function 0x28 is PLC Control (start/stop), which this server does not
    // serve. A client must learn that from an ANSWER, not from a timeout: an
    // error names the problem, a timeout gets reported as "the device is dead".
    uint8_t ctrl[] = {
        0x03, 0x00, 0x00, 0x13,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x07, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x28, 0x00
    };

    int r = srv.handle(s, ctrl, sizeof(ctrl), resp, sizeof(resp), &n);
    CHECK(r == S7SRV_REPLY, "an unserved function must still get an answer, got %d", r);
    CHECK(resp[8] == 0x03, "the answer is an AckData");
    CHECK(resp[17] == 0x81 && resp[18] == 0x04,
          "error must be 0x8104 'not implemented', got %02X%02X", resp[17], resp[18]);
}

//-----------------------------------------------------------------------------
static void test_malformed_is_refused()
{
    printf("Malformed input is refused, not parsed\n");

    uint8_t  resp[64];
    uint16_t n = 0;

    // Data before the COTP handshake.
    {
        S7Server srv; S7SrvSession s; srv.beginSession(s);
        int r = srv.handle(s, SETUP, sizeof(SETUP), resp, sizeof(resp), &n);
        CHECK(r == S7SRV_CLOSE, "S7 data before the COTP handshake must close");
        CHECK(n == 0, "and say nothing");
    }

    // The declared length disagrees with what was delivered. Believing the
    // header here is how a length field turns into a read primitive.
    {
        S7Server srv; S7SrvSession s; srv.beginSession(s);
        uint8_t lying[sizeof(CR)];
        memcpy(lying, CR, sizeof(CR));
        lying[3] = 0xF0;
        int r = srv.handle(s, lying, sizeof(lying), resp, sizeof(resp), &n);
        CHECK(r == S7SRV_CLOSE, "a frame whose header lies about its length must close");
    }

    // A COTP header claiming to be longer than the frame that carries it.
    {
        S7Server srv; S7SrvSession s; srv.beginSession(s);
        uint8_t bad[sizeof(CR)];
        memcpy(bad, CR, sizeof(CR));
        bad[4] = 0x7F;
        int r = srv.handle(s, bad, sizeof(bad), resp, sizeof(resp), &n);
        CHECK(r == S7SRV_CLOSE, "an over-long COTP LI must close");
    }

    // S7 parameter and data lengths that do not add up to the PDU.
    {
        S7Server srv; S7SrvSession s; srv.beginSession(s);
        srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);
        uint8_t bad[sizeof(SETUP)];
        memcpy(bad, SETUP, sizeof(SETUP));
        bad[14] = 0x00; bad[15] = 0xFF;   // param len = 255
        int r = srv.handle(s, bad, sizeof(bad), resp, sizeof(resp), &n);
        CHECK(r == S7SRV_CLOSE, "inconsistent S7 header lengths must close");
    }

    // A reply buffer too small to hold even an error.
    {
        S7Server srv; S7SrvSession s; srv.beginSession(s);
        uint8_t tiny[8];
        int r = srv.handle(s, CR, sizeof(CR), tiny, sizeof(tiny), &n);
        CHECK(r == S7SRV_CLOSE, "an unusable reply buffer must close, not overflow");
        CHECK(n == 0, "and write nothing");
    }

    // Truncated frames at every length: none may read past the end. Run this
    // under a sanitiser and it is the whole bounds-checking story in one loop.
    {
        for (uint16_t cut = 1; cut < sizeof(SETUP); cut++)
        {
            S7Server srv; S7SrvSession s; srv.beginSession(s);
            srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);
            uint8_t frag[sizeof(SETUP)];
            memcpy(frag, SETUP, cut);
            (void)srv.handle(s, frag, cut, resp, sizeof(resp), &n);
        }
        CHECK(true, "truncated frames survived (run under ASan for the real check)");
    }
}

//-----------------------------------------------------------------------------
static void test_counters()
{
    printf("Counters\n");

    S7Server srv;
    S7SrvSession s;
    srv.beginSession(s);

    uint8_t  resp[64];
    uint16_t n = 0;
    srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);
    srv.handle(s, SETUP, sizeof(SETUP), resp, sizeof(resp), &n);

    CHECK(srv.frames() == 2, "two good frames, got %u", (unsigned)srv.frames());
    CHECK(srv.rejected() == 0, "nothing was rejected, got %u", (unsigned)srv.rejected());

    const uint8_t junk[] = { 0x03, 0x00, 0x00, 0x08, 0x03, 0x99, 0x00, 0x00 };
    srv.handle(s, junk, sizeof(junk), resp, sizeof(resp), &n);
    CHECK(srv.rejected() == 1, "an unknown COTP type counts as rejected");
}

//-----------------------------------------------------------------------------
// Read Var / Write Var
//-----------------------------------------------------------------------------

static uint8_t g_db1[64];
static uint8_t g_mk[32];
static bool    g_cbReadCalled = false;

static bool cbRead(void* ctx, uint8_t area, uint16_t db, uint32_t start,
                   uint16_t len, uint8_t* dest)
{
    (void)ctx; (void)area; (void)db;
    g_cbReadCalled = true;
    if (start + len > sizeof(g_mk)) return false;
    memcpy(dest, g_mk + start, len);
    return true;
}

static bool cbWrite(void* ctx, uint8_t area, uint16_t db, uint32_t start,
                    uint16_t len, const uint8_t* src)
{
    (void)ctx; (void)area; (void)db;
    if (start + len > sizeof(g_mk)) return false;
    memcpy(g_mk + start, src, len);
    return true;
}

static const S7SrvArea AREAS[] = {
    { S7AreaDB, 1, g_db1, (uint16_t)sizeof(g_db1), false },
    { S7AreaMK, 0, NULL,  (uint16_t)sizeof(g_mk),  false },
    { S7AreaPE, 0, g_db1, 8,                       true  },   // read-only
};

/** Build a Read Var request for one item. */
static uint16_t buildRead(uint8_t* buf, uint8_t transport, uint16_t count,
                          uint16_t db, uint8_t area, uint32_t bitAddr)
{
    uint8_t* p = buf;
    *p++ = 0x03; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;       // TPKT, filled below
    *p++ = 0x02; *p++ = 0xF0; *p++ = 0x80;                    // COTP DT
    *p++ = 0x32; *p++ = 0x01;                                 // S7 job
    *p++ = 0x00; *p++ = 0x00;                                 // redundancy
    *p++ = 0x00; *p++ = 0x05;                                 // sequence
    *p++ = 0x00; *p++ = 14;                                   // param len
    *p++ = 0x00; *p++ = 0x00;                                 // data len
    *p++ = 0x04; *p++ = 0x01;                                 // Read Var, 1 item
    *p++ = 0x12; *p++ = 0x0A; *p++ = 0x10; *p++ = transport;
    *p++ = (uint8_t)(count >> 8); *p++ = (uint8_t)count;
    *p++ = (uint8_t)(db >> 8);    *p++ = (uint8_t)db;
    *p++ = area;
    *p++ = (uint8_t)(bitAddr >> 16); *p++ = (uint8_t)(bitAddr >> 8); *p++ = (uint8_t)bitAddr;
    const uint16_t total = (uint16_t)(p - buf);
    buf[2] = (uint8_t)(total >> 8); buf[3] = (uint8_t)total;
    return total;
}

/** Build a Write Var request for one item. */
static uint16_t buildWrite(uint8_t* buf, uint8_t transport, uint16_t count,
                           uint16_t db, uint8_t area, uint32_t bitAddr,
                           uint8_t resTs, uint16_t declaredLen,
                           const uint8_t* value, uint16_t valueLen)
{
    uint8_t* p = buf;
    *p++ = 0x03; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x02; *p++ = 0xF0; *p++ = 0x80;
    *p++ = 0x32; *p++ = 0x01;
    *p++ = 0x00; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x06;
    *p++ = 0x00; *p++ = 14;
    *p++ = (uint8_t)((4 + valueLen) >> 8); *p++ = (uint8_t)(4 + valueLen);
    *p++ = 0x05; *p++ = 0x01;
    *p++ = 0x12; *p++ = 0x0A; *p++ = 0x10; *p++ = transport;
    *p++ = (uint8_t)(count >> 8); *p++ = (uint8_t)count;
    *p++ = (uint8_t)(db >> 8);    *p++ = (uint8_t)db;
    *p++ = area;
    *p++ = (uint8_t)(bitAddr >> 16); *p++ = (uint8_t)(bitAddr >> 8); *p++ = (uint8_t)bitAddr;
    *p++ = 0x00; *p++ = resTs;
    *p++ = (uint8_t)(declaredLen >> 8); *p++ = (uint8_t)declaredLen;
    memcpy(p, value, valueLen); p += valueLen;
    const uint16_t total = (uint16_t)(p - buf);
    buf[2] = (uint8_t)(total >> 8); buf[3] = (uint8_t)total;
    return total;
}

/** Bring a server up to the point where it will serve reads and writes. */
static void ready(S7Server& srv, S7SrvSession& s, uint8_t* resp, uint16_t cap)
{
    srv.setAreas(AREAS, 3);
    srv.setAccessors(cbRead, cbWrite, NULL);
    srv.setMaxPduSize(480);
    srv.beginSession(s);
    uint16_t n = 0;
    srv.handle(s, CR, sizeof(CR), resp, cap, &n);
    srv.handle(s, SETUP, sizeof(SETUP), resp, cap, &n);
}

static void reset_areas()
{
    for (size_t i = 0; i < sizeof(g_db1); i++) g_db1[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(g_mk);  i++) g_mk[i]  = (uint8_t)(0xA0 + i);
    g_cbReadCalled = false;
}

static void test_read()
{
    printf("Read Var\n");
    reset_areas();

    S7Server srv; S7SrvSession s;
    uint8_t resp[600]; uint16_t n = 0;
    ready(srv, s, resp, sizeof(resp));

    // Four bytes of DB1 from offset 8.
    uint8_t req[64];
    uint16_t len = buildRead(req, S7WLByte, 4, 1, S7AreaDB, 8 * 8);
    int r = srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(r == S7SRV_REPLY, "a read must be answered");

    const uint8_t* item = resp + 7 + 12 + 2;
    CHECK(item[0] == 0xFF, "return code should be 0xFF, got %02X", item[0]);
    CHECK(item[1] == 0x04, "transport should be TS_ResByte, got %02X", item[1]);
    // BITS for byte reads: four bytes is 32.
    CHECK(((item[2] << 8) | item[3]) == 32, "byte length must be in BITS, got %d",
          (item[2] << 8) | item[3]);
    CHECK(memcmp(item + 4, g_db1 + 8, 4) == 0, "wrong bytes came back");

    // A callback-backed area goes through the accessor, not a buffer.
    len = buildRead(req, S7WLByte, 2, 0, S7AreaMK, 0);
    srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(g_cbReadCalled, "a NULL-data area must be served by the read callback");
    CHECK(item[0] == 0xFF && item[4] == 0xA0 && item[5] == 0xA1,
          "callback data did not arrive intact");
}

static void test_read_bit()
{
    printf("Read Var — single bit\n");
    reset_areas();
    g_db1[1] = 0x01;   // bit 0 set, 1..7 clear

    S7Server srv; S7SrvSession s;
    uint8_t resp[600]; uint16_t n = 0;
    ready(srv, s, resp, sizeof(resp));

    for (uint8_t bit = 0; bit < 8; bit++)
    {
        uint8_t req[64];
        const uint16_t len = buildRead(req, S7WLBit, 1, 1, S7AreaDB, 8 + bit);
        srv.handle(s, req, len, resp, sizeof(resp), &n);

        const uint8_t* item = resp + 7 + 12 + 2;
        CHECK(item[0] == 0xFF, "bit %u: return code %02X", bit, item[0]);
        CHECK(item[1] == 0x03, "bit %u: transport %02X, expected TS_ResBit", bit, item[1]);
        // 1, not 8. See the note in funRead(): sending 8 would make Snap7's C
        // client memcpy eight bytes into the one byte it allocated.
        CHECK(((item[2] << 8) | item[3]) == 1, "bit %u: length %d, expected 1",
              bit, (item[2] << 8) | item[3]);
        CHECK(item[4] == (bit == 0 ? 1 : 0),
              "bit %u of 0x01 read back as %u", bit, item[4]);
    }
}

static void test_read_refusals()
{
    printf("Read Var — what it refuses\n");
    reset_areas();

    S7Server srv; S7SrvSession s;
    uint8_t resp[600]; uint16_t n = 0;
    ready(srv, s, resp, sizeof(resp));

    uint8_t req[64];
    const uint8_t* item = resp + 7 + 12 + 2;

    // Past the end of the area.
    uint16_t len = buildRead(req, S7WLByte, 8, 1, S7AreaDB, 60 * 8);
    srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(item[0] == 0x05, "out of range should be 0x05, got %02X", item[0]);
    // A failed item still declares a length; clients parse it.
    CHECK(((item[2] << 8) | item[3]) == 4, "a failed item should declare length 4");

    // A DB that was never registered.
    len = buildRead(req, S7WLByte, 2, 99, S7AreaDB, 0);
    srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(item[0] == 0x0A, "missing area should be 0x0A, got %02X", item[0]);

    // A transport size that is not one.
    len = buildRead(req, 0x77, 1, 1, S7AreaDB, 0);
    srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(item[0] == 0x06, "bad transport should be 0x06, got %02X", item[0]);

    // A word read from an address that is not byte-aligned.
    len = buildRead(req, S7WLWord, 1, 1, S7AreaDB, 3);
    srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(item[0] == 0x05, "unaligned word read should be 0x05, got %02X", item[0]);

    // The whole request still succeeded; only the item failed.
    CHECK(resp[17] == 0x00 && resp[18] == 0x00,
          "the header error must stay 0 -- a failed ITEM is not a failed REQUEST");
}

static void test_write()
{
    printf("Write Var\n");
    reset_areas();

    S7Server srv; S7SrvSession s;
    uint8_t resp[600]; uint16_t n = 0;
    ready(srv, s, resp, sizeof(resp));

    uint8_t req[64];
    const uint8_t payload[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

    uint16_t len = buildWrite(req, S7WLByte, 4, 1, S7AreaDB, 16 * 8,
                              0x04, 32, payload, 4);
    int r = srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(r == S7SRV_REPLY, "a write must be answered");
    CHECK(resp[7 + 12 + 2] == 0xFF, "write should succeed, got %02X", resp[7 + 12 + 2]);
    CHECK(memcmp(g_db1 + 16, payload, 4) == 0, "the bytes did not land");

    // The callback path.
    const uint8_t two[2] = { 0x11, 0x22 };
    len = buildWrite(req, S7WLByte, 2, 0, S7AreaMK, 4 * 8, 0x04, 16, two, 2);
    srv.handle(s, req, len, resp, sizeof(resp), &n);
    CHECK(g_mk[4] == 0x11 && g_mk[5] == 0x22, "callback write did not land");
}

static void test_write_bit_both_conventions()
{
    printf("Write Var — a bit, from either client convention\n");

    // Snap7 1.4.3 declares a bit's length as 1; python-snap7 3.1.2 declares 8.
    // A bit is one byte on the wire either way, and the spec already pinned
    // the size, so both must be accepted -- refusing one would mean refusing
    // whichever client we happened not to test against.
    const uint16_t declared[2] = { 1, 8 };
    const char* who[2] = { "Snap7 1.4.3 (len=1)", "python-snap7 3.1.2 (len=8)" };

    for (int k = 0; k < 2; k++)
    {
        reset_areas();
        g_db1[20] = 0x00;

        S7Server srv; S7SrvSession s;
        uint8_t resp[600]; uint16_t n = 0;
        ready(srv, s, resp, sizeof(resp));

        uint8_t req[64];
        const uint8_t one = 0x01;
        uint16_t len = buildWrite(req, S7WLBit, 1, 1, S7AreaDB, 20 * 8 + 3,
                                  0x03, declared[k], &one, 1);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(resp[7 + 12 + 2] == 0xFF, "%s: write refused (%02X)", who[k], resp[7 + 12 + 2]);
        CHECK(g_db1[20] == 0x08, "%s: expected 0x08, got 0x%02X", who[k], g_db1[20]);

        // And clearing one bit must leave the other seven alone.
        g_db1[20] = 0xFF;
        const uint8_t zero = 0x00;
        len = buildWrite(req, S7WLBit, 1, 1, S7AreaDB, 20 * 8 + 3,
                         0x03, declared[k], &zero, 1);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(g_db1[20] == 0xF7, "%s: expected 0xF7, got 0x%02X", who[k], g_db1[20]);
    }
}

static void test_write_refusals()
{
    printf("Write Var — what it refuses\n");
    reset_areas();

    uint8_t resp[600]; uint16_t n = 0;
    uint8_t req[64];
    const uint8_t payload[4] = { 1, 2, 3, 4 };

    // A read-only AREA.
    {
        S7Server srv; S7SrvSession s;
        ready(srv, s, resp, sizeof(resp));
        const uint16_t len = buildWrite(req, S7WLByte, 4, 0, S7AreaPE, 0, 0x04, 32, payload, 4);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(resp[7 + 12 + 2] == 0x0A, "a read-only area must refuse, got %02X",
              resp[7 + 12 + 2]);
    }

    // A read-only SERVER.
    {
        S7Server srv; S7SrvSession s;
        ready(srv, s, resp, sizeof(resp));
        srv.setWriteEnabled(false);
        const uint16_t len = buildWrite(req, S7WLByte, 4, 1, S7AreaDB, 0, 0x04, 32, payload, 4);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(resp[7 + 12 + 2] == 0x0A, "a read-only server must refuse, got %02X",
              resp[7 + 12 + 2]);
        CHECK(g_db1[0] == 0x00, "and must not have written anything");
    }

    // The spec says four bytes and the value carries two. Writing the shorter
    // of the two would put a truncated value into a PLC.
    {
        reset_areas();
        S7Server srv; S7SrvSession s;
        ready(srv, s, resp, sizeof(resp));
        const uint16_t len = buildWrite(req, S7WLByte, 4, 1, S7AreaDB, 0, 0x04, 16, payload, 2);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(resp[7 + 12 + 2] == 0x07, "a size mismatch must be 0x07, got %02X",
              resp[7 + 12 + 2]);
        CHECK(g_db1[0] == 0x00, "and nothing may be written");
    }

    // Past the end.
    {
        reset_areas();
        S7Server srv; S7SrvSession s;
        ready(srv, s, resp, sizeof(resp));
        const uint16_t len = buildWrite(req, S7WLByte, 4, 1, S7AreaDB, 62 * 8, 0x04, 32, payload, 4);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(resp[7 + 12 + 2] == 0x05, "out of range must be 0x05, got %02X",
              resp[7 + 12 + 2]);
    }

    // A bit write to a callback area with no bit writer: refused rather than
    // served by a read-modify-write that would re-assert seven neighbours.
    {
        reset_areas();
        S7Server srv; S7SrvSession s;
        ready(srv, s, resp, sizeof(resp));
        const uint8_t one = 1;
        const uint16_t len = buildWrite(req, S7WLBit, 1, 0, S7AreaMK, 3, 0x03, 1, &one, 1);
        srv.handle(s, req, len, resp, sizeof(resp), &n);
        CHECK(resp[7 + 12 + 2] == 0x0A,
              "a bit write with no bit writer must refuse, got %02X", resp[7 + 12 + 2]);
    }
}

static void test_pdu_is_respected()
{
    printf("An answer never exceeds the negotiated PDU\n");
    reset_areas();

    S7Server srv; S7SrvSession s;
    uint8_t resp[600]; uint16_t n = 0;
    srv.setAreas(AREAS, 3);
    srv.setAccessors(cbRead, cbWrite, NULL);
    srv.setMaxPduSize(240);          // cap BELOW the buffer we hand it
    srv.beginSession(s);
    srv.handle(s, CR, sizeof(CR), resp, sizeof(resp), &n);
    srv.handle(s, SETUP, sizeof(SETUP), resp, sizeof(resp), &n);

    uint8_t req[64];
    const uint16_t len = buildRead(req, S7WLByte, 64, 1, S7AreaDB, 0);
    srv.handle(s, req, len, resp, sizeof(resp), &n);

    // A client that agreed to 240 must not be sent more, however much room we
    // happen to have.
    CHECK(n <= 7 + 240, "answer was %u bytes against a 240-byte PDU", n);
}

//-----------------------------------------------------------------------------
int main()
{
    printf("S7Server protocol tests\n\n");

    test_frame_length();
    test_connect();
    test_negotiate();
    test_unimplemented_is_answered();
    test_malformed_is_refused();
    test_counters();
    test_read();
    test_read_bit();
    test_read_refusals();
    test_write();
    test_write_bit_both_conventions();
    test_write_refusals();
    test_pdu_is_respected();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
