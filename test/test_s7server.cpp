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

    // A minimal Read Var job. Until Phase 1 this is not served, but the client
    // must learn that from an answer, not from a timeout.
    uint8_t read[] = {
        0x03, 0x00, 0x00, 0x1F,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x0E, 0x00, 0x00,
        0x04, 0x01,
        0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x00, 0x83, 0x00, 0x00, 0x00
    };

    int r = srv.handle(s, read, sizeof(read), resp, sizeof(resp), &n);
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
int main()
{
    printf("S7Server protocol tests\n\n");

    test_frame_length();
    test_connect();
    test_negotiate();
    test_unimplemented_is_answered();
    test_malformed_is_refused();
    test_counters();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
