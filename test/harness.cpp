/*
  A POSIX TCP server around S7Server, so a real S7 client can be pointed at
  the protocol engine without a board in the room.

      g++ -std=c++11 -I.. ../S7Server.cpp harness.cpp -o harness && ./harness 1102

  This is a TEST HARNESS, not an example: it blocks on accept() and recv(),
  which is exactly what the library is built not to do on a device. It exists
  because "does python-snap7 agree with us" is a different question from "are
  the bytes what we intended", and only a real client can answer it.

  The socket handling here is the part a device replaces. Everything below the
  S7Server calls is throwaway; everything at them is the real API.
*/

#include "../S7Server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// The address space the client will see. Deliberately a mix: a flat buffer for
// DB1, callbacks for the merkers, so both paths are exercised.
static uint8_t db1[256];
static uint8_t mk[128];
static uint8_t pe[64];

static bool mkRead(void* ctx, uint8_t area, uint16_t db, uint32_t start,
                   uint16_t len, uint8_t* dest)
{
    (void)ctx; (void)db;
    const uint8_t* src = (area == S7AreaPE) ? pe : mk;
    const size_t   cap = (area == S7AreaPE) ? sizeof(pe) : sizeof(mk);
    if (start + len > cap) return false;
    memcpy(dest, src + start, len);
    return true;
}

static bool mkWrite(void* ctx, uint8_t area, uint16_t db, uint32_t start,
                    uint16_t len, const uint8_t* src)
{
    (void)ctx; (void)area; (void)db;
    if (start + len > sizeof(mk)) return false;
    memcpy(mk + start, src, len);
    return true;
}

// A mix on purpose: a flat buffer for DB1, callbacks for the merkers, and a
// read-only process-input area -- so all three paths are exercised.
static const S7SrvIdentity IDENTITY = {
    "OpenPLC-TEST",              // systemName
    "CPU 315-2 PN/DP",           // moduleName
    "Bench",                     // plantId
    "Original Siemens Equipment",// copyright
    "S C-TEST00000001",          // serialNumber
    "CPU 315-2 PN/DP",           // moduleTypeName
    "6ES7 315-2EH14-0AB0",       // orderCode
};

static bool onControl(void* ctx, bool run)
{
    (void)ctx;
    printf("  control: %s\n", run ? "START" : "STOP");
    fflush(stdout);
    return true;
}

static const S7SrvArea AREAS[] = {
    { S7AreaDB, 1, db1,  (uint16_t)sizeof(db1), false },
    { S7AreaMK, 0, NULL, (uint16_t)sizeof(mk),  false },
    { S7AreaPE, 0, NULL, (uint16_t)sizeof(pe),  true  },
};

static bool mkWriteBit(void* ctx, uint8_t area, uint16_t db, uint32_t byteIndex,
                       uint8_t bitIndex, bool value)
{
    (void)ctx; (void)area; (void)db;
    if (byteIndex >= sizeof(mk)) return false;
    if (value) mk[byteIndex] |=  (uint8_t)(1u << bitIndex);
    else       mk[byteIndex] &= (uint8_t)~(1u << bitIndex);
    return true;
}

int main(int argc, char** argv)
{
    const int port = (argc > 1) ? atoi(argv[1]) : 1102;

    signal(SIGPIPE, SIG_IGN);

    for (size_t i = 0; i < sizeof(db1); i++) db1[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(mk);  i++) mk[i]  = (uint8_t)(0xA0 + i);
    for (size_t i = 0; i < sizeof(pe);  i++) pe[i]  = (uint8_t)(0x50 + i);

    S7Server server;
    server.setAreas(AREAS, (uint8_t)(sizeof(AREAS) / sizeof(AREAS[0])));
    server.setAccessors(mkRead, mkWrite, NULL);
    server.setBitWriter(mkWriteBit);
    server.setIdentity(&IDENTITY);
    server.setControlHandler(onControl);
    server.setMaxPduSize(480);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons((uint16_t)port);

    if (bind(ls, (sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    if (listen(ls, 4) != 0) { perror("listen"); return 1; }

    printf("harness listening on 127.0.0.1:%d\n", port);
    fflush(stdout);

    for (;;)
    {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) continue;
        setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        S7SrvSession session;
        server.beginSession(session);

        uint8_t  rx[S7SRV_FRAME_MAX];
        uint8_t  tx[S7SRV_FRAME_MAX];
        uint16_t have = 0;
        bool     alive = true;

        while (alive)
        {
            // Read until a complete frame is in hand. S7IsoFrameLength() says
            // how much that is as soon as four bytes have arrived.
            uint16_t need = S7IsoFrameLength(rx, have);
            if (need == 0xFFFF) break;

            const uint16_t want = need ? need : 4;
            if (have < want)
            {
                ssize_t got = recv(cs, rx + have, (size_t)(want - have), 0);
                if (got <= 0) break;
                have += (uint16_t)got;
                continue;
            }

            uint16_t txLen = 0;
            int r = server.handle(session, rx, need, tx, sizeof(tx), &txLen);

            if (txLen)
            {
                size_t sent = 0;
                while (sent < txLen)
                {
                    ssize_t w = send(cs, tx + sent, txLen - sent, 0);
                    if (w <= 0) { alive = false; break; }
                    sent += (size_t)w;
                }
            }
            if (r == S7SRV_CLOSE) alive = false;
            have = 0;
        }

        close(cs);
        printf("session closed  frames=%u rejected=%u reads=%u writes=%u\n",
               (unsigned)server.frames(), (unsigned)server.rejected(),
               (unsigned)server.reads(), (unsigned)server.writes());
        fflush(stdout);
    }
}
