/*=============================================================================|
|  PROJECT SETTIMINO                                                     2.2.0 |
|==============================================================================|
|  Copyright (C) 2013, 2025 Davide Nardella                                    |
|  Server role (C) 2026 Autonomy Logic                                         |
|  All rights reserved.                                                        |
|==============================================================================|
|  SETTIMINO is free software: you can redistribute it and/or modify           |
|  it under the terms of the Lesser GNU General Public License as published by |
|  the Free Software Foundation, either version 3 of the License, or           |
|  (at your option) any later version.                                         |
|                                                                              |
|  SETTIMINO is distributed in the hope that it will be useful,                |
|  but WITHOUT ANY WARRANTY; without even the implied warranty of              |
|  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               |
|  Lesser GNU General Public License for more details.                         |
|=============================================================================*/

/*
  THE SERVER SIDE OF S7.

  Settimino has always been a client: it dials a PLC and asks it questions.
  This is the other half -- it answers them. An S7 server lets an HMI, a SCADA
  system, TIA Portal or another PLC read and write this device's memory using
  the protocol they already speak, with no gateway in between.

  ----------------------------------------------------------------------------
  IT OWNS NO SOCKET. THAT IS THE WHOLE DESIGN.
  ----------------------------------------------------------------------------

  S7Client opens its own connection, blocks on recv, and retries on a timeout,
  which is the right shape for a client: a sketch asks for a value and waits.

  A server cannot work that way. It has to be reachable while the rest of the
  program runs, and on the devices this library targets "the rest of the
  program" may be a PLC scan cycle with a few hundred microseconds to spare. A
  server that blocks on a peer is a server that lets a peer halt the machine.

  So S7Server is a PURE PROTOCOL ENGINE. You hand it one complete ISO-TCP frame
  and a buffer; it hands you back the bytes to reply with. It never reads, never
  writes, never waits, never allocates, and never calls millis(). Where the
  bytes came from is yours to decide -- EthernetServer, WiFiServer, lwIP raw,
  a cooperative poll loop, or a unit test on a PC with no network at all.

  This is also why the server is useful to a platform Settimino has never
  supported: there is no transport to port.

  ----------------------------------------------------------------------------
  THE SHAPE OF A SESSION
  ----------------------------------------------------------------------------

    S7SrvSession s;
    server.beginSession(s);                  // once per accepted connection

    // when a complete frame has arrived:
    uint16_t replyLen = 0;
    int r = server.handle(s, frame, frameLen, reply, sizeof(reply), &replyLen);
    if (replyLen) client.write(reply, replyLen);
    if (r == S7SRV_CLOSE) client.stop();

  S7IsoFrameLength() tells you when a frame is complete, so you can size the
  read without guessing:

    // buf holds `have` bytes so far
    uint16_t need = S7IsoFrameLength(buf, have);
    // 0  -> need at least 4 bytes before the length is knowable
    // >0 -> the frame is `need` bytes long in total

  ----------------------------------------------------------------------------
  WHERE THE DATA COMES FROM
  ----------------------------------------------------------------------------

  Two ways, and they can be mixed area by area.

  A FLAT BUFFER, like Snap7's Srv_RegisterArea:

      static uint8_t db1[128];
      static const S7SrvArea areas[] = {
        { S7AreaDB, 1, db1, sizeof(db1) },
      };
      server.setAreas(areas, 1);

  Or CALLBACKS, for a device whose values do not live in a buffer at all --
  a PLC image assembled per scan, a sensor read on demand, a register file:

      static const S7SrvArea areas[] = {
        { S7AreaMK, 0, NULL, 256 },   // NULL data => ask the accessors
      };
      server.setAreas(areas, 1);
      server.setAccessors(myRead, myWrite, &myContext);

  The area table is `const` on purpose: it is fixed when the program is built
  and never changes, so on a microcontroller it belongs in flash. Passing a
  RAM array works and costs you the RAM.
*/

#ifndef S7SERVER_H
#define S7SERVER_H

#include <stdint.h>
#include <stddef.h>

//-----------------------------------------------------------------------------
// Area codes and word lengths.
//
// Guarded because Settimino.h defines the same constants for the client, and a
// sketch may well include both -- the client to talk to a PLC, the server to be
// talked to. They are protocol constants; there is only one correct value.
//-----------------------------------------------------------------------------
#ifndef S7AreaPE
#define S7AreaPE    0x81  // Process inputs  (I)
#define S7AreaPA    0x82  // Process outputs (Q)
#define S7AreaMK    0x83  // Merkers         (M)
#define S7AreaDB    0x84  // Data blocks     (DB)
#define S7AreaCT    0x1C  // Counters
#define S7AreaTM    0x1D  // Timers
#endif

#ifndef S7WLBit
#define S7WLBit     0x01
#define S7WLByte    0x02
#define S7WLWord    0x04
#define S7WLDWord   0x06
#define S7WLReal    0x08
#define S7WLCounter 0x1C
#define S7WLTimer   0x1D
#endif

//-----------------------------------------------------------------------------
// Sizes
//-----------------------------------------------------------------------------

// TPKT (4) + COTP data header (3). Every S7 frame carries it.
#define S7ISO_HEADER_SIZE   7

// The S7 PDU size range a real CPU will negotiate. 240 is what an S7-300
// offers and what every client copes with; 960 is the ceiling in the wild.
#define S7SRV_PDU_MIN     240
#define S7SRV_PDU_MAX     960

// Largest frame this server will ever produce or accept.
#define S7SRV_FRAME_MAX   (S7ISO_HEADER_SIZE + S7SRV_PDU_MAX)

// Smallest useful reply buffer: enough for a Connection Confirm and for an
// error answer to any request. Pass handle() at least this much.
#define S7SRV_REPLY_MIN   32

//-----------------------------------------------------------------------------
// handle() results
//-----------------------------------------------------------------------------
#define S7SRV_REPLY     0   // *respLen bytes are ready to send
#define S7SRV_NOREPLY   1   // frame consumed, nothing to say
#define S7SRV_CLOSE     2   // send *respLen (may be 0), then drop the connection

//-----------------------------------------------------------------------------
// Data access
//-----------------------------------------------------------------------------

/** Read `len` bytes at `start` from (area, dbNumber) into `dest`.
 *
 *  `start` is a BYTE offset, already converted from S7's bit-address form.
 *  Return false to answer the client with "address out of range" rather than
 *  inventing data -- a wrong value is worse than an error, because the client
 *  cannot tell it apart from a right one. */
typedef bool (*S7SrvReadFn)(void* ctx, uint8_t area, uint16_t dbNumber,
                            uint32_t start, uint16_t len, uint8_t* dest);

/** Write `len` bytes from `src` at `start` in (area, dbNumber).
 *
 *  Return false to answer with "address out of range". Bit writes arrive as a
 *  single byte whose value is 0 or 1, which is how S7 sends them. */
typedef bool (*S7SrvWriteFn)(void* ctx, uint8_t area, uint16_t dbNumber,
                             uint32_t start, uint16_t len, const uint8_t* src);

/** One addressable area.
 *
 *  `dbNumber` is meaningful only for S7AreaDB; leave it 0 elsewhere. `data`
 *  NULL means the accessors serve this area. `size` is in bytes and is the
 *  bound every request is checked against. */
struct S7SrvArea
{
    uint8_t   code;
    uint16_t  dbNumber;
    uint8_t*  data;
    uint16_t  size;
};

/** Per-connection state. The host owns one of these per accepted socket.
 *
 *  It is deliberately a plain struct with no constructor: an embedded host
 *  wants an array of them in .bss, sized at compile time, and wants to see
 *  exactly what a connection costs. Today that is four bytes. */
struct S7SrvSession
{
    uint8_t   isoConnected;  // a COTP Connection Confirm has been sent
    uint16_t  pduSize;       // negotiated size, 0 until Setup Communication
    uint8_t   reserved;      // keeps the struct 4 bytes and aligned
};

//-----------------------------------------------------------------------------
// Frame helper
//-----------------------------------------------------------------------------

/** Total length of the ISO-TCP frame starting at `head`, or 0 if not yet
 *  knowable (fewer than 4 bytes seen). Returns 0xFFFF if the header is not a
 *  TPKT at all, which means the peer is not speaking this protocol and the
 *  connection should be dropped rather than resynchronised. */
uint16_t S7IsoFrameLength(const uint8_t* head, uint16_t have);

//-----------------------------------------------------------------------------
// The server
//-----------------------------------------------------------------------------
class S7Server
{
public:
    S7Server();

    /** The address space. The table must outlive the server; `const` in flash
     *  is the intended use. */
    void setAreas(const S7SrvArea* areas, uint8_t count);

    /** Accessors for areas whose `data` is NULL. Either may be NULL, in which
     *  case that direction is refused for callback-backed areas. */
    void setAccessors(S7SrvReadFn readFn, S7SrvWriteFn writeFn, void* ctx);

    /** Cap on the negotiated PDU. Clamped into [240, 960]. A client asking for
     *  more gets this; a client asking for less gets what it asked for. */
    void setMaxPduSize(uint16_t size);

    /** Refuse every Write Var. A read-only server is a legitimate and safer
     *  configuration for classic S7, which has no authentication whatsoever.
     *  The refusal is a proper S7 error, not a dropped connection. */
    void setWriteEnabled(bool enabled);

    /** Reset per-connection state. Call once per accepted connection. */
    void beginSession(S7SrvSession& session);

    /** Process one complete ISO-TCP frame.
     *
     *  `req`/`reqLen` is exactly one frame, as measured by S7IsoFrameLength().
     *  `resp` receives the reply; `respCap` must be at least S7SRV_REPLY_MIN
     *  and, to answer reads, at least S7ISO_HEADER_SIZE + the negotiated PDU.
     *  Returns one of S7SRV_REPLY / S7SRV_NOREPLY / S7SRV_CLOSE.
     *
     *  Never blocks, never allocates, and touches nothing outside `session`,
     *  `resp` and whatever the accessors do. */
    int handle(S7SrvSession& session,
               const uint8_t* req, uint16_t reqLen,
               uint8_t* resp, uint16_t respCap, uint16_t* respLen);

    /** Counters, for a device with no debugger attached. Free to keep and the
     *  first thing you want when a client will not talk to you. */
    uint32_t frames() const     { return FFrames; }
    uint32_t rejected() const   { return FRejected; }

    /** Largest PDU this server will negotiate. */
    uint16_t maxPduSize() const { return FMaxPdu; }

private:
    const S7SrvArea* FAreas;
    uint8_t          FAreaCount;
    S7SrvReadFn      FReadFn;
    S7SrvWriteFn     FWriteFn;
    void*            FCtx;
    uint16_t         FMaxPdu;
    bool             FWriteEnabled;
    uint32_t         FFrames;
    uint32_t         FRejected;

    int  cotpConnect(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                     uint8_t* resp, uint16_t respCap, uint16_t* respLen);
    int  s7Dispatch(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                    uint8_t* resp, uint16_t respCap, uint16_t* respLen);
    int  funNegotiate(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                      uint8_t* resp, uint16_t respCap, uint16_t* respLen);
    int  errorAnswer(const uint8_t* req, uint8_t* resp, uint16_t respCap,
                     uint16_t* respLen, uint16_t errorCode);
};

#endif // S7SERVER_H
