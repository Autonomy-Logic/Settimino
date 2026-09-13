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
  The protocol is Snap7's -- this is the server side of what Settimino's client
  already speaks, and Snap7's TS7Worker is the reference for it. No protocol
  behaviour here is invented; where a choice existed it was made the way a real
  S7-300 makes it, because that is what the clients in the field were written
  against.

  Everything is written against the byte stream rather than against packed
  structs. Snap7 can afford `#pragma pack(1)` overlays because it runs on
  hosts with settled ABIs; a library that compiles for AVR, ARM, Xtensa and
  RISC-V cannot, and a misaligned 16-bit load is a fault on some of them and a
  silently wrong value on others. Byte offsets are tedious and they are right
  everywhere.
*/

#include "S7Server.h"
#include <string.h>

//-----------------------------------------------------------------------------
// Wire helpers. S7 is big-endian; most of the parts running it are not.
//-----------------------------------------------------------------------------
static inline uint16_t rdW(const uint8_t* p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static inline void wrW(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

//-----------------------------------------------------------------------------
// TPKT / COTP
//-----------------------------------------------------------------------------
// TPKT:  [0]=0x03 version  [1]=0x00 reserved  [2..3]=total length, big-endian,
//        INCLUDING these four bytes.
// COTP:  [4]=LI (length of the COTP header after this byte)
//        [5]=PDU type: 0xE0 CR, 0xD0 CC, 0x80 DT, 0x80|0x00 ...
#define TPKT_VERSION      0x03
#define COTP_PDU_CR       0xE0   // Connection Request
#define COTP_PDU_CC       0xD0   // Connection Confirm
#define COTP_PDU_DT       0xF0   // Data Transfer
#define COTP_PDU_DR       0x80   // Disconnect Request

// S7 PDU, immediately after the 7-byte ISO header:
//   [0]=0x32 protocol id   [1]=PDU type   [2..3]=redundancy (0)
//   [4..5]=sequence        [6..7]=param len   [8..9]=data len
//   type 2/3 answers carry two more bytes of error class/code at [10..11]
#define S7_PROTO_ID       0x32
#define S7_PDU_JOB        0x01
#define S7_PDU_ACK        0x02
#define S7_PDU_ACKDATA    0x03
#define S7_PDU_USERDATA   0x07

#define S7_REQ_HEADER     10
#define S7_RES_HEADER     12

// Functions
#define S7_FUN_READ       0x04
#define S7_FUN_WRITE      0x05
#define S7_FUN_NEGOTIATE  0xF0

// Error codes carried in the type-3 header (big-endian word).
// 0x8104 is what a real CPU answers for "this service is not implemented".
#define S7_ERR_NONE           0x0000
#define S7_ERR_NOT_IMPLEMENTED 0x8104

//-----------------------------------------------------------------------------
uint16_t S7IsoFrameLength(const uint8_t* head, uint16_t have)
{
    if (have < 4)
        return 0;                 // the length lives in bytes 2..3

    if (head[0] != TPKT_VERSION)
        return 0xFFFF;            // not TPKT: the peer is not speaking ISO-TCP

    const uint16_t len = rdW(head + 2);

    // A frame shorter than the ISO header cannot contain anything, and one
    // longer than the ceiling is either a different protocol or an attempt to
    // make us wait for bytes that will never come. Both are "drop it".
    if (len < S7ISO_HEADER_SIZE || len > S7SRV_FRAME_MAX)
        return 0xFFFF;

    return len;
}

//-----------------------------------------------------------------------------
S7Server::S7Server()
{
    FAreas        = NULL;
    FAreaCount    = 0;
    FReadFn       = NULL;
    FWriteFn      = NULL;
    FCtx          = NULL;
    FMaxPdu       = S7SRV_PDU_MIN;
    FWriteEnabled = true;
    FFrames       = 0;
    FRejected     = 0;
}

void S7Server::setAreas(const S7SrvArea* areas, uint8_t count)
{
    FAreas     = areas;
    FAreaCount = count;
}

void S7Server::setAccessors(S7SrvReadFn readFn, S7SrvWriteFn writeFn, void* ctx)
{
    FReadFn  = readFn;
    FWriteFn = writeFn;
    FCtx     = ctx;
}

void S7Server::setMaxPduSize(uint16_t size)
{
    if (size < S7SRV_PDU_MIN) size = S7SRV_PDU_MIN;
    if (size > S7SRV_PDU_MAX) size = S7SRV_PDU_MAX;
    FMaxPdu = size;
}

void S7Server::setWriteEnabled(bool enabled)
{
    FWriteEnabled = enabled;
}

void S7Server::beginSession(S7SrvSession& session)
{
    session.isoConnected = 0;
    session.pduSize      = 0;
    session.reserved     = 0;
}

//-----------------------------------------------------------------------------
int S7Server::handle(S7SrvSession& session,
                     const uint8_t* req, uint16_t reqLen,
                     uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    *respLen = 0;

    if (respCap < S7SRV_REPLY_MIN)
        return S7SRV_CLOSE;   // we cannot even answer an error; do not try

    if (reqLen < S7ISO_HEADER_SIZE || req[0] != TPKT_VERSION)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    // Trust the declared length over the delivered one only when they agree.
    // A mismatch means the caller's framing is wrong, and parsing past it is
    // how a length field becomes a read primitive.
    if (rdW(req + 2) != reqLen)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    FFrames++;

    const uint8_t cotpType = req[5];

    switch (cotpType)
    {
        case COTP_PDU_CR:
            return cotpConnect(session, req, reqLen, resp, respCap, respLen);

        case COTP_PDU_DT:
            if (!session.isoConnected)
            {
                // Data before the COTP handshake. A real CPU has nothing to
                // say to this and neither do we.
                FRejected++;
                return S7SRV_CLOSE;
            }
            return s7Dispatch(session, req, reqLen, resp, respCap, respLen);

        case COTP_PDU_DR:
            return S7SRV_CLOSE;

        default:
            FRejected++;
            return S7SRV_CLOSE;
    }
}

//-----------------------------------------------------------------------------
// COTP Connection Request -> Connection Confirm.
//
// The confirm is the request echoed back with the PDU type changed and the
// references swapped. That is what Snap7 does (IsoConfirmConnection) and it is
// what the clients expect: the variable part carries the TSAPs and the TPDU
// size the client proposed, and handing them straight back accepts them.
//
// Echoing also means we never have to parse the variable part, which is the
// part whose length a malicious client controls.
//-----------------------------------------------------------------------------
int S7Server::cotpConnect(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                          uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    // LI covers the COTP header from byte 5 onward, so the whole COTP part is
    // LI+1 bytes and must fit inside the frame after the 4 TPKT bytes.
    const uint8_t li = req[4];
    if (li < 6 || (uint16_t)(4 + 1 + li) != reqLen)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    if (reqLen > respCap)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    memcpy(resp, req, reqLen);
    resp[5] = COTP_PDU_CC;

    // DST-REF := the client's SRC-REF, so it recognises the answer.
    resp[6] = req[8];
    resp[7] = req[9];
    // SRC-REF := ours. Snap7 sends a constant here rather than echoing, and
    // clients accept it; a reference only has to be unique to us.
    resp[8] = 0x01;
    resp[9] = 0x00;

    s.isoConnected = 1;
    s.pduSize      = 0;    // still to be negotiated

    *respLen = reqLen;
    return S7SRV_REPLY;
}

//-----------------------------------------------------------------------------
// S7 PDU dispatch
//-----------------------------------------------------------------------------
int S7Server::s7Dispatch(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                         uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    const uint8_t* pdu    = req + S7ISO_HEADER_SIZE;
    const uint16_t pduLen = (uint16_t)(reqLen - S7ISO_HEADER_SIZE);

    if (pduLen < S7_REQ_HEADER || pdu[0] != S7_PROTO_ID)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    const uint16_t parLen  = rdW(pdu + 6);
    const uint16_t dataLen = rdW(pdu + 8);

    // The header's own idea of how long the PDU is must match what arrived.
    // Believing the header instead would let a client point the parameter
    // parser past the end of the buffer.
    if ((uint32_t)S7_REQ_HEADER + parLen + dataLen != pduLen || parLen < 1)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    const uint8_t fun = pdu[S7_REQ_HEADER];

    switch (fun)
    {
        case S7_FUN_NEGOTIATE:
            return funNegotiate(s, req, reqLen, resp, respCap, respLen);

        case S7_FUN_READ:
        case S7_FUN_WRITE:
            // Phase 1. Until then answer honestly rather than going silent:
            // a client that gets "not implemented" reports a useful message,
            // a client that gets nothing reports a timeout.
            return errorAnswer(req, resp, respCap, respLen, S7_ERR_NOT_IMPLEMENTED);

        default:
            return errorAnswer(req, resp, respCap, respLen, S7_ERR_NOT_IMPLEMENTED);
    }
}

//-----------------------------------------------------------------------------
// Setup Communication.
//
// The client proposes a parallel-job count and a PDU size; the CPU answers
// with what it will actually do. We accept the job counts as offered (we
// serialise anyway, so promising fewer would only make clients pipeline less)
// and clamp the PDU into what this build can buffer.
//-----------------------------------------------------------------------------
int S7Server::funNegotiate(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                           uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    const uint8_t* pdu = req + S7ISO_HEADER_SIZE;

    // Parameters: [0]=0xF0 [1]=unknown [2..3]=jobs1 [4..5]=jobs2 [6..7]=pdu
    if ((uint16_t)(reqLen - S7ISO_HEADER_SIZE) < S7_REQ_HEADER + 8)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    const uint8_t* reqPar = pdu + S7_REQ_HEADER;

    const uint16_t total = S7ISO_HEADER_SIZE + S7_RES_HEADER + 8;
    if (respCap < total)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    uint16_t wanted = rdW(reqPar + 6);
    if (wanted < S7SRV_PDU_MIN) wanted = S7SRV_PDU_MIN;
    if (wanted > FMaxPdu)       wanted = FMaxPdu;

    // ISO header
    resp[0] = TPKT_VERSION;
    resp[1] = 0x00;
    wrW(resp + 2, total);
    resp[4] = 0x02;              // COTP LI
    resp[5] = COTP_PDU_DT;
    resp[6] = 0x80;              // last data unit

    // S7 AckData header
    uint8_t* out = resp + S7ISO_HEADER_SIZE;
    out[0] = S7_PROTO_ID;
    out[1] = S7_PDU_ACKDATA;
    wrW(out + 2, 0x0000);        // redundancy
    out[4] = pdu[4];             // echo the sequence, or the client cannot
    out[5] = pdu[5];             // match the answer to its request
    wrW(out + 6, 8);             // param len
    wrW(out + 8, 0);             // data len
    wrW(out + 10, S7_ERR_NONE);

    // Answer parameters
    uint8_t* par = out + S7_RES_HEADER;
    par[0] = S7_FUN_NEGOTIATE;
    par[1] = 0x00;
    par[2] = reqPar[2]; par[3] = reqPar[3];   // parallel jobs, as offered
    par[4] = reqPar[4]; par[5] = reqPar[5];
    wrW(par + 6, wanted);

    s.pduSize = wanted;

    *respLen = total;
    return S7SRV_REPLY;
}

//-----------------------------------------------------------------------------
// A well-formed AckData carrying nothing but an error.
//
// Worth doing properly: "not implemented" is a documented S7 answer, and a
// client that receives it says so. Closing the connection instead produces a
// timeout, which is the least informative failure there is and the one that
// gets reported as "your device is broken".
//-----------------------------------------------------------------------------
int S7Server::errorAnswer(const uint8_t* req, uint8_t* resp, uint16_t respCap,
                          uint16_t* respLen, uint16_t errorCode)
{
    const uint8_t* pdu = req + S7ISO_HEADER_SIZE;

    const uint16_t total = S7ISO_HEADER_SIZE + S7_RES_HEADER;
    if (respCap < total)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    resp[0] = TPKT_VERSION;
    resp[1] = 0x00;
    wrW(resp + 2, total);
    resp[4] = 0x02;
    resp[5] = COTP_PDU_DT;
    resp[6] = 0x80;

    uint8_t* out = resp + S7ISO_HEADER_SIZE;
    out[0] = S7_PROTO_ID;
    out[1] = S7_PDU_ACKDATA;
    wrW(out + 2, 0x0000);
    out[4] = pdu[4];
    out[5] = pdu[5];
    wrW(out + 6, 0);
    wrW(out + 8, 0);
    wrW(out + 10, errorCode);

    *respLen = total;
    return S7SRV_REPLY;
}
