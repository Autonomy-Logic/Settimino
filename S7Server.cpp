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
  The protocol is Snap7's -- the server side of what Settimino's client already
  speaks. Where a choice existed it was made the way a real S7-300 makes it.

  Everything is written against the byte stream rather than packed structs,
  because a library compiling for AVR, ARM, Xtensa and RISC-V cannot rely on
  `#pragma pack(1)` overlays.
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
#define S7_FUN_START      0x28
#define S7_FUN_STOP       0x29

// Error codes carried in the type-3 header (big-endian word).
// 0x8104 is what a real CPU answers for "this service is not implemented".
#define S7_ERR_NONE           0x0000
#define S7_ERR_NOT_IMPLEMENTED 0x8104

// Per-ITEM result codes, carried inside the data section of a read or write
// answer. Distinct from the header's error word: a request can succeed while one
// of its items fails.
#define S7_ITEM_OK             0xFF
#define S7_ITEM_OUT_OF_RANGE   0x05
#define S7_ITEM_BAD_TRANSPORT  0x06
#define S7_ITEM_SIZE_MISMATCH  0x07
#define S7_ITEM_NOT_AVAILABLE  0x0A
#define S7_ITEM_OVER_PDU       0x85

// Transport size as it comes BACK. Note the unit changes: Bit, Byte and Int
// report a length in BITS, Real and Octet in BYTES. Getting this backwards
// produces a client that reads eight times too much or an eighth too little,
// and reads plausible garbage rather than erroring.
#define TS_RES_BIT    0x03
#define TS_RES_BYTE   0x04
#define TS_RES_INT    0x05
#define TS_RES_REAL   0x07
#define TS_RES_OCTET  0x09

// One request item: 0x12, 0x0A, 0x10, transport, count(2), db(2), area, addr(3)
#define S7_ITEM_SPEC_LEN  12

/** Bytes one element of a transport size occupies. 0 means "not a transport
 *  size this server knows", which is an error rather than a zero-length read. */
static uint8_t elementBytes(uint8_t transport)
{
    switch (transport)
    {
        case S7WLBit:     return 1;   // S7 sends one BYTE per bit
        case S7WLByte:    return 1;
        case S7WLChar:    return 1;
        case S7WLWord:    return 2;
        case S7WLInt:     return 2;
        case S7WLDWord:   return 4;
        case S7WLDInt:    return 4;
        case S7WLReal:    return 4;
        case S7WLCounter: return 2;
        case S7WLTimer:   return 2;
        default:          return 0;
    }
}

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
    FReads        = 0;
    FWrites       = 0;
    FWriteBitFn   = NULL;
    FIdentity     = NULL;
    FControlFn    = NULL;
    FCpuStatus    = S7SRV_CPU_RUN;
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

void S7Server::setBitWriter(S7SrvWriteBitFn writeBitFn)
{
    FWriteBitFn = writeBitFn;
}

void S7Server::setIdentity(const S7SrvIdentity* identity)
{
    FIdentity = identity;
}

void S7Server::setCpuStatus(uint8_t status)
{
    FCpuStatus = status;
}

void S7Server::setControlHandler(S7SrvControlFn fn)
{
    FControlFn = fn;
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
// COTP Connection Request -> Connection Confirm. The confirm is the request
// echoed back with the PDU type changed and the references swapped, which
// accepts the TSAPs and TPDU size the client proposed. Echoing also means we
// never parse the variable part, whose length a malicious client controls.
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

    // A UserData PDU is a different animal: its header has no error word and
    // its parameters carry a group and subfunction rather than a function.
    if (pdu[1] == S7_PDU_USERDATA)
        return userData(s, req, reqLen, resp, respCap, respLen);

    const uint8_t fun = pdu[S7_REQ_HEADER];

    switch (fun)
    {
        case S7_FUN_START:
            return funControl(s, req, reqLen, resp, respCap, respLen, true);

        case S7_FUN_STOP:
            return funControl(s, req, reqLen, resp, respCap, respLen, false);

        case S7_FUN_NEGOTIATE:
            return funNegotiate(s, req, reqLen, resp, respCap, respLen);

        case S7_FUN_READ:
            return funRead(s, req, reqLen, resp, respCap, respLen);

        case S7_FUN_WRITE:
            return funWrite(s, req, reqLen, resp, respCap, respLen);

        default:
            return errorAnswer(req, resp, respCap, respLen, S7_ERR_NOT_IMPLEMENTED);
    }
}

//-----------------------------------------------------------------------------
// Setup Communication. The client proposes a parallel-job count and a PDU size;
// we accept the job counts as offered (we serialise anyway) and clamp the PDU
// into what this build can buffer.
//-----------------------------------------------------------------------------
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
// Area lookup
//-----------------------------------------------------------------------------
const S7SrvArea* S7Server::findArea(uint8_t area, uint16_t dbNumber) const
{
    // Linear: the table is a handful of entries, and a binary search over
    // flash would cost more in code than it saves in cycles.
    for (uint8_t i = 0; i < FAreaCount; i++)
    {
        const S7SrvArea* a = &FAreas[i];
        if (a->code != area)
            continue;
        if (area == S7AreaDB && a->dbNumber != dbNumber)
            continue;
        return a;
    }
    return NULL;
}

//-----------------------------------------------------------------------------
// One parsed request item.
//-----------------------------------------------------------------------------
namespace {

struct Item
{
    uint8_t  transport;
    uint16_t count;
    uint16_t dbNumber;
    uint8_t  area;
    uint32_t bitAddr;    // S7 addresses are BIT addresses: byte * 8 + bit
};

/** Parse one 12-byte item spec. False when it is not a spec we understand. */
bool parseItem(const uint8_t* p, Item& out)
{
    // 0x12 = variable specification, 0x10 = S7ANY addressing. Anything else is
    // a syntax this server does not speak (symbolic addressing, for one), and
    // guessing at it would mean answering about the wrong variable.
    if (p[0] != 0x12 || p[2] != 0x10)
        return false;
    if (p[1] < 0x0A)          // declared length of the rest of the spec
        return false;

    out.transport = p[3];
    out.count     = rdW(p + 4);
    out.dbNumber  = rdW(p + 6);
    out.area      = p[8];
    out.bitAddr   = ((uint32_t)p[9] << 16) | ((uint32_t)p[10] << 8) | (uint32_t)p[11];
    return true;
}

} // namespace

//-----------------------------------------------------------------------------
// Read Var
//
// Answer layout: a 12-byte AckData header, then 2 parameter bytes (function +
// item count), then one result per item:
//
//     [0]    return code        0xFF, or why not
//     [1]    transport size     TS_RES_*
//     [2..3] length             BITS for Bit/Byte/Int, BYTES for Real/Octet
//     [4..]  the data
//     + one pad byte when the data length is odd AND this is not the last item
//
// S7 never transfers an odd byte count between items, and a client that does not
// find the next item where it expects it reads the wrong variable.
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
int S7Server::funRead(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                      uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    // s7Dispatch() already held the S7 header's own length fields against what
    // actually arrived, so reqLen has done its work by the time we get here.
    (void)reqLen;

    const uint8_t* pdu    = req + S7ISO_HEADER_SIZE;
    const uint16_t parLen = rdW(pdu + 6);

    // Too short to carry an item count. Answered, not closed -- see the note on
    // errorAnswer(): the frame parsed at every level we could resynchronise
    // from, and dropping the session would cost the client everything else it
    // was doing. Some clients send exactly this and ignore the reply.
    if (parLen < 2)
        return errorAnswer(req, resp, respCap, respLen, S7_ERR_NOT_IMPLEMENTED);

    uint8_t items = pdu[S7_REQ_HEADER + 1];
    if (items > S7SRV_MAX_ITEMS)
        items = S7SRV_MAX_ITEMS;   // as Snap7 does: serve the first 20

    // The specs must actually be present. Trusting the count over the bytes
    // that arrived is how an item count becomes a read primitive.
    if ((uint16_t)(2 + items * S7_ITEM_SPEC_LEN) > parLen)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    // The negotiated PDU bounds the answer, not our buffer: a client that
    // agreed to 240 bytes must not be sent 480 because we happen to have room.
    const uint16_t pduCap = s.pduSize ? s.pduSize : S7SRV_PDU_MIN;
    uint16_t cap = (uint16_t)(S7ISO_HEADER_SIZE + pduCap);
    if (cap > respCap)
        cap = respCap;

    uint8_t* out = resp + S7ISO_HEADER_SIZE;
    uint8_t* par = out + S7_RES_HEADER;
    par[0] = S7_FUN_READ;
    par[1] = items;

    uint16_t off = 2;   // bytes written into the data section so far
    int16_t  budget = (int16_t)pduCap;

    for (uint8_t i = 0; i < items; i++)
    {
        const uint8_t* spec = pdu + S7_REQ_HEADER + 2 + (uint16_t)i * S7_ITEM_SPEC_LEN;

        Item it;
        uint8_t  rc       = S7_ITEM_OK;
        uint8_t  resTs    = 0;
        uint16_t dataLen  = 0;   // bytes of payload
        uint8_t* dst      = par + off + 4;

        // Room for this item's 4-byte result header must exist before anything
        // is written into it.
        if ((uint16_t)(S7ISO_HEADER_SIZE + S7_RES_HEADER + off + 4) > cap)
        {
            rc = S7_ITEM_OVER_PDU;
        }
        else if (!parseItem(spec, it))
        {
            rc = S7_ITEM_BAD_TRANSPORT;
        }
        else
        {
            const uint8_t mult = elementBytes(it.transport);
            const uint32_t size = (uint32_t)mult * it.count;

            if (mult == 0)
            {
                rc = S7_ITEM_BAD_TRANSPORT;
            }
            else if (it.transport == S7WLBit && size > 1)
            {
                // More than one bit in a single item is not something a real
                // S7 CPU serves, so clients do not ask for it.
                rc = S7_ITEM_OUT_OF_RANGE;
            }
            else if (it.transport != S7WLBit && it.transport != S7WLTimer &&
                     it.transport != S7WLCounter && (it.bitAddr % 8) != 0)
            {
                // A byte-or-wider read from a non-byte-aligned bit address is
                // meaningless; a real CPU refuses it rather than rounding.
                rc = S7_ITEM_OUT_OF_RANGE;
            }
            else if ((int32_t)size > budget)
            {
                rc = S7_ITEM_OVER_PDU;
            }
            else if ((uint32_t)(S7ISO_HEADER_SIZE + S7_RES_HEADER + off + 4) + size > cap)
            {
                rc = S7_ITEM_OVER_PDU;
            }
            else
            {
                const S7SrvArea* area = findArea(it.area, it.dbNumber);
                if (area == NULL)
                {
                    rc = S7_ITEM_NOT_AVAILABLE;
                }
                else
                {
                    const uint32_t byteStart = it.bitAddr >> 3;
                    const uint8_t  bitIndex  = (uint8_t)(it.bitAddr & 0x07);

                    if (byteStart + size > area->size)
                    {
                        rc = S7_ITEM_OUT_OF_RANGE;
                    }
                    else if (area->data != NULL)
                    {
                        memcpy(dst, area->data + byteStart, (size_t)size);
                    }
                    else if (FReadFn != NULL &&
                             FReadFn(FCtx, it.area, it.dbNumber, byteStart,
                                     (uint16_t)size, dst))
                    {
                        // served
                    }
                    else
                    {
                        rc = S7_ITEM_OUT_OF_RANGE;
                    }

                    if (rc == S7_ITEM_OK)
                    {
                        budget -= (int16_t)size;
                        dataLen = (uint16_t)size;

                        switch (it.transport)
                        {
                            case S7WLBit:
                                // The byte came back whole; the client asked
                                // for one bit of it, and gets 0 or 1.
                                dst[0] = (uint8_t)((dst[0] & (1u << bitIndex)) ? 1 : 0);
                                resTs   = TS_RES_BIT;
                                break;
                            case S7WLInt:
                            case S7WLDInt:
                                resTs = TS_RES_INT;
                                break;
                            case S7WLReal:
                                resTs = TS_RES_REAL;
                                break;
                            case S7WLChar:
                            case S7WLTimer:
                            case S7WLCounter:
                                resTs = TS_RES_OCTET;
                                break;
                            default:
                                resTs = TS_RES_BYTE;
                                break;
                        }
                    }
                }
            }
        }

        if ((uint16_t)(S7ISO_HEADER_SIZE + S7_RES_HEADER + off + 4) > cap)
        {
            // Not even the failure fits. Stop and report what did.
            par[1] = i;
            break;
        }

        uint8_t* hdr = par + off;
        hdr[0] = rc;

        if (rc == S7_ITEM_OK)
        {
            hdr[1] = resTs;
            // The length unit is bits for Byte and Int, bytes for Real and
            // Octet. For TS_RES_BIT the answer is 1 either way.
            //
            // Sending 1 rather than 8 is deliberate: it is what Snap7's own
            // server sends and what the Wireshark dissector documents. Sending 8
            // would make one client's single-item path work and would make
            // Snap7's C client memcpy eight bytes into a one-byte buffer.
            wrW(hdr + 2, (resTs == TS_RES_BYTE || resTs == TS_RES_INT)
                             ? (uint16_t)(dataLen * 8)
                             : dataLen);
            off = (uint16_t)(off + 4 + dataLen);
            // S7 does not carry an odd byte count between items.
            if (i + 1 < items && (dataLen % 2) != 0)
            {
                hdr[4 + dataLen] = 0x00;
                off++;
            }
        }
        else
        {
            // A failed item carries no data, but it DOES carry a length --
            // Snap7 sends 4, and clients parse it.
            hdr[1] = 0x00;
            wrW(hdr + 2, 0x0004);
            off = (uint16_t)(off + 4);
        }
    }

    const uint16_t total = (uint16_t)(S7ISO_HEADER_SIZE + S7_RES_HEADER + off);

    resp[0] = TPKT_VERSION;
    resp[1] = 0x00;
    wrW(resp + 2, total);
    resp[4] = 0x02;
    resp[5] = COTP_PDU_DT;
    resp[6] = 0x80;

    out[0] = S7_PROTO_ID;
    out[1] = S7_PDU_ACKDATA;
    wrW(out + 2, 0x0000);
    out[4] = pdu[4];
    out[5] = pdu[5];
    wrW(out + 6, 2);                    // parameter length
    wrW(out + 8, (uint16_t)(off - 2));  // data length
    // Zero even when an item failed: the failure is per item, and a header
    // error would tell the client the whole request was rejected.
    wrW(out + 10, S7_ERR_NONE);

    FReads++;
    *respLen = total;
    return S7SRV_REPLY;
}

//-----------------------------------------------------------------------------
// Write Var. The request carries the same 12-byte item specs in its parameter
// section and the values in its data section, each prefixed by the same 4-byte
// header a read answer uses. The answer is one byte per item.
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
int S7Server::funWrite(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                       uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    // See funRead: the lengths were validated upstream. The answer is one byte
    // per item and cannot overflow the negotiated PDU, so the session is not
    // consulted either.
    (void)reqLen;
    (void)s;

    const uint8_t* pdu     = req + S7ISO_HEADER_SIZE;
    const uint16_t parLen  = rdW(pdu + 6);
    const uint16_t dataLen = rdW(pdu + 8);

    if (parLen < 2)
        return errorAnswer(req, resp, respCap, respLen, S7_ERR_NOT_IMPLEMENTED);

    uint8_t items = pdu[S7_REQ_HEADER + 1];
    if (items > S7SRV_MAX_ITEMS)
        items = S7SRV_MAX_ITEMS;

    if ((uint16_t)(2 + items * S7_ITEM_SPEC_LEN) > parLen)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    const uint8_t* dataSec = pdu + S7_REQ_HEADER + parLen;

    const uint16_t total = (uint16_t)(S7ISO_HEADER_SIZE + S7_RES_HEADER + 2 + items);
    if (total > respCap)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    uint8_t* out = resp + S7ISO_HEADER_SIZE;
    uint8_t* par = out + S7_RES_HEADER;
    par[0] = S7_FUN_WRITE;
    par[1] = items;
    uint8_t* results = par + 2;

    uint16_t dOff = 0;   // walk through the request's data section

    for (uint8_t i = 0; i < items; i++)
    {
        const uint8_t* spec = pdu + S7_REQ_HEADER + 2 + (uint16_t)i * S7_ITEM_SPEC_LEN;
        uint8_t rc = S7_ITEM_OK;

        Item it;
        if (!parseItem(spec, it))
        {
            // The value's length is unknown, so the data section can no longer
            // be walked: every later item would be read from the wrong offset.
            results[i] = S7_ITEM_BAD_TRANSPORT;
            for (uint8_t j = (uint8_t)(i + 1); j < items; j++)
                results[j] = S7_ITEM_BAD_TRANSPORT;
            break;
        }

        // Each value is prefixed by return code, transport size and length.
        if ((uint32_t)dOff + 4 > dataLen)
        {
            results[i] = S7_ITEM_SIZE_MISMATCH;
            break;
        }

        const uint8_t* vhdr    = dataSec + dOff;
        const uint8_t  vTs     = vhdr[1];
        const uint16_t vLenRaw = rdW(vhdr + 2);
        const uint8_t* value   = vhdr + 4;

        // How many bytes of payload this value actually occupies. The unit of
        // the length field depends on the transport size -- bits for Byte and
        // Int, bytes for Real and Octet.
        //
        // TS_RES_BIT is the exception, because implementations disagree about
        // the declared length (some send 1, some send 8). A single bit is always
        // one byte on the wire, so taking the payload as one byte and ignoring
        // the declared length accepts both without guessing.
        uint16_t vBytes;
        if (vTs == TS_RES_BIT)
            vBytes = 1;
        else if (vTs == TS_RES_BYTE || vTs == TS_RES_INT)
            vBytes = (uint16_t)(vLenRaw / 8);
        else
            vBytes = vLenRaw;

        if ((uint32_t)dOff + 4 + vBytes > dataLen)
        {
            results[i] = S7_ITEM_SIZE_MISMATCH;
            break;
        }

        const uint8_t  mult = elementBytes(it.transport);
        const uint32_t size = (uint32_t)mult * it.count;

        if (!FWriteEnabled)
        {
            // A read-only server. A proper refusal, not a dropped connection:
            // the client says "access denied" rather than "timeout".
            rc = S7_ITEM_NOT_AVAILABLE;
        }
        else if (mult == 0)
        {
            rc = S7_ITEM_BAD_TRANSPORT;
        }
        else if (size != vBytes)
        {
            // The spec says how much, the value says how much, and they must
            // agree. Writing min(a, b) would put a truncated value into a PLC.
            rc = S7_ITEM_SIZE_MISMATCH;
        }
        else if (it.transport != S7WLBit && it.transport != S7WLTimer &&
                 it.transport != S7WLCounter && (it.bitAddr % 8) != 0)
        {
            rc = S7_ITEM_OUT_OF_RANGE;
        }
        else
        {
            const S7SrvArea* area = findArea(it.area, it.dbNumber);
            const uint32_t byteStart = it.bitAddr >> 3;
            const uint8_t  bitIndex  = (uint8_t)(it.bitAddr & 0x07);

            if (area == NULL)
                rc = S7_ITEM_NOT_AVAILABLE;
            else if (area->readOnly)
                rc = S7_ITEM_NOT_AVAILABLE;
            else if (byteStart + size > area->size)
                rc = S7_ITEM_OUT_OF_RANGE;
            else if (it.transport == S7WLBit)
            {
                const bool on = (value[0] != 0);
                if (area->data != NULL)
                {
                    // A flat buffer owns its own bits, so updating one in
                    // place is exactly right.
                    if (on) area->data[byteStart] |=  (uint8_t)(1u << bitIndex);
                    else    area->data[byteStart] &= (uint8_t)~(1u << bitIndex);
                }
                else if (FWriteBitFn != NULL)
                {
                    if (!FWriteBitFn(FCtx, it.area, it.dbNumber, byteStart, bitIndex, on))
                        rc = S7_ITEM_OUT_OF_RANGE;
                }
                else
                {
                    // No bit writer. Refuse rather than read-modify-write the
                    // byte: behind a callback the other seven bits may be
                    // seven other outputs, and re-asserting them is not the
                    // same as leaving them alone.
                    rc = S7_ITEM_NOT_AVAILABLE;
                }
            }
            else if (area->data != NULL)
            {
                memcpy(area->data + byteStart, value, (size_t)size);
            }
            else if (FWriteFn != NULL)
            {
                if (!FWriteFn(FCtx, it.area, it.dbNumber, byteStart, (uint16_t)size, value))
                    rc = S7_ITEM_OUT_OF_RANGE;
            }
            else
            {
                rc = S7_ITEM_NOT_AVAILABLE;
            }
        }

        results[i] = rc;

        dOff = (uint16_t)(dOff + 4 + vBytes);
        // The same odd-byte padding a read answer uses, in the other direction.
        if (i + 1 < items && (vBytes % 2) != 0)
            dOff++;
    }

    resp[0] = TPKT_VERSION;
    resp[1] = 0x00;
    wrW(resp + 2, total);
    resp[4] = 0x02;
    resp[5] = COTP_PDU_DT;
    resp[6] = 0x80;

    out[0] = S7_PROTO_ID;
    out[1] = S7_PDU_ACKDATA;
    wrW(out + 2, 0x0000);
    out[4] = pdu[4];
    out[5] = pdu[5];
    wrW(out + 6, 2);
    wrW(out + 8, items);
    wrW(out + 10, S7_ERR_NONE);

    FWrites++;
    *respLen = total;
    return S7SRV_REPLY;
}

//-----------------------------------------------------------------------------
// PLC Control -- start and stop. Answer shape is the smallest a type-3 AckData
// can be: the 12-byte header plus a single parameter byte echoing the function.
//-----------------------------------------------------------------------------
int S7Server::funControl(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                         uint8_t* resp, uint16_t respCap, uint16_t* respLen,
                         bool run)
{
    (void)s; (void)reqLen;

    const uint8_t* pdu   = req + S7ISO_HEADER_SIZE;
    const uint16_t total = (uint16_t)(S7ISO_HEADER_SIZE + S7_RES_HEADER + 1);
    if (respCap < total)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    // No handler means no. Classic S7 has no authentication whatsoever, so a
    // device that stops its machine because an unauthenticated packet asked it
    // to is a hazard, not a feature. The host opts in.
    bool accepted = false;
    if (FControlFn != NULL)
        accepted = FControlFn(FCtx, run);

    if (accepted)
        FCpuStatus = run ? S7SRV_CPU_RUN : S7SRV_CPU_STOP;

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
    wrW(out + 6, 1);
    wrW(out + 8, 0);
    // A refusal is reported as an error rather than as a success that did
    // nothing, so the client can tell the difference.
    wrW(out + 10, accepted ? S7_ERR_NONE : S7_ERR_NOT_IMPLEMENTED);
    out[S7_RES_HEADER] = pdu[S7_REQ_HEADER];   // echo the function

    *respLen = total;
    return S7SRV_REPLY;
}

//-----------------------------------------------------------------------------
// System Status List
//-----------------------------------------------------------------------------
namespace {

/** SZL 0x0011 — module identification. The bytes are a real S7-315's, with
 *  the order code patched in; a client reads the MlfB out of record 1. */
const uint8_t SZL_0011[] = {
    0xFF, 0x09, 0x00, 0x78, 0x00, 0x11, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x04,
    0x00, 0x01, '6','E','S','7',' ','3','1','5','-','2','E','H','1','4','-','0','A','B','0',' ',
    0x00, 0xC0, 0x00, 0x04, 0x00, 0x01,
    0x00, 0x06, '6','E','S','7',' ','3','1','5','-','2','E','H','1','4','-','0','A','B','0',' ',
    0x00, 0xC0, 0x00, 0x04, 0x00, 0x01,
    0x00, 0x07, ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
    0x00, 0xC0, 0x56, 0x03, 0x02, 0x06,
    0x00, 0x81, 'B','o','o','t',' ','L','o','a','d','e','r',' ',' ',' ',' ',' ',' ',' ',' ',' ',
    0x00, 0x00, 0x41, 0x20, 0x09, 0x09
};

/** SZL 0x0424 — CPU mode. Byte 15 is the status, patched at send time. */
const uint8_t SZL_0424[] = {
    0xFF, 0x09, 0x00, 0x1C, 0x04, 0x24, 0x00, 0x00, 0x00, 0x14, 0x00, 0x01,
    0x51, 0x44, 0xFF,
    0x08,                                     // <- CPU status
    0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0x02, 0x05, 0x02, 0x01, 0x55, 0x90, 0x67
};

/** Offset of the status byte within SZL_0424. */
const uint8_t SZL_0424_STATUS_OFFSET = 15;

/** SZL 0x001C record numbers, in the order a real CPU emits them. */
const uint8_t SZL_001C_RECORDS[] = { 1, 2, 3, 4, 5, 7, 8, 9, 10, 11 };
const uint8_t SZL_001C_RECORD_COUNT = 10;
const uint8_t SZL_001C_STRING_LEN   = 32;
const uint8_t SZL_001C_RECORD_LEN   = 2 + SZL_001C_STRING_LEN;

/** Copy a C string into a fixed-width, zero-padded SZL field. */
void szlString(uint8_t* dst, const char* src, uint8_t width)
{
    uint8_t i = 0;
    if (src != NULL)
        for (; i < width && src[i] != '\0'; i++)
            dst[i] = (uint8_t)src[i];
    for (; i < width; i++)
        dst[i] = 0x00;
}

} // namespace

/** Build one SZL answer. Returns the payload length, or 0 for "not available". */
int S7Server::szlAnswer(const uint8_t* req, uint8_t* resp, uint16_t respCap,
                        uint16_t* respLen, uint16_t szlId, uint16_t szlIndex)
{
    const uint8_t* pdu = req + S7ISO_HEADER_SIZE;
    const uint8_t* rp  = pdu + S7_REQ_HEADER;

    // A UserData answer is a type-7 header (10 bytes, no error word) plus a
    // 12-byte parameter block, and only then the SZL data.
    const uint16_t fixed = S7ISO_HEADER_SIZE + 10 + 12;
    if (respCap < fixed + 8)
    {
        FRejected++;
        return S7SRV_CLOSE;
    }

    uint8_t* data    = resp + fixed;
    uint16_t dataLen = 0;
    uint16_t err     = 0x0000;

    const uint16_t room = (uint16_t)(respCap - fixed);

    if (FIdentity == NULL)
    {
        // No identity published. "Not available" is a real CPU's answer for an
        // SZL it does not keep, so a client that can cope will cope.
        err = 0x02D4;
        data[0] = 0x0A; data[1] = 0x00; data[2] = 0x00; data[3] = 0x00;
        dataLen = 4;
    }
    else if (szlId == 0x0011 && sizeof(SZL_0011) <= room)
    {
        memcpy(data, SZL_0011, sizeof(SZL_0011));
        if (FIdentity->orderCode != NULL)
        {
            // Both order-code records carry the same MlfB on a real CPU.
            szlString(data + 14, FIdentity->orderCode, 20);
            szlString(data + 48, FIdentity->orderCode, 20);
        }
        dataLen = (uint16_t)sizeof(SZL_0011);
    }
    else if (szlId == 0x0424 && sizeof(SZL_0424) <= room)
    {
        memcpy(data, SZL_0424, sizeof(SZL_0424));
        data[SZL_0424_STATUS_OFFSET] = FCpuStatus;
        dataLen = (uint16_t)sizeof(SZL_0424);
    }
    else if (szlId == 0x001C)
    {
        // Built rather than templated: every field is the project's, so there
        // is nothing constant to keep in flash but the shape.
        const uint16_t body  = (uint16_t)(SZL_001C_RECORD_COUNT * SZL_001C_RECORD_LEN);
        const uint16_t total = (uint16_t)(4 + 4 + 4 + body);
        if (total > room)
        {
            err = 0x02D4;
            data[0] = 0x0A; data[1] = 0x00; data[2] = 0x00; data[3] = 0x00;
            dataLen = 4;
        }
        else
        {
            data[0] = 0xFF;                       // return code
            data[1] = 0x09;                       // transport: octet string
            wrW(data + 2, (uint16_t)(total - 4)); // payload length
            wrW(data + 4, 0x001C);                // SZL id
            wrW(data + 6, 0x0000);                // index
            wrW(data + 8, SZL_001C_RECORD_LEN);   // bytes per record
            wrW(data + 10, SZL_001C_RECORD_COUNT);

            uint8_t* rec = data + 12;
            for (uint8_t i = 0; i < SZL_001C_RECORD_COUNT; i++)
            {
                const uint8_t index = SZL_001C_RECORDS[i];
                wrW(rec, index);

                const char* value = NULL;
                switch (index)
                {
                    case 1:  value = FIdentity->systemName;     break;
                    case 2:  value = FIdentity->moduleName;     break;
                    case 3:  value = FIdentity->plantId;        break;
                    case 4:  value = FIdentity->copyright;      break;
                    case 5:  value = FIdentity->serialNumber;   break;
                    case 7:  value = FIdentity->moduleTypeName; break;
                    default: value = NULL;                      break;
                }
                szlString(rec + 2, value, SZL_001C_STRING_LEN);
                rec += SZL_001C_RECORD_LEN;
            }
            dataLen = total;
        }
    }
    else
    {
        err = 0x02D4;
        data[0] = 0x0A; data[1] = 0x00; data[2] = 0x00; data[3] = 0x00;
        dataLen = 4;
    }

    (void)szlIndex;

    const uint16_t total = (uint16_t)(fixed + dataLen);

    resp[0] = TPKT_VERSION;
    resp[1] = 0x00;
    wrW(resp + 2, total);
    resp[4] = 0x02;
    resp[5] = COTP_PDU_DT;
    resp[6] = 0x80;

    uint8_t* out = resp + S7ISO_HEADER_SIZE;
    out[0] = S7_PROTO_ID;
    out[1] = S7_PDU_USERDATA;
    wrW(out + 2, 0x0000);
    out[4] = pdu[4];
    out[5] = pdu[5];
    wrW(out + 6, 12);        // parameter length
    wrW(out + 8, dataLen);

    uint8_t* par = out + 10;
    par[0] = rp[0]; par[1] = rp[1]; par[2] = rp[2];   // echo 00 01 12
    par[3] = 0x08;                                    // parameter length
    par[4] = 0x12;
    par[5] = 0x84;                                    // response + SZL group
    par[6] = rp[6];                                   // subfunction
    par[7] = rp[7];                                   // sequence
    wrW(par + 8, 0x0000);                             // no further packets
    wrW(par + 10, err);

    *respLen = total;
    return S7SRV_REPLY;
}

//-----------------------------------------------------------------------------
// UserData dispatch. Only the SZL group is served; everything else is answered
// "not available" rather than ignored.
//-----------------------------------------------------------------------------
int S7Server::userData(S7SrvSession& s, const uint8_t* req, uint16_t reqLen,
                       uint8_t* resp, uint16_t respCap, uint16_t* respLen)
{
    (void)s;

    const uint8_t* pdu    = req + S7ISO_HEADER_SIZE;
    const uint16_t pduLen = (uint16_t)(reqLen - S7ISO_HEADER_SIZE);
    const uint16_t parLen = rdW(pdu + 6);

    // As in funRead: understood, but not something we can serve. Answer it.
    if (pduLen < S7_REQ_HEADER + 8 || parLen < 8)
        return szlAnswer(req, resp, respCap, respLen, 0xFFFF, 0);

    const uint8_t* rp     = pdu + S7_REQ_HEADER;
    const uint8_t  group  = (uint8_t)(rp[5] & 0x0F);
    const uint8_t  subFun = rp[6];

    if (group != 0x04)      // 0x44 = request + SZL; the low nibble is the group
        return szlAnswer(req, resp, respCap, respLen, 0xFFFF, 0);

    if (subFun == 0x02)     // system state
        return szlAnswer(req, resp, respCap, respLen, 0xFFFF, 0);

    if (subFun != 0x01)
        return szlAnswer(req, resp, respCap, respLen, 0xFFFF, 0);

    // The SZL id and index live in the data section, behind a 4-byte header.
    const uint16_t dataLen = rdW(pdu + 8);
    if (dataLen < 8)
        return szlAnswer(req, resp, respCap, respLen, 0xFFFF, 0);

    const uint8_t* d = pdu + S7_REQ_HEADER + parLen;
    return szlAnswer(req, resp, respCap, respLen, rdW(d + 4), rdW(d + 6));
}

//-----------------------------------------------------------------------------
// A well-formed AckData carrying nothing but an error. Close when the byte
// stream can no longer be trusted, because a TPKT stream has no
// resynchronisation point; answer when the frame parsed and merely asks for
// something this server will not do.
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
