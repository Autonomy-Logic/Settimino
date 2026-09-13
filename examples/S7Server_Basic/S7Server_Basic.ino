/*
  S7Server_Basic — be an S7 CPU that an HMI can read and write.

  Settimino's other examples dial a PLC and ask it questions. This one waits to
  be asked: point TIA Portal, an HMI, python-snap7 or another Settimino sketch
  at this board's IP on port 102 and it will read and write the areas below.

  ---------------------------------------------------------------------------
  THE SERVER OWNS NO SOCKET, AND THAT IS WHY THIS LOOP LOOKS LIKE THIS
  ---------------------------------------------------------------------------

  S7Server is a protocol engine: you hand it a frame, it hands you a reply. All
  the socket work below is yours, which means it is also yours to change --
  swap EthernetServer for WiFiServer, or for whatever your platform offers, and
  the protocol code is untouched.

  It also means this loop() never blocks. It reads what has arrived and returns;
  it never waits for a peer. On a board that is also doing something real --
  running a control loop, driving outputs -- that is the difference between a
  server and a hazard.

  ---------------------------------------------------------------------------
  PORT 102 IS PRIVILEGED ON A PC, NOT ON A BOARD
  ---------------------------------------------------------------------------

  S7 lives on TCP 102. A board binds it freely. If you test against a PC-hosted
  client first, that is the port it will dial.

  ---------------------------------------------------------------------------
  THERE IS NO AUTHENTICATION IN CLASSIC S7. NONE.
  ---------------------------------------------------------------------------

  Anyone who can reach this port can read and write every area you register.
  That is the protocol, not this implementation -- a real S7-300 offers exactly
  the same guarantee. Put it on a trusted segment, and consider
  setWriteEnabled(false) if the clients only need to read.
*/

#include <SPI.h>
#include <Ethernet.h>
#include "S7Server.h"

byte mac[]   = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress ip(192, 168, 0, 70);

EthernetServer listener(102);
EthernetClient client;

S7Server     server;
S7SrvSession session;

// ---------------------------------------------------------------------------
// The address space.
//
// DB1 is a flat buffer: the client reads and writes it directly, and the
// sketch can look at it whenever it likes. That is the simple case.
//
// The merker area has no buffer (data = NULL) and is served by the callbacks
// below instead. Use that when the values do not live in memory as a block --
// a sensor read on demand, a register file, a PLC image assembled per scan.
// ---------------------------------------------------------------------------

static uint8_t db1[64];
static uint8_t merkers[32];

static bool onRead(void* ctx, uint8_t area, uint16_t db, uint32_t start,
                   uint16_t len, uint8_t* dest)
{
  (void)ctx; (void)area; (void)db;
  if (start + len > sizeof(merkers)) return false;   // refuse, do not invent
  memcpy(dest, merkers + start, len);
  return true;
}

static bool onWrite(void* ctx, uint8_t area, uint16_t db, uint32_t start,
                    uint16_t len, const uint8_t* src)
{
  (void)ctx; (void)area; (void)db;
  if (start + len > sizeof(merkers)) return false;
  memcpy(merkers + start, src, len);
  return true;
}

// `const` so the table lives in flash: it is fixed when the sketch is built
// and never changes, so there is no reason for it to cost RAM.
static const S7SrvArea AREAS[] = {
  { S7AreaDB, 1, db1,  sizeof(db1) },
  { S7AreaMK, 0, NULL, sizeof(merkers) },
};

// One frame in, one frame out. Sized for the PDU we are willing to negotiate --
// ask for more than you buffer and a client will send more than you can hold.
static const uint16_t PDU = 240;
static uint8_t rx[S7ISO_HEADER_SIZE + PDU];
static uint8_t tx[S7ISO_HEADER_SIZE + PDU];
static uint16_t have = 0;

void setup()
{
  Serial.begin(115200);

  Ethernet.begin(mac, ip);
  listener.begin();

  server.setAreas(AREAS, sizeof(AREAS) / sizeof(AREAS[0]));
  server.setAccessors(onRead, onWrite, NULL);
  server.setMaxPduSize(PDU);

  for (uint8_t i = 0; i < sizeof(db1); i++) db1[i] = i;

  Serial.print(F("S7 server on "));
  Serial.print(Ethernet.localIP());
  Serial.println(F(":102"));
}

void loop()
{
  if (!client || !client.connected())
  {
    EthernetClient incoming = listener.available();
    if (incoming)
    {
      client = incoming;
      server.beginSession(session);
      have = 0;
      Serial.println(F("client connected"));
    }
    return;
  }

  // Take only what has already arrived. Never wait for the rest: a peer that
  // sends half a frame and stops must not be able to stall this sketch.
  while (client.available() && have < sizeof(rx))
  {
    rx[have++] = (uint8_t)client.read();

    const uint16_t need = S7IsoFrameLength(rx, have);

    if (need == 0xFFFF)            // not ISO-TCP at all
    {
      client.stop();
      have = 0;
      Serial.println(F("client dropped: not speaking S7"));
      return;
    }

    if (need && have >= need)      // a whole frame is in hand
    {
      uint16_t txLen = 0;
      const int r = server.handle(session, rx, need, tx, sizeof(tx), &txLen);

      if (txLen) client.write(tx, txLen);
      if (r == S7SRV_CLOSE)
      {
        client.stop();
        Serial.println(F("client closed"));
      }
      have = 0;
    }
  }

  // The sketch's own work goes here, and it still runs while a client is
  // connected -- because nothing above waited for one.
}
