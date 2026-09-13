# Settimino — Autonomy Logic fork (2.2.0)

> **This is a fork.** The upstream project is
> **[davenardella/Settimino](https://github.com/davenardella/Settimino)**, by Dave
> Nardella, who also wrote [Snap7](https://snap7.sourceforge.net/). Everything
> good about the S7 protocol handling here is his work. Upstream's readme
> follows below, unchanged.
>
> The fork exists to add **the server role**, which upstream does not have — and
> the changes are meant to go back: each one is a self-contained commit, offered
> as a pull request rather than kept.

## What this fork adds

### 1. `S7Server` — answer S7 clients instead of only asking

Settimino has always been a client: it dials a PLC and asks it questions. The
new `S7Server` is the other half. An HMI, a SCADA system, TIA Portal or another
PLC can read and write this device's memory using the protocol they already
speak, with no gateway in between.

**It owns no socket, and that is the whole design.** You hand it one complete
ISO-TCP frame and a buffer; it hands you back the bytes to reply with. It never
reads, never writes, never waits, never allocates and never calls `millis()`.

```cpp
S7SrvSession s;
server.beginSession(s);                 // once per accepted connection

uint16_t replyLen = 0;
int r = server.handle(s, frame, frameLen, reply, sizeof(reply), &replyLen);
if (replyLen)          client.write(reply, replyLen);
if (r == S7SRV_CLOSE)  client.stop();
```

A client can block on `recv` — a sketch asks for a value and waits. A server
cannot: it has to stay reachable while the rest of the program runs, and on
these devices "the rest of the program" may be a control loop with a few
hundred microseconds to spare. A server that blocks on a peer is a server that
lets a peer halt the machine.

It also means the server works on platforms Settimino has never supported:
there is no transport to port. See `examples/S7Server_Basic`.

### 2. The platform is detected, not hand-edited

`Platform.h` required uncommenting a `#define` to pick your board. That is fine
when you install a library by unzipping it, and impossible when a tool installs
it for you — the edit is lost on every update.

It now deduces the family from the macros the core itself defines, and any
manual `#define` (or `-D` build flag) still wins. The fallback is `ARDUINO_LAN`,
which is what the file shipped hardcoded, so nothing changes for existing users.

### 3. Tests that run without a board

`test/` holds host-side tests — the protocol engine compiles and runs on a PC
with no network, which is what being transport-free buys you.

```
cd test
make test      # unit tests, under AddressSanitizer and UBSan
make interop   # a real python-snap7 client against the engine
```

The interop test matters most. The unit tests ask *are the bytes what we
intended*; interop asks *does a client written by someone else, against a real
Siemens CPU, agree* — and python-snap7 wraps Snap7's own client, which is as
close to authoritative as a protocol with no published standard gets.

CI runs both on every push, plus a compile matrix over AVR, SAMD, ESP32,
ESP8266 and RP2040, so `architectures=*` is checked rather than asserted.

### 4. Security, stated plainly

**Classic S7 has no authentication and no encryption. None.** Anyone who can
reach port 102 can read and write every area the server registers. That is the
protocol, not this implementation — a real S7-300 offers exactly the same
guarantee. Put it on a trusted segment. `setWriteEnabled(false)` makes a
read-only server, which is meaningfully safer where the clients only read.

---

# Settimino OFFICIAL (Latest : 2.1.0)

This is the **official** Settimino repository starting with release 2.0.1.

Previous releases are available in the <a href="https://sourceforge.net/projects/settimino/files/" target="_blank">SourceForge</a> repository.

The official site is still <a href="https://settimino.sourceforge.net/" target="_blank">here</a>, where you can find a lot of info.

---
## News for 2.1.0

* Arduino GIGA R1 WIFI with Ethernet Shield 2
* Arduino Portenta H7 with Portenta Hat Carrier
* Waveshare ESP32-S3-ETH

![new 2.1.0](img/new_2.1.0.jpeg)

## Arduino GIGA R1 WIFI

before everything, in platform.h select **GIGA_R1_LAN** as follows

```cpp
//#define ARDUINO_LAN    
//#define ESP8266_FAMILY  
//#define ESP32_WIFI
//#define M5STACK_WIFI
//#define M5STACK_LAN
//#define PORTENTA
#define GIGA_R1_LAN
//#define ESP32_S3_ETH
```

## Arduino Portenta

before everything, in platform.h select **PORTENTA** as follows

```cpp
//#define ARDUINO_LAN    
//#define ESP8266_FAMILY  
//#define ESP32_WIFI
//#define M5STACK_WIFI
//#define M5STACK_LAN
#define PORTENTA
//#define GIGA_R1_LAN
//#define ESP32_S3_ETH
```

## Waveshare ESP32-S3-ETH

https://www.waveshare.com/wiki/ESP32-S3-ETH

before everything, in platform.h select **ESP32_S3_ETH** as follows

```cpp
//#define ARDUINO_LAN    
//#define ESP8266_FAMILY  
//#define ESP32_WIFI
//#define M5STACK_WIFI
//#define M5STACK_LAN
//#define PORTENTA
//#define GIGA_R1_LAN
#define ESP32_S3_ETH
```
then, connect the board with the USB-C cable and follow this configuration:

![ESP32 S3 ETH_SETUP](img/ESP32-S3-ETH_SETUP.png)


