# XDP experiment

Captures packets on a NIC with an in-kernel **XDP program** (C), ships each one
through a **BPF ring buffer** into userspace, wraps it in a **C++ data class**
(`XdpData`), and hands it to a **C++ callback** (`PacketHandler`).

## Introduction

We are following that [paper](./doc/xdp-the-express-data-path.pdf) from the [tutorial](https://github.com/xdp-project/xdp-tutorial) using _vibe coding_.

## Prepare, Build & run

As preparation we need the following packages to be installed:
```sh
ap-get install cmake clang llvm libelf-dev libbpf1 libbpf-dev pkg-config gcc-multilib 
```

Afterwards one can build the project by:
```sh
cmake -S . -B build && cmake --build build
sudo ./build/xdp_demo enp5s0                      # demo: prints each packet
sudo ./build/xdp_app_integration_example enp5s0   # feeds packets into an app
```

Both accept `[interface] [--bpf <path-to-xdp_prog.o>]`. The BPF object path is
embedded at build time, so they run from any directory.

## Class hierarchy

```
PacketHandler (abstract C++ callback interface)             [src/PacketHandler.h]
   ^  pure virtual:  void on_packet_arrived(const XdpData&)
   |
   +-- DemoPacketHandler         demo: prints each packet     [src/main.cpp]
   +-- AppPacketHandler          feeds packets into an app    [src/AppIntegrationExample.cpp]

XdpData     C++ data class, parsed host-order view of a packet  [src/XdpData.h]

XdpMonitor  reusable load / attach / poll / detach lifecycle,
            holds a PacketHandler& as its callback target      [src/XdpMonitor.h]
```

**Why an interface?** Each user derives from `PacketHandler` and attaches its own
state; the monitor then calls `on_packet_arrived` once per packet. `XdpData` is
the "data class" of the experiment - a parsed, owned copy of the packet. `XdpMonitor`
is the glue that owns all kernel resources and dispatches records to the handler.

## Function calling flow

```
packet arrives on the NIC
   │   (kernel)
   ▼
xdp_capture_packet(ctx)                C, in-kernel          [xdp_prog.c]
   │   parses Eth/IP/TCP/UDP headers, fills struct xdp_packet
   ▼
bpf_ringbuf_submit(record)  ─────────►  BPF ring buffer (1 MiB, kernel)
   │   (userspace, libbpf)
   ▼
ring_buffer__poll(ring_buffer)         C                     [XdpMonitor.cpp]
   │
   ▼
handle_ringbuf_sample(ctx, data, size) extern "C" shim       [XdpMonitor.cpp]
   │
   ▼
XdpData::XdpData(raw_record)           C++                   [XdpData.cpp]
   │
   ▼
PacketHandler::on_packet_arrived(data) your C++ callback
```

**Why the `extern "C"` shim?** libbpf is a C library and calls back with a C ABI;
`handle_ringbuf_sample` is declared `extern "C"` so its symbol/signature match.
Inside it we safely switch to C++ - that is the "extern C → C++ callback" boundary.

## Data processing & the kernel data structs

```
wire bytes (network byte order)
   │   xdp_capture_packet() parses headers, copies fields
   ▼
struct xdp_packet   packed, fixed 159 bytes, NETWORK byte order   [packet.h]
   ├ destination_mac_address[6]      ├ source_mac_address[6]
   ├ ether_type (u16)                ├ source_ip_address (u32)
   ├ destination_ip_address (u32)    ├ source_port (u16)
   ├ destination_port (u16)          ├ ip_protocol (u8)
   ├ payload_byte_count (u32)        └ payload_bytes[128]
   │   XdpData ctor: ntohs/ntohl + inet_ntop + payload copy
   ▼
XdpData   host byte order, pre-formatted strings, raw payload vector
   ▼
on_packet_arrived(const XdpData&)
```

Why the struct looks like that:

- **`struct xdp_packet` (packet.h) is the *only* data structure shared between the
  kernel XDP program and userspace.** It is `#pragma pack(1)`, so the C and C++
  compilers produce a byte-identical layout - no padding mismatch across the
  kernel/userspace boundary.
- **Fixed-size payload `payload_bytes[128]`** (not a flexible array) keeps the
  record size constant (159 bytes), so every ring-buffer slot is uniform;
  `payload_byte_count` says how many of those bytes actually hold packet data.
- **All numeric fields stay in network byte order** (as on the wire) inside the
  kernel record. `XdpData` converts them to host order exactly once, in its
  constructor, so the per-packet callback stays cheap.
- **The ring buffer** (`BPF_MAP_TYPE_RINGBUF`, 1 MiB) is the kernel↔userspace
  channel: the XDP program is the producer (`bpf_ringbuf_reserve` → fill →
  `bpf_ringbuf_submit`), userspace is the consumer (`ring_buffer__poll`). It is
  multi-producer safe; if full, we drop *our copy* but still `XDP_PASS` the packet.
- **`bpf_xdp_load_bytes`** copies the payload with runtime bounds checks - safe for
  a variable-length copy that the verifier would reject if done with `memcpy`.

## Using the packet content in your own app

The demo just prints. To integrate the captured packet **content** into an existing
application, derive your own handler, translate `XdpData` into an app-owned struct,
and forward it into your application:

```cpp
#include "PacketHandler.h"   // derive from this
#include "XdpMonitor.h"      // reusable monitor

class MyApplication {                       // your existing application
public:
    void ingest_packet(const AppPacketView &view) { /* use the data */ }
};

class AppPacketHandler : public PacketHandler {
public:
    explicit AppPacketHandler(MyApplication &app) : app_(app) {}
    void on_packet_arrived(const XdpData &packet_data) override {
        AppPacketView view;                              // app's own struct
        view.destination_ipv4_address = packet_data.destination_ipv4_address();
        view.source_port              = packet_data.source_port();
        view.payload_bytes            = packet_data.payload_bytes(); // raw content
        app_.ingest_packet(view);                        // interlock!
    }
private:
    MyApplication &app_;   // reach the app's data structures
};

int main() {
    MyApplication    app;
    AppPacketHandler handler(app);
    XdpMonitor monitor("enp5s0", BPF_OBJECT_PATH, handler);
    return monitor.run();
}
```

How it interlocks: `XdpMonitor` holds a `PacketHandler&`; libbpf passes it as the
callback context, and the `extern "C"` shim dispatches every record into your
handler, which in turn reaches your application via the reference captured in its
constructor. `XdpData` is an *owned copy*, so you can keep it or read `payload_bytes()`
freely. This exact pattern, fully runnable, is in `src/AppIntegrationExample.cpp`
(binary `xdp_app_integration_example`).

**Event-loop apps:** instead of blocking `monitor.run()`, call
`monitor.poll_ring_buffer_once()` from your own loop, or run the monitor on a worker
thread.
