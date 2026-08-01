// =============================================================================
// PacketHandler.h
// =============================================================================
// The C++ callback interface for XDP packet events.
//
// This is the "C++ callback method" of the experiment. Users of the library
// derive a class from PacketHandler, implement on_packet_arrived(...), and
// hand an instance to the XDP monitor. The monitor then invokes
// on_packet_arrived(...) once per captured packet, passing a fully parsed
// XdpData object describing that packet.
//
// Why an interface instead of a plain function pointer?
// ----------------------------------------------------
// * It lets each user attach its own state (member variables) alongside the
//   callback - something a bare function pointer cannot do.
// * It is type-safe and idiomatic C++.
// * The ring-buffer glue between kernel and userspace stays a thin C shim
//   (the "extern C" function in main.cpp), and this interface keeps the
//   per-packet work comfortably on the C++ side of that boundary.
// =============================================================================

#ifndef XDP_EXPERIMENT_PACKET_HANDLER_H
#define XDP_EXPERIMENT_PACKET_HANDLER_H

#include "XdpData.h"     // the per-packet C++ data class passed to the callback

class PacketHandler
{
public:
    // Virtual destructor: ensures a derived handler is destroyed correctly
    // when deleted through a PacketHandler* pointer.
    virtual ~PacketHandler() = default;

    // ------------------------------------------------------------------
    // The per-packet callback method.
    // ------------------------------------------------------------------
    // Called by the XDP monitor once for every captured packet.
    //
    //   packet_data : an XdpData object holding the parsed metadata and
    //                 payload slice of one captured packet. It is a full
    //                 owned copy, so the handler may keep it or read it
    //                 freely without worrying about buffer lifetimes.
    //
    // Implementations should not block for long: while this runs, further
    // packets keep arriving and are queued in the ring buffer.
    virtual void on_packet_arrived(const XdpData &packet_data) = 0;
};

#endif // XDP_EXPERIMENT_PACKET_HANDLER_H
