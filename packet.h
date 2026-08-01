// =============================================================================
// packet.h
// =============================================================================
// Shared definition of the packet record exchanged between:
//
//   * the in-kernel XDP/BPF program (written in C, "xdp_prog.c"), and
//   * the userspace C++ program ("main.cpp" / "XdpData.cpp").
//
// The XDP program fills one of these records per captured packet and pushes it
// into a BPF ring buffer. The userspace program reads the record out of the
// ring buffer and wraps it in the C++ class XdpData.
//
// Because this header is included from BOTH C and C++ translation units, it
// must stay valid in both languages and must not depend on any C++ features.
//
// Layout / packing
// ----------------
// The struct uses "#pragma pack(1)" so the C and C++ compilers produce a
// byte-for-byte identical, tightly packed layout. Without packing, the two
// compilers could insert different padding bytes and the record would be
// misinterpreted across the C/C++ boundary.
//
// The payload is a FIXED-SIZE array (not a flexible array member) on purpose:
// flexible array members are a GNU extension in C++ and would make the record
// size harder to reason about. A fixed maximum keeps the code portable and
// simple; the "payload_byte_count" field records how many of the reserved
// bytes actually contain packet data.
// =============================================================================

#ifndef XDP_EXPERIMENT_PACKET_H
#define XDP_EXPERIMENT_PACKET_H

#include <stdint.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
// Maximum number of packet payload bytes copied into a record. The XDP
// program truncates any larger payload. Kept modest so each ring buffer slot
// stays small and the buffer can hold many records.
#define XDP_PACKET_MAX_PAYLOAD_BYTES 128

// ---------------------------------------------------------------------------
// Packet record struct
// ---------------------------------------------------------------------------
// One instance of this struct is created for each packet that the XDP program
// decides to capture, and is delivered to userspace through the ring buffer.
//
// Field semantics (all numeric values are stored in NETWORK byte order, the
// same order in which they appear on the wire):
//
//   destination_mac_address[6] : destination MAC address of the frame.
//   source_mac_address[6]      : source MAC address of the frame.
//   ether_type                 : EtherType (e.g. 0x0800 == IPv4).
//   source_ip_address          : IPv4 source address (4 bytes, network order).
//   destination_ip_address     : IPv4 destination address (network order).
//   source_port                : TCP/UDP source port (0 if not TCP/UDP).
//   destination_port           : TCP/UDP destination port (0 if not TCP/UDP).
//   ip_protocol                : IP protocol number (e.g. 6 == TCP, 17 == UDP).
//   payload_byte_count         : how many bytes of "payload_bytes" are real
//                                packet data (0 .. XDP_PACKET_MAX_PAYLOAD_BYTES).
//   payload_bytes[...]         : the first payload_byte_count bytes of the
//                                packet's application payload (if any).
#pragma pack(push, 1)   // ensure an identical, tightly packed layout in C and C++
struct xdp_packet {
    uint8_t destination_mac_address[6];
    uint8_t source_mac_address[6];
    uint16_t ether_type;
    uint32_t source_ip_address;
    uint32_t destination_ip_address;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t ip_protocol;
    uint32_t payload_byte_count;
    uint8_t payload_bytes[XDP_PACKET_MAX_PAYLOAD_BYTES];
};
#pragma pack(pop)       // restore the compiler's default alignment rules

#endif // XDP_EXPERIMENT_PACKET_H
