// =============================================================================
// XdpData.h
// =============================================================================
// The C++ data class that represents a single captured XDP packet.
//
// A raw "struct xdp_packet" (packet.h) arrives from the kernel through the
// BPF ring buffer. It is a plain C struct with fixed-size fields, mostly in
// network byte order. XdpData wraps it and exposes the data through safe,
// readable, host-order C++ accessors - exactly the "C++ data class for the
// XDP data" the experiment asks for.
//
// Design decisions
// ----------------
// * We COPY the raw record into this object (not store a pointer). Ring
//   buffer memory is only valid until the ring buffer is consumed/advanced,
//   so an owning copy keeps the object usable anywhere.
// * All byte-order conversion happens once, in the constructor. The accessors
//   are then trivial and cheap, which keeps the per-packet callback fast.
// * MAC addresses and IPv4 addresses are stored as pre-formatted strings so
//   callers can print them directly without repeating inet_ntop logic.
// * The payload is kept as raw bytes (std::vector<uint8_t>) so callers can
//   interpret it however they like; a small hex-dump helper is provided.
// =============================================================================

#ifndef XDP_EXPERIMENT_XDP_DATA_H
#define XDP_EXPERIMENT_XDP_DATA_H

#include "packet.h"          // the shared "struct xdp_packet" definition

#include <cstdint>           // fixed-width integer types (uint16_t, ...)
#include <string>            // std::string for formatted addresses
#include <vector>            // std::vector<uint8_t> for the raw payload

class XdpData
{
public:
    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------
    // Builds a fully parsed, host-order C++ view of one raw kernel record.
    //
    //   raw_packet_record : pointer to the record read from the ring buffer.
    //                       Must point to at least sizeof(struct xdp_packet)
    //                       readable bytes. We copy those bytes into our own
    //                       storage immediately.
    explicit XdpData(const struct xdp_packet *raw_packet_record);

    // ------------------------------------------------------------------
    // Metadata accessors (host byte order, ready for display/logging).
    // ------------------------------------------------------------------

    // Destination MAC address, formatted as "aa:bb:cc:dd:ee:ff".
    const std::string &destination_mac_address() const { return destination_mac_address_; }

    // Source MAC address, formatted as "aa:bb:cc:dd:ee:ff".
    const std::string &source_mac_address() const { return source_mac_address_; }

    // EtherType as a raw 16-bit value in HOST byte order (e.g. 0x0800 = IPv4).
    uint16_t ether_type() const { return ether_type_; }

    // Source IPv4 address, formatted as dotted quad "192.168.1.1".
    const std::string &source_ipv4_address() const { return source_ipv4_address_; }

    // Destination IPv4 address, formatted as dotted quad "192.168.1.1".
    const std::string &destination_ipv4_address() const { return destination_ipv4_address_; }

    // IP protocol number in HOST byte order (6 = TCP, 17 = UDP, 1 = ICMP, ...).
    uint8_t ip_protocol() const { return ip_protocol_; }

    // Human-readable protocol name ("TCP", "UDP", "ICMP", "Other(42)").
    std::string ip_protocol_name() const;

    // Source TCP/UDP port (0 when the protocol has no ports).
    uint16_t source_port() const { return source_port_; }

    // Destination TCP/UDP port (0 when the protocol has no ports).
    uint16_t destination_port() const { return destination_port_; }

    // Number of meaningful bytes in the payload vector (0 .. MAX_PAYLOAD).
    size_t payload_byte_count() const { return payload_bytes_.size(); }

    // Raw application payload bytes (host order, as-is from the wire).
    const std::vector<uint8_t> &payload_bytes() const { return payload_bytes_; }

    // Multi-line hex + ASCII dump of the payload, for convenient printing.
    std::string payload_hex_dump() const;

private:
    // ------------------------------------------------------------------
    // Owned, parsed copy of the packet data.
    // ------------------------------------------------------------------
    std::string destination_mac_address_;   // formatted "aa:bb:cc:dd:ee:ff"
    std::string source_mac_address_;        // formatted "aa:bb:cc:dd:ee:ff"
    uint16_t    ether_type_;                // host byte order EtherType
    std::string source_ipv4_address_;       // formatted dotted quad
    std::string destination_ipv4_address_;  // formatted dotted quad
    uint8_t     ip_protocol_;               // IP protocol number
    uint16_t    source_port_;               // host byte order, 0 if none
    uint16_t    destination_port_;          // host byte order, 0 if none
    std::vector<uint8_t> payload_bytes_;    // copy of the raw payload slice
};

#endif // XDP_EXPERIMENT_XDP_DATA_H
