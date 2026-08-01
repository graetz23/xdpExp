// =============================================================================
// XdpData.cpp
// =============================================================================
// Implementation of the XdpData C++ data class.
//
// The constructor performs ALL parsing / byte-order conversion from the raw
// kernel record ("struct xdp_packet") into the friendly host-order C++ form,
// so the per-packet callback stays fast and readable.
// =============================================================================

#include "XdpData.h"

#include <arpa/inet.h>    // inet_ntop() : binary IPv4 address -> dotted string
#include <cstdio>         // snprintf()  : format MAC addresses / hex dump
#include <cstring>        // memcpy()    : copy the raw record into our storage

namespace
{
// ---------------------------------------------------------------------------
// Anonymous-namespace helper functions (internal to this translation unit).
// ---------------------------------------------------------------------------

// Formats a raw 6-byte MAC address (as found in the packet) into the
// conventional "aa:bb:cc:dd:ee:ff" text form.
std::string format_mac_address(const uint8_t mac_bytes[6])
{
    char formatted_mac[18]; // "aa:bb:cc:dd:ee:ff" (17 chars) + NUL
    std::snprintf(formatted_mac, sizeof(formatted_mac),
                  "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac_bytes[0], mac_bytes[1], mac_bytes[2],
                  mac_bytes[3], mac_bytes[4], mac_bytes[5]);
    return std::string(formatted_mac);
}

// Formats a raw 4-byte IPv4 address (in network byte order) into the
// conventional dotted-quad text form, e.g. "192.168.1.1".
std::string format_ipv4_address(const uint32_t ipv4_address_network_order)
{
    char formatted_ip[INET_ADDRSTRLEN]; // 16 bytes is enough for IPv4 + NUL
    inet_ntop(AF_INET, &ipv4_address_network_order, formatted_ip,
              sizeof(formatted_ip));
    return std::string(formatted_ip);
}

} // namespace

// =============================================================================
// Constructor: parse one raw kernel record into the C++ data class.
// =============================================================================
XdpData::XdpData(const struct xdp_packet *raw_packet_record)
    : ether_type_(0),        // initialized, then overwritten below
      ip_protocol_(0),
      source_port_(0),
      destination_port_(0)
{
    if (raw_packet_record == nullptr) {
        return; // defensive: nothing to copy; object stays all-zeros/empty
    }

    // Copy the raw record into our own storage so this object is valid even
    // after the ring buffer moves on to newer records.
    const struct xdp_packet record_copy = *raw_packet_record;

    // MAC addresses: convert raw bytes to printable text form.
    destination_mac_address_ = format_mac_address(record_copy.destination_mac_address);
    source_mac_address_      = format_mac_address(record_copy.source_mac_address);

    // EtherType: stored in network byte order on the wire; convert to host
    // byte order so callers can compare against ETH_P_IP etc. directly.
    ether_type_ = ntohs(record_copy.ether_type);

    // IPv4 addresses: convert the raw network-order 32-bit values to dotted
    // quad strings. (inet_ntop expects network byte order - just what we have.)
    source_ipv4_address_      = format_ipv4_address(record_copy.source_ip_address);
    destination_ipv4_address_ = format_ipv4_address(record_copy.destination_ip_address);

    // Protocol number and ports (host byte order for the ports).
    ip_protocol_    = record_copy.ip_protocol;
    source_port_    = ntohs(record_copy.source_port);
    destination_port_ = ntohs(record_copy.destination_port);

    // Copy only the bytes that actually hold payload (payload_byte_count),
    // never more than the record actually declared.
    const size_t payload_length =
        static_cast<size_t>(record_copy.payload_byte_count);
    const size_t bytes_to_copy =
        (payload_length <= XDP_PACKET_MAX_PAYLOAD_BYTES) ? payload_length
                                                         : XDP_PACKET_MAX_PAYLOAD_BYTES;
    payload_bytes_.assign(record_copy.payload_bytes,
                          record_copy.payload_bytes + bytes_to_copy);
}

// =============================================================================
// ip_protocol_name: human-readable name for the IP protocol number.
// =============================================================================
std::string XdpData::ip_protocol_name() const
{
    switch (ip_protocol_) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: {
            // Fall back to showing the numeric protocol number.
            char unknown_protocol[32];
            std::snprintf(unknown_protocol, sizeof(unknown_protocol),
                          "Other(%u)", static_cast<unsigned>(ip_protocol_));
            return std::string(unknown_protocol);
        }
    }
}

// =============================================================================
// payload_hex_dump: multi-line hex + ASCII dump of the captured payload bytes.
// =============================================================================
std::string XdpData::payload_hex_dump() const
{
    // Each dump line shows up to 16 bytes: "00 01 ... 0f  |<ascii>|".
    constexpr size_t bytes_per_line = 16;
    std::string hex_dump;

    for (size_t line_offset = 0; line_offset < payload_bytes_.size();
         line_offset += bytes_per_line) {
        char hex_part[3 * bytes_per_line + 1];  // "xx " x 16 + NUL
        char ascii_part[bytes_per_line + 1];    // 16 visible chars + NUL
        size_t ascii_pos = 0;

        for (size_t column = 0; column < bytes_per_line; ++column) {
            const size_t byte_index = line_offset + column;
            if (byte_index < payload_bytes_.size()) {
                const uint8_t current_byte = payload_bytes_[byte_index];
                std::snprintf(hex_part + 3 * column, 4, "%02x ", current_byte);
                // Printable ASCII is shown as-is; everything else becomes '.'.
                ascii_part[ascii_pos++] =
                    (current_byte >= 0x20 && current_byte <= 0x7e)
                        ? static_cast<char>(current_byte)
                        : '.';
            } else {
                std::snprintf(hex_part + 3 * column, 4, "   "); // pad the rest
            }
        }
        ascii_part[ascii_pos] = '\0';

        hex_dump += "    " + std::string(hex_part) + " |" + ascii_part + "|\n";
    }

    return hex_dump;
}
