// =============================================================================
// xdp_prog.c
// =============================================================================
// The in-kernel XDP (eXpress Data Path) program.
//
// What this program does
// ---------------------
// When attached to a network interface (e.g. "enp5s0"), the kernel invokes
// this function for EVERY received packet, before the normal network stack
// sees it. This program:
//
//   1. Bounds-checks and parses the Ethernet / IPv4 / TCP / UDP headers.
//   2. Copies the interesting metadata plus a slice of the payload into a
//      packed "struct xdp_packet" record (see packet.h).
//   3. Pushes that record into a BPF ring buffer so the userspace C++
//      program can read it and call its C++ callback method per packet.
//   4. Returns XDP_PASS so the packet keeps flowing through the kernel's
//      normal networking stack (non-disruptive, good for testing).
//
// Why is this a separate C file?
// ------------------------------
// XDP/BPF programs run inside the kernel and are written in a restricted C
// subset. They CANNOT call C++ functions, use libc, or use heap memory. The
// kernel executes this bytecode directly. This is why the "C++ callback"
// lives on the userspace side and is fed through the ring buffer bridge.
//
// The only way userspace (and thus C++) learns about a packet is by reading
// the ring buffer. This file is that kernel-side producer.
//
// "extern C" note
// ---------------
// This file is compiled as plain C, so every function it defines already has
// "C" linkage by default. The entry point below (xdp_capture_packet) is the
// function the kernel jumps into when a packet arrives. It is referenced from
// userspace only by name/section ("SEC("xdp")"), never by direct call, which
// is exactly the C-ABI boundary between kernel BPF and userspace C++.
// =============================================================================

#include "packet.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------------
// Ring buffer map
// ---------------------------------------------------------------------------
// This is the data channel between the kernel BPF program and the userspace
// C++ program. "BPF_MAP_TYPE_RINGBUF" is a fixed-size circular buffer.
// The XDP program reserves a slot, writes the record, and submits it; the
// userspace program polls it and hands each record to the C++ callback.
//
//   .name             : "captured_packets_ringbuf" - the exact string the
//                       userspace program looks up to get this map's fd.
//   .type             : BPF_MAP_TYPE_RINGBUF - multi-producer ring buffer.
//   .max_entries      : 1 MiB of ring buffer space (power of two required).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} captured_packets_ringbuf SEC(".maps");

// ---------------------------------------------------------------------------
// Section / program name
// ---------------------------------------------------------------------------
// SEC("xdp") tells libbpf this function is an XDP program. The function name
// "xdp_capture_packet" is what the userspace program searches for with
// bpf_object__find_program_by_name(...). Both strings must match between the
// two sides - that is our "extern C" contract.
//
//   context argument (struct xdp_md *):
//     - ctx->data     : pointer to the start of the received packet.
//     - ctx->data_end : pointer to one-past-the-end of the received packet.
//     All packet parsing MUST verify reads stay below data_end, or the kernel
//     verifier will reject the program.
SEC("xdp")
int xdp_capture_packet(struct xdp_md *xdp_context)
{
    // ------------------------------------------------------------------
    // Fetch the packet buffer bounds from the kernel-provided metadata.
    // "data" and "data_end" delimit the raw bytes of the received frame.
    // ------------------------------------------------------------------
    void *packet_data      = (void *)(long)xdp_context->data;
    void *packet_data_end  = (void *)(long)xdp_context->data_end;

    // ------------------------------------------------------------------
    // 1) Ethernet header (14 bytes).
    // ------------------------------------------------------------------
    // Guard: the whole 14-byte Ethernet header must fit inside the packet
    // buffer. If not, the frame is malformed / too short; hand it back to
    // the kernel network stack untouched (XDP_PASS).
    struct ethhdr *ethernet_header = (struct ethhdr *)packet_data;
    if ((void *)(ethernet_header + 1) > packet_data_end) {
        return XDP_PASS;
    }

    // Only IPv4 frames are interesting for this example. "h_proto" is stored
    // in network byte order on the wire, so compare against bpf_htons(ETH_P_IP).
    // Non-IPv4 frames (ARP, IPv6, VLAN-tagged, ...) pass through untouched.
    if (ethernet_header->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // ------------------------------------------------------------------
    // 2) IPv4 header.
    // ------------------------------------------------------------------
    // The IPv4 header starts right after the Ethernet header. Guard again:
    // at least the fixed part of the IP header must fit.
    struct iphdr *ip_header = (struct iphdr *)(ethernet_header + 1);
    if ((void *)(ip_header + 1) > packet_data_end) {
        return XDP_PASS;
    }

    // "ihl" (IP header length) counts in 32-bit words; multiply by 4 to get
    // bytes. This tells us where the transport header begins.
    uint32_t ip_header_length_bytes = (uint32_t)ip_header->ihl * 4;

    // Transport header position: directly after the IP header.
    void *transport_header = (void *)ip_header + ip_header_length_bytes;

    // ------------------------------------------------------------------
    // 3) TCP / UDP ports.
    // ------------------------------------------------------------------
    // Ports only exist for TCP and UDP; initialize to zero for other protocols.
    // All port/address values are read here in network byte order and stored
    // as-is; the C++ side converts them to host byte order for display.
    uint16_t source_port = 0;
    uint16_t destination_port = 0;

    if (ip_header->protocol == IPPROTO_TCP) {
        // Guard: the TCP header must fit inside the packet buffer.
        struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
        if ((void *)(tcp_header + 1) > packet_data_end) {
            return XDP_PASS;
        }
        source_port = tcp_header->source;
        destination_port = tcp_header->dest;
    } else if (ip_header->protocol == IPPROTO_UDP) {
        // Guard: the UDP header must fit inside the packet buffer.
        struct udphdr *udp_header = (struct udphdr *)transport_header;
        if ((void *)(udp_header + 1) > packet_data_end) {
            return XDP_PASS;
        }
        source_port = udp_header->source;
        destination_port = udp_header->dest;
    }
    // Note: we deliberately skip the "doff" (data offset) field of the TCP
    // header. For simplicity the payload copy below always starts right after
    // the fixed TCP header (20 bytes), which is accurate for the vast
    // majority of real-world packets without TCP options.

    // ------------------------------------------------------------------
    // 4) Compute where the application payload starts.
    // ------------------------------------------------------------------
    // Payload = everything after the Ethernet + IP + transport headers.
    void *payload_start = (void *)ip_header + ip_header_length_bytes;
    if (ip_header->protocol == IPPROTO_TCP) {
        payload_start += sizeof(struct tcphdr);   // fixed 20-byte TCP header
    } else if (ip_header->protocol == IPPROTO_UDP) {
        payload_start += sizeof(struct udphdr);   // fixed 8-byte UDP header
    }

    // ------------------------------------------------------------------
    // 5) Reserve a slot in the ring buffer for the record.
    // ------------------------------------------------------------------
    // bpf_ringbuf_reserve(map, size, flags) returns a writable buffer of
    // "size" bytes (or NULL if the ring buffer is full). We reserve the full
    // fixed-size record defined in packet.h.
    struct xdp_packet *packet_record = (struct xdp_packet *)bpf_ringbuf_reserve(
        &captured_packets_ringbuf, sizeof(struct xdp_packet), 0);
    if (packet_record == NULL) {
        // Ring buffer full - drop THIS COPY for userspace, but still let the
        // packet itself continue on its normal path.
        return XDP_PASS;
    }

    // ------------------------------------------------------------------
    // 6) Fill the record with the parsed packet metadata.
    // ------------------------------------------------------------------
    // MAC addresses: copy the 6 raw bytes (network order, same as on wire).
    __builtin_memcpy(packet_record->destination_mac_address,
                     ethernet_header->h_dest,
                     sizeof(packet_record->destination_mac_address));
    __builtin_memcpy(packet_record->source_mac_address,
                     ethernet_header->h_source,
                     sizeof(packet_record->source_mac_address));

    // EtherType: copy the raw 16-bit value (already in network byte order).
    packet_record->ether_type = ethernet_header->h_proto;

    // IP addresses: raw 4 bytes each, network byte order.
    packet_record->source_ip_address = ip_header->saddr;
    packet_record->destination_ip_address = ip_header->daddr;

    // Ports: network byte order, 0 when the protocol has no ports.
    packet_record->source_port = source_port;
    packet_record->destination_port = destination_port;

    // IP protocol number (6 = TCP, 17 = UDP, ...).
    packet_record->ip_protocol = ip_header->protocol;

    // ------------------------------------------------------------------
    // 7) Copy as much of the payload as fits into the record.
    // ------------------------------------------------------------------
    // CRITICAL verifier note: never apply a bitwise/shift/truncation op
    // directly to the packet pointer (PTR_TO_PACKET). The verifier only
    // allows ADD/SUB and bounds-compare on packet pointers; anything else
    // ("rX <<= 32", "rX >>= 32") makes it reject the program with -EACCES.
    // So we convert the pointer positions to plain 64-bit INTEGERS FIRST via
    // the (long) casts below; from that point on every register is a scalar
    // where all arithmetic is allowed.
    //
    //   payload_offset_bytes : offset of the payload within the frame.
    //   payload_available_bytes : how many payload bytes exist in the packet
    //                             (negative if the transport header overran
    //                             the frame, i.e. no payload).
    const long payload_offset_bytes =
        (long)payload_start - (long)packet_data;
    const long payload_available_bytes =
        (long)packet_data_end - (long)payload_start;

    // Clamp the copy length: at least 0, at most the fixed array capacity.
    // All comparisons below run on scalars, never on the packet pointer.
    uint32_t payload_bytes_to_copy = 0;
    if (payload_available_bytes > 0) {
        payload_bytes_to_copy = (uint32_t)payload_available_bytes;
        if (payload_bytes_to_copy > XDP_PACKET_MAX_PAYLOAD_BYTES) {
            payload_bytes_to_copy = XDP_PACKET_MAX_PAYLOAD_BYTES;
        }
    }
    packet_record->payload_byte_count = payload_bytes_to_copy;

    // Only copy if there is actually payload to copy.
    //
    // We use bpf_xdp_load_bytes(ctx, offset, dst, len) instead of memcpy():
    // the copy length here is a runtime value, and the BPF verifier rejects a
    // variable-length call to memcpy. This helper safely reads "len" bytes
    // from the frame at "offset" relative to xdp_md->data, doing its own
    // runtime bounds check. It returns 0 on success; we ignore the result
    // since a read failure simply means there is nothing meaningful to show.
    if (payload_bytes_to_copy > 0) {
        bpf_xdp_load_bytes(xdp_context, (uint32_t)payload_offset_bytes,
                           packet_record->payload_bytes, payload_bytes_to_copy);
    }

    // ------------------------------------------------------------------
    // 8) Commit the record to the ring buffer.
    // ------------------------------------------------------------------
    // Once submitted, the userspace C++ program can read this record and will
    // invoke its per-packet callback for it. Flags argument: 0 = default.
    bpf_ringbuf_submit(packet_record, 0);

    // ------------------------------------------------------------------
    // 9) Let the packet continue through the kernel's normal network stack.
    // ------------------------------------------------------------------
    // Returning XDP_PASS means "I only observed this packet, do not drop or
    // redirect it". This keeps the experiment non-disruptive for testing.
    return XDP_PASS;
}

// ---------------------------------------------------------------------------
// License
// ---------------------------------------------------------------------------
// BPF programs must declare their license in a special ".license" section.
// GPL is required because we use GPL-licensed BPF helpers (ring buffer ops).
char xdp_program_license[] SEC("license") = "GPL";
