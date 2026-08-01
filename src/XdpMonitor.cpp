// =============================================================================
// XdpMonitor.cpp
// =============================================================================
// Implementation of the XdpMonitor class (see XdpMonitor.h for the design).
//
// This file also contains the "extern C" ring buffer sample shim:
//   handle_ringbuf_sample(...)
// libbpf calls it for every record in the ring buffer; it converts the raw
// kernel record into an XdpData object and dispatches to the C++ callback.
// =============================================================================

#include "XdpMonitor.h"

#include <bpf/libbpf.h>      // libbpf API: loading BPF objects, ring buffers
#include <linux/if_link.h>   // XDP_FLAGS_* constants for attaching
#include <net/if.h>          // if_nametoindex(): interface name -> index

#include <csignal>           // signal() / SIGINT for clean shutdown
#include <cstdint>           // uint*_t fixed-width integer types
#include <cstdio>            // std::fprintf, std::printf
#include <cstring>           // std::strerror
#include <string>            // std::string

#include "XdpData.h"         // C++ data class for the captured packet data
#include "packet.h"          // shared "struct xdp_packet" record layout

// ---------------------------------------------------------------------------
// Globals (internal to this translation unit)
// ---------------------------------------------------------------------------

// Flag flipped by the SIGINT handler; the poll loop checks it to know when to
// stop. "volatile sig_atomic_t" is the only type that is safe to write from a
// signal handler.
static volatile sig_atomic_t stop_monitoring_requested = 0;

// ---------------------------------------------------------------------------
// Signal handler for graceful shutdown (Ctrl-C / SIGINT).
// ---------------------------------------------------------------------------
// C++ forbids most operations inside a signal handler; we only set a flag and
// let the poll loop react to it.
extern "C" void handle_interrupt_signal(int /*signal_number*/)
{
    stop_monitoring_requested = 1;
}

// ---------------------------------------------------------------------------
// The "extern C" bridge function (called by libbpf per ring buffer sample).
// ---------------------------------------------------------------------------
// libbpf consumes the ring buffer and, for every submitted record, invokes a
// callback with this C signature:
//
//     int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t size);
//
// "extern \"C\"" guarantees the C++ compiler emits a plain C symbol with C
// calling conventions, which is what libbpf (a C library) requires.
//
// Arguments:
//   callback_context : the pointer we passed to ring_buffer__new() - here it
//                      is the PacketHandler to notify.
//   raw_record_data  : points directly into the ring buffer slot holding the
//                      "struct xdp_packet" filled by the XDP program.
//   record_size      : number of bytes in that slot.
//
// Return value:
//   0 on success; nonzero tells libbpf to stop consuming. We always succeed.
extern "C" int handle_ringbuf_sample(void *callback_context, void *raw_record_data,
                                     size_t record_size)
{
    // Verify the record is at least as large as our fixed struct. If a
    // different/unexpected record showed up, skip it defensively.
    if (record_size < sizeof(struct xdp_packet)) {
        return 0;
    }

    // Convert the raw kernel record (C struct, network byte order) into the
    // C++ data class. This is where the C -> C++ boundary is crossed.
    const struct xdp_packet *raw_record =
        static_cast<const struct xdp_packet *>(raw_record_data);
    const XdpData packet_data(raw_record);

    // Dispatch to the C++ callback method on the handler supplied as context.
    PacketHandler *packet_handler = static_cast<PacketHandler *>(callback_context);
    if (packet_handler != nullptr) {
        packet_handler->on_packet_arrived(packet_data);
    }

    return 0; // keep consuming; never ask libbpf to stop on a normal packet
}

// =============================================================================
// XdpMonitor implementation
// =============================================================================

// Constructor stores the target interface name, the BPF object file path and
// the handler object (which must outlive the monitor).
XdpMonitor::XdpMonitor(const std::string &target_interface_name,
                       const std::string &bpf_object_file_path,
                       PacketHandler &packet_handler)
    : target_interface_name_(target_interface_name),
      bpf_object_file_path_(bpf_object_file_path),
      packet_handler_(packet_handler)
{
}

// Clean up all kernel resources when the monitor is destroyed.
XdpMonitor::~XdpMonitor()
{
    detach_xdp_program();
    close_ring_buffer();
    close_bpf_object();
}

// Install SIGINT/SIGTERM handlers so Ctrl-C asks the monitor to stop cleanly.
void XdpMonitor::install_signal_handlers()
{
    std::signal(SIGINT, handle_interrupt_signal);
    std::signal(SIGTERM, handle_interrupt_signal);
}

// ---------------------------------------------------------------------------
// run(): the full monitor lifecycle. Returns 0 on clean exit, nonzero on error.
// ---------------------------------------------------------------------------
int XdpMonitor::run()
{
    // 1) Resolve the interface name to a kernel interface index.
    if (!resolve_interface_index()) {
        return 1;
    }

    // 2) Load the BPF object from disk into the kernel.
    if (!load_bpf_object()) {
        return 1;
    }

    // 3) Find the XDP program and the ring buffer map inside the object.
    if (!find_bpf_program_and_map()) {
        return 1;
    }

    // 4) Attach the XDP program to the interface (generic XDP mode).
    if (!attach_xdp_program()) {
        return 1;
    }

    // 5) Open the ring buffer consumer; the sample callback receives the
    //    handler as its context so it can reach the C++ callback.
    if (!open_ring_buffer()) {
        return 1;
    }

    std::printf("Monitoring interface '%s' (ifindex=%d). Press Ctrl-C to stop.\n",
                target_interface_name_.c_str(), interface_index_);

    // 6) Poll the ring buffer until the signal handler asks us to stop.
    poll_ring_buffer();

    std::printf("\nShutting down cleanly.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// poll_ring_buffer_once(): one pass over the ring buffer, for applications
// with their own event loop. Returns bytes processed or a negative errno.
// ---------------------------------------------------------------------------
int XdpMonitor::poll_ring_buffer_once()
{
    if (ring_buffer_ == nullptr) {
        return -EINVAL;
    }
    return ring_buffer__poll(ring_buffer_, config::POLL_TIMEOUT_MS);
}

// ---------------------------------------------------------------------------
// Step 1: interface name -> index.
// ---------------------------------------------------------------------------
bool XdpMonitor::resolve_interface_index()
{
    interface_index_ = if_nametoindex(target_interface_name_.c_str());
    if (interface_index_ == 0) {
        std::fprintf(stderr,
                     "Error: unknown network interface '%s' (errno=%d: %s)\n",
                     target_interface_name_.c_str(), errno, std::strerror(errno));
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 2: load the BPF object file into the kernel.
// ---------------------------------------------------------------------------
bool XdpMonitor::load_bpf_object()
{
    bpf_object_ = bpf_object__open_file(bpf_object_file_path_.c_str(), nullptr);
    if (bpf_object_ == nullptr) {
        std::fprintf(stderr,
                     "Error: failed to open BPF object '%s' (errno=%d: %s)\n",
                     bpf_object_file_path_.c_str(), errno, std::strerror(errno));
        return false;
    }

    if (bpf_object__load(bpf_object_) != 0) {
        std::fprintf(stderr, "Error: failed to load BPF object into the kernel\n");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 3: locate the XDP program and ring buffer map by name.
// ---------------------------------------------------------------------------
bool XdpMonitor::find_bpf_program_and_map()
{
    // Find the program by its function name (see xdp_prog.c).
    xdp_program_ = bpf_object__find_program_by_name(bpf_object_,
                                                    config::XDP_PROGRAM_NAME);
    if (xdp_program_ == nullptr) {
        std::fprintf(stderr, "Error: XDP program '%s' not found in object\n",
                     config::XDP_PROGRAM_NAME);
        return false;
    }

    // Find the ring buffer map by its declared name.
    ringbuf_map_ = bpf_object__find_map_by_name(bpf_object_,
                                                config::RINGBUF_MAP_NAME);
    if (ringbuf_map_ == nullptr) {
        std::fprintf(stderr, "Error: ring buffer map '%s' not found in object\n",
                     config::RINGBUF_MAP_NAME);
        return false;
    }

    // Get the file descriptor of the loaded program (needed to attach).
    xdp_program_fd_ = bpf_program__fd(xdp_program_);
    if (xdp_program_fd_ < 0) {
        std::fprintf(stderr, "Error: failed to get XDP program file descriptor\n");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 4: attach the XDP program to the interface.
// ---------------------------------------------------------------------------
// We use GENERIC XDP mode (XDP_FLAGS_SKB_MODE). The r8169 NIC driver on this
// machine does not support native driver-mode XDP, so generic XDP is the
// compatible choice. Generic XDP runs the program at the software receive
// path - slightly slower than native, but works on any NIC.
bool XdpMonitor::attach_xdp_program()
{
    const int attach_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
    if (bpf_xdp_attach(interface_index_, xdp_program_fd_, attach_flags, nullptr) != 0) {
        std::fprintf(stderr,
                     "Error: failed to attach XDP program to '%s' (errno=%d: %s).\n"
                     "  Run with sudo, and make sure no other XDP program is\n"
                     "  already attached (check: ip link show %s).\n",
                     target_interface_name_.c_str(), errno, std::strerror(errno),
                     target_interface_name_.c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 5: open the ring buffer consumer.
// ---------------------------------------------------------------------------
// ring_buffer__new(map_fd, sample_cb, sample_cb_ctx, opts) registers
// handle_ringbuf_sample as the per-record callback. The "ctx" we pass is the
// PacketHandler; libbpf forwards it to the callback unchanged, which is how
// the C shim reaches the C++ callback method.
bool XdpMonitor::open_ring_buffer()
{
    const int ringbuf_fd = bpf_map__fd(ringbuf_map_);
    if (ringbuf_fd < 0) {
        std::fprintf(stderr, "Error: failed to get ring buffer map fd\n");
        return false;
    }

    ring_buffer_ = ring_buffer__new(ringbuf_fd, handle_ringbuf_sample,
                                    &packet_handler_, nullptr);
    if (ring_buffer_ == nullptr) {
        std::fprintf(stderr, "Error: failed to open ring buffer consumer\n");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 6: poll the ring buffer until Ctrl-C is received.
// ---------------------------------------------------------------------------
void XdpMonitor::poll_ring_buffer()
{
    while (!stop_monitoring_requested) {
        // ring_buffer__poll() drains all pending records, invoking the
        // callback for each. Returns bytes processed, or a negative errno.
        const int poll_result = ring_buffer__poll(ring_buffer_,
                                                  config::POLL_TIMEOUT_MS);
        if (poll_result < 0) {
            std::fprintf(stderr, "Error: ring buffer poll failed (%d: %s)\n",
                         -poll_result, std::strerror(-poll_result));
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Teardown helpers (called by the destructor).
// ---------------------------------------------------------------------------
void XdpMonitor::detach_xdp_program()
{
    if (interface_index_ >= 0 && xdp_program_fd_ >= 0) {
        // Removing the program restores normal packet flow on the NIC.
        const int detach_flags = XDP_FLAGS_SKB_MODE;
        bpf_xdp_detach(interface_index_, detach_flags, nullptr);
        xdp_program_fd_ = -1;
    }
}

void XdpMonitor::close_ring_buffer()
{
    if (ring_buffer_ != nullptr) {
        ring_buffer__free(ring_buffer_);
        ring_buffer_ = nullptr;
    }
}

void XdpMonitor::close_bpf_object()
{
    if (bpf_object_ != nullptr) {
        bpf_object__close(bpf_object_);
        bpf_object_ = nullptr;
    }
}
