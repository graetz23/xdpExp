// =============================================================================
// XdpMonitor.h
// =============================================================================
// Reusable XDP monitor: loads a BPF object, attaches the XDP program to a
// network interface, polls the packet ring buffer, and dispatches every
// captured packet to a C++ PacketHandler callback.
//
// This class is the reusable bridge between the in-kernel XDP program and an
// application. Both executables in this project use it:
//
//   * xdp_demo                      (src/main.cpp)              - prints packets
//   * xdp_app_integration_example   (src/AppIntegrationExample.cpp)
//                                   - feeds packets into an "existing app"
//
// "extern C" bridge (the C boundary)
// ----------------------------------
// libbpf (a C library) drives the ring buffer consumption and calls back into
// our code with C calling conventions. The function handle_ringbuf_sample(...)
// is declared "extern \"C\"" so it has exactly the C symbol/ABI libbpf expects.
// Inside that C function we safely switch into C++: we build an XdpData object
// and dispatch to the C++ PacketHandler::on_packet_arrived callback. This is
// the "extern C -> C++ callback" boundary the experiment asks for.
// =============================================================================

#ifndef XDP_EXPERIMENT_XDP_MONITOR_H
#define XDP_EXPERIMENT_XDP_MONITOR_H

#include <string>     // std::string for interface name / object file path

#include "PacketHandler.h"   // the C++ callback interface the monitor notifies

// Forward declaration of the libbpf types we store as opaque pointers. Keeping
// them out of the header avoids leaking libbpf internals into every consumer.
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct ring_buffer;

// ---------------------------------------------------------------------------
// Runtime configuration (self-explanatory, centralized here).
// ---------------------------------------------------------------------------
namespace config
{
    // Name of the XDP program inside the object (must match xdp_prog.c).
    // "inline" (C++17) gives these single, shared definitions across all
    // translation units that include this header - otherwise the linker would
    // see multiple definitions.
    inline const char *XDP_PROGRAM_NAME     = "xdp_capture_packet";
    // Name of the ring buffer map (must match xdp_prog.c).
    inline const char *RINGBUF_MAP_NAME     = "captured_packets_ringbuf";
    // Poll timeout in ms for each ring_buffer__poll() call.
    inline const int   POLL_TIMEOUT_MS      = 250;
} // namespace config

// ---------------------------------------------------------------------------
// XdpMonitor: loads, attaches, polls, and detaches the XDP program.
// ===========================================================================
class XdpMonitor
{
public:
    // Constructor stores the target interface name, the BPF object file path
    // and the handler object. The handler must outlive the monitor (we keep a
    // plain reference to it).
    XdpMonitor(const std::string &target_interface_name,
               const std::string &bpf_object_file_path,
               PacketHandler &packet_handler);

    // Non-copyable: holds kernel resources and a reference; copying would lead
    // to double-detach / dangling references.
    XdpMonitor(const XdpMonitor &) = delete;
    XdpMonitor &operator=(const XdpMonitor &) = delete;

    // Clean up all kernel resources when the monitor is destroyed.
    ~XdpMonitor();

    // ------------------------------------------------------------------
    // run(): the full monitor lifecycle. Blocks in the poll loop until the
    // signal handler requests a stop. Returns 0 on clean exit, nonzero on
    // error. This is the simplest way to drive the monitor (used by both
    // example programs). Applications with their own event loop can instead
    // poll the ring buffer themselves (see poll_ring_buffer_once).
    // ------------------------------------------------------------------
    int run();

    // ------------------------------------------------------------------
    // Alternative integration for event-loop driven applications:
    // performs ONE non-blocking-ish poll of the ring buffer, delivering any
    // pending records to the callback. The application calls this from its own
    // loop instead of using run(). Returns bytes processed, or a negative
    // errno on failure.
    // ------------------------------------------------------------------
    int poll_ring_buffer_once();

    // Installs SIGINT/SIGTERM handlers so Ctrl-C asks the monitor to stop
    // cleanly (detaching the XDP program). Call once before run().
    static void install_signal_handlers();

private:
    // ------------------------------------------------------------------
    // Member state.
    // ------------------------------------------------------------------
    std::string       target_interface_name_; // e.g. "enp5s0"
    std::string       bpf_object_file_path_;  // path to the compiled xdp_prog.o
    PacketHandler    &packet_handler_;        // C++ callback to notify per packet
    int               interface_index_ = -1;  // kernel index of the interface
    struct bpf_object  *bpf_object_  = nullptr; // loaded BPF object handle
    struct bpf_program *xdp_program_ = nullptr; // the XDP program handle
    struct bpf_map      *ringbuf_map_ = nullptr; // the ring buffer map handle
    struct ring_buffer  *ring_buffer_  = nullptr; // the ring buffer consumer
    int               xdp_program_fd_ = -1;  // program fd after loading

    // ------------------------------------------------------------------
    // Lifecycle steps (called in order by run()).
    // ------------------------------------------------------------------
    bool resolve_interface_index();   // step 1: interface name -> index
    bool load_bpf_object();           // step 2: open + load the BPF object
    bool find_bpf_program_and_map();  // step 3: locate program and map by name
    bool attach_xdp_program();        // step 4: attach to the interface
    bool open_ring_buffer();          // step 5: open the ring buffer consumer
    void poll_ring_buffer();          // step 6: poll until asked to stop
    void detach_xdp_program();        // teardown: detach from the interface
    void close_ring_buffer();         // teardown: free the consumer
    void close_bpf_object();          // teardown: close the BPF object
};

#endif // XDP_EXPERIMENT_XDP_MONITOR_H
