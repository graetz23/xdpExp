// =============================================================================
// main.cpp
// =============================================================================
// The demo executable "xdp_demo".
//
// This is the simplest way to use the experiment: it implements a small
// PacketHandler (DemoPacketHandler) that prints every captured packet, and
// hands it to the reusable XdpMonitor (see XdpMonitor.h) which does all the
// kernel work:
//
//   1. Loads the BPF object "xdp_prog.o" (compiled from xdp_prog.c) into the
//      kernel using libbpf.
//   2. Attaches the XDP program to a network interface given on the command
//      line (generic XDP mode - the only mode the r8169 NIC driver supports).
//   3. Opens the ring buffer map and polls it continuously.
//   4. For every packet record the kernel pushes into the ring buffer, the
//      monitor invokes the C++ callback method on the PacketHandler.
//
// For an example of integrating the captured packet CONTENT into an existing
// application, see src/AppIntegrationExample.cpp (binary
// "xdp_app_integration_example").
// =============================================================================

#include <cstdio>              // std::fprintf, std::printf
#include <cstdlib>             // std::exit (unused, kept for clarity)
#include <iostream>            // std::cout
#include <string>              // std::string

#include "PacketHandler.h"     // C++ callback interface (the callback method)
#include "XdpData.h"           // C++ data class for the captured packet data
#include "XdpMonitor.h"        // reusable load / attach / poll / detach logic

// ---------------------------------------------------------------------------
// Configuration constants (self-explanatory, centralized here).
// ---------------------------------------------------------------------------
namespace config
{
    // Absolute path of the compiled BPF object, embedded at build time by
    // CMake (it points into the build directory). A "--bpf <path>" command
    // line argument overrides this at runtime. Because the path is absolute,
    // the program finds xdp_prog.o no matter which directory it runs from.
    const char *BPF_OBJECT_FILE_PATH = XDP_BPF_OBJECT_FILE_PATH;
} // namespace config

// ---------------------------------------------------------------------------
// Simple command-line argument parsing.
// ---------------------------------------------------------------------------
// Supported usage:
//   xdp_demo [interface] [--bpf <path-to-xdp_prog.o>]
//
//   interface : network interface to attach to (default: "enp5s0").
//   --bpf path: optional override for the embedded BPF object file path
//               (useful when testing a freshly rebuilt object elsewhere).
namespace args
{
    // Returns true if parsing succeeded, storing the (optional) interface
    // name and the (optional) BPF object path override in the output args.
    bool parse(int argc, char *argv[],
               std::string &target_interface_name,
               std::string &bpf_object_path)
    {
        for (int index = 1; index < argc; ++index) {
            const std::string current_argument = argv[index];
            if (current_argument == "--bpf") {
                if (index + 1 >= argc) {
                    std::fprintf(stderr,
                                 "Error: '--bpf' requires a path argument.\n");
                    return false;
                }
                bpf_object_path = argv[++index];
            } else if (target_interface_name.empty()) {
                target_interface_name = current_argument;
            } else {
                std::fprintf(stderr,
                             "Error: unexpected argument '%s'.\n",
                             current_argument.c_str());
                return false;
            }
        }
        return true;
    }
} // namespace args

// ---------------------------------------------------------------------------
// Demo PacketHandler: a concrete C++ callback implementation.
// ---------------------------------------------------------------------------
// This class implements the C++ callback method "on_packet_arrived". It is
// invoked once per captured packet. For this example it simply prints a
// readable summary of every packet to stdout. You would replace this class
// with your own PacketHandler subclass to do real work per packet.
class DemoPacketHandler : public PacketHandler
{
public:
    void on_packet_arrived(const XdpData &packet_data) override
    {
        // Print a one-line summary of the captured packet.
        std::printf("packet: %s  %s:%u -> %s:%u  (proto=%s, ethertype=0x%04x, "
                    "payload=%zu bytes)\n",
                    packet_data.source_mac_address().c_str(),
                    packet_data.source_ipv4_address().c_str(),
                    static_cast<unsigned>(packet_data.source_port()),
                    packet_data.destination_ipv4_address().c_str(),
                    static_cast<unsigned>(packet_data.destination_port()),
                    packet_data.ip_protocol_name().c_str(),
                    static_cast<unsigned>(packet_data.ether_type()),
                    packet_data.payload_byte_count());

        // Also print the raw payload as a hex dump so the "data class"
        // really shows the packet data, not just metadata.
        std::cout << packet_data.payload_hex_dump() << std::flush;
    }
};

// =============================================================================
// main()
// =============================================================================
int main(int argc, char *argv[])
{
    // Parse command-line arguments:
    //   xdp_demo [interface] [--bpf <path-to-xdp_prog.o>]
    // The interface defaults to "enp5s0"; the BPF object path defaults to the
    // absolute path embedded at build time (config::BPF_OBJECT_FILE_PATH).
    std::string target_interface_name; // empty -> filled below with default
    std::string bpf_object_file_path;  // empty -> embedded default is used
    if (!args::parse(argc, argv, target_interface_name, bpf_object_file_path)) {
        std::fprintf(stderr,
                     "Usage: %s [interface] [--bpf <path-to-xdp_prog.o>]\n",
                     argv[0]);
        return 1;
    }
    if (target_interface_name.empty()) {
        target_interface_name = "enp5s0";
    }
    if (bpf_object_file_path.empty()) {
        bpf_object_file_path = config::BPF_OBJECT_FILE_PATH;
    }

    // Install the Ctrl-C handler so the monitor can detach cleanly.
    XdpMonitor::install_signal_handlers();

    // Build the monitor around the demo handler and run it.
    DemoPacketHandler demo_packet_handler;
    XdpMonitor monitor(target_interface_name, bpf_object_file_path,
                       demo_packet_handler);
    return monitor.run();
}
