// =============================================================================
// AppIntegrationExample.cpp
// =============================================================================
// Executable "xdp_app_integration_example".
//
// Shows how an EXISTING application consumes the captured packet CONTENT.
// The demo (src/main.cpp) just prints packets; this example feeds the parsed
// packet data into a small stand-in "application" (MyApplication).
//
// The interlocking idea (this is the important part):
//
//   1. Your application (here: MyApplication) owns its own data structures
//      and exposes an entry point to receive packet events (ingest_packet).
//   2. You derive a PacketHandler subclass (here: AppPacketHandler) that
//      knows about your application. In its constructor it grabs a reference
//      to the application.
//   3. In the per-packet callback on_packet_arrived(...) the handler reads
//      the packet data (metadata + payload bytes) from the XdpData object and
//      forwards it into the application.
//   4. You hand the handler to the reusable XdpMonitor. The monitor polls the
//      kernel ring buffer and calls on_packet_arrived once per packet - so
//      every packet eventually reaches your application's ingest_packet.
//
// The chain of ownership is:  XdpMonitor -> PacketHandler -> MyApplication.
// =============================================================================

#include <cstdint>       // uint8_t, uint16_t fixed-width types
#include <cstdio>        // std::printf
#include <map>           // std::map (per-protocol packet counters)
#include <string>        // std::string
#include <vector>        // std::vector<uint8_t> (raw payload bytes)

#include "PacketHandler.h"   // C++ callback interface to derive from
#include "XdpData.h"         // C++ data class holding the packet content
#include "XdpMonitor.h"      // reusable load / attach / poll / detach logic

// ---------------------------------------------------------------------------
// Application-level packet view
// ---------------------------------------------------------------------------
// The app's OWN representation of a packet. It is intentionally independent
// of XdpData: the app code only ever sees this struct, never the kernel
// record. If you change the kernel record layout, only the handler (step 3
// above) has to be updated - the app code stays untouched.
struct AppPacketView {
    std::string              source_ipv4_address;   // e.g. "192.168.1.20"
    std::string              destination_ipv4_address; // e.g. "93.184.216.34"
    uint16_t                 source_port = 0;       // TCP/UDP source port
    uint16_t                 destination_port = 0;  // TCP/UDP destination port
    std::string              protocol_name;         // "TCP", "UDP", ...
    std::vector<uint8_t>     payload_bytes;         // raw application payload
};

// ---------------------------------------------------------------------------
// MyApplication: a stand-in for an existing application
// ---------------------------------------------------------------------------
// In a real project this would be your actual application object. It simply
// needs an entry point that accepts the packet data the handler forwards.
// Here it keeps per-protocol counters and prints a short line per packet, to
// demonstrate that the packet content has genuinely reached the application.
class MyApplication
{
public:
    // The entry point the handler calls for every captured packet.
    void ingest_packet(const AppPacketView &packet_view)
    {
        // Feed the packet content into "application logic": here we just
        // count packets per protocol and print the first 16 payload bytes.
        protocol_packet_counters_[packet_view.protocol_name] += 1;

        std::printf("app: %s -> %s:%u  (proto=%s, payload=%zu bytes)\n",
                    packet_view.source_ipv4_address.c_str(),
                    packet_view.destination_ipv4_address.c_str(),
                    static_cast<unsigned>(packet_view.destination_port),
                    packet_view.protocol_name.c_str(),
                    packet_view.payload_bytes.size());

        const size_t preview_bytes =
            packet_view.payload_bytes.size() < 16 ? packet_view.payload_bytes.size() : 16;
        for (size_t i = 0; i < preview_bytes; ++i) {
            std::printf("%02x ", packet_view.payload_bytes[i]);
        }
        std::printf("\n");
    }

    // Print a summary of the per-protocol counters (called on shutdown).
    void print_summary() const
    {
        std::printf("\napp summary (packets per protocol):\n");
        for (const auto &protocol_and_count : protocol_packet_counters_) {
            std::printf("  %-10s : %zu\n",
                        protocol_and_count.first.c_str(),
                        protocol_and_count.second);
        }
    }

private:
    // Application-owned data: how many packets arrived per protocol.
    std::map<std::string, size_t> protocol_packet_counters_;
};

// ---------------------------------------------------------------------------
// AppPacketHandler: the C++ callback that connects XDP data to the app
// ---------------------------------------------------------------------------
// This is the class that makes the interlocking work. It implements the
// PacketHandler interface from PacketHandler.h and holds a reference to the
// application. Every captured packet arrives here via on_packet_arrived().
class AppPacketHandler : public PacketHandler
{
public:
    // Grab a reference to the application so we can push packets into it.
    explicit AppPacketHandler(MyApplication &target_application)
        : target_application_(target_application)
    {
    }

    // Called by XdpMonitor once per captured packet.
    void on_packet_arrived(const XdpData &packet_data) override
    {
        // Translate the XdpData packet into the application's own struct.
        // This reads the packet CONTENT: metadata + raw payload bytes.
        AppPacketView packet_view;
        packet_view.source_ipv4_address    = packet_data.source_ipv4_address();
        packet_view.destination_ipv4_address = packet_data.destination_ipv4_address();
        packet_view.source_port            = packet_data.source_port();
        packet_view.destination_port       = packet_data.destination_port();
        packet_view.protocol_name          = packet_data.ip_protocol_name();
        packet_view.payload_bytes          = packet_data.payload_bytes();

        // Hand the packet over to the application.
        target_application_.ingest_packet(packet_view);
    }

private:
    MyApplication &target_application_;   // the app we push packets into
};

// ---------------------------------------------------------------------------
// main(): wire the application, the handler, and the monitor together.
// ===========================================================================
int main(int argc, char *argv[])
{
    // Same command-line interface as the demo:
    //   xdp_app_integration_example [interface] [--bpf <path-to-xdp_prog.o>]
    std::string target_interface_name = "enp5s0";
    std::string bpf_object_file_path;
    for (int index = 1; index < argc; ++index) {
        const std::string current_argument = argv[index];
        if (current_argument == "--bpf" && index + 1 < argc) {
            bpf_object_file_path = argv[++index];
        } else if (target_interface_name == "enp5s0") {
            target_interface_name = current_argument;
        } else {
            std::fprintf(stderr,
                         "Usage: %s [interface] [--bpf <path-to-xdp_prog.o>]\n",
                         argv[0]);
            return 1;
        }
    }
    if (bpf_object_file_path.empty()) {
        bpf_object_file_path = XDP_BPF_OBJECT_FILE_PATH; // embedded by CMake
    }

    // Install the Ctrl-C handler so the monitor can detach cleanly.
    XdpMonitor::install_signal_handlers();

    // The interlock, in three lines:
    //   the app owns its data, the handler knows the app, the monitor knows
    //   the handler. Every captured packet flows app <- handler <- monitor.
    MyApplication   my_application;          // the "existing application"
    AppPacketHandler packet_handler(my_application); // C++ callback for it
    XdpMonitor monitor(target_interface_name, bpf_object_file_path,
                       packet_handler);

    const int exit_code = monitor.run();

    // After the monitor stops cleanly, show what the application collected.
    // (On a startup failure the monitor never captured anything, so we skip
    // the summary to avoid printing a misleading empty report.)
    if (exit_code == 0) {
        my_application.print_summary();
    }
    return exit_code;
}
