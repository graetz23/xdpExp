# =============================================================================
# CMake build file for the XDP experiment project.
#
# What this file builds:
#   1. "xdp_prog.o"   - the in-kernel XDP/BPF program, written in C and
#                       compiled by clang with the "bpf" target. This object
#                       file contains the bytecode that the Linux kernel runs
#                       when a packet arrives on the attached interface.
#   2. "xdp_demo"     - the userspace C++ demo program that:
#                         - loads the BPF object into the kernel,
#                         - attaches it to a network interface,
#                         - receives packet records through a BPF ring buffer,
#                         - builds an XdpData object for every packet and
#                           calls a C++ callback method on a PacketHandler.
#                       It prints every captured packet (see src/main.cpp).
#   3. "xdp_app_integration_example"
#                     - a second userspace program showing how the captured
#                       packet CONTENT can be fed into an existing application
#                       (see src/AppIntegrationExample.cpp). It reuses the
#                       same XdpMonitor / PacketHandler / XdpData building
#                       blocks as the demo.
# =============================================================================

cmake_minimum_required(VERSION 3.16)

# The project uses two languages: C (for the BPF program) and C++ (for the
# userspace program). CMake needs to know about both so it can pick the right
# compilers for each source file.
project(xdp_experiment LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Compiler settings for the C++ userspace program.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)            # allow GNU extensions (e.g. flexible
                                        # array members in the shared struct)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # write compile_commands.json for tools

# ---------------------------------------------------------------------------
# Locate libbpf, the userspace library we use to load/attach BPF programs and
# to consume the ring buffer. It is found through pkg-config.
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

# ---------------------------------------------------------------------------
# Locate the clang toolchain used to compile the BPF program. Regular gcc/g++
# cannot produce BPF bytecode; clang is required for the "bpf" target.
# llvm-strip is used later to strip debug info from the BPF object.
# ---------------------------------------------------------------------------
find_program(BPF_CLANG_COMPILER clang REQUIRED)
find_program(BPF_OBJECT_STRIPPER llvm-strip REQUIRED)

# ---------------------------------------------------------------------------
# Build the in-kernel XDP/BPF program.
#
# We invoke clang directly (not add_library) because BPF bytecode cannot be
# produced by the normal C compiler. The custom command below turns
# "xdp_prog.c" into "xdp_prog.o" (ELF object containing BPF instructions).
# The BPF source is compiled with the "bpf" target and with optimization so
# that the verifier accepts the program.
# ---------------------------------------------------------------------------
set(XDP_BPF_SOURCE_FILE "${CMAKE_SOURCE_DIR}/xdp_prog.c")
set(XDP_BPF_OBJECT_FILE "${CMAKE_BINARY_DIR}/xdp_prog.o")

add_custom_command(
    OUTPUT  ${XDP_BPF_OBJECT_FILE}
    COMMAND ${BPF_CLANG_COMPILER}
            -O2 -g -target bpf
            -I${CMAKE_SOURCE_DIR}
            -c ${XDP_BPF_SOURCE_FILE}
            -o ${XDP_BPF_OBJECT_FILE}
    DEPENDS ${XDP_BPF_SOURCE_FILE} ${CMAKE_SOURCE_DIR}/packet.h
    COMMENT "Compiling XDP/BPF program to ${XDP_BPF_OBJECT_FILE}"
    VERBATIM
)

# Wrap the custom command in a target so it participates in the default build.
add_custom_target(xdp_program_object ALL DEPENDS ${XDP_BPF_OBJECT_FILE})

# ---------------------------------------------------------------------------
# Build the userspace C++ executables.
#
# Both executables share the same building blocks:
#   * XdpMonitor.cpp   - load / attach / poll / detach of the XDP program
#   * XdpData.cpp      - the C++ data class for a captured packet
#   * PacketHandler.h / XdpMonitor.h - callback interface + monitor class
#   * packet.h         - the shared kernel/userspace record struct
# The only difference is the PacketHandler implementation they use
# (and their main()).
# ---------------------------------------------------------------------------

# Sources common to both executables.
set(XDP_USERSHARE_SOURCES
    src/XdpData.cpp
    src/XdpMonitor.cpp
)

# --- Demo executable: prints every captured packet (src/main.cpp). ---------
add_executable(xdp_demo
    src/main.cpp
    ${XDP_USERSHARE_SOURCES}
)

# --- App-integration example: feeds packets into an existing app. ----------
add_executable(xdp_app_integration_example
    src/AppIntegrationExample.cpp
    ${XDP_USERSHARE_SOURCES}
)

# Make sure the BPF object file is built before the executables are linked and
# before the programs are run from the build directory.
add_dependencies(xdp_demo xdp_program_object)
add_dependencies(xdp_app_integration_example xdp_program_object)

# Apply the same settings to both executables:
#   - include the shared "packet.h" header and the local src/ headers,
#   - link against libbpf (headers + library resolved via pkg-config above),
#   - embed the ABSOLUTE path of the built BPF object so the programs find
#     "xdp_prog.o" no matter which directory they are launched from. A
#     user-supplied "--bpf <path>" CLI argument still overrides the default.
foreach(xdp_executable IN ITEMS xdp_demo xdp_app_integration_example)
    target_include_directories(${xdp_executable} PRIVATE
        ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(${xdp_executable} PRIVATE PkgConfig::LIBBPF)
    target_compile_definitions(${xdp_executable} PRIVATE
        XDP_BPF_OBJECT_FILE_PATH="${XDP_BPF_OBJECT_FILE}")
endforeach()
