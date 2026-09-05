// Exercise media mapping, CAB preflight and Binary-stream extraction without
// invoking a signer, creating subprocesses, or changing the installer.
#include "msi_recursive.hpp"
#include "platform.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 16 * 1024 * 1024) return 0;
    try {
        static platform::TempDir temp;
        const auto path = temp.path() + "/input.msi";
        platform::write_whole_file(path, data, size);
        (void)rewrite_msi_payload(path, [](const auto &, const auto &) { return false; });
    } catch (const std::exception &) {}
    return 0;
}
