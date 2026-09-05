// Only PE certificate-table inspection remains local; format hashing and
// signature insertion are provided by osslsigncode.
#include "signing.hpp"
#include "platform.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 256 * 1024) return 0;
    try {
        static platform::TempDir temp;
        const auto path = temp.path() + "/input.exe";
        platform::write_whole_file(path, data, size);
        (void)pe_has_signature(path);
    } catch (const std::exception &) {}
    return 0;
}
