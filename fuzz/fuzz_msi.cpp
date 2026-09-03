#include "msi.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // A v3 CFB needs roughly 7 MiB before its FAT spills into DIFAT sectors.
    // Keep that parser surface reachable for runs that opt into a larger
    // -max_len while retaining a firm bound on per-input memory and I/O.
    if (size > 16 * 1024 * 1024)
        return 0;

    static const std::string path =
        "/tmp/aas-sign-fuzz-msi-" + std::to_string(::getpid()) + ".msi";
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return 0;
    size_t off = 0;
    while (off < size) {
        ssize_t n = ::write(fd, data + off, size - off);
        if (n <= 0) {
            ::close(fd);
            return 0;
        }
        off += size_t(n);
    }
    ::close(fd);
    try {
        MsiFile msi(path);
        (void)msi.authenticode_hash(false);
        auto enhanced = msi.authenticode_hash(true);

        // Force the regular-stream serializer path and then parse the result.
        std::vector<uint8_t> signature(4096 + std::min<size_t>(size, 4096));
        if (size)
            std::copy_n(data, std::min(size, signature.size()),
                        signature.data());
        msi.inject_signature(signature, enhanced.metadata);
        MsiFile rewritten(path);
        (void)rewritten.authenticode_hash(false);
        (void)rewritten.authenticode_hash(true);
    } catch (const std::exception &) {
        // Rejection of malformed compound files is expected.
    }
    return 0;
}
