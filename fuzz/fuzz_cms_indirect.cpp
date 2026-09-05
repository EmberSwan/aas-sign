#include "cms.hpp"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 1024 * 1024) return 0;
    const std::vector<uint8_t> bytes(data, data + size);
    try {
        auto content = cms_extract_indirect_data(bytes);
        (void)cms_auth_attrs_hash(content);
    } catch (const std::exception &) {}
    try { (void)cms_has_signer(bytes); } catch (const std::exception &) {}
    return 0;
}
