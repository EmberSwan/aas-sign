#pragma once

#include "platform.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct MsiDigest {
    std::array<uint8_t, 32> file{};
    std::vector<uint8_t> metadata;
};

class MsiFile {
public:
    explicit MsiFile(const std::string &path);
    ~MsiFile();
    MsiFile(const MsiFile &) = delete;
    MsiFile &operator=(const MsiFile &) = delete;
    MsiDigest authenticode_hash(bool enhanced) const;
    void inject_signature(const std::vector<uint8_t> &cms_der,
                          const std::vector<uint8_t> &metadata_digest);

private:
    struct Node;
    platform::File file_;
    uint16_t major_ = 0;
    uint32_t sector_size_ = 0;
    std::vector<uint8_t> header_;
    Node *root_ = nullptr;
    std::vector<Node> nodes_;

    std::vector<uint8_t> serialize();
};
