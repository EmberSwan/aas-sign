#pragma once

#include <cstddef>
#include <functional>
#include <string>

struct MsiRewriteResult {
    size_t signed_files = 0;
    size_t preserved_files = 0;
};

// The caller owns a staged copy and signs the outer installer after this
// returns. Every CAB and Binary stream is preflighted before the first callback.
// The callback receives PE candidates and returns true when it signed one,
// false when preserving an existing signature. Throwing aborts reconstruction.
MsiRewriteResult rewrite_msi_payload(
    const std::string &staged_msi,
    const std::function<bool(const std::string &, const std::string &)> &sign_if_unsigned);
