#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

// Native MSI database and cabinet APIs. Feature code never opens an installer
// session: editing a database does not run installation or custom actions.
namespace platform {

struct MsiStreamPath { std::string path; };
using MsiValue = std::variant<int32_t, std::string, MsiStreamPath>;
using MsiRows = std::vector<std::vector<std::string>>;

class MsiDatabase {
public:
    explicit MsiDatabase(const std::string &path);
    ~MsiDatabase();
    MsiDatabase(const MsiDatabase &) = delete;
    MsiDatabase &operator=(const MsiDatabase &) = delete;
    MsiRows query(const std::string &sql, const std::vector<MsiValue> &params = {});
    void execute(const std::string &sql, const std::vector<MsiValue> &params = {});
    // SQL must select one stream column in exactly one row.
    uint64_t extract_stream(const std::string &sql, const std::string &key,
                            const std::string &output, uint64_t limit);
    int32_t word_count();
    std::string package_code();
    void renew_package_code();
    void commit();
private:
    void *impl_;
    std::string path_;
};

struct CabinetMember {
    std::string name;
    std::string path;  // generated private staging path, never the member name
    uint32_t size = 0;
    uint16_t date = 0, time = 0, attributes = 0;
};

void extract_cabinet(const std::string &path, const std::vector<CabinetMember> &members);
void create_cabinet(const std::string &path, const std::vector<CabinetMember> &members);
std::array<int32_t, 4> msi_file_hash(const std::string &path);

} // namespace platform
