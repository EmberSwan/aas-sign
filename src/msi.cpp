#include "msi.hpp"
#include "platform.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>
#include <utility>

namespace {
constexpr uint32_t FREE = 0xffffffff, END = 0xfffffffe;
constexpr uint32_t FAT = 0xfffffffd, DIF = 0xfffffffc, NONE = 0xffffffff;
constexpr uint32_t MINI_CUTOFF = 4096;
constexpr uint32_t MAX_REGULAR_SECTORS = 0xfffffffa;
constexpr uint64_t V3_MAX_STREAM_SIZE = 0x80000000ULL;

uint64_t ceil_div(uint64_t n, uint64_t d)
{
    return n ? 1 + (n - 1) / d : 0;
}

size_t checked_size(uint64_t n, const char *what)
{
    if (n > std::numeric_limits<size_t>::max())
        throw std::runtime_error(std::string(what) + " is too large");
    return size_t(n);
}

uint32_t checked_sector_count(uint64_t n)
{
    if (n > MAX_REGULAR_SECTORS)
        throw std::runtime_error("serialized MSI has too many sectors");
    return uint32_t(n);
}

uint16_t get16(const uint8_t *p)
{
    return uint16_t(uint32_t(p[0]) | uint32_t(p[1]) << 8);
}
uint32_t get32(const uint8_t *p)
{
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 |
           uint32_t(p[3]) << 24;
}
uint64_t get64(const uint8_t *p)
{
    return uint64_t(get32(p)) | uint64_t(get32(p + 4)) << 32;
}
void put16(uint8_t *p, uint16_t v)
{
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
}
void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = uint8_t(v >> (8 * i));
}
void put64(uint8_t *p, uint64_t v)
{
    put32(p, uint32_t(v));
    put32(p + 4, uint32_t(v >> 32));
}

std::vector<uint8_t> read_file(platform::File &f)
{
    uint64_t n = f.size();
    std::vector<uint8_t> b(checked_size(n, "MSI"));
    if (!b.empty())
        f.read_at(0, b.data(), b.size());
    return b;
}
uint16_t upper_ascii(uint16_t c)
{
    return c >= 'a' && c <= 'z' ? uint16_t(c - 'a' + 'A') : c;
}
bool sig_name(const std::vector<uint8_t> &n, bool ex)
{
    const char *s = ex ? "MsiDigitalSignatureEx" : "DigitalSignature";
    if (n.size() != 2 * (std::strlen(s) + 2) || get16(n.data()) != 5)
        return false;
    for (size_t i = 0; s[i]; ++i)
        if (get16(n.data() + 2 + 2 * i) != uint8_t(s[i]))
            return false;
    return get16(n.data() + n.size() - 2) == 0;
}
bool sig_name_folded(const std::vector<uint8_t> &n, bool ex)
{
    const char *s = ex ? "MsiDigitalSignatureEx" : "DigitalSignature";
    if (n.size() != 2 * (std::strlen(s) + 2) || get16(n.data()) != 5)
        return false;
    for (size_t i = 0; s[i]; ++i)
        if (upper_ascii(get16(n.data() + 2 + 2 * i)) !=
            upper_ascii(uint8_t(s[i])))
            return false;
    return get16(n.data() + n.size() - 2) == 0;
}
std::vector<uint8_t> make_name(const char *s)
{
    std::vector<uint8_t> n(2 * (std::strlen(s) + 2));
    put16(n.data(), 5);
    for (size_t i = 0; s[i]; ++i)
        put16(n.data() + 2 + 2 * i, uint8_t(s[i]));
    return n;
}
int hash_cmp(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    size_t n = std::min(a.size(), b.size());
    int d = n ? std::memcmp(a.data(), b.data(), n) : 0;
    if (d)
        return d;
    if (a.size() == b.size())
        return 0;
    return a.size() > b.size() ? -1 : 1;
}
int tree_cmp(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    if (a.size() != b.size())
        return a.size() < b.size() ? -1 : 1;
    for (size_t i = 0; i + 1 < a.size(); i += 2) {
        auto x = upper_ascii(get16(a.data() + i));
        auto y = upper_ascii(get16(b.data() + i));
        if (x != y)
            return x < y ? -1 : 1;
    }
    return 0;
}
}  // namespace

struct MsiFile::Node {
    std::vector<uint8_t> raw, name, data;
    uint8_t type = 0;
    std::vector<Node> children;
};

MsiFile::~MsiFile() = default;

MsiFile::MsiFile(const std::string &path) : file_(path)
{
    auto file = read_file(file_);
    static const uint8_t magic[] = {0xd0, 0xcf, 0x11, 0xe0,
                                    0xa1, 0xb1, 0x1a, 0xe1};
    if (file.size() < 512 || std::memcmp(file.data(), magic, 8))
        throw std::runtime_error("not an MSI compound file");
    if (!std::all_of(file.begin() + 8, file.begin() + 24,
                     [](uint8_t b) { return b == 0; }) ||
        !std::all_of(file.begin() + 34, file.begin() + 40,
                     [](uint8_t b) { return b == 0; }))
        throw std::runtime_error("invalid MSI compound-file header");
    header_.assign(file.begin(), file.begin() + 512);
    major_ = get16(file.data() + 26);
    uint16_t shift = get16(file.data() + 30), mshift = get16(file.data() + 32);
    if ((major_ != 3 && major_ != 4) || get16(file.data() + 24) != 0x003e ||
        (shift != (major_ == 3 ? 9 : 12)) || mshift != 6 ||
        get16(file.data() + 28) != 0xfffe)
        throw std::runtime_error("unsupported MSI compound-file header");
    sector_size_ = uint32_t(1) << shift;
    if (file.size() < sector_size_ || file.size() % sector_size_)
        throw std::runtime_error("truncated MSI compound file");
    if (major_ == 4 &&
        !std::all_of(file.begin() + 512, file.begin() + sector_size_,
                     [](uint8_t b) { return b == 0; }))
        throw std::runtime_error("invalid MSI compound-file header padding");
    if (get32(file.data() + 56) != MINI_CUTOFF)
        throw std::runtime_error("unsupported MSI mini-stream cutoff");
    uint64_t sector_count = file.size() / sector_size_ - 1;
    auto sec = [&](uint32_t id) -> const uint8_t * {
        uint64_t o = (uint64_t(id) + 1) * sector_size_;
        if (id >= 0xfffffffa || o + sector_size_ > file.size())
            throw std::runtime_error("MSI sector out of range");
        return file.data() + o;
    };
    uint32_t nfat = get32(file.data() + 44), difirst = get32(file.data() + 68),
             ndif = get32(file.data() + 72), ep = sector_size_ / 4;
    if (!nfat || nfat > sector_count || ndif > sector_count)
        throw std::runtime_error("invalid MSI allocation-table counts");
    std::vector<uint32_t> fatids;
    for (int i = 0; i < 109 && fatids.size() < nfat; i++) {
        auto x = get32(file.data() + 76 + 4 * i);
        if (x != FREE)
            fatids.push_back(x);
    }
    uint32_t ds = difirst;
    std::vector<uint32_t> difids;
    std::vector<uint8_t> allocation_seen(size_t(sector_count), uint8_t{0});
    for (uint32_t k = 0; k < ndif; k++) {
        if (ds >= sector_count || allocation_seen[ds])
            throw std::runtime_error("invalid or cyclic MSI DIFAT");
        allocation_seen[ds] = 1;
        difids.push_back(ds);
        auto p = sec(ds);
        for (uint32_t i = 0; i < ep - 1 && fatids.size() < nfat; i++) {
            auto x = get32(p + 4 * i);
            if (x != FREE)
                fatids.push_back(x);
        }
        ds = get32(p + 4 * (ep - 1));
    }
    if (fatids.size() != nfat || (ndif && ds != END))
        throw std::runtime_error("invalid MSI DIFAT");
    uint64_t fat_entries = uint64_t(nfat) * ep;
    if (fat_entries > std::numeric_limits<size_t>::max() / sizeof(uint32_t))
        throw std::runtime_error("MSI FAT is too large");
    std::vector<uint32_t> fat;
    fat.reserve(size_t(fat_entries));
    for (auto id : fatids) {
        if (id >= sector_count || allocation_seen[id])
            throw std::runtime_error("invalid or duplicate MSI FAT sector");
        allocation_seen[id] = 1;
        auto p = sec(id);
        for (uint32_t i = 0; i < ep; i++)
            fat.push_back(get32(p + 4 * i));
    }
    if (sector_count > fat.size())
        throw std::runtime_error("MSI FAT does not cover the file");
    for (auto id : fatids)
        if (id >= fat.size() || fat[id] != FAT)
            throw std::runtime_error("MSI FAT sector is not marked as FAT");
    for (auto id : difids)
        if (id >= fat.size() || fat[id] != DIF)
            throw std::runtime_error("MSI DIFAT sector is not marked as DIFAT");
    auto chain = [&](uint32_t start, const std::vector<uint32_t> &tab) {
        std::vector<uint32_t> out;
        uint32_t x = start;
        while (x != END) {
            if (x >= tab.size() || out.size() >= tab.size())
                throw std::runtime_error("invalid or cyclic MSI sector chain");
            out.push_back(x);
            x = tab[x];
        }
        return out;
    };
    auto claim_regular = [&](const std::vector<uint32_t> &c,
                             const char *what) {
        for (auto id : c) {
            if (id >= sector_count)
                throw std::runtime_error(std::string(what) +
                                         " sector is out of range");
            if (allocation_seen[id])
                throw std::runtime_error(std::string("overlapping MSI ") +
                                         what + " sector chain");
            allocation_seen[id] = 1;
        }
    };
    auto regular = [&](uint32_t start, uint64_t size, const char *what) {
        std::vector<uint8_t> out;
        if (!size) {
            if (start != END && start != FREE)
                throw std::runtime_error(std::string("invalid empty MSI ") +
                                         what + " stream");
            return out;
        }
        auto c = chain(start, fat);
        claim_regular(c, what);
        if (size > uint64_t(c.size()) * sector_size_ ||
            size > std::numeric_limits<size_t>::max())
            throw std::runtime_error("truncated MSI stream");
        out.reserve(size_t(size));
        for (auto id : c) {
            size_t n =
                size_t(std::min<uint64_t>(sector_size_, size - out.size()));
            auto p = sec(id);
            out.insert(out.end(), p, p + n);
            if (out.size() == size)
                break;
        }
        return out;
    };
    uint32_t dir_start = get32(file.data() + 48);
    auto dir_chain = chain(dir_start, fat);
    // The field is unsupported in v3 and redundant with the FAT directory
    // chain in v4.  Although MS-CFB requires a canonical value, real-world
    // files can contain a stale count.  Ignore it while reading: chain() and
    // regular() bound the chain, detect cycles, and reject physical overlap.
    // serialize() restores the canonical count.
    uint64_t dir_size = uint64_t(dir_chain.size()) * sector_size_;
    auto dirbytes = regular(dir_start, dir_size, "directory");
    if (dirbytes.size() < 128 || dirbytes.size() % 128)
        throw std::runtime_error("invalid MSI directory stream");
    struct E {
        std::vector<uint8_t> raw, name;
        uint8_t type;
        uint32_t l, r, ch, start;
        uint64_t size;
    };
    std::vector<E> es;
    for (size_t o = 0; o < dirbytes.size(); o += 128) {
        E e;
        e.raw.assign(dirbytes.data() + o, dirbytes.data() + o + 128);
        uint16_t nl = get16(e.raw.data() + 64);
        e.type = e.raw[66];
        if (nl > 64 || (e.type != 0 && nl < 2) || (nl & 1) ||
            (nl && get16(e.raw.data() + nl - 2) != 0))
            throw std::runtime_error("invalid MSI directory name");
        e.name.assign(e.raw.begin(), e.raw.begin() + nl);
        e.l = get32(e.raw.data() + 68);
        e.r = get32(e.raw.data() + 72);
        e.ch = get32(e.raw.data() + 76);
        e.start = get32(e.raw.data() + 116);
        e.size = get64(e.raw.data() + 120);
        if (major_ == 3) {
            // Older CFB implementations left the high DWORD uninitialized.
            // MS-CFB requires current v3 readers to ignore it.
            e.size = uint32_t(e.size);
            if (e.size > V3_MAX_STREAM_SIZE)
                throw std::runtime_error("MSI v3 stream exceeds 2 GiB");
        }
        es.push_back(std::move(e));
    }
    if (es[0].type != 5)
        throw std::runtime_error("MSI root entry is missing");
    static const char root_name[] = "Root Entry";
    if (es[0].name.size() != sizeof(root_name) * 2)
        throw std::runtime_error("invalid MSI root entry name");
    for (size_t i = 0; i < sizeof(root_name); ++i)
        if (get16(es[0].name.data() + 2 * i) != uint8_t(root_name[i]))
            throw std::runtime_error("invalid MSI root entry name");
    if (!std::all_of(es[0].raw.begin() + 100, es[0].raw.begin() + 108,
                     [](uint8_t b) { return b == 0; }))
        throw std::runtime_error("invalid MSI root creation time");
    std::vector<uint32_t> minifat;
    uint32_t nmf = get32(file.data() + 64);
    if (nmf > sector_count)
        throw std::runtime_error("invalid MSI mini-FAT count");
    if (nmf) {
        auto raw = regular(get32(file.data() + 60),
                           uint64_t(nmf) * sector_size_, "mini-FAT");
        for (size_t i = 0; i < raw.size(); i += 4)
            minifat.push_back(get32(raw.data() + i));
    }
    auto ministream = regular(es[0].start, es[0].size, "mini-stream");
    std::vector<uint8_t> mini_seen(
        size_t(ceil_div(ministream.size(), uint64_t{64})), uint8_t{0});
    auto stream = [&](const E &e) {
        if (!e.size)
            return std::vector<uint8_t>{};
        if (e.size >= MINI_CUTOFF)
            return regular(e.start, e.size, "user-stream");
        auto c = chain(e.start, minifat);
        if (e.size > uint64_t(c.size()) * 64 ||
            e.size > std::numeric_limits<size_t>::max())
            throw std::runtime_error("truncated MSI mini stream");
        std::vector<uint8_t> out;
        out.reserve(size_t(e.size));
        for (auto id : c) {
            if (id >= mini_seen.size() || mini_seen[id])
                throw std::runtime_error(
                    "overlapping or out-of-range MSI mini-sector chain");
            mini_seen[id] = 1;
            uint64_t o = uint64_t(id) * 64;
            if (o + 64 > ministream.size())
                throw std::runtime_error("MSI mini sector out of range");
            size_t n = size_t(std::min<uint64_t>(64, e.size - out.size()));
            size_t offset = size_t(o);
            out.insert(out.end(), ministream.data() + offset,
                       ministream.data() + offset + n);
        }
        return out;
    };
    std::vector<uint8_t> seen(es.size());
    std::function<void(uint32_t, std::vector<Node> &, size_t)> walk =
        [&](uint32_t id, std::vector<Node> &out, size_t depth) {
            if (id == NONE)
                return;
            if (depth > 1024)
                throw std::runtime_error("MSI directory tree is too deep");
            if (id >= es.size() || seen[id])
                throw std::runtime_error(
                    "invalid or cyclic MSI directory tree");
            seen[id] = 1;
            walk(es[id].l, out, depth + 1);
            auto &e = es[id];
            if (e.type != 1 && e.type != 2)
                throw std::runtime_error("invalid MSI directory entry");
            Node n{e.raw, e.name, {}, e.type, {}};
            if (e.type == 2)
                n.data = stream(e);
            else
                walk(e.ch, n.children, depth + 1);
            out.push_back(std::move(n));
            walk(es[id].r, out, depth + 1);
        };
    Node root{es[0].raw, es[0].name, {}, 5, {}};
    walk(es[0].ch, root.children, 0);
    int basic_signatures = 0, enhanced_signatures = 0;
    for (const auto &child : root.children) {
        bool basic = sig_name(child.name, false);
        bool enhanced = sig_name(child.name, true);
        if ((!basic && sig_name_folded(child.name, false)) ||
            (!enhanced && sig_name_folded(child.name, true)))
            throw std::runtime_error(
                "case-folded MSI signature stream name collision");
        if (!basic && !enhanced)
            continue;
        if (child.type != 2)
            throw std::runtime_error(
                "reserved MSI signature name is not a stream");
        int &count = basic ? basic_signatures : enhanced_signatures;
        if (++count > 1)
            throw std::runtime_error("duplicate MSI signature stream");
    }
    nodes_.push_back(std::move(root));
    root_ = &nodes_[0];
}

MsiDigest MsiFile::authenticode_hash(bool enhanced) const
{
    auto sorted = [](const std::vector<Node> &v, bool root) {
        std::vector<const Node *> r;
        for (auto &n : v)
            if (!root || (!sig_name(n.name, false) && !sig_name(n.name, true)))
                r.push_back(&n);
        std::sort(r.begin(), r.end(), [](auto a, auto b) {
            return hash_cmp(a->name, b->name) < 0;
        });
        return r;
    };
    auto meta_one = [](platform::Sha256 &h, const Node &n) {
        if (n.type != 5)
            h.update(n.name.data(), n.name.size() - 2);
        if (n.type == 2)
            h.update(n.raw.data() + 120, 4);
        else
            h.update(n.raw.data() + 80, 16);
        h.update(n.raw.data() + 96, 4);
        if (n.type != 5)
            h.update(n.raw.data() + 100, 16);
    };
    std::function<void(platform::Sha256 &, const Node &, bool)> meta =
        [&](platform::Sha256 &h, const Node &n, bool root) {
            meta_one(h, n);
            for (auto c : sorted(n.children, root)) {
                if (c->type == 2)
                    meta_one(h, *c);
                else
                    meta(h, *c, false);
            }
        };
    std::function<void(platform::Sha256 &, const Node &, bool)> content =
        [&](platform::Sha256 &h, const Node &n, bool root) {
            for (auto c : sorted(n.children, root)) {
                if (c->type == 2 && !c->data.empty())
                    h.update(c->data.data(), c->data.size());
                else if (c->type == 1)
                    content(h, *c, false);
            }
            h.update(n.raw.data() + 80, 16);
        };
    MsiDigest d;
    platform::Sha256 h;
    if (enhanced) {
        platform::Sha256 mh;
        meta(mh, *root_, true);
        auto m = mh.finish();
        d.metadata.assign(m.begin(), m.end());
        h.update(m.data(), m.size());
    }
    content(h, *root_, true);
    d.file = h.finish();
    return d;
}

void MsiFile::inject_signature(const std::vector<uint8_t> &cms,
                               const std::vector<uint8_t> &metadata)
{
    if (!metadata.empty() && metadata.size() != 32)
        throw std::runtime_error(
            "MSI enhanced metadata digest must be exactly 32 bytes");
    auto &c = root_->children;
    c.erase(std::remove_if(c.begin(), c.end(),
                           [](auto &n) {
                               return sig_name(n.name, false) ||
                                      sig_name(n.name, true);
                           }),
            c.end());
    auto add = [&](const char *s, const std::vector<uint8_t> &d) {
        Node n;
        n.raw.assign(128, 0);
        n.name = make_name(s);
        std::copy(n.name.begin(), n.name.end(), n.raw.begin());
        put16(n.raw.data() + 64, uint16_t(n.name.size()));
        n.type = 2;
        n.raw[66] = 2;
        n.raw[67] = 1;
        put32(n.raw.data() + 68, NONE);
        put32(n.raw.data() + 72, NONE);
        put32(n.raw.data() + 76, NONE);
        n.data = d;
        // Existing children are already in CFB tree order. Keep their
        // relative order (including non-ASCII names) and only locate the
        // synthetic U+0005-prefixed signature name among them.
        auto pos = std::lower_bound(c.begin(), c.end(), n,
            [](const Node &a, const Node &b) {
                return tree_cmp(a.name, b.name) < 0;
            });
        c.insert(pos, std::move(n));
    };
    add("DigitalSignature", cms);
    if (!metadata.empty())
        add("MsiDigitalSignatureEx", metadata);
    auto out = serialize();
    file_.write_at(0, out.data(), out.size());
    file_.truncate(out.size());
    file_.flush();
}

std::vector<uint8_t> MsiFile::serialize()
{
    struct F {
        Node *n;
        uint32_t rb_parent = NONE, left = NONE, right = NONE, child = NONE,
                 start = END;
        uint64_t size = 0;
        uint8_t color = 1;
        size_t rank = 0;
        std::vector<uint32_t> children;
    };
    std::vector<F> fs;
    std::function<uint32_t(Node &)> flat = [&](Node &n) {
        if (fs.size() >= MAX_REGULAR_SECTORS)
            throw std::runtime_error("MSI has too many directory entries");
        uint32_t id = uint32_t(fs.size());
        fs.push_back({&n});
        for (auto &x : n.children) {
            uint32_t child = flat(x);
            fs[id].children.push_back(child);
        }
        return id;
    };
    flat(*root_);
    auto rotateL = [&](uint32_t x) {
        uint32_t y = fs[x].right;
        fs[x].right = fs[y].left;
        if (fs[y].left != NONE)
            fs[fs[y].left].rb_parent = x;
        fs[y].rb_parent = fs[x].rb_parent;
        if (fs[x].rb_parent == NONE) {
        } else if (x == fs[fs[x].rb_parent].left)
            fs[fs[x].rb_parent].left = y;
        else
            fs[fs[x].rb_parent].right = y;
        fs[y].left = x;
        fs[x].rb_parent = y;
    };
    auto rotateR = [&](uint32_t x) {
        uint32_t y = fs[x].left;
        fs[x].left = fs[y].right;
        if (fs[y].right != NONE)
            fs[fs[y].right].rb_parent = x;
        fs[y].rb_parent = fs[x].rb_parent;
        if (fs[x].rb_parent != NONE) {
            if (x == fs[fs[x].rb_parent].right)
                fs[fs[x].rb_parent].right = y;
            else
                fs[fs[x].rb_parent].left = y;
        }
        fs[y].right = x;
        fs[x].rb_parent = y;
    };
    for (uint32_t p = 0; p < fs.size(); ++p)
        if (fs[p].n->type != 2) {
            const auto &kids = fs[p].children;
            for (size_t i = 0; i < kids.size(); ++i)
                fs[kids[i]].rank = i;
            uint32_t root = NONE;
            for (auto z : kids) {
                fs[z].left = fs[z].right = NONE;
                fs[z].color = 0;
                uint32_t y = NONE, x = root;
                while (x != NONE) {
                    y = x;
                    x = fs[z].rank < fs[x].rank ? fs[x].left : fs[x].right;
                }
                fs[z].rb_parent = y;
                if (y == NONE)
                    root = z;
                else if (fs[z].rank < fs[y].rank)
                    fs[y].left = z;
                else
                    fs[y].right = z;
                while (fs[z].rb_parent != NONE &&
                       fs[fs[z].rb_parent].color == 0) {
                    uint32_t q = fs[z].rb_parent, g = fs[q].rb_parent;
                    if (q == fs[g].left) {
                        uint32_t u = fs[g].right;
                        if (u != NONE && fs[u].color == 0) {
                            fs[q].color = fs[u].color = 1;
                            fs[g].color = 0;
                            z = g;
                        } else {
                            if (z == fs[q].right) {
                                z = q;
                                rotateL(z);
                                q = fs[z].rb_parent;
                                g = fs[q].rb_parent;
                            }
                            fs[q].color = 1;
                            fs[g].color = 0;
                            rotateR(g);
                        }
                    } else {
                        uint32_t u = fs[g].left;
                        if (u != NONE && fs[u].color == 0) {
                            fs[q].color = fs[u].color = 1;
                            fs[g].color = 0;
                            z = g;
                        } else {
                            if (z == fs[q].left) {
                                z = q;
                                rotateR(z);
                                q = fs[z].rb_parent;
                                g = fs[q].rb_parent;
                            }
                            fs[q].color = 1;
                            fs[g].color = 0;
                            rotateL(g);
                        }
                    }
                }
                while (root != NONE && fs[root].rb_parent != NONE)
                    root = fs[root].rb_parent;
                fs[root].color = 1;
            }
            fs[p].child = root;
        }
    uint32_t ss = sector_size_, ep = ss / 4;
    std::vector<uint32_t> mf;
    uint64_t mini_sector_count = 0;
    for (auto &f : fs) {
        if (f.n->type != 2)
            continue;
        f.size = f.n->data.size();
        if (major_ == 3 && f.size > V3_MAX_STREAM_SIZE)
            throw std::runtime_error("MSI v3 stream exceeds 2 GiB");
        if (!f.size || f.size >= MINI_CUTOFF)
            continue;
        uint64_t count = ceil_div(f.size, uint64_t{64});
        if (count > MAX_REGULAR_SECTORS - mini_sector_count)
            throw std::runtime_error("MSI mini-stream is too large");
        f.start = uint32_t(mini_sector_count);
        for (uint64_t i = 0; i < count; ++i) {
            uint32_t current = uint32_t(mini_sector_count + i);
            mf.push_back(i + 1 == count ? END : current + 1);
        }
        mini_sector_count += count;
    }
    uint64_t mini_size = mini_sector_count * 64;
    if (major_ == 3 && mini_size > V3_MAX_STREAM_SIZE)
        throw std::runtime_error("MSI v3 mini-stream exceeds 2 GiB");
    fs[0].size = mini_size;

    struct Run {
        uint32_t id, start, count;
    };
    std::vector<Run> runs;
    uint64_t data_sector_count = 0;
    auto add_run = [&](uint32_t id, uint64_t size) {
        if (!size)
            return;
        uint64_t count = ceil_div(size, uint64_t{ss});
        if (count > MAX_REGULAR_SECTORS - data_sector_count)
            throw std::runtime_error("serialized MSI data is too large");
        uint32_t start = uint32_t(data_sector_count);
        runs.push_back({id, start, uint32_t(count)});
        fs[id].start = start;
        data_sector_count += count;
    };
    add_run(0, mini_size);
    for (uint32_t i = 1; i < fs.size(); ++i)
        if (fs[i].n->type == 2 && fs[i].size >= MINI_CUTOFF)
            add_run(i, fs[i].size);

    uint64_t mf_bytes = uint64_t(mf.size()) * sizeof(uint32_t);
    uint64_t dir_bytes = uint64_t(fs.size()) * 128;
    uint64_t mf_sector_count = ceil_div(mf_bytes, uint64_t{ss});
    uint64_t dir_sector_count = ceil_div(dir_bytes, uint64_t{ss});
    uint64_t base_sector_count = data_sector_count + mf_sector_count;
    if (base_sector_count > MAX_REGULAR_SECTORS - dir_sector_count)
        throw std::runtime_error("serialized MSI is too large");
    base_sector_count += dir_sector_count;

    uint64_t nfat64 = 0, ndif64 = 0;
    for (;;) {
        uint64_t allocated = base_sector_count + ndif64 + nfat64;
        if (allocated > MAX_REGULAR_SECTORS)
            throw std::runtime_error("serialized MSI has too many sectors");
        uint64_t nf = ceil_div(allocated, uint64_t{ep});
        uint64_t nd = nf <= 109 ? 0 : ceil_div(nf - 109, uint64_t{ep - 1});
        if (nf == nfat64 && nd == ndif64)
            break;
        nfat64 = nf;
        ndif64 = nd;
    }
    uint64_t total64 = base_sector_count + ndif64 + nfat64;
    checked_sector_count(total64);
    uint32_t data_secs = uint32_t(data_sector_count);
    uint32_t mf_secs = uint32_t(mf_sector_count);
    uint32_t dir_secs = uint32_t(dir_sector_count);
    uint32_t nfat = uint32_t(nfat64), ndif = uint32_t(ndif64);
    uint32_t base = uint32_t(base_sector_count);
    uint32_t dif0 = base, fat0 = base + ndif;
    uint64_t ft_entries64 = nfat64 * ep;
    if (ft_entries64 >
        std::numeric_limits<size_t>::max() / sizeof(uint32_t))
        throw std::runtime_error("serialized MSI FAT is too large");
    size_t ft_entries = size_t(ft_entries64);
    std::vector<uint32_t> ft(ft_entries, FREE);
    for (const auto &run : runs) {
        for (uint32_t i = 0; i < run.count; ++i)
            ft[run.start + i] = i + 1 == run.count ? END : run.start + i + 1;
    }
    uint32_t pos = data_secs;
    uint32_t mf0 = mf_secs ? pos : END;
    for (uint32_t i = 0; i < mf_secs; i++)
        ft[pos + i] = i + 1 == mf_secs ? END : pos + i + 1;
    pos += mf_secs;
    uint32_t dir0 = pos;
    for (uint32_t i = 0; i < dir_secs; i++)
        ft[pos + i] = i + 1 == dir_secs ? END : pos + i + 1;
    pos += dir_secs;
    for (uint32_t i = 0; i < ndif; i++)
        ft[pos + i] = DIF;
    pos += ndif;
    for (uint32_t i = 0; i < nfat; i++)
        ft[pos + i] = FAT;
    size_t out_size = checked_size((total64 + 1) * ss, "serialized MSI");
    std::vector<uint8_t> out(out_size);
    std::copy(header_.begin(), header_.end(), out.begin());
    put16(out.data() + 26, major_);
    put16(out.data() + 30, uint16_t(major_ == 3 ? 9 : 12));
    put32(out.data() + 40, major_ == 4 ? dir_secs : 0);
    put32(out.data() + 44, nfat);
    put32(out.data() + 48, dir0);
    put32(out.data() + 60, mf0);
    put32(out.data() + 64, mf_secs);
    put32(out.data() + 68, ndif ? dif0 : END);
    put32(out.data() + 72, ndif);
    for (int i = 0; i < 109; i++)
        put32(out.data() + 76 + 4 * i,
              i < int(nfat) ? fat0 + uint32_t(i) : FREE);
    for (const auto &f : fs) {
        if (f.n->type != 2 || f.n->data.empty())
            continue;
        uint64_t offset;
        if (f.size < MINI_CUTOFF) {
            offset = (uint64_t(fs[0].start) + 1) * ss +
                     uint64_t(f.start) * 64;
        } else {
            offset = (uint64_t(f.start) + 1) * ss;
        }
        size_t write_offset = checked_size(offset, "MSI stream offset");
        if (write_offset > out.size() ||
            f.n->data.size() > out.size() - write_offset)
            throw std::runtime_error("serialized MSI stream is out of range");
        std::copy(f.n->data.begin(), f.n->data.end(),
                  out.data() + write_offset);
    }
    for (size_t i = 0; i < mf.size(); i++)
        put32(out.data() + size_t(mf0 + 1) * ss + 4 * i, mf[i]);
    if (mf_secs) {
        size_t first_free = size_t(mf0 + 1) * ss + mf.size() * 4;
        size_t mini_fat_end = size_t(mf0 + 1 + mf_secs) * ss;
        std::fill(out.data() + first_free, out.data() + mini_fat_end,
                  uint8_t{0xff});
    }
    for (uint32_t i = 0; i < fs.size(); i++) {
        auto p = out.data() + size_t(dir0 + 1) * ss + 128 * i;
        std::copy(fs[i].n->raw.begin(), fs[i].n->raw.end(), p);
        std::fill(p, p + 64, 0);
        std::copy(fs[i].n->name.begin(), fs[i].n->name.end(), p);
        put16(p + 64, uint16_t(fs[i].n->name.size()));
        p[66] = fs[i].n->type;
        p[67] = fs[i].color;
        put32(p + 68, fs[i].left);
        put32(p + 72, fs[i].right);
        put32(p + 76, fs[i].child);
        put32(p + 116, fs[i].n->type == 1 ? 0 : fs[i].start);
        put64(p + 120, fs[i].size);
    }
    for (size_t i = fs.size(); i < size_t(dir_secs) * ss / 128; ++i) {
        auto p = out.data() + size_t(dir0 + 1) * ss + 128 * i;
        put32(p + 68, NONE);
        put32(p + 72, NONE);
        put32(p + 76, NONE);
    }
    for (uint32_t i = 0; i < ndif; i++) {
        auto p = out.data() + size_t(dif0 + i + 1) * ss;
        for (uint32_t j = 0; j < ep - 1; j++) {
            uint32_t x = 109 + i * (ep - 1) + j;
            put32(p + 4 * j, x < nfat ? fat0 + x : FREE);
        }
        put32(p + 4 * (ep - 1), i + 1 < ndif ? dif0 + i + 1 : END);
    }
    for (uint32_t i = 0; i < nfat; i++) {
        auto p = out.data() + size_t(fat0 + i + 1) * ss;
        for (uint32_t j = 0; j < ep; j++)
            put32(p + 4 * j, ft[size_t(i) * ep + j]);
    }
    return out;
}
