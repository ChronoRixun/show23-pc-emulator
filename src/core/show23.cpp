// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/show23.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <openssl/evp.h>
#include "common/logging/log.h"
#include "core/file_sys/ifile.h"
#include "core/net/host_net.h"

namespace Show23 {
namespace {
std::filesystem::path local_ca;
bool enabled{};
VAddr local_main{};

class VerifiedFile final : public Core::FileSys::IFile {
public:
    explicit VerifiedFile(std::vector<u8> data) : bytes{std::move(data)} {}
    s64 Read(void* dst, u64 size) override {
        const size_t count = std::min<u64>(size, bytes.size() - position);
        if (count) {
            std::memcpy(dst, bytes.data() + position, count);
            position += count;
        }
        return count;
    }
    s64 Write(const void*, u64) override { return -1; }
    bool Seek(s64 offset, Common::FS::SeekOrigin origin) override {
        using enum Common::FS::SeekOrigin;
        const s64 base = origin == SetOrigin ? 0 : origin == End ? bytes.size() : position;
        if (offset < -base || offset > static_cast<s64>(bytes.size()) - base) {
            return false;
        }
        position = base + offset;
        return true;
    }
    u64 Tell() const override { return position; }
    u64 Size() const override { return bytes.size(); }
    bool Flush() override { return true; }
    bool IsOpen() const override { return true; }

private:
    std::vector<u8> bytes;
    size_t position{};
};
} // namespace

void RequestLocal(std::filesystem::path path) {
    if (path.empty()) {
        Refuse("a local CA file is required");
    }
    local_ca = std::filesystem::absolute(path);
}
bool ResolveLoopback(std::string_view host, u32& address) {
    if (host.ends_with('.')) {
        host.remove_suffix(1);
    }
    if (host.empty() || host.find('\0') != std::string_view::npos) {
        return false;
    }
    std::string name{host};
    std::ranges::transform(name, name.begin(), [](char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
    });
    if (name == "localhost" || name == "production.mlb.mlbtheshow.net" ||
        name == "production.mlb23.mlbtheshow.net") {
        address = htonl(INADDR_LOOPBACK);
        return true;
    }
    in_addr ip{};
    if (inet_pton(AF_INET, name.c_str(), &ip) == 1 && (ntohl(ip.s_addr) >> 24) == 127) {
        address = ip.s_addr;
        return true;
    }
    return false;
}

bool LocalRequested() { return !local_ca.empty(); }
const std::filesystem::path& LocalCaPath() { return local_ca; }
bool Enabled() { return enabled; }
bool LocalActive() { return local_main != 0; }
VAddr LocalMainBase() { return local_main; }
void ActivateLocal(VAddr base) { local_main = base; }

[[noreturn]] void Refuse(const char* reason) {
    std::fprintf(stderr, "MLB The Show 23: %s\n", reason);
    std::fflush(stderr);
    LOG_CRITICAL(Loader, "MLB The Show 23: {}", reason);
    std::exit(EXIT_FAILURE);
}

std::unique_ptr<Core::FileSys::IFile> VerifyMain(std::unique_ptr<Core::FileSys::IFile> file) {
    constexpr size_t size = 38785273;
    constexpr std::array<u8, 32> expected = {
        0x78, 0x85, 0x8c, 0x91, 0xee, 0x74, 0xe6, 0x90,
        0x56, 0xc8, 0x00, 0x0c, 0xb5, 0x4d, 0x34, 0x51,
        0xb2, 0xd7, 0x38, 0xb9, 0xb9, 0xd3, 0xd8, 0x9c,
        0x00, 0x6b, 0x70, 0x4b, 0xe3, 0xec, 0x3a, 0xa1,
    };
    if (!file || !file->IsOpen() || file->Size() != size) {
        Refuse("unsupported main executable size; version 1.00 is required");
    }
    std::vector<u8> bytes(size);
    size_t done = 0;
    while (done < size) {
        const auto count = file->Read(bytes.data() + done, size - done);
        if (count <= 0 || u64(count) > size - done) {
            Refuse("could not read the complete main executable");
        }
        done += count;
    }
    std::array<u8, EVP_MAX_MD_SIZE> digest{};
    unsigned length{};
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 ||
        length != expected.size() || !std::equal(expected.begin(), expected.end(), digest.begin())) {
        Refuse("unsupported main executable SHA-256; version 1.00 is required");
    }
    enabled = true;
    return std::make_unique<VerifiedFile>(std::move(bytes));
}
} // namespace Show23
