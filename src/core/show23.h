// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <filesystem>
#include <memory>
#include <string_view>
#include "common/types.h"

namespace Core::FileSys {
class IFile;
}

namespace Show23 {
// Legacy wire identity and authorization code shared with the local server.
// Rename these values together with the server in a later protocol change.
inline constexpr const char* LocalOnlineId = "ScoutLocal";
inline constexpr u64 LocalAccountId = 0x0123456789abcdefULL;
inline constexpr const char* LocalAuthCode = "ScoutLocalAuthCode0001";
inline constexpr s32 LocalIssuerId = 256;

void RequestLocal(std::filesystem::path ca_path);
bool LocalRequested();
bool ResolveLoopback(std::string_view host, u32& address);
const std::filesystem::path& LocalCaPath();
bool Enabled();
bool LocalActive();
void InstallLocalTrust(VAddr base, u64 bytes_from_record);
inline constexpr u64 TrustRecordOffset = 0x1f38703;
VAddr LocalMainBase();
std::unique_ptr<Core::FileSys::IFile> VerifyMain(std::unique_ptr<Core::FileSys::IFile> file);
[[noreturn]] void Refuse(const char* reason);
} // namespace Show23
