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
