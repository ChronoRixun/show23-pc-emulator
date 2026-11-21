// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <memory>

namespace Core::FileSys {
class IFile;
}

namespace Show23 {
void BeginBoot();
std::unique_ptr<Core::FileSys::IFile> InspectMain(const Core::FileSys::IFile& verified_main);
} // namespace Show23
