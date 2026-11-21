// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <boost/container/set.hpp>
#include <boost/container/small_vector.hpp>
#include "common/types.h"

namespace Serialization {
struct Archive;
}

namespace Shader {

using PFN_SrtWalker = void PS4_SYSV_ABI (*)(const u32* /*user_data*/, u32* /*flat_dst*/);
PFN_SrtWalker RegisterWalkerCode(const u8* ptr, size_t size);

struct PersistentSrtInfo {
    // Special case when fetch shader uses step rates.
    struct SrtSharpReservation {
        u32 sgpr_base;
        u32 dword_offset;
        u32 num_dwords;
    };

    // A table of 8-dword descriptors that the shader indexes with a per-pixel value. The walker
    // leaves the table's V# at vsharp_off_dw in the flat buffer; CopySharpTables then copies the
    // start of the table to table_off_dw.
    struct SharpTable {
        std::array<u16, 4> vsharp_off_dw;
        u16 table_off_dw;
    };

    PFN_SrtWalker walker_func{};
    size_t walker_func_size{};
    u32 flattened_bufsize_dw = 16; // NumUserDataRegs
    u32 num_sharp_tables = 0;
    std::array<SharpTable, 4> sharp_tables{};

    void Serialize(Serialization::Archive& ar) const;
    bool Deserialize(Serialization::Archive& ar);
};

/// Fills in the copies of the descriptor tables recorded in srt, after its walker has run.
void CopySharpTables(const PersistentSrtInfo& srt, u32* flatbuf);

} // namespace Shader
