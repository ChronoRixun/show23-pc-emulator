# MLB The Show 23 emulator fork

This branch builds shadPS4 for the PS4 base version of MLB The Show 23. Its upstream base is
`312cfbae77821627aa511bdee8717e1b7c3c9a23`. The fork retains the upstream GPL-2.0-or-later
licence and source notices. It is independently maintained.

## Running the game

Ordinary boot enables the game's compatibility settings for CUSA35521 version 01.00 after
verifying the main executable. The supported SELF is 38,785,273 bytes and its SHA-256 is
`78858c91ee74e69056c8000cb54d3451b2d738b9b9d3d89c006b704be3ec3aa1`.
Select the base executable and disable automatic game patches for this version.

To use the companion local service, supply `--show23-local-ca <path>` with the public CA
file created for that installation. Start the companion on IPv4 loopback ports 10000 (game)
and 10080 (Web API and HTTP content). Local mode requires both the matching title metadata
and the exact executable above. The emulator checks the mounted file and boots the bytes it
verified. Missing or invalid trust material or an unsupported image stops the boot. Trust is
changed only inside the game's process. The local account and request completions belong to
this session. The emulator confines game traffic to loopback and uses the synthetic identity
expected by the companion.

## Compatibility behavior

- Oversized direct compute groups are folded across Z when an X/Y slice fits. The affected
  shared-memory workload uses backing storage and a second pass. Unsupported oversized direct
  groups and oversized indirect groups retain the game's skip behavior and warn once per session.
- Per-pixel indexed image tables preserve binding counts, order and empty entries. Resolved
  tables can be reused while their contents and image registrations match.
- Eligible single-mip arrays beyond the host layer limit use 3D storage, views and shader
  coordinates. Two game-specific overlap rules preserve block reinterpretations and composed mip chains.
- Reads of shared-page poll labels can use the backing copy. Selected event-label writes are
  mirrored on GPU-written pages. Synchronous downloads can share a completion. Buffers within
  one shader stage can share a descriptor write.
- On hosts with transform feedback, the hardware vertex shader declares its position output.
  This suppressed intermittent distortion in cutaways in development runs. Its underlying
  cause is still unknown.
- The verified local session handles the known unresolved script operand on Windows. Its
  exception guard checks the mapped main executable and the faulting instruction.
- The title defaults include precise readbacks, a submit interval of 128, red-zone protection,
  a separate enabled shader cache and direct memory access disabled. Other titles retain their
  own settings. General set, descriptor-construction, image lookup and ownership fixes also apply
  elsewhere.

The duplicate shader-read offset and texture overlap improvements incorporate work from
[victorgbd/mlb_pc](https://github.com/victorgbd/mlb_pc) on the same emulator code base.

## Building

Use the upstream Windows x64 dependencies and the pinned submodules. The release configuration
uses CMake with Ninja, clang-cl, Release interprocedural optimization and a linker map.
The game, the per-install CA and the companion's data are supplied separately.
