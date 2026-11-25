# Contributing

Thanks for helping improve BitCrack Distributed. Please follow the lightweight guidelines below.

## Getting Started
- Use a recent CMake (3.18+) and a C++17 compiler.
- Windows: `./build.bat` (Visual Studio 2022). POSIX: `cmake -S . -B build && cmake --build build --config Release`.
- Optional GPU: install CUDA (NVIDIA) or OpenCL SDK (AMD/Intel/NVIDIA).
- No GUI toolkit is needed: the node's UI is the built-in web dashboard (`--dashboard`; page source in `network/dashboard/dashboard.html`, embedded at build time).

## Tests
- Catch2 v3 is optional. To force fetch and build tests: set `-DBITCRACK_FORCE_FETCH_CATCH2=ON` at configure time.
- Build: `cmake --build build_vs2022 --config Release --target bitcrack_tests` (Windows) or `cmake --build build --config Release --target bitcrack_tests` (POSIX).
- Run: `build_vs2022/tests/Release/bitcrack_tests.exe` (Windows) or `./build/tests/bitcrack_tests` (POSIX).

## Coding Guidelines
- C++17, prefer standard library over custom helpers.
- Keep headers lightweight; avoid adding test-only hooks to public interfaces unless absolutely necessary.
- Log via `Logger`; prefer warn/error for user-visible issues, debug for chatty traces.
- Configuration: use `ConfigManager`; do not expose internal tuning knobs (e.g., commit quorum) without discussion.

## Pull Requests
- Include a short summary of behavior change and risks.
- Add or update tests when logic changes.
- Run a Release build (or the fastest equivalent) for the touched targets.
- Keep PRs focused and small; prefer follow-ups for unrelated refactors.
