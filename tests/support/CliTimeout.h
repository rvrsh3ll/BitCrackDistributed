#pragma once
// Prefix for tests that run the real CLI through the shell: kills the node
// after 60 s if it hangs. macOS has no `timeout` (GNU coreutils), but perl
// ships with it and an alarm survives exec, so it does the same job there.
#if defined(__APPLE__)
#define BCD_TEST_TIMEOUT "perl -e 'alarm 60; exec @ARGV' "
#else
#define BCD_TEST_TIMEOUT "timeout 60 "
#endif
