#pragma once

#include <chrono>
#include <string>

// Process-wide shutdown request latch driven by SIGINT/SIGTERM (POSIX) or the
// console control handler (Windows: Ctrl+C, Ctrl+Break, console close).
//
// The signal handler is async-signal-safe: it only bumps a lock-free atomic
// counter and write()s one byte to a non-blocking self-pipe. Everything else
// (stopping the engine/NetworkManager, saving state) happens on normal
// threads that notice the request via requested()/waitFor()/readLine().
//
// A second signal while a shutdown is already pending force-exits the process
// immediately with exit code 130 (_exit on POSIX, ExitProcess on Windows).
namespace ShutdownSignal {

// Install the handlers. Idempotent. Returns false if installation failed (the
// process then keeps the default signal behaviour).
bool install();

// True once a shutdown has been requested (by a signal or by request()).
bool requested();

// Number of shutdown signals/requests seen so far.
int count();

// Request a shutdown from normal (non-signal) code, e.g. tests or a 'quit'
// path that wants to wake waiters. Does NOT force-exit on repeated calls.
void request();

// Block for up to `timeout` or until a shutdown is requested, whichever comes
// first. Returns requested().
bool waitFor(std::chrono::milliseconds timeout);

enum class ReadResult { Line, Eof, Shutdown };

// Read one line from stdin (without the trailing newline / CR) while also
// watching for a shutdown request. On POSIX this poll()s fd 0 together with
// the self-pipe, so a Ctrl-C interrupts a blocked console read; it reads fd 0
// directly and must not be mixed with std::cin on the same stream.
ReadResult readLine(std::string& out);

// Test-only: clear the latch and drain the self-pipe.
void resetForTest();

} // namespace ShutdownSignal
