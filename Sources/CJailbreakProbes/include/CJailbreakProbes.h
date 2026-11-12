//
//  CJailbreakProbes.h
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

#ifndef CJAILBREAKPROBES_H
#define CJAILBREAKPROBES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Probes that answer yes or no return 1 for yes, 0 for no, and -1 when the probe cannot run in this build.

/// Whether this build can issue system calls directly. True on arm64 only.
bool jbp_direct_syscalls_supported(void);

/// Asks the kernel whether the path exists, with `access(2)` issued directly instead of through libc.
int jbp_direct_access(const char *path);

/// Asks the kernel whether the path can be opened for reading, with `open(2)` issued directly.
int jbp_direct_open(const char *path);

/// Reads a symbolic link with `readlink(2)` issued directly.
/// Returns the number of bytes written to the buffer, or -1 if the path is not a readable symbolic link
/// or the probe cannot run in this build. The buffer is not null-terminated.
long jbp_direct_readlink(const char *path, char *buffer, size_t size);

/// Whether a function's first instructions are a jump to somewhere else, as an inline hook leaves them.
/// Reads at most the first four arm64 instructions.
bool jbp_instructions_are_trampoline(const uint32_t *instructions, size_t count);

/// Whether the named function, resolved at run time, starts with a trampoline.
int jbp_function_is_trampoline(const char *symbol);

/// Whether the process is allowed to fork. The child exits immediately.
int jbp_fork_succeeds(void);

/// Whether something accepts TCP connections on the loopback interface at the port.
int jbp_loopback_port_is_open(uint16_t port, int timeout_milliseconds);

#ifdef __cplusplus
}
#endif

#endif
