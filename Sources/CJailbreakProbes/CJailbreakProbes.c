//
//  CJailbreakProbes.c
//  JailbreakDetector
//
//  Created by Roman Croitor on 12.11.2026.
//

#include "CJailbreakProbes.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <ptrauth.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// MARK: - Direct system calls

#if defined(__arm64__) || defined(__aarch64__)

enum {
    JBP_SYSCALL_OPEN = 5,
    JBP_SYSCALL_CLOSE = 6,
    JBP_SYSCALL_ACCESS = 33,
    JBP_SYSCALL_READLINK = 58,
};

/// Issues a BSD system call without going through libc, so that a hook on the libc wrapper is not involved.
/// The kernel takes the call number in x16 and reports failure by setting the carry flag.
static long jbp_syscall(long number, long first, long second, long third, bool *failed) {
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    register long x16 __asm__("x16") = number;
    long carry;
    __asm__ volatile(
        "svc #0x80\n"
        "cset %[carry], cs\n"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x16), [carry] "=&r"(carry)
        :
        : "x17", "cc", "memory");
    *failed = carry != 0;
    return x0;
}

bool jbp_direct_syscalls_supported(void) {
    return true;
}

int jbp_direct_access(const char *path) {
    bool failed;
    jbp_syscall(JBP_SYSCALL_ACCESS, (long)path, F_OK, 0, &failed);
    return failed ? 0 : 1;
}

int jbp_direct_open(const char *path) {
    bool failed;
    long descriptor = jbp_syscall(JBP_SYSCALL_OPEN, (long)path, O_RDONLY | O_CLOEXEC, 0, &failed);
    if (failed) {
        return 0;
    }
    jbp_syscall(JBP_SYSCALL_CLOSE, descriptor, 0, 0, &failed);
    return 1;
}

long jbp_direct_readlink(const char *path, char *buffer, size_t size) {
    bool failed;
    long length = jbp_syscall(JBP_SYSCALL_READLINK, (long)path, (long)buffer, (long)size, &failed);
    return failed ? -1 : length;
}

#else

bool jbp_direct_syscalls_supported(void) {
    return false;
}

int jbp_direct_access(const char *path) {
    return -1;
}

int jbp_direct_open(const char *path) {
    return -1;
}

long jbp_direct_readlink(const char *path, char *buffer, size_t size) {
    return -1;
}

#endif

// MARK: - Function prologues

/// `B <offset>`, an unconditional jump.
static bool jbp_is_branch(uint32_t instruction) {
    return (instruction & 0xFC000000u) == 0x14000000u;
}

/// `BR x16` or `BR x17`, a jump through one of the two scratch registers that hooking frameworks use.
static bool jbp_is_branch_through_scratch_register(uint32_t instruction) {
    return instruction == 0xD61F0200u || instruction == 0xD61F0220u;
}

bool jbp_instructions_are_trampoline(const uint32_t *instructions, size_t count) {
    if (instructions == NULL || count == 0) {
        return false;
    }
    if (jbp_is_branch(instructions[0])) {
        return true;
    }
    size_t limit = count < 4 ? count : 4;
    for (size_t index = 0; index < limit; index++) {
        if (jbp_is_branch_through_scratch_register(instructions[index])) {
            return true;
        }
    }
    return false;
}

int jbp_function_is_trampoline(const char *symbol) {
#if defined(__arm64__) || defined(__aarch64__)
    void *address = dlsym(RTLD_DEFAULT, symbol);
    if (address == NULL) {
        return -1;
    }
    address = ptrauth_strip(address, ptrauth_key_function_pointer);
    uint32_t instructions[4];
    memcpy(instructions, address, sizeof(instructions));
    return jbp_instructions_are_trampoline(instructions, 4) ? 1 : 0;
#else
    return -1;
#endif
}

// MARK: - Fork

int jbp_fork_succeeds(void) {
    // Resolved at run time so that the binary does not import the symbol.
    pid_t (*fork_function)(void) = (pid_t (*)(void))dlsym(RTLD_DEFAULT, "fork");
    if (fork_function == NULL) {
        return -1;
    }
    pid_t child = fork_function();
    if (child == 0) {
        _exit(0);
    }
    if (child < 0) {
        return 0;
    }
    int status;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    return 1;
}

// MARK: - Loopback ports

int jbp_loopback_port_is_open(uint16_t port, int timeout_milliseconds) {
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return -1;
    }
    int enabled = 1;
    setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
    fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL, 0) | O_NONBLOCK);

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int is_open = 0;
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0) {
        is_open = 1;
    } else if (errno == EINPROGRESS) {
        struct pollfd poll_descriptor = {.fd = descriptor, .events = POLLOUT};
        if (poll(&poll_descriptor, 1, timeout_milliseconds) > 0) {
            int error = 0;
            socklen_t length = sizeof(error);
            if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0) {
                is_open = 1;
            }
        }
    }
    close(descriptor);
    return is_open;
}
