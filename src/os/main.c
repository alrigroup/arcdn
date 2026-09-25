/* ====================================================================
 * Copyright (c) 2026 ALRI Development. All rights reserved.
 * Licensed under the terms in the repository LICENSE file.
 * ==================================================================== */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "home_os.h"
#include <stddef.h>
#include <stdint.h>

/* ---------- forward declarations ---------- */

static int  os_get_exe_dir(char *buf, int size);
static int  os_connect_timeout(int fd, const char *addr, uint16_t port, int timeout_ms);
static int  os_set_recv_timeout(int fd, int timeout_ms);

/* ---------- public API ---------- */

int home_os_get_exe_dir(char *buf, int size) {
    if (!buf || size <= 0) return -1;
    return os_get_exe_dir(buf, size);
}

int home_os_connect_timeout(int fd, const char *addr, uint16_t port, int timeout_ms) {
    if (fd < 0 || addr == NULL || port == 0U || timeout_ms <= 0) return -1;
    return os_connect_timeout(fd, addr, port, timeout_ms);
}

int home_os_set_recv_timeout(int fd, int timeout_ms) {
    if (fd < 0 || timeout_ms <= 0) return -1;
    return os_set_recv_timeout(fd, timeout_ms);
}

/* ---------- OS dispatch ---------- */

#ifdef __linux__
    #include "linux/path.c"
    #include "linux/net.c"
#elif defined(_WIN32)
    #include "windows/path.c"
    #include "windows/net.c"
#else
    #error "alrios: no home.web OS implementation for this OS"
#endif
