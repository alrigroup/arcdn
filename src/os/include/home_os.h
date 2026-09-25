/* ====================================================================
 * Copyright (c) 2026 ALRI Development. All rights reserved.
 * Licensed under the terms in the repository LICENSE file.
 * ==================================================================== */

#ifndef HOME_OS_H
#define HOME_OS_H

#include <stdint.h>

int home_os_get_exe_dir(char *buf, int size);
int home_os_connect_timeout(int fd, const char *addr, uint16_t port, int timeout_ms);
int home_os_set_recv_timeout(int fd, int timeout_ms);

#endif
