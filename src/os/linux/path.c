/* ====================================================================
 * Copyright (c) 2026 ALRI Development. All rights reserved.
 * Licensed under the terms in the repository LICENSE file.
 * ==================================================================== */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int os_get_exe_dir(char *buf, int size) {
    ssize_t n;
    char *separator;

    if (buf == NULL || size < 2) {
        return -1;
    }

    n = readlink("/proc/self/exe", buf, (size_t)size - 1U);
    if (n <= 0 || n >= (ssize_t)size) {
        buf[0] = '\0';
        return -1;
    }
    buf[n] = '\0';

    separator = strrchr(buf, '/');
    if (separator != NULL) {
        if (separator == buf) {
            buf[1] = '\0';
        } else {
            *separator = '\0';
        }
        return 0;
    }

    if (snprintf(buf, (size_t)size, ".") != 1) {
        buf[0] = '\0';
        return -1;
    }
    return 0;
}
