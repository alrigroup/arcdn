/* ====================================================================
 * Copyright (c) 2026 ALRI Development. All rights reserved.
 * Licensed under the terms in the repository LICENSE file.
 * ==================================================================== */

#include <stdio.h>
#include <string.h>
#include <windows.h>

static int os_get_exe_dir(char *buf, int size) {
    DWORD n;
    char *separator;

    if (buf == NULL || size < 2) {
        return -1;
    }

    n = GetModuleFileNameA(NULL, buf, (DWORD)size);
    if (n == 0U || n >= (DWORD)size) {
        buf[0] = '\0';
        return -1;
    }

    separator = strrchr(buf, '\\');
    if (separator == NULL) {
        separator = strrchr(buf, '/');
    }
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
