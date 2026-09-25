/* ====================================================================
 * Copyright (c) 2026 ALRI Development. All rights reserved.
 * Licensed under the terms in the repository LICENSE file.
 * ==================================================================== */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int os_connect_timeout(int fd, const char *addr, uint16_t port, int timeout_ms) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) <= 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    int rc = connect(fd, (const struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) {
        return (fcntl(fd, F_SETFL, flags) == 0) ? 0 : -1;
    }
    if (errno != EINPROGRESS) {
        (void)fcntl(fd, F_SETFL, flags);
        return -1;
    }

    fd_set wfds;
    struct timeval tv;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel;
    do {
        sel = select(fd + 1, NULL, &wfds, NULL, &tv);
    } while (sel < 0 && errno == EINTR);

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    int socket_error_rc = -1;
    if (sel > 0 && FD_ISSET(fd, &wfds)) {
        socket_error_rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
    }
    if (fcntl(fd, F_SETFL, flags) < 0) {
        return -1;
    }
    return (sel > 0 && socket_error_rc == 0 && soerr == 0) ? 0 : -1;
}

static int os_set_recv_timeout(int fd, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
