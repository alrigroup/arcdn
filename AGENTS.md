# AGENTS.md — Autonomous AI Agent Operating Protocol & Technical Invariants

> **Target Audience**: Autonomous AI Agents (Antigravity, Claude Code, Cursor, Copilot) & Systems Performance Engineers.  
> **Repository**: `arcdn` (High-Throughput Static Delivery, Media Streaming & Zero-Copy Edge Server)  
> **Visibility**: Public Open-Core  
> **Asset Owner**: ALRI Group | **Engineering**: ALRI Development  
> **License**: ARGLP (ALRI Group License Permissive — Version 2)  
> **Primary Technical Reference**: Consult [`DOCS.md`](DOCS.md) for complete function signatures, data structures, and protocol diagrams.

---

## 1. Project Mission & Identity

**ARCDN** is the native static asset delivery and video streaming engine for the ALRIOS platform. Written in optimized C with an OS Hardware Abstraction Layer (HAL), it operates as a high-throughput edge server designed to serve media, stylesheets, JavaScript bundles, fonts, and images with sub-millisecond response latency.

### Core Architectural Specifications
- **Operating Port**: TCP `3005` (bind `127.0.0.1` by default, configurable in `cdn.cfg`).
- **IPC Gateway Registration**: Automatically connects to the ARWS reverse proxy gateway via loopback TCP on port `9500` upon bootstrap, announcing routes for virtual hosts `cdn.alrigroup.com` and `cdn.localhost` under wildcard scope `/*`.
- **Media Streaming Engine**: Full implementation of **HTTP 206 Partial Content** byte-range slicing supporting RFC 7233 (`Range: bytes=start-end`), enabling instant HTML5 `<video>` scrubbing and media streaming.
- **MIME Resolution**: Static in-memory mapping table covering 19 standardized web media and asset extensions.
- **Cache-Control Guarantee**: Emits immutable caching headers (`max-age=31536000, public, immutable`) for all successful static asset dispatches.

---

## 2. Directory Structure & Key Files

```
arcdn/
├── arcdn.arappmake           # ALRIOS package manifest & compilation rules
├── DOCS.md                   # Complete 290+ lines technical reference manual
├── README.md                 # Public overview & operational guide
├── AGENTS.md                 # This autonomous agent operating protocol
├── src/
│   ├── cdn_server.c          # Core HTTP engine, Range parser, MIME resolver, IPC client (1,125 lines)
│   └── os/
│       ├── main.c            # OS HAL bootstrap and thread manager
│       ├── include/
│       │   └── home_os.h     # HAL networking, path, and high-resolution timer declarations
│       ├── linux/
│       │   ├── net.c         # POSIX non-blocking socket implementation (epoll, fcntl)
│       │   └── path.c        # POSIX path resolution and realpath canonicalization
│       └── windows/
│           ├── net.c         # WinSock2 implementation (WSAPoll, ioctlsocket)
│           └── path.c        # Win32 GetFullPathNameW path resolution
```

---

## 3. Essential Commands & Toolchain Invariants

### 3.1 Compilation from Source (Linux x64)
```bash
cc -O2 \
  -Isrc -Isrc/os/include -I../../ALRIOS/arkernel/include -I../../ALRIOS/arkernel/os/include -I../../ALRIOS/arkernel/ipc \
  -o cdn_web \
  src/cdn_server.c src/os/main.c ../../ALRIOS/arkernel/os/main.c \
  -lssl -lcrypto -lpthread
```

### 3.2 Packaging into ALRIOS Modular Archive (`.arapp`)
```bash
# Invoked from repository root via armake tool
armake build . arcdn.arapp
```

### 3.3 Running in Standalone Debug Mode
```bash
./cdn_web                       # Starts server on port 3005, registers on port 9500
```

### 3.4 Operational CLI Commands (Dispatched via `alrios cdn`)
```bash
alrios cdn status               # Reports TCP port, entry count, memory footprint, uptime
alrios cdn routes               # Dumps active host bindings and gateway IPC status
alrios cdn list                 # Dumps all mapped virtual path entries (up to 1,024)
alrios cdn add <path> <file>    # Dynamically maps a new virtual path to physical disk file
alrios cdn del <path>           # Unmounts an existing virtual path
alrios cdn ping                 # Diagnostics heartbeat returning "pong"
```

---

## 4. Architectural Rules & The "NEVER" List

Autonomous AI Agents operating within this codebase must strictly observe these inviolable rules:

### 4.1 Strict Prohibitions
- ❌ **NEVER add file-upload or file-writing logic**: ARCDN is strictly a read-only delivery engine. File uploads, POST mutations, or disk writes are banned here and belong in specialized backend APIs.
- ❌ **NEVER bypass anti-directory traversal sanitization**: Any request path containing `..`, `%2e%2e`, backslashes `\`, or null bytes `0x00` (`%00`) must be immediately dropped with `400 Bad Request`.
- ❌ **NEVER allocate dynamic memory on the request path without immediate release**: Avoid `malloc()` within request loops; rely on fixed stack buffers or pre-allocated tables (`g_entries`, `MAX_ENTRIES = 1024`).
- ❌ **NEVER emit mutable cache headers for static assets**: Static media must always receive `Cache-Control: public, max-age=31536000, immutable`.
- ❌ **NEVER perform unaligned 64-bit offsets in Range Requests**: Byte range offsets (`start`, `end`, `size`) must be parsed and clamped using `long long` / `int64_t` to support files larger than 2 GiB without overflow.

---

## 5. Code Style & Engineering Standards

### 5.1 Correct vs. Incorrect Implementations

#### Anti-Traversal Path Validation
```c
/* INCORRECT: Incomplete check vulnerable to URL encoding and null bytes */
if (strstr(path, "..") != NULL) {
    return -1;
}

/* CORRECT (ARCDN Standard): Multi-layer sanitization with null-byte detection */
static int is_path_safe(const char *path) {
    if (!path || path[0] == '\0') return 0;
    if (strstr(path, "..") || strstr(path, "%2e") || strstr(path, "%2E")) return 0;
    if (strchr(path, '\\') || strstr(path, "%5c") || strstr(path, "%5C")) return 0;
    for (const char *p = path; *p; p++) {
        if ((unsigned char)*p < 0x20 || *p == 0x7F) return 0;
    }
    return 1;
}
```

#### HTTP 206 Range Request Header Emission
```c
/* CORRECT (ARCDN Standard): Exact RFC 7233 byte-range response */
char range_hdr[256];
snprintf(range_hdr, sizeof(range_hdr),
         "HTTP/1.1 206 Partial Content\r\n"
         "Content-Type: %s\r\n"
         "Content-Length: %lld\r\n"
         "Content-Range: bytes %lld-%lld/%lld\r\n"
         "Accept-Ranges: bytes\r\n"
         "Cache-Control: public, max-age=31536000, immutable\r\n"
         "Access-Control-Allow-Origin: *\r\n"
         "Connection: close\r\n\r\n",
         mime_type, (end - start + 1), start, end, total_size);
```

### 5.2 Mandatory Copyright Header
Every new C source or header file created must begin with:
```c
/*
 * Copyright (c) 2026 ALRIGROUP and its affiliates.
 * Engineered and maintained by ALRI Development.
 *
 * This code is licensed under the ARGLP - ALRI GROUP LICENSE PERMISSIVE
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses
 */
```

---

## 6. Pre-Commit & Pull Request Verification Checklist

Before submitting changes, the agent must verify:
1. `cdn_server.c` compiles with zero warnings under `-O2 -Wall -Wextra`.
2. All Range Request math handles files > 2 GiB cleanly using 64-bit integer arithmetic.
3. No secrets, `.env` files, or binary artifacts (`cdn_web`, `*.arapp`) are staged.
4. Any new MIME type added is registered in `get_mime()` in `cdn_server.c` and documented in `DOCS.md`.
5. Git commits adhere to Conventional Commits with the mandatory trailer:
   `Signed-off-by: ALRI Development <dev@alrigroup.com>`.
