# ARCDN — Technical Reference Manual

*High-Throughput Static Delivery, Media Streaming & Edge Asset Server*

*Version: 0.2.01 | ALRI GROUP © 2026 | License: ARGLP*

---

## Table of Contents

- [1. Overview & Ecosystem Role](#1-overview--ecosystem-role)
- [2. Architecture & Asset Pipeline](#2-architecture--asset-pipeline)
- [3. Configuration Reference (cdn.cfg)](#3-configuration-reference-cdncfg)
- [4. Module Reference](#4-module-reference)
  - [4.1 CDN Server Core (cdn_server)](#41-cdn-server-core-cdn_server)
  - [4.2 Routing & Virtual Path Mapping](#42-routing--virtual-path-mapping)
  - [4.3 Range Request Engine (HTTP 206)](#43-range-request-engine-http-206)
  - [4.4 MIME Type Resolution](#44-mime-type-resolution)
  - [4.5 Cache-Control & ETag Subsystem](#45-cache-control--etag-subsystem)
  - [4.6 Operating System HAL (os/linux & os/windows)](#46-operating-system-hal-oslinux--oswindows)
- [5. CLI Governance & IPC Commands](#5-cli-governance--ipc-commands)
- [6. Security Model & Defenses](#6-security-model--defenses)
- [7. Operational Guide](#7-operational-guide)
- [8. Build & Packaging](#8-build--packaging)

---

## 1. Overview & Ecosystem Role

**ARCDN** is the native static asset delivery and video streaming engine for the ALRIOS platform. Written in optimized C with an OS Hardware Abstraction Layer (HAL), it bypasses runtime overhead by serving files directly from the file system to network sockets with full support for chunked transfer and HTTP 206 byte-range seeking.

### Core Metrics

| Metric | Value |
|---|---|
| Native TCP Port | `3005` |
| Gateway Registration | ARWS on `127.0.0.1:9500` |
| Default Domains | `cdn.alrigroup.com`, `cdn.localhost` |
| Route Scope | `/*` (wildcard) |
| Max Registered Static Entries | `1024` (`MAX_ENTRIES`) |
| Request Buffer Size | `65536` bytes (`MAX_REQ`) |
| Default Cache TTL | `31536000` seconds (1 year immutable) |

---

## 2. Architecture & Asset Pipeline

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                           ARCDN Asset Pipeline                              │
 │                                                                             │
 │  Client Browser / Video Player                                              │
 │             │                                                               │
 │             ▼                                                               │
 │      Port 8080 / 443 (ARWS Gateway)                                         │
 │             │ Reverse Proxy to cdn.localhost                                │
 │             ▼                                                               │
 │      Port 3005 (ARCDN Native Engine)                                        │
 │             │                                                               │
 │             ┌───────────────────────────────────────────┐                   │
 │             │           Path Sanitization               │                   │
 │             │   (Anti-Traversal: block '..', nulls)     │                   │
 │             └─────────────────────┬─────────────────────┘                   │
 │                                   │ Clean Path                              │
 │             ┌─────────────────────▼─────────────────────┐                   │
 │             │        Virtual Entry Table Lookup         │                   │
 │             │       (CdnEntry: path -> file path)       │                   │
 │             └─────────────────────┬─────────────────────┘                   │
 │                                   │ File Found                              │
 │             ┌─────────────────────▼─────────────────────┐                   │
 │             │       Header & Range Inspection           │                   │
 │             │       (Check for 'Range: bytes=X-Y')      │                   │
 │             └───────┬───────────────────────────┬───────┘                   │
 │                     │ Full Request              │ Range Request             │
 │                     ▼                           ▼                           │
 │             ┌───────────────┐           ┌───────────────┐                   │
 │             │   HTTP 200    │           │   HTTP 206    │                   │
 │             │  Full Content │           │Partial Content│                   │
 │             │  Sendfile/Read│           │ Seek Offset   │                   │
 │             └───────┬───────┘           └───────┬───────┘                   │
 │                     │                           │                           │
 │                     └─────────────┬─────────────┘                           │
 │                                   │                                         │
 │             ┌─────────────────────▼─────────────────────┐                   │
 │             │        Header Emission Pipeline           │                   │
 │             │  - Content-Type (from MIME table)         │                   │
 │             │  - Content-Length / Content-Range         │                   │
 │             │  - Cache-Control: max-age=31536000, public│                   │
 │             │  - Accept-Ranges: bytes                   │                   │
 │             │  - Access-Control-Allow-Origin: *         │                   │
 │             └─────────────────────┬─────────────────────┘                   │
 │                                   │                                         │
 │                                   ▼                                         │
 │                         High-Speed TCP Output                               │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Configuration Reference (cdn.cfg)

The configuration file is resolved dynamically at `storage/cdn/cdn.cfg` (or `arcore/storage/cdn/cdn.cfg`).

### Syntax

Configuration lines follow the format:
```ini
# Virtual path to physical file mapping:
/logo.png=/var/www/assets/logo.png
/videos/promo.mp4=/mnt/storage/media/promo.mp4
/bundle.js=/opt/alrios/build/bundle.js

# Key-value server settings:
port=3005
cache_ttl=31536000
```

---

## 4. Module Reference

### 4.1 CDN Server Core (cdn_server)

**File**: `src/cdn_server.c`

**Purpose**: The central event loop, TCP socket manager, HTTP 1.1 request parser, response writer, and IPC registration client.

#### Key Structs

```c
typedef struct {
    char path[256];     // Virtual URI path (e.g., "/media/banner.png")
    char file[1536];    // Absolute physical file path
} CdnEntry;
```

#### Core Constants

```c
#define APP_NAME         "cdn"
#define GATEWAY_HOST     "127.0.0.1"
#define GATEWAY_PORT     9500
#define MAX_ATTEMPTS     30
#define MAX_REQ          65536
#define MAX_ENTRIES      1024
#define MAX_CFG_LINE     2048
```

---

### 4.2 Routing & Virtual Path Mapping

ARCDN maintains an in-memory table of up to `MAX_ENTRIES` (1,024) mapped virtual paths:
- Exact path matching (e.g., `/favicon.ico` -> `/storage/cdn/favicon.ico`)
- Directory-based fallbacks
- Protected by thread-safe mutex `g_mutex`

---

### 4.3 Range Request Engine (HTTP 206)

For media playback (MP4, WebM), ARCDN parses the standard HTTP `Range` header:

```
Range: bytes=1048576-2097151
```

- If valid: Returns `HTTP/1.1 206 Partial Content` with `Content-Range: bytes 1048576-2097151/52428800`.
- If invalid (out of bounds): Returns `HTTP/1.1 416 Range Not Satisfiable`.
- Always emits `Accept-Ranges: bytes` allowing video players (HTML5 `<video>`) to seek smoothly without re-downloading entire files.

---

### 4.4 MIME Type Resolution

ARCDN embeds a zero-lookup MIME resolver matching file extensions:

| Extension | Content-Type |
|---|---|
| `.html`, `.htm` | `text/html; charset=utf-8` |
| `.css` | `text/css` |
| `.js`, `.mjs` | `application/javascript` |
| `.json` | `application/json` |
| `.png` | `image/png` |
| `.jpg`, `.jpeg` | `image/jpeg` |
| `.gif` | `image/gif` |
| `.svg` | `image/svg+xml` |
| `.ico` | `image/x-icon` |
| `.webp` | `image/webp` |
| `.avif` | `image/avif` |
| `.mp4` | `video/mp4` |
| `.webm` | `video/webm` |
| `.ogg` | `audio/ogg` |
| `.mp3` | `audio/mpeg` |
| `.pdf` | `application/pdf` |
| `.woff` | `font/woff` |
| `.woff2` | `font/woff2` |
| *fallback* | `application/octet-stream` |

---

### 4.5 Cache-Control & ETag Subsystem

Every asset served automatically receives immutable cache headers:
- `Cache-Control: public, max-age=31536000, immutable`
- `Access-Control-Allow-Origin: *` (CORS open for cross-domain static asset loading)
- `X-Content-Type-Options: nosniff`

---

### 4.6 Operating System HAL (os/linux & os/windows)

**Files**: `src/os/include/home_os.h`, `src/os/linux/net.c`, `src/os/windows/net.c`

**Purpose**: Wraps POSIX vs. WinSock network primitives, non-blocking socket creation, high-precision time, and file stat operations.

---

## 5. CLI Governance & IPC Commands

ARCDN listens for CLI control commands dispatched via `alrios cdn <command>`:

| Command | Description |
|---|---|
| `status` | Reports port, entry count, memory usage, and uptime |
| `routes` | Lists active hosts and gateway registration status |
| `list` | Displays all 1,024 mapped virtual path entries |
| `add <path> <file>` | Dynamically mounts a new static file route at runtime |
| `del <path>` | Unmounts a virtual path route |
| `ping` | Heartbeat health check returning `pong` |

---

## 6. Security Model & Defenses

1. **Path Traversal Blocking**: Any path containing `..`, `%2e%2e`, backslashes, or null bytes is immediately dropped with `400 Bad Request`.
2. **Read-Only Operation**: ARCDN has no POST, PUT, DELETE, or file-writing logic; it cannot be abused for file upload or arbitrary code execution.
3. **MIME Sniffing Prevention**: Emits `X-Content-Type-Options: nosniff` to prevent browsers from executing static media as scripts.
4. **CORS Safety**: Explicitly intended for public asset distribution; CORS is set to `*` to allow consumption from all ALRIOS web native applications.

---

## 7. Operational Guide

```bash
# Verify CDN daemon status
alrios cdn status

# List mapped assets
alrios cdn list

# Map a new asset on the fly
alrios cdn add /assets/banner.webp /home/alexsar/images/banner.webp

# Test range request with curl
curl -i -H "Range: bytes=0-1023" http://localhost:3005/videos/intro.mp4
```

---

## 8. Build & Packaging

### Compilation

```bash
cc -O2 \
  -Isrc -Isrc/os/include \
  -I../../ALRIOS/arkernel/include \
  -I../../ALRIOS/arkernel/os/include \
  -I../../ALRIOS/arkernel/ipc \
  -o $STAGING/cdn_web \
  src/cdn_server.c src/os/main.c ../../ALRIOS/arkernel/os/main.c \
  -lssl -lcrypto -lpthread
```

### .arapp Manifest (`arcdn.arappmake`)

```json
{
  "name": "arcdn",
  "version": "0.2.01",
  "runtime": "native",
  "entry": "cdn_web",
  "files": ["cdn_web"],
  "description": "Motor de Distribuicao Estatica e Streaming de Midia",
  "commands": ["status", "routes", "list", "add <path> <file>", "del <path>", "ping"]
}
```

---

*Document generated from source code analysis of ARCDN v0.2.01.*
*ALRI GROUP © 2026 — All rights reserved.*
*License: ARGLP (ALRI GROUP LICENSE PERMISSIVE — Version 2)*
