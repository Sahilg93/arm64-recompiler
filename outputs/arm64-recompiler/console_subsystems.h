/*
 * Core Windows OS Subsystem Engines natively targeting Apple Silicon ARM64.
 *
 * Engines:
 *   1. Unified Handle Table (Files, Console, Events, Mappings)
 *   2. Filesystem & Directory Traversal Engine (POSIX opendir/stat/fnmatch)
 *   3. Virtual Memory & Memory-Mapped File Engine (mmap/mprotect)
 *   4. Threading & Synchronization Engine (pthread/locks/events)
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/ioctl.h>

// Forward declarations of runtime helpers
void guest_store(uint64_t addr, uint64_t value, uint32_t width);
uint64_t guest_load(uint64_t addr, uint32_t width);
void *guest_pointer(uint64_t addr, uint32_t width);
unsigned char *guest_writable_span(uint64_t addr, uint64_t size);
void guest_set_last_error(uint32_t error);
uint64_t guest_get_last_error(void);
uint64_t guest_heap_alloc(uint64_t handle, uint32_t flags, uint64_t size);
uint64_t guest_heap_free(uint64_t handle, uint32_t flags, uint64_t address);

/* ========================================================================= */
/* 1. Path Normalization & Error Mapping                                     */
/* ========================================================================= */

static inline void set_win32_errno(int err) {
    switch (err) {
        case 0: guest_set_last_error(0); break;
        case ENOENT: guest_set_last_error(2); break;  // ERROR_FILE_NOT_FOUND
        case ENOTDIR: guest_set_last_error(3); break; // ERROR_PATH_NOT_FOUND
        case EACCES: guest_set_last_error(5); break;  // ERROR_ACCESS_DENIED
        case EEXIST: guest_set_last_error(80); break; // ERROR_FILE_EXISTS
        case EINVAL: guest_set_last_error(87); break; // ERROR_INVALID_PARAMETER
        default: guest_set_last_error(1); break;      // ERROR_INVALID_FUNCTION
    }
}

static inline void normalize_win_path_a(const char *in, char *out, size_t out_cap) {
    if (!in || !out || out_cap == 0) return;
    /* Skip extended length prefixes \\?\ or \??\ */
    if (strncmp(in, "\\\\?\\", 4) == 0 || strncmp(in, "\\??\\", 4) == 0)
        in += 4;
    // Skip Windows drive letters like C: or c:
    if (((in[0] >= 'a' && in[0] <= 'z') || (in[0] >= 'A' && in[0] <= 'Z')) && in[1] == ':') {
        in += 2;
    }
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_cap; ++i) {
        char c = in[i];
        if (c == '\\') c = '/';
        out[j++] = c;
    }
    out[j] = '\0';
}

static inline void normalize_win_path_w(uint64_t wstr_addr, char *out, size_t out_cap) {
    if (!wstr_addr || !out || out_cap == 0) return;
    char temp[1024] = {0};
    size_t i = 0;
    while (i + 1 < sizeof(temp)) {
        uint16_t ch = (uint16_t)guest_load(wstr_addr + i * 2, 2);
        if (!ch) break;
        temp[i] = (ch < 128) ? (char)ch : '_';
        i++;
    }
    temp[i] = '\0';
    normalize_win_path_a(temp, out, out_cap);
}

/* ========================================================================= */
/* 2. Unified Handle Table Engine                                            */
/* ========================================================================= */

enum HandleKind {
    HANDLE_KIND_FREE = 0,
    HANDLE_KIND_FILE,
    HANDLE_KIND_FIND,
    HANDLE_KIND_EVENT,
    HANDLE_KIND_MUTEX,
    HANDLE_KIND_MAPPING,
    HANDLE_KIND_THREAD,
    HANDLE_KIND_SOCKET,
    HANDLE_KIND_PROCESS
};

struct HandleEntry {
    enum HandleKind kind;
    int fd;
    DIR *dirp;
    char find_dir[1024];
    char find_pattern[256];
    bool manual_reset;
    bool signaled;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    void *map_ptr;
    size_t map_size;
    uint32_t map_protect;
    void *object;
    void (*release_object)(void *);
    uint64_t (*wait_object)(uint64_t, uint32_t);
};

#define MAX_HANDLES 1024
static struct HandleEntry g_handles[MAX_HANDLES];
static pthread_mutex_t g_handle_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_handles_initialized = false;

static void init_handle_table(void) {
    if (g_handles_initialized) return;
    pthread_mutex_lock(&g_handle_lock);
    if (!g_handles_initialized) {
        memset(g_handles, 0, sizeof(g_handles));
        // Standard handles at fixed slots:
        // 0 -> stdin (fd 0)
        g_handles[0].kind = HANDLE_KIND_FILE;
        g_handles[0].fd = 0;
        // 1 -> stdout (fd 1)
        g_handles[1].kind = HANDLE_KIND_FILE;
        g_handles[1].fd = 1;
        // 2 -> stderr (fd 2)
        g_handles[2].kind = HANDLE_KIND_FILE;
        g_handles[2].fd = 2;
        g_handles_initialized = true;
    }
    pthread_mutex_unlock(&g_handle_lock);
}

static uint64_t alloc_handle(enum HandleKind kind) {
    init_handle_table();
    pthread_mutex_lock(&g_handle_lock);
    for (size_t i = 3; i < MAX_HANDLES; ++i) {
        if (g_handles[i].kind == HANDLE_KIND_FREE) {
            memset(&g_handles[i], 0, sizeof(struct HandleEntry));
            g_handles[i].kind = kind;
            g_handles[i].fd = -1;
            pthread_mutex_init(&g_handles[i].mutex, NULL);
            pthread_cond_init(&g_handles[i].cond, NULL);
            pthread_mutex_unlock(&g_handle_lock);
            return (uint64_t)(0x1000 + i);
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return 0; // Out of handles
}

static struct HandleEntry *get_handle(uint64_t h) {
    init_handle_table();
    if (h == 0 || h == UINT64_MAX) return NULL;
    // Map standard Windows handles
    if (h == (uint64_t)(uint32_t)-10) return &g_handles[0]; // STD_INPUT_HANDLE
    if (h == (uint64_t)(uint32_t)-11) return &g_handles[1]; // STD_OUTPUT_HANDLE
    if (h == (uint64_t)(uint32_t)-12) return &g_handles[2]; // STD_ERROR_HANDLE
    // Map legacy console runtime handles
    if (h == 1 || h == (0x7fff0000 | 1)) return &g_handles[1];
    if (h == 2) return &g_handles[2];

    if (h >= 0x1000 && h < 0x1000 + MAX_HANDLES) {
        size_t idx = (size_t)(h - 0x1000);
        if (g_handles[idx].kind != HANDLE_KIND_FREE)
            return &g_handles[idx];
    }
    return NULL;
}

uint64_t guest_close_handle_unified(uint64_t handle) {
    init_handle_table();
    if (!handle || handle == UINT64_MAX) return 0;
    if (handle >= 0x7fff0000 && handle <= 0x7fffffff) return 1;
    if (handle >= (uint64_t)(uint32_t)-12 && handle <= (uint64_t)(uint32_t)-10) return 1; // don't close stdio

    pthread_mutex_lock(&g_handle_lock);
    if (handle >= 0x1000 && handle < 0x1000 + MAX_HANDLES) {
        size_t idx = (size_t)(handle - 0x1000);
        struct HandleEntry *e = &g_handles[idx];
        if (e->kind != HANDLE_KIND_FREE) {
            if (e->fd >= 0 && e->fd > 2) close(e->fd);
            if (e->dirp) closedir(e->dirp);
            if (e->release_object) e->release_object(e->object);
            if (e->map_ptr && e->map_size) munmap(e->map_ptr, e->map_size);
            pthread_mutex_destroy(&e->mutex);
            pthread_cond_destroy(&e->cond);
            memset(e, 0, sizeof(*e));
            pthread_mutex_unlock(&g_handle_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return 1;
}

/* ========================================================================= */
/* 3. File I/O Engine (CreateFile, ReadFile, WriteFile, SetFilePointer, etc.) */
/* ========================================================================= */

uint64_t subsys_CreateFileA(uint64_t lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode,
                           uint64_t lpSecurity, uint32_t dwCreationDisposition, uint32_t dwFlags, uint64_t hTemplate) {
    (void)dwShareMode; (void)lpSecurity; (void)dwFlags; (void)hTemplate;
    char path_buf[1024];
    const char *raw_name = (const char *)guest_pointer(lpFileName, 1);
    normalize_win_path_a(raw_name ? raw_name : "", path_buf, sizeof(path_buf));

    int flags = 0;
    bool read = (dwDesiredAccess & 0x80000000u) != 0;
    bool write = (dwDesiredAccess & 0x40000000u) != 0;
    if (read && write) flags = O_RDWR;
    else if (write) flags = O_WRONLY;
    else flags = O_RDONLY;

    switch (dwCreationDisposition) {
        case 1: flags |= (O_CREAT | O_EXCL); break;   // CREATE_NEW
        case 2: flags |= (O_CREAT | O_TRUNC); break;  // CREATE_ALWAYS
        case 3: break;                                 // OPEN_EXISTING
        case 4: flags |= O_CREAT; break;              // OPEN_ALWAYS
        case 5: flags |= O_TRUNC; break;              // TRUNCATE_EXISTING
        default: break;
    }

    int fd = open(path_buf, flags, 0666);
    if (fd < 0) {
        set_win32_errno(errno);
        return (uint64_t)(int64_t)-1;
    }

    uint64_t h = alloc_handle(HANDLE_KIND_FILE);
    struct HandleEntry *e = get_handle(h);
    if (e) e->fd = fd;
    guest_set_last_error(0);
    return h;
}

uint64_t subsys_CreateFileW(uint64_t lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode,
                           uint64_t lpSecurity, uint32_t dwCreationDisposition, uint32_t dwFlags, uint64_t hTemplate) {
    char path_buf[1024];
    normalize_win_path_w(lpFileName, path_buf, sizeof(path_buf));
    uint64_t name_addr = guest_heap_alloc(0x7fff2001, 0, strlen(path_buf) + 1);
    if (name_addr) {
        char *p = (char *)guest_pointer(name_addr, 1);
        if (p) strcpy(p, path_buf);
    }
    uint64_t res = subsys_CreateFileA(name_addr, dwDesiredAccess, dwShareMode, lpSecurity, dwCreationDisposition, dwFlags, hTemplate);
    if (name_addr) guest_heap_free(0x7fff2001, 0, name_addr);
    return res;
}

uint64_t subsys_ReadFile(uint64_t hFile, uint64_t lpBuffer, uint32_t nNumberOfBytesToRead,
                        uint64_t lpNumberOfBytesRead, uint64_t lpOverlapped) {
    (void)lpOverlapped;
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->kind != HANDLE_KIND_FILE || e->fd < 0) {
        guest_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    void *buf = nNumberOfBytesToRead ? guest_writable_span(lpBuffer, nNumberOfBytesToRead) : NULL;
    if (!buf && nNumberOfBytesToRead) {
        guest_set_last_error(87);
        return 0;
    }
    ssize_t bytes = nNumberOfBytesToRead ? read(e->fd, buf, nNumberOfBytesToRead) : 0;
    if (bytes < 0) {
        set_win32_errno(errno);
        return 0;
    }
    if (lpNumberOfBytesRead)
        guest_store(lpNumberOfBytesRead, (uint64_t)bytes, 4);
    guest_set_last_error(0);
    return 1;
}

uint64_t subsys_GetFileInformationByHandle(uint64_t handle, uint64_t output) {
    struct HandleEntry *entry = get_handle(handle);
    if (!entry || entry->kind != HANDLE_KIND_FILE || entry->fd < 0) {
        guest_set_last_error(6);
        return 0;
    }
    if (!output) {
        guest_set_last_error(87);
        return 0;
    }
    struct stat st;
    if (fstat(entry->fd, &st) != 0) {
        set_win32_errno(errno);
        return 0;
    }

    guest_store(output, S_ISDIR(st.st_mode) ? 0x10 : 0x80, 4);
    const time_t times[] = {st.st_birthtime, st.st_atime, st.st_mtime};
    for (size_t i = 0; i < sizeof times / sizeof *times; ++i)
        guest_store(output + 4 + 8 * i, ((uint64_t)times[i] + 11644473600ULL) * 10000000ULL, 8);
    guest_store(output + 28, (uint32_t)st.st_dev, 4);
    guest_store(output + 32, (uint64_t)st.st_size >> 32, 4);
    guest_store(output + 36, (uint32_t)st.st_size, 4);
    guest_store(output + 40, (uint32_t)st.st_nlink, 4);
    guest_store(output + 44, (uint64_t)st.st_ino >> 32, 4);
    guest_store(output + 48, (uint32_t)st.st_ino, 4);
    return 1;
}

uint64_t subsys_SetFilePointer(uint64_t hFile, int32_t lDistanceToMove, uint64_t lpDistanceToMoveHigh, uint32_t dwMoveMethod) {
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->kind != HANDLE_KIND_FILE || e->fd < 0) {
        guest_set_last_error(6);
        return (uint32_t)-1;
    }
    int64_t dist = (int64_t)lDistanceToMove;
    if (lpDistanceToMoveHigh) {
        uint32_t hi = (uint32_t)guest_load(lpDistanceToMoveHigh, 4);
        dist |= ((int64_t)hi << 32);
    }
    int whence = (dwMoveMethod == 1) ? SEEK_CUR : (dwMoveMethod == 2) ? SEEK_END : SEEK_SET;
    off_t pos = lseek(e->fd, (off_t)dist, whence);
    if (pos == (off_t)-1) {
        set_win32_errno(errno);
        return (uint32_t)-1;
    }
    if (lpDistanceToMoveHigh) {
        guest_store(lpDistanceToMoveHigh, (uint64_t)(pos >> 32), 4);
    }
    guest_set_last_error(0);
    return (uint32_t)pos;
}

uint64_t subsys_SetFilePointerEx(uint64_t hFile, int64_t liDistanceToMove, uint64_t lpNewFilePointer, uint32_t dwMoveMethod) {
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->kind != HANDLE_KIND_FILE || e->fd < 0) {
        guest_set_last_error(6);
        return 0;
    }
    int whence = (dwMoveMethod == 1) ? SEEK_CUR : (dwMoveMethod == 2) ? SEEK_END : SEEK_SET;
    off_t pos = lseek(e->fd, (off_t)liDistanceToMove, whence);
    if (pos == (off_t)-1) {
        set_win32_errno(errno);
        return 0;
    }
    if (lpNewFilePointer) {
        guest_store(lpNewFilePointer, (uint64_t)pos, 8);
    }
    guest_set_last_error(0);
    return 1;
}

uint64_t subsys_GetFileSize(uint64_t hFile, uint64_t lpFileSizeHigh) {
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->kind != HANDLE_KIND_FILE || e->fd < 0) {
        guest_set_last_error(6);
        return (uint32_t)-1;
    }
    struct stat st;
    if (fstat(e->fd, &st) != 0) {
        set_win32_errno(errno);
        return (uint32_t)-1;
    }
    if (lpFileSizeHigh) {
        guest_store(lpFileSizeHigh, (uint64_t)(st.st_size >> 32), 4);
    }
    guest_set_last_error(0);
    return (uint32_t)st.st_size;
}

uint64_t subsys_GetFileSizeEx(uint64_t hFile, uint64_t lpFileSize) {
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->kind != HANDLE_KIND_FILE || e->fd < 0) {
        guest_set_last_error(6);
        return 0;
    }
    struct stat st;
    if (fstat(e->fd, &st) != 0) {
        set_win32_errno(errno);
        return 0;
    }
    if (lpFileSize) {
        guest_store(lpFileSize, (uint64_t)st.st_size, 8);
    }
    guest_set_last_error(0);
    return 1;
}

uint64_t subsys_FlushFileBuffers(uint64_t hFile) {
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->kind != HANDLE_KIND_FILE || e->fd < 0) return 0;
    fsync(e->fd);
    return 1;
}

uint64_t subsys_DuplicateHandle(uint64_t hSourceProcess, uint64_t hSourceHandle,
                               uint64_t hTargetProcess, uint64_t lpTargetHandle,
                               uint32_t dwDesiredAccess, uint32_t bInheritHandle, uint32_t dwOptions) {
    (void)hSourceProcess; (void)hTargetProcess; (void)dwDesiredAccess; (void)bInheritHandle; (void)dwOptions;
    enum HandleKind kind = HANDLE_KIND_FILE;
    if (hSourceHandle == (uint64_t)-2 || (int64_t)hSourceHandle == -2) {
        kind = HANDLE_KIND_THREAD;
    } else if (hSourceHandle == (uint64_t)-1 || (int64_t)hSourceHandle == -1) {
        kind = HANDLE_KIND_PROCESS;
    } else {
        struct HandleEntry *src = get_handle(hSourceHandle);
        if (src) kind = src->kind;
    }
    uint64_t new_h = alloc_handle(kind);
    struct HandleEntry *src = get_handle(hSourceHandle);
    struct HandleEntry *dst = get_handle(new_h);
    if (dst) {
        dst->fd = (src && src->fd >= 0) ? dup(src->fd) : -1;
    }
    if (lpTargetHandle) guest_store(lpTargetHandle, new_h, 8);
    return 1;
}

/* ========================================================================= */
/* 4. Filesystem & Directory Traversal Engine                                 */
/* ========================================================================= */

uint64_t subsys_GetFileAttributesA(uint64_t lpFileName) {
    char path_buf[1024];
    const char *raw = (const char *)guest_pointer(lpFileName, 1);
    normalize_win_path_a(raw ? raw : "", path_buf, sizeof(path_buf));
    struct stat st;
    if (stat(path_buf, &st) != 0) {
        set_win32_errno(errno);
        return (uint32_t)-1; // INVALID_FILE_ATTRIBUTES
    }
    uint32_t attr = S_ISDIR(st.st_mode) ? 0x10 : 0x80; // FILE_ATTRIBUTE_DIRECTORY / NORMAL
    return attr;
}

uint64_t subsys_GetFileAttributesW(uint64_t lpFileName) {
    char path_buf[1024];
    normalize_win_path_w(lpFileName, path_buf, sizeof(path_buf));
    struct stat st;
    if (stat(path_buf, &st) != 0) {
        set_win32_errno(errno);
        return (uint32_t)-1;
    }
    return S_ISDIR(st.st_mode) ? 0x10 : 0x80;
}

uint64_t subsys_DeleteFileA(uint64_t lpFileName) {
    char path[1024];
    const char *raw = (const char *)guest_pointer(lpFileName, 1);
    normalize_win_path_a(raw ? raw : "", path, sizeof(path));
    if (unlink(path) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_DeleteFileW(uint64_t lpFileName) {
    char path[1024];
    normalize_win_path_w(lpFileName, path, sizeof(path));
    if (unlink(path) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_CreateDirectoryA(uint64_t lpPathName, uint64_t lpSecurity) {
    (void)lpSecurity;
    char path[1024];
    const char *raw = (const char *)guest_pointer(lpPathName, 1);
    normalize_win_path_a(raw ? raw : "", path, sizeof(path));
    if (mkdir(path, 0755) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_CreateDirectoryW(uint64_t lpPathName, uint64_t lpSecurity) {
    (void)lpSecurity;
    char path[1024];
    normalize_win_path_w(lpPathName, path, sizeof(path));
    if (mkdir(path, 0755) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_RemoveDirectoryA(uint64_t lpPathName) {
    char path[1024];
    const char *raw = (const char *)guest_pointer(lpPathName, 1);
    normalize_win_path_a(raw ? raw : "", path, sizeof(path));
    if (rmdir(path) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_RemoveDirectoryW(uint64_t lpPathName) {
    char path[1024];
    normalize_win_path_w(lpPathName, path, sizeof(path));
    if (rmdir(path) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_GetCurrentDirectoryA(uint32_t nBufferLength, uint64_t lpBuffer) {
    char buf[1024];
    if (!getcwd(buf, sizeof(buf))) return 0;
    size_t len = strlen(buf);
    if (nBufferLength > len && lpBuffer) {
        char *out = (char *)guest_pointer(lpBuffer, len + 1);
        if (out) strcpy(out, buf);
    }
    return (uint32_t)len;
}

uint64_t subsys_GetCurrentDirectoryW(uint32_t nBufferLength, uint64_t lpBuffer) {
    char buf[1024];
    if (!getcwd(buf, sizeof(buf))) return 0;
    size_t len = strlen(buf);
    if (nBufferLength > len && lpBuffer) {
        for (size_t i = 0; i <= len; ++i)
            guest_store(lpBuffer + i * 2, (uint16_t)buf[i], 2);
    }
    return (uint32_t)len;
}

// The console filesystem models the host root as the guest's C: drive.
uint64_t subsys_GetFullPathNameW(uint64_t input, uint32_t capacity,
                                 uint64_t output, uint64_t file_part) {
    uint16_t source[PATH_MAX], path[PATH_MAX];
    size_t length = 0;
    if (!input || !guest_load(input, 2)) {
        guest_set_last_error(123);
        return 0;
    }
    while (length < PATH_MAX) {
        uint16_t unit = (uint16_t)guest_load(input + length * 2, 2);
        if (!unit)
            break;
        source[length++] = unit == '/' ? '\\' : unit;
    }
    if (length == PATH_MAX)
        goto too_long;

    size_t start = 0, used = 3;
    path[0] = 'C';
    path[1] = ':';
    path[2] = '\\';
    if (length > 1 && source[1] == ':') {
        if (source[0] != 'C' && source[0] != 'c') {
            guest_set_last_error(15);
            return 0;
        }
        start = 2;
    }
    if (length - start > 1 && source[start] == '\\' && source[start + 1] == '\\') {
        guest_set_last_error(123);
        return 0;
    }
    if (start == length || source[start] != '\\') {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof cwd)) {
            set_win32_errno(errno);
            return 0;
        }
        for (size_t i = 1; cwd[i]; ++i) {
            if (used == PATH_MAX - 1)
                goto too_long;
            if ((unsigned char)cwd[i] >= 128) {
                guest_set_last_error(1113);
                return 0;
            }
            path[used++] = cwd[i] == '/' ? '\\' : (unsigned char)cwd[i];
        }
    }
    while (start < length) {
        while (start < length && source[start] == '\\')
            ++start;
        size_t end = start;
        while (end < length && source[end] != '\\')
            ++end;
        size_t count = end - start;
        if (!count)
            break;
        if (count == 2 && source[start] == '.' && source[start + 1] == '.') {
            while (used > 3 && path[used - 1] != '\\')
                --used;
            if (used > 3)
                --used;
        } else if (count != 1 || source[start] != '.') {
            if (used + count + (used > 3) >= PATH_MAX)
                goto too_long;
            if (used > 3)
                path[used++] = '\\';
            memcpy(path + used, source + start, count * sizeof *path);
            used += count;
        }
        start = end;
    }
    if (source[length - 1] == '\\' && used > 3) {
        if (used == PATH_MAX - 1)
            goto too_long;
        path[used++] = '\\';
    }
    if (!output || capacity <= used)
        return used + 1;
    for (size_t i = 0; i < used; ++i)
        guest_store(output + i * 2, path[i], 2);
    guest_store(output + used * 2, 0, 2);
    if (file_part) {
        size_t i = used;
        while (path[i - 1] != '\\')
            --i;
        guest_store(file_part, i == used ? 0 : output + i * 2, 8);
    }
    return used;

too_long:
    guest_set_last_error(206);
    return 0;
}

uint64_t subsys_GetFinalPathNameByHandleW(uint64_t hFile, uint64_t lpszFilePath, uint32_t cchFilePath, uint32_t dwFlags) {
    (void)dwFlags;
    struct HandleEntry *e = get_handle(hFile);
    if (!e || e->fd < 0) {
        guest_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    char posix_path[MAXPATHLEN];
    char win_path[MAXPATHLEN + 16];
    if (fcntl(e->fd, F_GETPATH, posix_path) < 0) {
        snprintf(win_path, sizeof(win_path), "\\\\?\\C:\\dev\\fd%d", e->fd);
    } else {
        snprintf(win_path, sizeof(win_path), "\\\\?\\C:%s", posix_path);
        for (char *p = win_path; *p; ++p) {
            if (*p == '/') *p = '\\';
        }
    }
    size_t len = strlen(win_path);
    size_t required = len + 1;
    if (!lpszFilePath || cchFilePath < required) {
        guest_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER (0x7a)
        return (uint64_t)required;
    }
    for (size_t i = 0; i <= len; ++i) {
        guest_store(lpszFilePath + i * 2, (uint16_t)(unsigned char)win_path[i], 2);
    }
    guest_set_last_error(0);
    return (uint64_t)len;
}

uint64_t subsys_SetCurrentDirectoryA(uint64_t lpPathName) {
    char path[1024];
    const char *raw = (const char *)guest_pointer(lpPathName, 1);
    normalize_win_path_a(raw ? raw : "", path, sizeof(path));
    if (chdir(path) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_SetCurrentDirectoryW(uint64_t lpPathName) {
    char path[1024];
    normalize_win_path_w(lpPathName, path, sizeof(path));
    if (chdir(path) == 0) return 1;
    set_win32_errno(errno);
    return 0;
}

uint64_t subsys_GetTempPathA(uint32_t nBufferLength, uint64_t lpBuffer) {
    const char *tmp = "/tmp/";
    size_t len = strlen(tmp);
    if (nBufferLength > len && lpBuffer) {
        char *out = (char *)guest_pointer(lpBuffer, len + 1);
        if (out) strcpy(out, tmp);
    }
    return (uint32_t)len;
}

uint64_t subsys_GetTempPathW(uint32_t nBufferLength, uint64_t lpBuffer) {
    const char *tmp = "/tmp/";
    size_t len = strlen(tmp);
    if (nBufferLength > len && lpBuffer) {
        for (size_t i = 0; i <= len; ++i)
            guest_store(lpBuffer + i * 2, (uint16_t)tmp[i], 2);
    }
    return (uint32_t)len;
}

/* FindFirstFileW / FindNextFileW Implementation */
static bool fill_find_data_w(uint64_t lpFindFileData, const char *full_path, const char *file_name) {
    struct stat st;
    if (stat(full_path, &st) != 0) return false;

    // WIN32_FIND_DATAW layout:
    // 0: dwFileAttributes (4)
    // 4: ftCreationTime (8)
    // 12: ftLastAccessTime (8)
    // 20: ftLastWriteTime (8)
    // 28: nFileSizeHigh (4)
    // 32: nFileSizeLow (4)
    // 36: dwReserved0 (4)
    // 40: dwReserved1 (4)
    // 44: cFileName (WCHAR[260] = 520)
    // 564: cAlternateFileName (WCHAR[14] = 28)
    uint32_t attr = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
    guest_store(lpFindFileData, attr, 4);

    // Convert UNIX epoch to Windows 100ns FILETIME (epoch 1601)
    uint64_t ft = ((uint64_t)st.st_mtime + 11644473600ULL) * 10000000ULL;
    guest_store(lpFindFileData + 4, ft, 8);
    guest_store(lpFindFileData + 12, ft, 8);
    guest_store(lpFindFileData + 20, ft, 8);

    guest_store(lpFindFileData + 28, (uint64_t)(st.st_size >> 32), 4);
    guest_store(lpFindFileData + 32, (uint64_t)(st.st_size & 0xffffffff), 4);

    // Store cFileName as UTF-16
    size_t name_len = strlen(file_name);
    if (name_len > 259) name_len = 259;
    for (size_t i = 0; i < name_len; ++i)
        guest_store(lpFindFileData + 44 + i * 2, (uint16_t)file_name[i], 2);
    guest_store(lpFindFileData + 44 + name_len * 2, 0, 2);

    return true;
}

uint64_t subsys_FindFirstFileW(uint64_t lpFileName, uint64_t lpFindFileData) {
    char norm_path[1024];
    normalize_win_path_w(lpFileName, norm_path, sizeof(norm_path));

    char dir_part[1024] = ".", pat_part[256] = "*";
    char *slash = strrchr(norm_path, '/');
    if (slash) {
        *slash = '\0';
        strncpy(dir_part, norm_path, sizeof(dir_part) - 1);
        strncpy(pat_part, slash + 1, sizeof(pat_part) - 1);
    } else {
        strncpy(pat_part, norm_path, sizeof(pat_part) - 1);
    }

    DIR *d = opendir(dir_part);
    if (!d) {
        set_win32_errno(errno);
        return (uint64_t)(int64_t)-1; // INVALID_HANDLE_VALUE
    }

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (fnmatch(pat_part, de->d_name, 0) == 0) {
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", dir_part, de->d_name);
            if (fill_find_data_w(lpFindFileData, full, de->d_name)) {
                uint64_t h = alloc_handle(HANDLE_KIND_FIND);
                struct HandleEntry *e = get_handle(h);
                if (e) {
                    e->dirp = d;
                    strncpy(e->find_dir, dir_part, sizeof(e->find_dir) - 1);
                    strncpy(e->find_pattern, pat_part, sizeof(e->find_pattern) - 1);
                }
                guest_set_last_error(0);
                return h;
            }
        }
    }

    closedir(d);
    guest_set_last_error(2); // ERROR_FILE_NOT_FOUND
    return (uint64_t)(int64_t)-1;
}

uint64_t subsys_FindNextFileW(uint64_t hFindFile, uint64_t lpFindFileData) {
    struct HandleEntry *e = get_handle(hFindFile);
    if (!e || e->kind != HANDLE_KIND_FIND || !e->dirp) {
        guest_set_last_error(6);
        return 0;
    }

    struct dirent *de;
    while ((de = readdir(e->dirp)) != NULL) {
        if (fnmatch(e->find_pattern, de->d_name, 0) == 0) {
            char full[1024];
            snprintf(full, sizeof(full), "%s/%s", e->find_dir, de->d_name);
            if (fill_find_data_w(lpFindFileData, full, de->d_name)) {
                guest_set_last_error(0);
                return 1;
            }
        }
    }
    guest_set_last_error(18); // ERROR_NO_MORE_FILES
    return 0;
}

uint64_t subsys_FindClose(uint64_t hFindFile) {
    return guest_close_handle_unified(hFindFile);
}

/* ========================================================================= */
/* 5. Virtual Memory & Memory-Mapped File Engine                             */
/* ========================================================================= */

/*
 * VirtualAlloc returns raw host mmap addresses (zero tag). The guest uses them
 * directly, so each region is recorded here: guest memory accesses resolve the
 * address through subsys_mapping_span and perform the host copy with the
 * fault signal armed. Pages left PROT_NONE (reserved, decommitted or
 * PAGE_NOACCESS) or PROT_READ then raise SIGSEGV/SIGBUS, which the runtime
 * delivers to guest VEH/SEH handlers as EXCEPTION_ACCESS_VIOLATION.
 */
#define MAX_VM_REGIONS 1024
struct VmRegion {
    uintptr_t base;
    size_t size;
};
static struct VmRegion g_vm_regions[MAX_VM_REGIONS];
static size_t g_vm_region_count;
static pthread_mutex_t g_vm_lock = PTHREAD_MUTEX_INITIALIZER;

static int subsys_win32_prot(uint32_t protect) {
    switch (protect & 0xff) {
    case 0x01: return PROT_NONE;
    case 0x02: return PROT_READ;
    case 0x04: case 0x08: return PROT_READ | PROT_WRITE;
    case 0x10: return PROT_READ | PROT_EXEC;
    case 0x20: return PROT_READ | PROT_EXEC;
    case 0x40: case 0x80: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default: return -1;
    }
}

static size_t subsys_page_size(void) {
    return (size_t)sysconf(_SC_PAGESIZE);
}

/* Caller holds g_vm_lock. */
static struct VmRegion *subsys_vm_region(uintptr_t addr, size_t size) {
    for (size_t i = 0; i < g_vm_region_count; ++i) {
        struct VmRegion *r = &g_vm_regions[i];
        if (addr >= r->base && size <= r->size && addr - r->base <= r->size - size)
            return r;
    }
    return NULL;
}

/* Per-page Windows protection, kept beside each region for VirtualProtect's old value. */
struct VmProtect {
    uintptr_t page;
    uint32_t protect;
};
static struct VmProtect *g_vm_protect;
static size_t g_vm_protect_count, g_vm_protect_capacity;

/* Caller holds g_vm_lock. */
static uint32_t subsys_vm_get_protect(uintptr_t page) {
    for (size_t i = 0; i < g_vm_protect_count; ++i)
        if (g_vm_protect[i].page == page)
            return g_vm_protect[i].protect;
    return 0x01;
}

/* Caller holds g_vm_lock. A protection of zero forgets the page. */
static bool subsys_vm_set_protect(uintptr_t start, uintptr_t end, uint32_t protect) {
    size_t page_size = subsys_page_size();
    for (uintptr_t page = start; page < end; page += page_size) {
        size_t i = 0;
        while (i < g_vm_protect_count && g_vm_protect[i].page != page)
            ++i;
        if (!protect) {
            if (i < g_vm_protect_count)
                g_vm_protect[i] = g_vm_protect[--g_vm_protect_count];
            continue;
        }
        if (i == g_vm_protect_count) {
            if (g_vm_protect_count == g_vm_protect_capacity) {
                size_t capacity = g_vm_protect_capacity ? g_vm_protect_capacity * 2 : 256;
                struct VmProtect *grown = realloc(g_vm_protect, capacity * sizeof *grown);
                if (!grown)
                    return false;
                g_vm_protect = grown;
                g_vm_protect_capacity = capacity;
            }
            g_vm_protect[g_vm_protect_count++].page = page;
        }
        g_vm_protect[i].protect = protect;
    }
    return true;
}

unsigned char *subsys_mapping_span(uint64_t addr, uint64_t size) {
    pthread_mutex_lock(&g_vm_lock);
    bool region = subsys_vm_region((uintptr_t)addr, (size_t)size) != NULL;
    pthread_mutex_unlock(&g_vm_lock);
    if (region)
        return (unsigned char *)(uintptr_t)addr;
    pthread_mutex_lock(&g_handle_lock);
    for (size_t i = 0; i < MAX_HANDLES; ++i) {
        if (g_handles[i].kind == HANDLE_KIND_MAPPING && g_handles[i].map_ptr) {
            uintptr_t base = (uintptr_t)g_handles[i].map_ptr;
            size_t sz = g_handles[i].map_size;
            if (addr >= base && (addr + size) <= (base + sz)) {
                pthread_mutex_unlock(&g_handle_lock);
                return (unsigned char *)(uintptr_t)addr;
            }
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    return NULL;
}

uint64_t subsys_VirtualAlloc(uint64_t lpAddress, uint64_t dwSize, uint32_t flAllocationType, uint32_t flProtect) {
    const uint32_t mem_commit = 0x1000, mem_reserve = 0x2000;
    int prot = subsys_win32_prot(flProtect);
    if (!dwSize || prot < 0 || !(flAllocationType & (mem_commit | mem_reserve))) {
        guest_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    size_t page_size = subsys_page_size();
    uintptr_t start = (uintptr_t)lpAddress & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)lpAddress + dwSize + page_size - 1) & ~(page_size - 1);
    bool commit = (flAllocationType & mem_commit) != 0;

    pthread_mutex_lock(&g_vm_lock);
    if (lpAddress) {
        struct VmRegion *region = subsys_vm_region(start, end - start);
        if (region) {
            /* MEM_COMMIT inside a reservation changes protection without discarding data. */
            if (!commit || mprotect((void *)start, end - start, prot) ||
                !subsys_vm_set_protect(start, end, flProtect & 0xff)) {
                pthread_mutex_unlock(&g_vm_lock);
                guest_set_last_error(487); // ERROR_INVALID_ADDRESS
                return 0;
            }
            pthread_mutex_unlock(&g_vm_lock);
            guest_set_last_error(0);
            return start;
        }
    }
    if (g_vm_region_count == MAX_VM_REGIONS) {
        pthread_mutex_unlock(&g_vm_lock);
        guest_set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
        return 0;
    }
    size_t sz = end - start;
    if (!lpAddress)
        sz = (dwSize + page_size - 1) & ~(page_size - 1);
    /* Never MAP_FIXED: a guest hint must not replace host mappings. */
    void *ptr = mmap(lpAddress ? (void *)start : NULL, sz, commit ? prot : PROT_NONE,
                     MAP_ANON | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED) {
        pthread_mutex_unlock(&g_vm_lock);
        guest_set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
        return 0;
    }
    if (lpAddress && (uintptr_t)ptr != start) {
        munmap(ptr, sz);
        pthread_mutex_unlock(&g_vm_lock);
        guest_set_last_error(487); // ERROR_INVALID_ADDRESS
        return 0;
    }
    if (commit && !subsys_vm_set_protect((uintptr_t)ptr, (uintptr_t)ptr + sz, flProtect & 0xff)) {
        munmap(ptr, sz);
        pthread_mutex_unlock(&g_vm_lock);
        guest_set_last_error(8);
        return 0;
    }
    g_vm_regions[g_vm_region_count++] = (struct VmRegion){(uintptr_t)ptr, sz};
    pthread_mutex_unlock(&g_vm_lock);
    guest_set_last_error(0);
    return (uint64_t)(uintptr_t)ptr;
}

uint64_t subsys_VirtualFree(uint64_t lpAddress, uint64_t dwSize, uint32_t dwFreeType) {
    const uint32_t mem_decommit = 0x4000, mem_release = 0x8000;
    if (!lpAddress || (dwFreeType != mem_decommit && dwFreeType != mem_release)) {
        guest_set_last_error(87);
        return 0;
    }
    size_t page_size = subsys_page_size();
    pthread_mutex_lock(&g_vm_lock);
    for (size_t i = 0; i < g_vm_region_count; ++i) {
        struct VmRegion *region = &g_vm_regions[i];
        if (dwFreeType == mem_release) {
            /* Windows requires dwSize == 0 here; earlier shims ignored it, so stay lenient. */
            if (region->base != (uintptr_t)lpAddress)
                continue;
            subsys_vm_set_protect(region->base, region->base + region->size, 0);
            munmap((void *)region->base, region->size);
            g_vm_regions[i] = g_vm_regions[--g_vm_region_count];
            pthread_mutex_unlock(&g_vm_lock);
            guest_set_last_error(0);
            return 1;
        }
        uintptr_t start = (uintptr_t)lpAddress & ~(page_size - 1);
        uintptr_t end = dwSize ? (((uintptr_t)lpAddress + dwSize + page_size - 1) & ~(page_size - 1))
                               : region->base + region->size;
        if (start < region->base || end > region->base + region->size || end <= start)
            continue;
        /* Decommit: drop the contents and leave the pages reserved (PROT_NONE). */
        void *fresh = mmap((void *)start, end - start, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
        subsys_vm_set_protect(start, end, 0);
        pthread_mutex_unlock(&g_vm_lock);
        if (fresh == MAP_FAILED) {
            set_win32_errno(errno);
            return 0;
        }
        guest_set_last_error(0);
        return 1;
    }
    pthread_mutex_unlock(&g_vm_lock);
    guest_set_last_error(487); // ERROR_INVALID_ADDRESS
    return 0;
}

/*
 * VirtualProtect for VirtualAlloc regions. Returns false when the range is not
 * one of them so the caller can try image sections.
 */
bool subsys_vm_protect(uint64_t address, uint64_t size, uint32_t protect, uint32_t *old, bool *ok) {
    size_t page_size = subsys_page_size();
    uintptr_t start = (uintptr_t)address & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)address + (size ? size : 1) + page_size - 1) & ~(page_size - 1);
    pthread_mutex_lock(&g_vm_lock);
    if (!subsys_vm_region(start, end - start)) {
        pthread_mutex_unlock(&g_vm_lock);
        return false;
    }
    int prot = subsys_win32_prot(protect);
    *old = subsys_vm_get_protect(start);
    *ok = false;
    if (prot < 0)
        guest_set_last_error(87);
    else if (mprotect((void *)start, end - start, prot) || !subsys_vm_set_protect(start, end, protect & 0xff))
        set_win32_errno(errno);
    else {
        guest_set_last_error(0);
        *ok = true;
    }
    pthread_mutex_unlock(&g_vm_lock);
    return true;
}

uint64_t subsys_CreateFileMappingW(uint64_t hFile, uint64_t lpAttributes, uint32_t flProtect,
                                  uint32_t dwMaximumSizeHigh, uint32_t dwMaximumSizeLow, uint64_t lpName) {
    (void)lpAttributes; (void)lpName;
    uint64_t sz = ((uint64_t)dwMaximumSizeHigh << 32) | dwMaximumSizeLow;
    int fd = -1;

    if (hFile != (uint64_t)-1 && hFile != 0xffffffff && hFile != 0) {
        struct HandleEntry *src = get_handle(hFile);
        if (!src || src->kind != HANDLE_KIND_FILE) {
            guest_set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        }
        fd = dup(src->fd);
        if (!sz) {
            struct stat st;
            if (fstat(src->fd, &st) == 0) sz = (uint64_t)st.st_size;
        }
    }

    if (!sz && fd < 0) {
        guest_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    uint64_t h = alloc_handle(HANDLE_KIND_MAPPING);
    struct HandleEntry *map = get_handle(h);
    if (map) {
        map->fd = fd;
        map->map_size = (size_t)sz;
        map->map_protect = flProtect ? flProtect : 0x04;
    }
    guest_set_last_error(0);
    return h;
}

uint64_t subsys_MapViewOfFileEx(uint64_t hFileMappingObject, uint32_t dwDesiredAccess,
                                uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow,
                                uint64_t dwNumberOfBytesToMap, uint64_t lpBaseAddress) {
    struct HandleEntry *e = get_handle(hFileMappingObject);
    if (!e || e->kind != HANDLE_KIND_MAPPING) {
        guest_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }

    size_t sz = dwNumberOfBytesToMap ? (size_t)dwNumberOfBytesToMap : e->map_size;
    off_t off = (off_t)(((uint64_t)dwFileOffsetHigh << 32) | dwFileOffsetLow);

    int prot = PROT_READ | PROT_WRITE;
    if (dwDesiredAccess == 4) { // FILE_MAP_READ
        prot = PROT_READ;
    }

    int flags = (dwDesiredAccess == 1 ? MAP_PRIVATE : MAP_SHARED); // FILE_MAP_COPY
    void *hint = lpBaseAddress ? (void *)(uintptr_t)lpBaseAddress : NULL;
    if (hint) flags |= MAP_FIXED;

    void *ptr;
    if (e->fd >= 0) {
        ptr = mmap(hint, sz, prot, flags, e->fd, off);
    } else {
        ptr = mmap(hint, sz, prot, MAP_ANON | flags, -1, 0);
    }

    if (ptr == MAP_FAILED) {
        set_win32_errno(errno);
        return 0;
    }

    e->map_ptr = ptr;
    e->map_size = sz;
    guest_set_last_error(0);
    return (uint64_t)(uintptr_t)ptr;
}

uint64_t subsys_MapViewOfFile(uint64_t hFileMappingObject, uint32_t dwDesiredAccess,
                             uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow, uint64_t dwNumberOfBytesToMap) {
    return subsys_MapViewOfFileEx(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, 0);
}

uint64_t subsys_UnmapViewOfFile(uint64_t lpBaseAddress) {
    if (!lpBaseAddress) {
        guest_set_last_error(87);
        return 0;
    }
    pthread_mutex_lock(&g_handle_lock);
    for (size_t i = 0; i < MAX_HANDLES; ++i) {
        if (g_handles[i].kind == HANDLE_KIND_MAPPING && (uint64_t)(uintptr_t)g_handles[i].map_ptr == lpBaseAddress) {
            munmap(g_handles[i].map_ptr, g_handles[i].map_size);
            g_handles[i].map_ptr = NULL;
            pthread_mutex_unlock(&g_handle_lock);
            guest_set_last_error(0);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_handle_lock);
    guest_set_last_error(6);
    return 0;
}

/* ========================================================================= */
/* 6. Threading & Synchronization Engine                                     */
/* ========================================================================= */

uint64_t subsys_CreateEventA(uint64_t lpEventAttributes, uint32_t bManualReset, uint32_t bInitialState, uint64_t lpName) {
    (void)lpEventAttributes; (void)lpName;
    uint64_t h = alloc_handle(HANDLE_KIND_EVENT);
    struct HandleEntry *e = get_handle(h);
    if (e) {
        e->manual_reset = (bManualReset != 0);
        e->signaled = (bInitialState != 0);
    }
    return h;
}

uint64_t subsys_CreateEventW(uint64_t lpEventAttributes, uint32_t bManualReset, uint32_t bInitialState, uint64_t lpName) {
    return subsys_CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
}

uint64_t subsys_SetEvent(uint64_t hEvent) {
    struct HandleEntry *e = get_handle(hEvent);
    if (!e || e->kind != HANDLE_KIND_EVENT) return 0;
    pthread_mutex_lock(&e->mutex);
    e->signaled = true;
    pthread_cond_broadcast(&e->cond);
    pthread_mutex_unlock(&e->mutex);
    return 1;
}

uint64_t subsys_ResetEvent(uint64_t hEvent) {
    struct HandleEntry *e = get_handle(hEvent);
    if (!e || e->kind != HANDLE_KIND_EVENT) return 0;
    pthread_mutex_lock(&e->mutex);
    e->signaled = false;
    pthread_mutex_unlock(&e->mutex);
    return 1;
}

uint64_t subsys_WaitForSingleObject(uint64_t hHandle, uint32_t dwMilliseconds) {
    struct HandleEntry *e = get_handle(hHandle);
    if (!e) return 0; // WAIT_OBJECT_0
    if (e->wait_object)
        return e->wait_object(hHandle, dwMilliseconds);
    if (e->kind == HANDLE_KIND_EVENT) {
        pthread_mutex_lock(&e->mutex);
        if (e->signaled) {
            if (!e->manual_reset) e->signaled = false;
            pthread_mutex_unlock(&e->mutex);
            return 0; // WAIT_OBJECT_0
        }
        if (dwMilliseconds == 0) {
            pthread_mutex_unlock(&e->mutex);
            return 0x00000102; // WAIT_TIMEOUT
        }
        if (dwMilliseconds == 0xffffffff) { // INFINITE
            while (!e->signaled) pthread_cond_wait(&e->cond, &e->mutex);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += dwMilliseconds / 1000;
            ts.tv_nsec += (dwMilliseconds % 1000) * 1000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            int rc = 0;
            while (!e->signaled && rc == 0) rc = pthread_cond_timedwait(&e->cond, &e->mutex, &ts);
        }
        bool was_sig = e->signaled;
        if (was_sig && !e->manual_reset) e->signaled = false;
        pthread_mutex_unlock(&e->mutex);
        return was_sig ? 0 : 0x00000102;
    }
    return 0; // WAIT_OBJECT_0 for file/console handles
}

uint64_t subsys_WaitForMultipleObjects(uint32_t nCount, uint64_t lpHandles, uint32_t bWaitAll, uint32_t dwMilliseconds) {
    (void)bWaitAll; (void)dwMilliseconds;
    if (nCount == 0 || !lpHandles) return 0;
    // Check first available signaled handle
    for (uint32_t i = 0; i < nCount && i < 64; ++i) {
        uint64_t h = guest_load(lpHandles + i * 8, 8);
        struct HandleEntry *e = get_handle(h);
        if (e && e->kind == HANDLE_KIND_EVENT && e->signaled) {
            if (!e->manual_reset) e->signaled = false;
            return i; // WAIT_OBJECT_0 + i
        }
    }
    return 0; // WAIT_OBJECT_0
}

/* SRW Lock Fast Inlined Implementations */
uint64_t subsys_InitializeSRWLock(uint64_t pLock) {
    if (pLock) guest_store(pLock, 0, 8);
    return 0;
}

uint64_t subsys_AcquireSRWLockExclusive(uint64_t pLock) {
    if (pLock) {
        uint64_t *val = (uint64_t *)guest_pointer(pLock, 8);
        if (val) {
            while (__atomic_test_and_set((volatile void *)val, __ATOMIC_ACQUIRE))
                sched_yield();
        }
    }
    return 0;
}

uint64_t subsys_ReleaseSRWLockExclusive(uint64_t pLock) {
    if (pLock) {
        uint64_t *val = (uint64_t *)guest_pointer(pLock, 8);
        if (val) __atomic_clear((volatile void *)val, __ATOMIC_RELEASE);
    }
    return 0;
}

uint64_t subsys_AcquireSRWLockShared(uint64_t pLock) {
    return subsys_AcquireSRWLockExclusive(pLock);
}

uint64_t subsys_ReleaseSRWLockShared(uint64_t pLock) {
    return subsys_ReleaseSRWLockExclusive(pLock);
}

uint64_t subsys_SleepConditionVariableSRW(uint64_t pCond, uint64_t pLock, uint32_t dwMilliseconds, uint32_t Flags) {
    (void)pCond; (void)Flags;
    subsys_ReleaseSRWLockExclusive(pLock);
    if (dwMilliseconds && dwMilliseconds != 0xffffffff)
        usleep((useconds_t)dwMilliseconds * 1000);
    else
        sched_yield();
    subsys_AcquireSRWLockExclusive(pLock);
    return 1;
}

uint64_t subsys_WakeConditionVariable(uint64_t pCond) { (void)pCond; return 0; }
uint64_t subsys_WakeAllConditionVariable(uint64_t pCond) { (void)pCond; return 0; }
uint64_t subsys_InitOnceExecuteOnce(uint64_t pInitOnce, uint64_t pInitFn, uint64_t pParam, uint64_t pContext) {
    (void)pInitFn; (void)pParam; (void)pContext;
    if (!pInitOnce) return 0;
    uint64_t state = guest_load(pInitOnce, 8);
    if (state == 1) return 1; // Already initialized
    guest_store(pInitOnce, 1, 8);
    return 1;
}

static pthread_mutex_t g_addr_init_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_addr_buckets_inited = false;
static struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} g_addr_buckets[256];

static void ensure_addr_buckets_init(void) {
    if (__builtin_expect(!g_addr_buckets_inited, 0)) {
        pthread_mutex_lock(&g_addr_init_lock);
        if (!g_addr_buckets_inited) {
            for (size_t i = 0; i < 256; ++i) {
                pthread_mutex_init(&g_addr_buckets[i].mutex, NULL);
                pthread_cond_init(&g_addr_buckets[i].cond, NULL);
            }
            g_addr_buckets_inited = true;
        }
        pthread_mutex_unlock(&g_addr_init_lock);
    }
}

uint64_t subsys_WaitOnAddress(uint64_t address, uint64_t compare_address, size_t size, uint32_t milliseconds) {
    if (!address || !compare_address || (size != 1 && size != 2 && size != 4 && size != 8)) {
        guest_set_last_error(87);
        return 0;
    }
    ensure_addr_buckets_init();
    size_t b_idx = (size_t)((address >> 2) & 255);

    uint64_t val = guest_load(address, (uint32_t)size);
    uint64_t cmp = guest_load(compare_address, (uint32_t)size);
    if (val != cmp)
        return 1;

    if (milliseconds == 0) {
        guest_set_last_error(1460);
        return 0;
    }

    pthread_mutex_lock(&g_addr_buckets[b_idx].mutex);
    val = guest_load(address, (uint32_t)size);
    cmp = guest_load(compare_address, (uint32_t)size);
    if (val != cmp) {
        pthread_mutex_unlock(&g_addr_buckets[b_idx].mutex);
        return 1;
    }

    int rc = 0;
    if (milliseconds == UINT32_MAX) {
        rc = pthread_cond_wait(&g_addr_buckets[b_idx].cond, &g_addr_buckets[b_idx].mutex);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += milliseconds / 1000;
        ts.tv_nsec += (milliseconds % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        rc = pthread_cond_timedwait(&g_addr_buckets[b_idx].cond, &g_addr_buckets[b_idx].mutex, &ts);
    }
    pthread_mutex_unlock(&g_addr_buckets[b_idx].mutex);

    if (rc == ETIMEDOUT) {
        guest_set_last_error(1460);
        return 0;
    }
    return 1;
}

void subsys_WakeByAddressSingle(uint64_t address) {
    if (!address) return;
    ensure_addr_buckets_init();
    size_t b_idx = (size_t)((address >> 2) & 255);
    pthread_mutex_lock(&g_addr_buckets[b_idx].mutex);
    pthread_cond_signal(&g_addr_buckets[b_idx].cond);
    pthread_mutex_unlock(&g_addr_buckets[b_idx].mutex);
}

void subsys_WakeByAddressAll(uint64_t address) {
    if (!address) return;
    ensure_addr_buckets_init();
    size_t b_idx = (size_t)((address >> 2) & 255);
    pthread_mutex_lock(&g_addr_buckets[b_idx].mutex);
    pthread_cond_broadcast(&g_addr_buckets[b_idx].cond);
    pthread_mutex_unlock(&g_addr_buckets[b_idx].mutex);
}

uint64_t subsys_CreateWaitableTimerExW(uint64_t lpTimerAttributes, uint64_t lpTimerName, uint32_t dwFlags, uint32_t dwDesiredAccess) {
    (void)lpTimerAttributes; (void)lpTimerName; (void)dwDesiredAccess;
    uint64_t h = alloc_handle(HANDLE_KIND_EVENT);
    struct HandleEntry *e = get_handle(h);
    if (e) {
        e->manual_reset = (dwFlags & 1) != 0;
        e->signaled = false;
    }
    return h;
}

uint64_t subsys_CreateWaitableTimerW(uint64_t lpTimerAttributes, uint64_t lpTimerName, uint32_t bManualReset) {
    return subsys_CreateWaitableTimerExW(lpTimerAttributes, lpTimerName, bManualReset ? 1 : 0, 0);
}

uint64_t subsys_SetWaitableTimer(uint64_t hTimer, uint64_t lpDueTime, uint32_t lPeriod, uint64_t pfnCompletionRoutine) {
    (void)lpDueTime; (void)lPeriod; (void)pfnCompletionRoutine;
    struct HandleEntry *e = get_handle(hTimer);
    if (!e || e->kind != HANDLE_KIND_EVENT) {
        guest_set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }
    pthread_mutex_lock(&e->mutex);
    e->signaled = true;
    pthread_cond_broadcast(&e->cond);
    pthread_mutex_unlock(&e->mutex);
    return 1;
}

uint64_t subsys_GetConsoleScreenBufferInfo(uint64_t hConsoleOutput, uint64_t lpConsoleScreenBufferInfo) {
    (void)hConsoleOutput;
    if (!lpConsoleScreenBufferInfo) {
        guest_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    int cols = 80, rows = 25;
#ifdef TIOCGWINSZ
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        cols = ws.ws_col;
        rows = ws.ws_row;
    }
#endif
    // dwSize: (cols, rows)
    guest_store(lpConsoleScreenBufferInfo + 0, (uint16_t)cols, 2);
    guest_store(lpConsoleScreenBufferInfo + 2, (uint16_t)rows, 2);
    // dwCursorPosition: (0, 0)
    guest_store(lpConsoleScreenBufferInfo + 4, 0, 2);
    guest_store(lpConsoleScreenBufferInfo + 6, 0, 2);
    // wAttributes: 0x0007 (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
    guest_store(lpConsoleScreenBufferInfo + 8, 7, 2);
    // srWindow: Left=0, Top=0, Right=cols-1, Bottom=rows-1
    guest_store(lpConsoleScreenBufferInfo + 10, 0, 2);
    guest_store(lpConsoleScreenBufferInfo + 12, 0, 2);
    guest_store(lpConsoleScreenBufferInfo + 14, (uint16_t)(cols > 0 ? cols - 1 : 0), 2);
    guest_store(lpConsoleScreenBufferInfo + 16, (uint16_t)(rows > 0 ? rows - 1 : 0), 2);
    // dwMaximumWindowSize: (cols, rows)
    guest_store(lpConsoleScreenBufferInfo + 18, (uint16_t)cols, 2);
    guest_store(lpConsoleScreenBufferInfo + 20, (uint16_t)rows, 2);
    guest_set_last_error(0);
    return 1;
}

uint64_t subsys_GetEnvironmentVariableW(uint64_t lpName, uint64_t lpBuffer, uint32_t nSize) {
    if (!lpName) {
        guest_set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    char name[1024];
    size_t i = 0;
    while (i < sizeof(name) - 1) {
        uint16_t ch = (uint16_t)guest_load(lpName + i * 2, 2);
        if (!ch) break;
        name[i++] = (char)(ch > 127 ? '?' : ch);
    }
    name[i] = '\0';
    const char *val = getenv(name);
    if (!val) {
        guest_set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    size_t val_len = strlen(val);
    if (nSize <= val_len) {
        guest_set_last_error(0);
        return (uint32_t)(val_len + 1);
    }
    if (lpBuffer) {
        for (size_t j = 0; j < val_len; ++j) {
            guest_store(lpBuffer + j * 2, (uint16_t)(unsigned char)val[j], 2);
        }
        guest_store(lpBuffer + val_len * 2, 0, 2);
    }
    guest_set_last_error(0);
    return (uint32_t)val_len;
}

uint64_t subsys_GetComputerNameExW(uint32_t nameType, uint64_t lpBuffer, uint64_t nSize) {
    (void)nameType;
    if (!nSize) {
        guest_set_last_error(87);
        return 0;
    }
    char host[256];
    if (gethostname(host, sizeof(host)) != 0) {
        strncpy(host, "localhost", sizeof(host));
    }
    size_t len = strlen(host);
    uint32_t in_size = (uint32_t)guest_load(nSize, 4);
    if (in_size <= len || !lpBuffer) {
        guest_store(nSize, (uint32_t)(len + 1), 4);
        guest_set_last_error(234); // ERROR_MORE_DATA
        return 0;
    }
    for (size_t i = 0; i <= len; ++i) {
        guest_store(lpBuffer + i * 2, (uint16_t)(unsigned char)host[i], 2);
    }
    guest_store(nSize, (uint32_t)len, 4);
    guest_set_last_error(0);
    return 1;
}

uint64_t subsys_GetUserProfileDirectoryW(uint64_t hToken, uint64_t lpProfileDir, uint64_t lpcchSize) {
    (void)hToken;
    if (!lpcchSize) {
        guest_set_last_error(87);
        return 0;
    }
    const char *home = getenv("HOME");
    if (!home) home = "/";
    size_t len = strlen(home);
    uint32_t in_size = (uint32_t)guest_load(lpcchSize, 4);
    if (in_size <= len || !lpProfileDir) {
        guest_store(lpcchSize, (uint32_t)(len + 1), 4);
        guest_set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    for (size_t i = 0; i <= len; ++i) {
        guest_store(lpProfileDir + i * 2, (uint16_t)(unsigned char)home[i], 2);
    }
    guest_store(lpcchSize, (uint32_t)len, 4);
    guest_set_last_error(0);
    return 1;
}
