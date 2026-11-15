#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct section {
    uint64_t address, size, initial_size;
    const unsigned char *initial;
    uint64_t writable;
};
/* Ahead-of-time modules registered by build_console_modules.py. */
struct guest_dispatch_entry {
    uint64_t rva;
    void (*fn)(void *cpu, uint64_t return_va);
};

struct guest_module_export {
    const char *name;
    uint64_t ordinal, address;
    const char *forwarder; /* "DLL.Name" or "DLL.#ordinal" when address is 0 */
};

struct guest_module_import {
    const char *dll, *name;
    uint64_t ordinal, slot;
};

struct guest_module {
    const char *name;
    uint64_t base, size;
    uint64_t exception_rva, exception_size;
    /* SHA-256 and size of the DLL file this module was lifted from. */
    unsigned char file_hash[32];
    size_t file_size;
    const struct section *sections;
    size_t section_count;
    const struct guest_dispatch_entry *dispatch;
    size_t dispatch_count;
    const struct guest_module_export *exports;
    size_t export_count;
    void (*entry)(void *, uint64_t);
    const struct guest_module_import *imports;
    size_t import_count;
    uint64_t *dependencies;
    bool loading;
    unsigned references;
    unsigned char **memory;
    /* The image as mapped (page-aligned, size rounded up to a page), or NULL. */
    unsigned char *image;
};
