#include <assert.h>
#define main console_entry
#include "console_runtime.c"
#undef main

const struct section guest_sections[1] = {{0}};
const uint64_t guest_section_count = 0;
const uint64_t guest_image_base = 0x140000000;
uint32_t lifted_console(void) { return 0; }

int main(void) {
    printf("Starting Virtual Memory & MapViewOfFile Parity Tests...\n");

    // 1. VirtualAlloc & Zero-Tag Virtual Memory
    uint64_t vmem = subsys_VirtualAlloc(0, 16384, 0x1000 | 0x2000, 0x04);
    assert(vmem != 0);
    assert((vmem & UINT64_C(0xFF00000000000000)) == 0); // Must be zero-tag (true 64-bit VA)
    printf("  [PASS] subsys_VirtualAlloc allocated zero-tag memory at %p\n", (void*)(uintptr_t)vmem);

    // Write and read via guest_store and guest_load
    guest_store(vmem, 0x1122334455667788ULL, 8);
    uint64_t loaded = guest_load(vmem, 8);
    assert(loaded == 0x1122334455667788ULL);
    printf("  [PASS] guest_store / guest_load on zero-tag virtual address verified: %#llx\n", (unsigned long long)loaded);

    // Free VirtualAlloc
    uint64_t free_ok = subsys_VirtualFree(vmem, 16384, 0x8000);
    assert(free_ok == 1);
    printf("  [PASS] subsys_VirtualFree released memory\n");

    // 2. File-backed MapViewOfFile
    char tmp_path[] = "/tmp/arm64_mmap_test_XXXXXX";
    int fd = mkstemp(tmp_path);
    assert(fd >= 0);
    const char test_data[] = "Ripgrep & Vivado native ARM64 memory-mapped engine test!";
    ssize_t written = write(fd, test_data, sizeof(test_data));
    assert(written == sizeof(test_data));
    close(fd);

    uint64_t path_guest = vmem; // use a small buffer or stack
    // convert tmp_path to wide in path_buf
    uint16_t wide_path[512] = {0};
    for (size_t i = 0; i < strlen(tmp_path); ++i) wide_path[i] = (uint16_t)tmp_path[i];
    uint64_t wide_addr = subsys_VirtualAlloc(0, 4096, 0x1000, 0x04);
    memcpy((void*)(uintptr_t)wide_addr, wide_path, sizeof(wide_path));

    uint64_t hFile = subsys_CreateFileW(wide_addr, 0xC0000000, 0, 0, 3, 0x80, 0);
    assert(hFile != 0 && hFile != (uint64_t)-1);
    printf("  [PASS] subsys_CreateFileW opened temporary file\n");

    uint64_t hMap = subsys_CreateFileMappingW(hFile, 0, 0x04, 0, 0, 0);
    assert(hMap != 0);
    printf("  [PASS] subsys_CreateFileMappingW created file mapping\n");

    uint64_t mapped_addr = subsys_MapViewOfFile(hMap, 2, 0, 0, 0);
    assert(mapped_addr != 0);
    assert((mapped_addr & UINT64_C(0xFF00000000000000)) == 0); // Zero-tag
    assert(strcmp((const char*)(uintptr_t)mapped_addr, test_data) == 0);
    printf("  [PASS] subsys_MapViewOfFile matched contents: \"%s\"\n", (const char*)(uintptr_t)mapped_addr);

    // Verify guest_load reads from mapped region
    uint64_t first_qword = guest_load(mapped_addr, 8);
    uint64_t expected_qword;
    memcpy(&expected_qword, test_data, 8);
    assert(first_qword == expected_qword);
    printf("  [PASS] guest_load correctly dereferenced memory-mapped file\n");

    // Write to mapped region via guest_store
    const char new_msg[] = "Native ARM64 Vivado";
    for (size_t i = 0; i < strlen(new_msg); ++i) {
        guest_store(mapped_addr + i, (unsigned char)new_msg[i], 1);
    }

    // Unmap
    uint64_t unmap_ok = subsys_UnmapViewOfFile(mapped_addr);
    assert(unmap_ok == 1);
    guest_close_handle(hMap);
    guest_close_handle(hFile);
    subsys_VirtualFree(wide_addr, 4096, 0x8000);
    printf("  [PASS] subsys_UnmapViewOfFile and CloseHandle succeeded\n");

    // Reopen and verify file on disk was modified by the map
    int verify_fd = open(tmp_path, O_RDONLY);
    char verify_buf[64] = {0};
    read(verify_fd, verify_buf, sizeof(verify_buf) - 1);
    close(verify_fd);
    unlink(tmp_path);
    assert(strncmp(verify_buf, "Native ARM64 Vivado", 19) == 0);
    printf("  [PASS] Disk persistence verified after memory-mapped write\n");

    // 3. Anonymous MapViewOfFile (PAGEFILE-backed)
    uint64_t hAnonMap = subsys_CreateFileMappingW((uint64_t)-1, 0, 0x04, 0, 4096, 0);
    assert(hAnonMap != 0);
    uint64_t anon_ptr = subsys_MapViewOfFile(hAnonMap, 2, 0, 0, 4096);
    assert(anon_ptr != 0);
    guest_store(anon_ptr, 0xCAFEBABE, 4);
    guest_store(anon_ptr + 4092, 0xDEADBEEF, 4);
    assert(guest_load(anon_ptr, 4) == 0xCAFEBABE);
    assert(guest_load(anon_ptr + 4092, 4) == 0xDEADBEEF);
    assert(subsys_UnmapViewOfFile(anon_ptr) == 1);
    guest_close_handle(hAnonMap);
    printf("  [PASS] Anonymous pagefile-backed mapping verified with guest_store/load\n");

    printf("\nALL VIRTUAL MEMORY & MMAP TESTS PASSED!\n");
    return 0;
}
