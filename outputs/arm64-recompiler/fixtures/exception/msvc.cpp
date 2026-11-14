// Build in an x64 Visual Studio Developer Command Prompt:
// cl /nologo /EHsc /MD /O2 msvc.cpp /Fe:msvc-exception.exe
#include <cstdio>
#include <windows.h>

static volatile unsigned order;
struct Error { int value; };
struct Guard {
    unsigned digit;
    ~Guard() { order = order * 10 + digit; }
};

__declspec(noinline) static void inner() {
    Guard guard{1};
    throw Error{42};
}

__declspec(noinline) static void outer() {
    Guard guard{2};
    inner();
}

__declspec(noinline) static int check_seh() {
    volatile int *volatile address = nullptr;
    __try {
        return *address;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
                EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return 73;
    }
}

// The fault comes from a raw VirtualAlloc page, so on the ARM64 launcher it is
// a real SIGSEGV/SIGBUS delivered through the runtime's signal-to-SEH path.
__declspec(noinline) static int check_virtual_alloc_seh() {
    volatile int *page = static_cast<volatile int *>(
        VirtualAlloc(nullptr, 0x10000, MEM_RESERVE, PAGE_NOACCESS));
    if (!page)
        return 0;
    volatile ULONG_PTR address = 0, writing = 2;
    int result = 0;
    __try {
        result = page[16];
    } __except (address = GetExceptionInformation()->ExceptionRecord->ExceptionInformation[1],
                writing = GetExceptionInformation()->ExceptionRecord->ExceptionInformation[0],
                GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
                EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        result = 74;
    }
    if (address != reinterpret_cast<ULONG_PTR>(page + 16) || writing != 0)
        result = 0;
    VirtualFree(const_cast<int *>(page), 0, MEM_RELEASE);
    return result;
}

int main() {
    try {
        outer();
    } catch (const Error &error) {
        if (error.value != 42 || order != 12)
            return 1;
        try {
            throw;
        } catch (const Error &again) {
            if (&again != &error)
                return 2;
        }
        if (check_seh() != 73)
            return 3;
        if (check_virtual_alloc_seh() != 74)
            return 5;
        std::puts("C++ cleanup, rethrow, and SEH passed");
        return 0;
    }
    return 4;
}
