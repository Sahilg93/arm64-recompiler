/* Minimal Win32 declarations for this CRT-free x64 test fixture. */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define WINAPI __stdcall
#define IMPORT __declspec(dllimport)
#define TRUE 1
#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1
#define TLS_OUT_OF_INDEXES UINT32_MAX
#define INFINITE UINT32_MAX
#define WAIT_OBJECT_0 0
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#define ERROR_INVALID_ADDRESS 487

typedef uint32_t DWORD;
typedef int BOOL;
typedef uintptr_t ULONG_PTR;
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *LPVOID;
typedef intptr_t (WINAPI *FARPROC)(void);

IMPORT BOOL WINAPI CloseHandle(HANDLE);
IMPORT HANDLE WINAPI CreateThread(void *, size_t, DWORD (WINAPI *)(LPVOID), LPVOID, DWORD, DWORD *);
IMPORT __declspec(noreturn) void WINAPI ExitProcess(DWORD);
IMPORT BOOL WINAPI FreeLibrary(HMODULE);
IMPORT DWORD WINAPI GetCurrentThreadId(void);
IMPORT DWORD WINAPI GetLastError(void);
IMPORT BOOL WINAPI GetExitCodeThread(HANDLE, DWORD *);
IMPORT FARPROC WINAPI GetProcAddress(HMODULE, const char *);
IMPORT HMODULE WINAPI LoadLibraryW(const wchar_t *);
IMPORT DWORD WINAPI TlsAlloc(void);
IMPORT LPVOID WINAPI VirtualAlloc(LPVOID, size_t, DWORD, DWORD);
IMPORT BOOL WINAPI VirtualFree(LPVOID, size_t, DWORD);
IMPORT BOOL WINAPI TlsFree(DWORD);
IMPORT LPVOID WINAPI TlsGetValue(DWORD);
IMPORT BOOL WINAPI TlsSetValue(DWORD, LPVOID);
IMPORT DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
