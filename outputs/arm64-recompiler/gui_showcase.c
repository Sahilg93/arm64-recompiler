#include <windows.h>

int main(void) {
    MessageBoxA(NULL, "This Windows PE x86-64 binary was recompiled to native Apple Silicon ARM64!", "Hybrid GUI Showcase", MB_OK);
    ExitProcess(0);
}
