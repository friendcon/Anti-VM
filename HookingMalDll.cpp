#include <Windows.h>
#include <stdio.h>
#include <ctime>

#define STR_MODULE_NAME                   "HookingMalDll.dll"
#define STR_HIDE_PROCESS_NAME             "VBoxService.exe"
#define STR_HIDE_PROCESS_NAME2            "VBoxTray.exe"
#define STR_HIDE_PROCESS_NAME3            "VBoxControl.exe"
#define STATUS_SUCCESS                  (0x00000000L) 

// 배열 선언

// VBox File Name
LPCSTR VboxlpFileName[31] = {
      "C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
      "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
      "C:\\windows\\System32\\Drivers\\VBoxSF.sys",
      "C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
      "C:\\WINDOWS\\system32\\vboxdisp.dll",
      "C:\\WINDOWS\\system32\\vboxhook.dll",
      "C:\\WINDOWS\\system32\\vboxmrxnp.dll",
      "C:\\WINDOWS\\system32\\vboxogl.dll",
      "C:\\WINDOWS\\system32\\vboxoglarrayspu.dll",
      "C:\\WINDOWS\\system32\\vboxoglcrutil.dll",
      "C:\\WINDOWS\\system32\\vboxoglerrorspu.dll",
      "C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll",
      "C:\\WINDOWS\\system32\\vboxoglpackspu.dll",
      "C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll",
      "C:\\WINDOWS\\system32\\vboxservice.exe",
      "C:\\WINDOWS\\system32\\vboxtray.exe",
      "C:\\WINDOWS\\system32\\VBoxControl.exe",
      "C:\\program files\\oracle\\virtualbox guest additions\\",
      "C:\\windows\\system32\\drivers\\vmmouse.sys",
      "C:\\windows\\system32\\drivers\\vmhgfs.sys",
      "C:\\windows\\system32\\drivers\\vm3dmp.sys",
      "C:\\windows\\system32\\drivers\\vmci.sys",
      "C:\\windows\\system32\\drivers\\vmhgfs.sys",
      "C:\\windows\\system32\\drivers\\vmmemctl.sys",
      "C:\\windows\\system32\\drivers\\vmmouse.sys",
      "C:\\windows\\system32\\drivers\\vmrawdsk.sys",
      "C:\\windows\\system32\\drivers\\vmusbmouse.sys",
      "\\\\.\\VBoxMiniRdrDN",
      "\\\\.\\pipe\\VBoxMiniRdDN",
      "\\\\.\\VBoxTrayIPC",
      "\\\\.\\pipe\\VBoxTrayIPC"
};

// VBox IpSub Key
LPCTSTR VboxlpSubKey[12] = {
   "HARDWARE\\ACPI\\DSDT\\VBOX__",
   "HARDWARE\\ACPI\\DSDT\\VBOX__\\VBOXBIOS",
   "HARDWARE\\ACPI\\FADT\\VBOX__" ,
   "HARDWARE\\ACPI\\FADT\\VBOX__\\VBOXFACP",
   "HARDWARE\\ACPI\\RSDT\\VBOX__",
   "HARDWARE\\ACPI\\RSDT\\VBOX__\\VBOXXSDT",
   "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
   "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
   "SYSTEM\\ControlSet001\\Services\\VBoxService",
   "SYSTEM\\ControlSet001\\Services\\VBoxSF",
   "SYSTEM\\ControlSet001\\Services\\VBoxVideo",
   "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
};

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    BYTE Reserved1[52];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// ZwQuerySystemInformation 매개변수
typedef NTSTATUS(WINAPI* PFZWQUERYSYSTEMINFORMATION) (
    SYSTEM_INFORMATION_CLASS    SystemInformationClass,
    PVOID                       SystemInformation,
    ULONG                       SystemInformationLength,
    PULONG                      ReturnLength
    );

// CreateProcessA 매개변수
typedef BOOL(WINAPI* PFCREATEPROCESSA) (
    LPCTSTR                 lpApplicationName,
    LPTSTR                  lpCommandLine,
    LPSECURITY_ATTRIBUTES   lpProcessAttributes,
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    BOOL                    bInheritHandles,
    DWORD                   dwCreationFlags,
    LPVOID                  lpEnvironment,
    LPCTSTR                 lpCurrentDirectory,
    LPSTARTUPINFO           lpStartupInfo,
    LPPROCESS_INFORMATION   lpProcessInformation
    );

// CreateProcessW 매개변수
typedef BOOL(WINAPI* PFCREATEPROCESSW) (
    LPCTSTR                 lpApplicationName,
    LPTSTR                  lpCommandLine,
    LPSECURITY_ATTRIBUTES   lpProcessAttributes,
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    BOOL                    bInheritHandles,
    DWORD                   dwCreationFlags,
    LPVOID                  lpEnvironment,
    LPCTSTR                 lpCurrentDirectory,
    LPSTARTUPINFO           lpStartupInfo,
    LPPROCESS_INFORMATION   lpProcessInformation
    );

// CreateFileA 매개변수
typedef HANDLE(WINAPI* PFCREATEFILEA) (
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

// CreateFileW 매개변수
typedef HANDLE(WINAPI* PFCREATEFILEW) (
    LPCSTR                  lpFileName,
    DWORD                   dwDesiredAccess,
    DWORD                   dwShareMode,
    LPSECURITY_ATTRIBUTES   lpSecurityAttributes,
    DWORD                   dwCreationDisposition,
    DWORD                   dwFlagsAndAttributes,
    HANDLE                  hTemplateFile
    );

// GetFileAttributesExA 매개변수
typedef BOOL(WINAPI* PFGETFILEATTRIBUTESEXA) (
    LPCSTR                 lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation
    );

// GetFileAttributesExW 매개변수
typedef BOOL(WINAPI* PFGETFILEATTRIBUTESEXW) (
    LPCSTR                 lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation
    );

// GetFileAttributesA 매개변수
typedef DWORD(WINAPI* PFGETFILEATTRIBUTESA) (
    LPCSTR  lpFileName
    );

// GetFileAttributesW 매개변수
typedef DWORD(WINAPI* PFGETFILEATTRIBUTESW) (
    LPCSTR  lpFileName
    );

typedef LSTATUS(WINAPI* PFREGOPENKEYEXA) (
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
    );

typedef LSTATUS(WINAPI* PFREGOPENKEYEXW) (
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
    );

typedef LSTATUS(WINAPI* PFREGQUERYVALUEEXA) (
    HKEY    hKey,
    LPCSTR  lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
    );

typedef LSTATUS(WINAPI* PFREGQUERYVALUEEXW) (
    HKEY    hKey,
    LPCSTR  lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
    );

typedef DWORD(WINAPI* PFWNETGETPROVIDERNAMEA) (
    DWORD   dwNetType,
    LPSTR   lpProviderName,
    LPDWORD lpBufferSize
    );
typedef DWORD(WINAPI* PFWNETGETPROVIDERNAMEW) (
    DWORD   dwNetType,
    LPSTR   lpProviderName,
    LPDWORD lpBufferSize
    );


// 마우스 포인터 typedef 리턴 값(WINAPI PF+함수명대문자)


// 매개변수는 MSDN에서


BYTE g_pOrgCPA[5] = { 0, };
BYTE g_pOrgCPW[5] = { 0, };
BYTE g_pOrgZwQSI[5] = { 0, };
BYTE g_pOrgCFA[5] = { 0, };
BYTE g_pOrgCFW[5] = { 0, };
BYTE g_pOrgGFAEA[5] = { 0, };
BYTE g_pOrgGFAEW[5] = { 0, };
BYTE g_pOrgGFAA[5] = { 0, };
BYTE g_pOrgGFAW[5] = { 0, };
BYTE g_pOrgROKEA[5] = { 0, };
BYTE g_pOrgROKEW[5] = { 0, };
BYTE g_pOrgRQVEA[5] = { 0, };
BYTE g_pOrgRQVEW[5] = { 0, };
BYTE g_pOrgWNGPNA[5] = { 0, };
BYTE g_pOrgWNGPNW[5] = { 0, };
//BYTE g_p0rg+대문자만가져다쓰기

BOOL hook_by_code(LPCTSTR szDllName, LPCTSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes) {
    FARPROC pFunc;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = { 0xE9, 0, };
    PBYTE pByte;

    pFunc = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;
    if (pByte[0] == 0xE9)
        return FALSE;

    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    memcpy(pOrgBytes, pFunc, 5);

    dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
    memcpy(&pBuf[1], &dwAddress, 4);

    memcpy(pFunc, pBuf, 5);

    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}

BOOL unhook_by_code(LPCTSTR szDllName, LPCTSTR szFuncName, PBYTE pOrgBytes) {
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;

    pFunc = (FARPROC)GetProcAddress(GetModuleHandle(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;
    if (pByte[0] != 0xE9)
        return FALSE;

    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    memcpy(pFunc, pOrgBytes, 5);

    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken)) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL,             // lookup privilege on local system
        lpszPrivilege,    // privilege to lookup 
        &luid)) {         // receives LUID of privilege 
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

BOOL InjectDll2(HANDLE hProcess, LPCTSTR szDllName) {
    HANDLE hThread;
    LPVOID pRemoteBuf;
    DWORD dwBufSize = lstrlen(szDllName) + 1;
    FARPROC pThreadProc;

    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
        MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL)
        return FALSE;

    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
        dwBufSize, NULL);

    pThreadProc = GetProcAddress(GetModuleHandle("kernel32.dll"),
        "LoadLibraryA");
    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pThreadProc,
        pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    CloseHandle(hThread);

    return TRUE;
}

BOOL WINAPI NewCreateProcessA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    BOOL bRet;
    FARPROC pFunc;

    // unhook
    unhook_by_code("kernel32.dll", "CreateProcessA", g_pOrgCPA);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessA");
    bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    // 생성된 자식 프로세스에 stealth2.dll 을 인젝션 시킴
    if (bRet)
        InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

    // hook
    hook_by_code("kernel32.dll", "CreateProcessA",
        (PROC)NewCreateProcessA, g_pOrgCPA);

    return bRet;
}


// New~마우스 포인터 이름
// 리턴값 선언
// FARPROC pFunc
// --> unhook_by_code("dll", "함수원래이름", "g_p0rg~~~~")


BOOL WINAPI NewCreateProcessW(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    BOOL bRet;
    FARPROC pFunc;

    // unhook
    unhook_by_code("kernel32.dll", "CreateProcessW", g_pOrgCPW);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessW");
    bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

    // 생성된 자식 프로세스에 stealth2.dll 을 인젝션 시킴
    if (bRet)
        InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

    // hook
    hook_by_code("kernel32.dll", "CreateProcessW",
        (PROC)NewCreateProcessW, g_pOrgCPW);

    return bRet;
}

NTSTATUS WINAPI NewZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status;
    FARPROC pFunc;
    PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
    char szProcName[MAX_PATH] = { 0, };

    unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", g_pOrgZwQSI);

    pFunc = GetProcAddress(GetModuleHandle("ntdll.dll"),
        "ZwQuerySystemInformation");
    status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
        (SystemInformationClass, SystemInformation,
            SystemInformationLength, ReturnLength);

    if (status != STATUS_SUCCESS)
        goto __NTQUERYSYSTEMINFORMATION_END;

    if (SystemInformationClass == SystemProcessInformation)
    {
        pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

        while (TRUE)
        {
            WideCharToMultiByte(CP_ACP, 0, (PWSTR)pCur->Reserved2[1], -1,
                szProcName, MAX_PATH, NULL, NULL);

            if (!_strcmpi(szProcName, STR_HIDE_PROCESS_NAME)
                || !_strcmpi(szProcName, STR_HIDE_PROCESS_NAME2)
                || !_strcmpi(szProcName, STR_HIDE_PROCESS_NAME3))
            {
                if (pCur->NextEntryOffset == 0)
                    pPrev->NextEntryOffset = 0;
                else
                    pPrev->NextEntryOffset += pCur->NextEntryOffset;
            }
            else
                pPrev = pCur;   // 원하는 프로세스를 못 찾은 경우만 pPrev 세팅

            if (pCur->NextEntryOffset == 0)
                break;

            pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
        }
    }

__NTQUERYSYSTEMINFORMATION_END:

    hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
        (PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);

    return status;
}

HANDLE WINAPI NewCreateFileA(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
) {
    HANDLE ret;
    FARPROC pFunc;

    unhook_by_code("kernel32.dll", "CreateFileA",
        g_pOrgCFA);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateFileA");
    ret = ((PFCREATEFILEA)pFunc)(lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    for (int i = 0; i < 30; i++) {
        if (lpFileName != NULL || ret != INVALID_HANDLE_VALUE) {
            if (!_stricmp(lpFileName, VboxlpFileName[i])) {
                printf("%s\n", lpFileName);
                ret = INVALID_HANDLE_VALUE;
            }
        }
    }

    hook_by_code("kernel32.dll", "CreateFileA",
        (PROC)NewCreateFileA, g_pOrgCFA);

    return ret;
}

HANDLE WINAPI NewCreateFileW(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
) {
    HANDLE ret;
    FARPROC pFunc;

    unhook_by_code("kernel32.dll", "CreateFileW",
        g_pOrgCFW);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateFileW");
    ret = ((PFCREATEFILEW)pFunc)(lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    for (int i = 0; i < 30; i++) {
        if (lpFileName != NULL || ret != INVALID_HANDLE_VALUE) {
            if (!_stricmp(lpFileName, VboxlpFileName[i])) {
                printf("%s\n", lpFileName);
                ret = INVALID_HANDLE_VALUE;
            }
        }
    }

    hook_by_code("kernel32.dll", "CreateFileW",
        (PROC)NewCreateFileW, g_pOrgCFW);

    return ret;
}

BOOL WINAPI NewGetFileAttributesExA(
    LPCSTR                 lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation
) {
    BOOL ret;
    FARPROC pFunc;

    unhook_by_code("kernel32.dll", "GetFileAttributesExA",
        g_pOrgGFAEA);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetFileAttributesExA");
    ret = ((PFGETFILEATTRIBUTESEXA)pFunc)(lpFileName,
        fInfoLevelId,
        lpFileInformation);

    for (int i = 0; i < 30; i++) {
        if (lpFileName != NULL || ret != 0) {
            if (!_stricmp(lpFileName, VboxlpFileName[i])) {
                printf("%s\n", lpFileName);
                ret = 0;
            }
        }
    }

    hook_by_code("kernel32.dll", "GetFileAttributesExA",
        (PROC)NewGetFileAttributesExA, g_pOrgGFAEA);

    return ret;
}

BOOL WINAPI NewGetFileAttributesExW(
    LPCSTR                 lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID                 lpFileInformation
) {
    BOOL ret;
    FARPROC pFunc;

    unhook_by_code("kernel32.dll", "GetFileAttributesExW",
        g_pOrgGFAEW);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetFileAttributesExW");
    ret = ((PFGETFILEATTRIBUTESEXW)pFunc)(lpFileName,
        fInfoLevelId,
        lpFileInformation);

    for (int i = 0; i < 30; i++) {
        if (lpFileName != NULL || ret != 0) {
            if (!_stricmp(lpFileName, VboxlpFileName[i])) {
                printf("%s\n", lpFileName);
                ret = 0;
            }
        }
    }

    hook_by_code("kernel32.dll", "GetFileAttributesExW",
        (PROC)NewGetFileAttributesExW, g_pOrgGFAEW);

    return ret;
}

DWORD WINAPI NewGetFileAttributesA(
    LPCSTR lpFileName
) {
    DWORD ret;
    FARPROC pFunc;

    unhook_by_code("kernel32.dll", "GetFileAttributesA",
        g_pOrgGFAA);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetFileAttributesA");
    ret = ((PFGETFILEATTRIBUTESA)pFunc)(lpFileName);

    for (int i = 0; i < 30; i++) {
        if (lpFileName != NULL || ret != INVALID_FILE_ATTRIBUTES) {
            if (!_stricmp(lpFileName, VboxlpFileName[i])) {
                printf("%s\n", lpFileName);
                ret = INVALID_FILE_ATTRIBUTES;
            }
        }
    }

    hook_by_code("kernel32.dll", "GetFileAttributesA",
        (PROC)NewGetFileAttributesA, g_pOrgGFAA);

    return ret;
}

DWORD WINAPI NewGetFileAttributesW(
    LPCSTR lpFileName
) {
    DWORD ret;
    FARPROC pFunc;

    unhook_by_code("kernel32.dll", "GetFileAttributesW",
        g_pOrgGFAW);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetFileAttributesW");
    ret = ((PFGETFILEATTRIBUTESW)pFunc)(lpFileName);

    for (int i = 0; i < 30; i++) {
        if (lpFileName != NULL || ret != INVALID_FILE_ATTRIBUTES) {
            if (!_stricmp(lpFileName, VboxlpFileName[i])) {
                printf("%s\n", lpFileName);
                ret = INVALID_FILE_ATTRIBUTES;
            }
        }
    }

    hook_by_code("kernel32.dll", "GetFileAttributesW",
        (PROC)NewGetFileAttributesW, g_pOrgGFAW);

    return ret;
}

LSTATUS WINAPI NewRegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    LSTATUS bRet = 0;
    FARPROC pFunc;

    unhook_by_code("advapi32.dll", "RegOpenKeyExA", g_pOrgROKEA);

    pFunc = GetProcAddress(GetModuleHandle("advapi32.dll"), "RegOpenKeyExA");

    bRet = ((PFREGOPENKEYEXA)pFunc)(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    for (int i = 0; i < 12; i++)
    {
        if (!_stricmp(lpSubKey, VboxlpSubKey[i]))
        {
            bRet = ERROR_BADKEY;
        }
    }

    hook_by_code("advapi32.dll", "RegOpenKeyExA", (PROC)NewRegOpenKeyExA, g_pOrgROKEA);

    return bRet;
}

LSTATUS WINAPI NewRegOpenKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    LSTATUS bRet = 0;
    FARPROC pFunc;

    unhook_by_code("advapi32.dll", "RegOpenKeyExW", g_pOrgROKEW);

    pFunc = GetProcAddress(GetModuleHandle("advapi32.dll"), "RegOpenKeyExW");

    bRet = ((PFREGOPENKEYEXW)pFunc)(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    for (int i = 0; i < 12; i++)
    {
        if (!_stricmp((LPCTSTR)lpSubKey, VboxlpSubKey[i]))
        {
            bRet = ERROR_BADKEY;
        }
    }

    hook_by_code("advapi32.dll", "RegOpenKeyExW", (PROC)NewRegOpenKeyExW, g_pOrgROKEW);

    return bRet;
}

LSTATUS WINAPI NewRegQueryValueExA(
    HKEY    hKey,
    LPCSTR  lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
) {
    LSTATUS bRet = 0;
    FARPROC pFunc;

    unhook_by_code("advapi32.dll", "RegQueryValueExA", g_pOrgRQVEA);
    pFunc = GetProcAddress(GetModuleHandle("advapi32.dll"), "RegQueryValueExA");

    bRet = ((PFREGQUERYVALUEEXA)pFunc)(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    if (0 == _stricmp(lpValueName, "SystemBiosVersion")) {
        strcpy_s((LPSTR)lpData, 20, "LGE    - 2");
    }
    else if (0 == _stricmp(lpValueName, "VideoBiosDate")) {
        strcpy_s((LPSTR)lpData, 20, "08/07/20");
    }
    else if (0 == _stricmp(lpValueName, "SystemBiosDate")) {
        strcpy_s((LPSTR)lpData, 20, "05/28/15"); //Vbox에서는 06/23/99
    }
    else if (0 == _stricmp(lpValueName, "VideoBiosVersion")) {
        bRet = ERROR_FILE_NOT_FOUND;
    }
    else if (0 == _stricmp(lpValueName, "Identifier")) {
        strcpy_s((LPSTR)lpData, 30, "SAMSUNG MZNLN256HCHP-000EMT2");
    }

    hook_by_code("advapi32.dll", "RegQueryValueExA", (PROC)NewRegQueryValueExA, g_pOrgRQVEA);

    return bRet;
}

LSTATUS WINAPI NewRegQueryValueExW(
    HKEY    hKey,
    LPCSTR  lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE  lpData,
    LPDWORD lpcbData
) {
    LSTATUS bRet = 0;
    FARPROC pFunc;

    unhook_by_code("advapi32.dll", "RegQueryValueExW", g_pOrgRQVEW);
    pFunc = GetProcAddress(GetModuleHandle("advapi32.dll"), "RegQueryValueExW");

    bRet = ((PFREGQUERYVALUEEXW)pFunc)(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    if (0 == _stricmp(lpValueName, "SystemBiosVersion")) {
        strcpy_s((LPSTR)lpData, 20, "LGE    - 2");
    }

    else if (0 == _stricmp(lpValueName, "VideoBiosDate")) {
        strcpy_s((LPSTR)lpData, 20, "08/07/20");
    }

    else if (0 == _stricmp(lpValueName, "SystemBiosDate")) {
        strcpy_s((LPSTR)lpData, 20, "05/28/15");
    }

    else if (0 == _stricmp(lpValueName, "Identifier")) {
        strcpy_s((LPSTR)lpData, 30, "SAMSUNG MZNLN256HCHP-000EMT2");
    }

    hook_by_code("advapi32.dll", "RegQueryValueExW", (PROC)NewRegQueryValueExW, g_pOrgRQVEW);

    return bRet;
}

DWORD WINAPI NewWNetGetProviderNameA(
    DWORD   dwNetType,
    LPSTR   lpProviderName,
    LPDWORD lpBufferSize
) {
    LSTATUS bRet = 0;
    FARPROC pFunc;

    pFunc = GetProcAddress(GetModuleHandle("Mpr.dll"), "WNetGetProviderNameA");

    bRet = ERROR_NO_NETWORK;

    unhook_by_code("Mpr.dll", "WNetGetProviderNameA", g_pOrgWNGPNA);
    hook_by_code("Mpr.dll", "WNetGetProviderNameA", (PROC)NewWNetGetProviderNameA, g_pOrgWNGPNA);

    return bRet;
}

DWORD WINAPI NewWNetGetProviderNameW(
    DWORD   dwNetType,
    LPSTR   lpProviderName,
    LPDWORD lpBufferSize
) {
    LSTATUS bRet = 0;
    FARPROC pFunc;

    pFunc = GetProcAddress(GetModuleHandle("Mpr.dll"), "WNetGetProviderNameW");

    bRet = ERROR_NO_NETWORK;
    unhook_by_code("Mpr.dll", "WNetGetProviderNameW", g_pOrgWNGPNW);
    hook_by_code("Mpr.dll", "WNetGetProviderNameW", (PROC)NewWNetGetProviderNameW, g_pOrgWNGPNW);

    return bRet;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = { 0, };
    char* p = NULL;

    // HideProc2.exe 프로세스에는 인젝션 되지 않도록 예외처리
    GetModuleFileName(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if ((p != NULL) && (!_stricmp(p + 1, "HookingMal.exe") || !_stricmp(p + 1, "agent.exe") || !_stricmp(p + 1, "python.exe")))
        return TRUE;

    // change privilege
    SetPrivilege(SE_DEBUG_NAME, TRUE);

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // hook
        hook_by_code("kernel32.dll", "CreateProcessA",
            (PROC)NewCreateProcessA, g_pOrgCPA);
        hook_by_code("kernel32.dll", "CreateProcessW",
            (PROC)NewCreateProcessW, g_pOrgCPW);
        hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
            (PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);
        hook_by_code("kernel32.dll", "CreateFileA",
            (PROC)NewCreateFileA, g_pOrgCFA);
        hook_by_code("kernel32.dll", "CreateFileW",
            (PROC)NewCreateFileW, g_pOrgCFW);
        hook_by_code("kernel32.dll", "GetFileAttributesExA",
            (PROC)NewGetFileAttributesExA, g_pOrgGFAEA);
        hook_by_code("kernel32.dll", "GetFileAttributesExW",
            (PROC)NewGetFileAttributesExW, g_pOrgGFAEW);
        hook_by_code("kernel32.dll", "GetFileAttributesA",
            (PROC)NewGetFileAttributesA, g_pOrgGFAA);
        hook_by_code("kernel32.dll", "GetFileAttributesW",
            (PROC)NewGetFileAttributesW, g_pOrgGFAW);
        hook_by_code("advapi32.dll", "RegOpenKeyExA",
            (PROC)NewRegOpenKeyExA, g_pOrgROKEA);
        hook_by_code("advapi32.dll", "RegOpenKeyExW",
            (PROC)NewRegOpenKeyExW, g_pOrgROKEW);
        hook_by_code("advapi32.dll", "RegQueryValueExA",
            (PROC)NewRegQueryValueExA, g_pOrgRQVEA);
        hook_by_code("advapi32.dll", "RegQueryValueExW",
            (PROC)NewRegQueryValueExW, g_pOrgRQVEW);
        hook_by_code("Mpr.dll", "WNetGetProviderNameA", 
            (PROC)NewWNetGetProviderNameW, g_pOrgWNGPNA);
        hook_by_code("Mpr.dll", "WNetGetProviderNameW", 
            (PROC)NewWNetGetProviderNameW, g_pOrgWNGPNW);


        break;

    case DLL_PROCESS_DETACH:
        // unhook
        unhook_by_code("kernel32.dll", "CreateProcessA",
            g_pOrgCPA);
        unhook_by_code("kernel32.dll", "CreateProcessW",
            g_pOrgCPW);
        unhook_by_code("ntdll.dll", "ZwQuerySystemInformation",
            g_pOrgZwQSI);
        unhook_by_code("kernel32.dll", "CreateFileA",
            g_pOrgCFA);
        unhook_by_code("kernel32.dll", "CreateFileW",
            g_pOrgCFW);
        unhook_by_code("kernel32.dll", "GetFileAttributesExA",
            g_pOrgGFAEA);
        unhook_by_code("kernel32.dll", "GetFileAttributesExW",
            g_pOrgGFAEW);
        unhook_by_code("kernel32.dll", "GetFileAttributesA",
            g_pOrgGFAA);
        unhook_by_code("kernel32.dll", "GetFileAttributesW",
            g_pOrgGFAW);
        unhook_by_code("advapi32.dll", "RegOpenKeyExA",
            g_pOrgROKEA);
        unhook_by_code("advapi32.dll", "RegOpenKeyExW",
            g_pOrgROKEW);
        unhook_by_code("advapi32.dll", "RegQueryValueExA",
            g_pOrgRQVEA);
        unhook_by_code("advapi32.dll", "RegQueryValueExW",
            g_pOrgRQVEW);
        unhook_by_code("Mpr.dll", "WNetGetProviderNameA",
            g_pOrgWNGPNA);
        unhook_by_code("Mpr.dll", "WNetGetProviderNameW", 
            g_pOrgWNGPNW);

        break;
    }

    return TRUE;
}