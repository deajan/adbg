// Simple and basic anti debugging routines
// Ported to mingw by Orsiris de Jong https://github.com/deajan/adbg
// (for fun only, won't be maintained... Please fork and improve :)

#include <windows.h>
#include <winternl.h>
#include <stdbool.h>

// Print some shady stuff to stdout if debugger is found and exit ?
// Comment to keep normal behavior
#define EXIT_ON_DEBUGGER_FOUND TRUE

#ifdef EXIT_ON_DEBUGGER_FOUND
#include <stdio.h>
#endif

#include "adbg.h"

WORD GetVersionWord(void) {
    OSVERSIONINFO verInfo = { sizeof(OSVERSIONINFO) };
    GetVersionEx(&verInfo);
    return MAKEWORD(verInfo.dwMinorVersion, verInfo.dwMajorVersion);
}
BOOL IsWin8OrHigher(void) { return GetVersionWord() >= _WIN32_WINNT_WIN8; }
BOOL IsVistaOrHigher(void) { return GetVersionWord() >= _WIN32_WINNT_VISTA; }

// Current PEB for 64bit and 32bit processes accordingly
PVOID GetPEB(void) {
#ifdef _WIN64
    return (PVOID)__readgsqword(0x0C * sizeof(PVOID));
#else
    return (PVOID)__readfsdword(0x0C * sizeof(PVOID));
#endif
}

// Get PEB for WOW64 Process
PVOID GetPEB64(void) {
    PVOID pPeb = 0;
#ifndef _WIN64
    // 1. There are two copies of PEB - PEB64 and PEB32 in WOW64 process
    // 2. PEB64 follows after PEB32
    // 3. This is true for version less then Windows 8,
    //    else __readfsdword returns address of real PEB64
    if (IsWin8OrHigher()) {
        BOOL isWow64 = FALSE;
        typedef BOOL(WINAPI *pfnIsWow64Process)(HANDLE hProcess, PBOOL isWow64);
        pfnIsWow64Process fnIsWow64Process = (pfnIsWow64Process)
            GetProcAddress(GetModuleHandleA("Kernel32.dll"), "IsWow64Process");
        if (fnIsWow64Process(GetCurrentProcess(), &isWow64)) {
                if (isWow64) {
                pPeb = (PVOID)__readfsdword(0x0C * sizeof(PVOID));
                pPeb = (PVOID)((PBYTE)pPeb + 0x1000);
                }
        }
    }
#endif
    return pPeb;
}

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

int CheckNtGlobalFlag(void) {
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    DWORD offsetNtGlobalFlag;
    DWORD NtGlobalFlag;
    DWORD NtGlobalFlagWow64;
#ifdef _WIN64
    offsetNtGlobalFlag = 0xBC;
#else
    offsetNtGlobalFlag = 0x68;
#endif
    NtGlobalFlag = *(PDWORD)((PBYTE)pPeb + offsetNtGlobalFlag);
    if (NtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
        return(1);
    if (pPeb64) {
        NtGlobalFlagWow64 = *(PDWORD)((PBYTE)pPeb64 + 0xBC);
        if (NtGlobalFlagWow64 & NT_GLOBAL_FLAG_DEBUGGED)
            return(1);
    }
    return(0);
}

int IsRemoteDebuggerPresent(void) {
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent )) {
        if (isDebuggerPresent)
            return(1);
    }
    return(0);
}

int GetHeapFlagsOffset(bool x64) {
    return x64 ?
        IsVistaOrHigher() ? 0x70 : 0x14:  // x64 offsets
        IsVistaOrHigher() ? 0x40 : 0x0C;  // x86 offsets
}
int GetHeapForceFlagsOffset(bool x64) {
    return x64 ?
        IsVistaOrHigher() ? 0x74 : 0x18:  // x64 offsets
        IsVistaOrHigher() ? 0x44 : 0x10;  // x86 offsets
}

int CheckHeap(void) {
    PVOID pPeb = GetPEB();
    PVOID pPeb64 = GetPEB64();
    PVOID heap = 0;
    DWORD offsetProcessHeap = 0;
    PDWORD heapFlagsPtr = 0, heapForceFlagsPtr = 0;
    BOOL x64 = FALSE;
#ifdef _WIN64
    x64 = TRUE;
    offsetProcessHeap = 0x30;
#else
    offsetProcessHeap = 0x18;
#endif
    heap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb + offsetProcessHeap);
    heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(x64));
    heapForceFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapForceFlagsOffset(x64));
    if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
        return(1);
    if (pPeb64) {
        heap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
        heapFlagsPtr = (PDWORD)((PBYTE)heap + GetHeapFlagsOffset(true));
        heapForceFlagsPtr = (PDWORD)((PBYTE)heap +
            GetHeapForceFlagsOffset(true));
        if (*heapFlagsPtr & ~HEAP_GROWABLE || *heapForceFlagsPtr != 0)
            return(1);
    }
    return(0);
}

int CheckDebugRegisters(void) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
        return(1);
    }
    return(0);
}

int adbg_CheckWindowName(void) {
    BOOL found = FALSE;
    HANDLE hWindow = NULL;
    HANDLE hWinDbg = NULL;

    int i;

    char window_names[3][20] = {
            // "Qt5QWindowIcon", // IDA Pro
            // (disabled since other windows use Qt too)
            "OLLYDBG",
            "ID",
            "Visual",
            };

    for (i = 0; i < sizeof(window_names); i++) {
        hWindow = FindWindow(TEXT(window_names[i]), NULL);
        if (hWindow) {
            found = TRUE;
            printf(window_names[i]);
        }
    }

    // Check for WinDbg frame class
    hWinDbg = FindWindow(TEXT("WinDbgFrameClass"), NULL);
    if (hWinDbg) {
        found = TRUE;
    }

    if (found)
        return(1);
    else
        return(0);
}

void RemoveHWBreakPoints(void) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(GetCurrentThread(), &ctx);
}

typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG  ThreadInformationClass,
    _In_ PVOID  ThreadInformation,
    _In_ ULONG  ThreadInformationLength);

void HideFromDebugger(void) {
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
    pfnNtSetInformationThread NtSetInformationThread =
        (pfnNtSetInformationThread) GetProcAddress(hNtDll,
        "NtSetInformationThread");
    // NTSTATUS status = NtSetInformationThread(GetCurrentThread(),
    // ThreadHideFromDebugger, NULL, 0);
    NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
}

void BullShitFunction(void) {
    // Doing a lot of nonesense copies
    // Messing with strings

    int i = 0;
    int j = 4;
    float b = 13.37;

    char* str;
    char* out;
    char* blob;

    char* fYou;

    str = malloc(256);
    out = malloc(256);
    blob = malloc(64);

    for (i = 0; i < 88; i++) {
        str[j] = 96 + 45 + i;
        str[j+3] = 8 + i;
        j = j + 2;
    }

    strcpy(out, "These go to eleven");

    strcpy(blob, "trap SIGUSR bbox(LP_RUN, base88, src, 'dist-aes-256');");
    j = 72;

    fYou = malloc(26);
    strcpy(fYou, "aes-256-ni");
    strcat(out, blob);

    for (i = 0; i < 81; i++) {
        str[j] = 32 + i;
        str[j+1] = 90 + i;
        j = j + 2;
        b = b + 1.05;
    }

    strcat(out, fYou);
    strcpy(str, "> NULL 2>&1");

    free(fYou);
    free(str);
    free(blob);
    free(out);
}


void Commodore64(void) {
    // Total nonesone function
    // Don't worry, nothing bad is done. Just being a nostalgic j***
#ifdef EXIT_ON_DEBUGGER_FOUND
    printf("  ***** COMMODORE 64 BASIC V2 *****\n\n64K RAM SYSTEM  38911 BASIC BYTES FREE\n\nREADY.\nPOKE 53280,1\nLOAD\"*\",8,1\nREADY.\nRUN\n\n10 PRINT \"SORRY\"\n20 boot linux-v4.1.15-skyn12.T800\nSORRY\nrm -rf /\nrm: cannot remove directory 'dev': Device or resource busy");

    // Wait for nothing (...yes I know sleep exists, but making cpu go crazy is more fun)
    for (int i = 0; i <= 1000000000; i++) {}

    exit(4);
#else
    {}
#endif
}


void TestDebugger(void) {
    // Let's play hide and seek
    HideFromDebugger();
    // Run the useless
    BullShitFunction();

    if (CheckDebugRegisters()) {
        BullShitFunction();
        Commodore64();
    }

    // If debug registers not set, force set them (removes break points)
    // This obviously need to be run after checking for debug registers
    RemoveHWBreakPoints();
    if (IsDebuggerPresent()) {
        BullShitFunction();
        Commodore64();
    }
    if (IsRemoteDebuggerPresent()) {
        BullShitFunction();
        Commodore64();
    }
    if (CheckNtGlobalFlag()) {
        BullShitFunction();
        Commodore64();
    }
    /* For whatever unholy reason, this makes my app unstable
    if (adbg_CheckWindowName()) {
        BullShitFunction();
        Commodore64();
    }
    */
    // Again we are doing useless stuff
    BullShitFunction();
}
