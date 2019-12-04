#pragma once

#include <windows.h>
#include <stdbool.h>

WORD GetVersionWord(void);
BOOL IsWin8OrHigher(void);
BOOL IsVistaOrHigher(void);

// Current PEB for 64bit and 32bit processes accordingly
PVOID GetPEB(void);

// Get PEB for WOW64 Process
PVOID GetPEB64(void);

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

int CheckNtGlobalFlag(void);
int IsRemoteDebuggerPresent(void);
int GetHeapFlagsOffset(bool);
int GetHeapForceFlagsOffset(bool);
int CheckHeap(void);
int CheckDebugRegisters(void);
int adbg_CheckWindowName(void);
void RemoveHWBreakPoints(void);

typedef NTSTATUS (NTAPI *pfnNtSetInformationThread)(
	_In_ HANDLE ThreadHandle,
	_In_ ULONG  ThreadInformationClass,
	_In_ PVOID  ThreadInformation,
	_In_ ULONG  ThreadInformationLength
	);

//const ULONG ThreadHideFromDebugger = 0x11; // included in winternl.h, no need to reinclude

void HideFromDebugger(void);

void BullShitFunction(void);
void Commodore64(void);
void TestDebugger(void);