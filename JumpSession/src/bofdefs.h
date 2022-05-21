#pragma once
#pragma intrinsic(memcpy,strlen)
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

//MSVCRT
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char * string1, const char * string2);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscmp(const wchar_t* _lhs, const wchar_t* _rhs);
WINBASEAPI int __cdecl MSVCRT$sprintf_s(char* buffer, size_t sizeOfBuffer, const char* format);

//ADVAPI32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid); 
WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength); 
WINADVAPI WINBOOL WINAPI ADVAPI32$CreateProcessAsUserA(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateTokenEx (HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$RevertToSelf();

//K32
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI WINBOOL WINAPI KERNEL32$InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
WINBASEAPI WINBOOL WINAPI KERNEL32$UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
WINBASEAPI VOID WINAPI KERNEL32$DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI VOID WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);
WINBASEAPI VOID WINAPI KERNEL32$GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread();
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();


//NTDLL
WINBASEAPI NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcRoutineContext, PVOID ApcStatusBlock, ULONG ApcReserved);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

//MSVCRT
#define memset MSVCRT$memset
#define wcscmp MSVCRT$wcscmp
#define free MSVCRT$free
#define _stricmp MSVCRT$_stricmp
#define sprintf_s MSVCRT$sprintf_s

//ADVAPI32
#define OpenProcessToken ADVAPI32$OpenProcessToken
#define LookupPrivilegeValueA ADVAPI32$LookupPrivilegeValueA
#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
#define DuplicateTokenEx ADVAPI32$DuplicateTokenEx 
#define ImpersonateLoggedOnUser ADVAPI32$ImpersonateLoggedOnUser
#define CreateProcessAsUserA ADVAPI32$CreateProcessAsUserA
#define OpenThreadToken ADVAPI32$OpenThreadToken
#define RevertToSelf ADVAPI32$RevertToSelf

//K32
#define CloseHandle KERNEL32$CloseHandle 
#define CreateToolhelp32Snapshot KERNEL32$CreateToolhelp32Snapshot 
#define Process32First KERNEL32$Process32First 
#define Process32Next KERNEL32$Process32Next
#define InitializeProcThreadAttributeList KERNEL32$InitializeProcThreadAttributeList 
#define UpdateProcThreadAttribute KERNEL32$UpdateProcThreadAttribute 
#define DeleteProcThreadAttributeList KERNEL32$DeleteProcThreadAttributeList 
#define OpenProcess KERNEL32$OpenProcess 
#define GetNativeSystemInfo KERNEL32$GetNativeSystemInfo
#define GetSystemInfo KERNEL32$GetSystemInfo
#define HeapAlloc KERNEL32$HeapAlloc 
#define GetProcessHeap KERNEL32$GetProcessHeap
#define GetCurrentProcess KERNEL32$GetCurrentProcess 
#define GetCurrentThread KERNEL32$GetCurrentThread
#define GetLastError KERNEL32$GetLastError

//NTDLL
#define NtAllocateVirtualMemory NTDLL$NtAllocateVirtualMemory
#define NtWriteVirtualMemory NTDLL$NtWriteVirtualMemory
#define NtProtectVirtualMemory NTDLL$NtProtectVirtualMemory
#define NtQueueApcThread NTDLL$NtQueueApcThread
#define NtResumeThread NTDLL$NtResumeThread