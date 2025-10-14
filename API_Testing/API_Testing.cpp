#include <windows.h>
#include <iostream>
#include <string>

// Định nghĩa cấu trúc UNICODE_STRING
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// Định nghĩa cấu trúc PEB
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    struct _PEB_LDR_DATA* Ldr; // Con trỏ đến PEB_LDR_DATA
    // Các trường khác có thể được thêm nếu cần
} PEB, * PPEB;

// Định nghĩa cấu trúc PEB_LDR_DATA
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// Định nghĩa cấu trúc LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

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

//// Hàm lấy modules (vd: kernel32.dll, ntdll.dll, ...)
//HMODULE GetModuleHandleReplacement(IN DWORD szModuleName) {
//    PPEB pPeb = (PPEB)__readgsqword(0x60); // Lấy PEB từ GS:[0x60]
//    if (!pPeb || !pPeb->Ldr) return NULL;
//
//    PPEB_LDR_DATA pLdr = pPeb->Ldr;
//    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
//
//    while (pDte && pDte != (PLDR_DATA_TABLE_ENTRY)&pLdr->InMemoryOrderModuleList) {
//        if (pDte->FullDllName.Length != 0) {
//            int size_needed = WideCharToMultiByte(CP_ACP, 0, pDte->FullDllName.Buffer, -1, NULL, 0, NULL, NULL);
//            char* moduleName = new char[size_needed];
//            WideCharToMultiByte(CP_ACP, 0, pDte->FullDllName.Buffer, -1, moduleName, size_needed, NULL, NULL);
//
//            if (fnv1a_hash(moduleName) == szModuleName) {
//                delete[] moduleName;
//                return (HMODULE)pDte->DllBase;
//            }
//            delete[] moduleName;
//        }
//        pDte = (PLDR_DATA_TABLE_ENTRY)pDte->InMemoryOrderLinks.Flink;
//    }
//    return NULL;
//}
//
//// Hàm lấy các function API từ module truyền vào
//FARPROC GetNtApiByHash(HMODULE hModule, DWORD functionHash) {
//    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
//    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
//    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
//    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDataDir.VirtualAddress);
//
//    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);
//    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
//    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
//
//    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
//        const char* functionName = (const char*)((BYTE*)hModule + addressOfNames[i]);
//        if (fnv1a_hash(functionName) == functionHash) {
//            WORD functionOrdinal = addressOfNameOrdinals[i];
//            return (FARPROC)((BYTE*)hModule + addressOfFunctions[functionOrdinal]);
//        }
//    }
//    return nullptr;
//}

int main() {
    // Array of function names
    const char* functionNames[] = {
        "ntdll.dll",
        "user32.dll",
        "kernel32.dll",
        "NtAddBootEntry",
        "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "NtOpenProcess",
        "NtClose",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtCreateUserProcess",
        "Process32NextW",
        "Process32FirstW",
        "CreateToolhelp32Snapshot",
        "TpAllocWait",
        "TpSetWait",
        "NtWaitForSingleObject",
        nullptr
    };

    // Process each function name in the array
    for (int i = 0; functionNames[i] != nullptr; i++) {
        DWORD hashValue = fnv1a_hash(functionNames[i]);
        std::cout << "Hash of " << functionNames[i] << " = 0x"
            << std::hex << hashValue << std::endl;
    }

    //// Ví dụ sử dụng GetModuleHandleReplacement và GetNtApiByHash
    //DWORD moduleHash = fnv1a_hash("ntdll.dll");
    //HMODULE hModule = GetModuleHandleReplacement(moduleHash);
    //if (hModule) {
    //    DWORD apiHash = fnv1a_hash("NtAllocateVirtualMemory");
    //    FARPROC pFunc = GetNtApiByHash(hModule, apiHash);
    //    if (pFunc) {
    //        std::cout << "Found NtAllocateVirtualMemory at: " << (void*)pFunc << std::endl;
    //    }
    //}

    return 0;
}