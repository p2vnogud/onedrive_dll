#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>

// Hàm mã hóa một chuỗi thành mảng ký tự hex
void encode_string_to_hex(const char* input, char* output, int output_size) {
    snprintf(output, output_size, "char %s_string[] = { ", input);
    int len = strlen(input);
    int offset = strlen(output);

    for (int i = 0; i < len; ++i) {
        char hex[8];
        snprintf(hex, sizeof(hex), "'\\x%02x'", (unsigned char)input[i]);
        strncat(output, hex, output_size - offset - 1);
        offset += strlen(hex);

        if (i < len - 1) {
            strncat(output, ", ", output_size - offset - 1);
            offset += 2;
        }
    }

    strncat(output, ", 0 }; // ", output_size - offset - 1);
    strncat(output, input, output_size - offset - 1);
}

// Hàm mã hóa mảng các chuỗi
void encode_string_array(const char* inputs[], int count, char* output, int output_size) {
    output[0] = '\0'; // Xóa buffer đầu ra

    for (int i = 0; i < count; ++i) {
        char temp[512]; // Buffer tạm cho từng chuỗi
        encode_string_to_hex(inputs[i], temp, sizeof(temp));
        strncat(output, temp, output_size - strlen(output) - 1);
        strncat(output, "\n", output_size - strlen(output) - 1);
    }
}

int main() {
    // Mảng các chuỗi cần mã hóa
    const char* strings[] = {
        "NTDLL.DLL",
        "user32.dll",
        "NtCreateUserProcess",
        "MessageBoxA",
        "KERNEL32.dll"
    };
    int count = sizeof(strings) / sizeof(strings[0]);

    char output[2048]; // Buffer đầu ra (đảm bảo đủ lớn)
    encode_string_array(strings, count, output, sizeof(output));

    printf("%s", output);

    return 0;
}