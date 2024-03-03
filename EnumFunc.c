#include <Windows.h>
#include <stdio.h>

#include <stdlib.h>
#include <time.h>   

// Функция для генерации случайного значения SEED
unsigned int generateRandomSeed() {
    srand((unsigned int)time(NULL)); // Инициализация генератора случайных чисел
    return rand() * 383939234;
}
#define SEED generateRandomSeed()
#define STR "_CRC32"

unsigned int crc32h(char* message) {
    int i, crc;
    unsigned int byte, c;
    const unsigned int g0 = SEED, g1 = g0 >> 1,
        g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
        g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;
    i = 0;
    crc = 0xFFFFFFFF;
    while ((byte = message[i]) != 0) {
        crc = crc ^ byte;
        c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
            ((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
            ((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
            ((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
        crc = ((unsigned)crc >> 8) ^ c;
        i = i + 1;
    }
    return ~crc;
}
#define HASH(API) crc32h((char*)API)
int main() {
    printf("// Random SEED generated for CRC32:\n");
    printf("#define SEED 0x%0.8X\n", SEED);
    printf("#define %s%s \t 0x%0.8X \n", "NtAllocateVirtualMemory", STR, HASH("NtAllocateVirtualMemory"));
    return 0;
}
