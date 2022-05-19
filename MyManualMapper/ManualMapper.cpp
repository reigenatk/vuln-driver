#include <iostream>
#include "pe_mapper.hpp"
#include <psapi.h>
#include <Windows.h>

HANDLE hProcess;

void __declspec(noreturn) fail()
{
    printf("Failed\n");
    (void)_getwche();
    abort();
}

char* stristr(const char* haystack, const char* needle) {
    do {
        const char* h = haystack;
        const char* n = needle;
        while (tolower((unsigned char)*h) == tolower((unsigned char)*n) && *n) {
            h++;
            n++;
        }
        if (*n == 0) {
            return (char*)haystack;
        }
    } while (*haystack++);
    return 0;
}

HMODULE FindModule(HANDLE process, const char* module_name) {
    HMODULE res = NULL;
    size_t req_size = sizeof(HMODULE*) * 100;
    HMODULE* mod_ptr = (HMODULE*) malloc(req_size);
    DWORD needed_size;
    while (true) {
        // call to this populates mod_ptr with pointer to array of HMODULE objects
        NTSTATUS ret = EnumProcessModulesEx(process, mod_ptr, req_size, &needed_size, LIST_MODULES_ALL);
        if (ret == 0) {
            printf("EnumProcessModulesEx failed\n");
            fail();
        }
        if (req_size < needed_size) {
            // try again with the needed size
            realloc(mod_ptr, needed_size);
        }
        else {
            // all good 
            break;
        }
    }
    int numModules = needed_size / sizeof(HMODULE);
    for (int i = 0; i < numModules; i++) {
        const size_t sz = 30;
        char name_of_module[sz];
        GetModuleBaseNameA(process, mod_ptr[i], name_of_module, sz);
        if (stristr(name_of_module, module_name)) {
            // found it
            res = mod_ptr[i];
            break;
        }
    }
    if (!res) {
        printf("Module %s not found in process %s\n", module_name, process);
        fail();
    }
    free(mod_ptr);
    return res;
}

int main() {
    // pass in lambdas into the constructor
    pe_mapper::mapping dll_mapping(
        // write memory
        [](uintptr_t address, uintptr_t buffer, size_t size) -> bool
        {
            SIZE_T nWritten;
            WriteProcessMemory(hProcess, (LPVOID)address, (LPCVOID)buffer, size, &nWritten);
            return nWritten == size;
        },
        // size_t memory
            [&](size_t size) -> uintptr_t
        {
            return (uintptr_t)VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        },
            // free memory
            [](uintptr_t address) -> void
        {
            VirtualFreeEx(hProcess, (LPVOID)address, 0, MEM_RELEASE);
        },
            // get function. Load the desired import's module in, and then get procadress on the import, and get the import's address
            [](std::string module_name, std::string function_name) -> uintptr_t
        {
            const auto ssss = std::filesystem::path(module_name).filename().string();

            const uintptr_t remote_module_base = (uintptr_t)FindModule(hProcess, ssss.c_str());
            if (!remote_module_base)
            {
                printf("couldnt find module %s in remote process\n", ssss.c_str());
                return 0;
            }

            const auto local_module =
                reinterpret_cast<uintptr_t>(
                    LoadLibraryExA(module_name.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES));
            if (!local_module)
            {
                printf("failed to load module %s locally\n", module_name.c_str());
                return 0;
            }

            const auto local_export =
                reinterpret_cast<uintptr_t>(
                    GetProcAddress(reinterpret_cast<HMODULE>(local_module), function_name.c_str()));
            if (!local_export)
            {
                printf("GetProcAddress(%s, %s) failed\n", module_name.c_str(), function_name.c_str());
                return 0;
            }

            return (local_export - local_module) + remote_module_base;
        }
        );

    if (!dll_mapping.read_image("D:\\Coding\\C++\\CSGO Hacking\\mycsgostuff\\x64\Debug\\CSGODLL.dll", "DllEntryPoint")) {
        printf("Read Image failed\n");
        return 0;
    }

    if (!dll_mapping.load_image()) {
        printf("Load Image Failed\n");
        return 0;
    }
	return 0;
}