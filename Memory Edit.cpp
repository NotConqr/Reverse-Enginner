#include <iostream>
#include <string>
#include <unordered_map>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

class Mem {
public:
    // Static handle to the process, used for memory operations.
    static HANDLE pHandle;

    // Structure to hold process information.
    PROCESSENTRY32 processEntry;

    // Stores the base addresses of each loaded module in the target process.
    std::unordered_map<std::string, uintptr_t> modules;

    // Stores the base address of the main module (the main executable).
    uintptr_t mainModuleBase = 0;

    // Opens the target process and retrieves its modules.
    bool OpenGameProcess(int procID) {
        if (procID == 0) return false;

        // Take a snapshot of all processes in the system.
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        processEntry.dwSize = sizeof(PROCESSENTRY32);
        
        // Iterate through processes to find the target process by ID.
        if (Process32First(hSnap, &processEntry)) {
            do {
                if (processEntry.th32ProcessID == procID) {
                    // Open a handle to the target process with full access.
                    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
                    if (pHandle == NULL) {
                        CloseHandle(hSnap);
                        return false;
                    }
                    // Retrieve all modules associated with the process.
                    getModules(procID);
                    CloseHandle(hSnap);
                    return true;
                }
            } while (Process32Next(hSnap, &processEntry));
        }
        CloseHandle(hSnap);
        return false;
    }

    // Retrieves and stores the base address of all modules loaded by the process.
    void getModules(DWORD procID) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);
        if (hSnap == INVALID_HANDLE_VALUE) return;

        MODULEENTRY32 mEntry;
        mEntry.dwSize = sizeof(MODULEENTRY32);

        // Iterate through modules and store their names and base addresses.
        if (Module32First(hSnap, &mEntry)) {
            do {
                modules[mEntry.szModule] = (uintptr_t)mEntry.modBaseAddr;
                if (strcmp(mEntry.szModule, processEntry.szExeFile) == 0) {
                    mainModuleBase = (uintptr_t)mEntry.modBaseAddr;
                }
            } while (Module32Next(hSnap, &mEntry));
        }
        CloseHandle(hSnap);
    }

    // Converts a memory code string (like "module+offset") to an actual memory address.
    uintptr_t LoadUIntPtrCode(const std::string& name, const std::string& file) {
        // Assume 'name' has the format "module+offset".
        size_t plusPos = name.find('+');
        std::string moduleName = name.substr(0, plusPos);
        uintptr_t offset = std::stoul(name.substr(plusPos + 1), nullptr, 16);

        // If "base" or "main" is specified, use the main module base address.
        if (moduleName == "base" || moduleName == "main") {
            return mainModuleBase + offset;
        }
        // Otherwise, look for the module in the module map and add the offset.
        else if (modules.count(moduleName) > 0) {
            return modules[moduleName] + offset;
        }
        return 0;
    }

    // Reads a string from memory at the specified code address.
    std::string readString(const std::string& code) {
        uintptr_t address = LoadUIntPtrCode(code, "");
        char buffer[10];

        // Attempt to read memory at the calculated address.
        if (ReadProcessMemory(pHandle, (LPCVOID)address, buffer, sizeof(buffer), NULL)) {
            return std::string(buffer);
        }
        return "";
    }

    // Writes data to memory at the specified code address.
    bool writeMemory(const std::string& code, const std::string& type, const std::string& value) {
        uintptr_t address = LoadUIntPtrCode(code, "");

        // Write based on the data type.
        if (type == "float") {
            float fValue = std::stof(value);
            return WriteProcessMemory(pHandle, (LPVOID)address, &fValue, sizeof(fValue), NULL);
        } else if (type == "int") {
            int iValue = std::stoi(value);
            return WriteProcessMemory(pHandle, (LPVOID)address, &iValue, sizeof(iValue), NULL);
        } else if (type == "byte") {
            BYTE bValue = static_cast<BYTE>(std::stoi(value));
            return WriteProcessMemory(pHandle, (LPVOID)address, &bValue, sizeof(bValue), NULL);
        } else if (type == "string") {
            return WriteProcessMemory(pHandle, (LPVOID)address, value.c_str(), value.size(), NULL);
        }
        return false;
    }

    // Retrieves the process ID of a process by its name.
    int getProcIDFromName(const std::string& name) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 pEntry;
        pEntry.dwSize = sizeof(PROCESSENTRY32);
        int procID = 0;

        // Iterate through all processes to find the one with the specified name.
        if (Process32First(hSnap, &pEntry)) {
            do {
                if (name == pEntry.szExeFile) {
                    procID = pEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pEntry));
        }
        CloseHandle(hSnap);
        return procID;
    }

    // Closes the handle to the opened process.
    void closeProcess() {
        if (pHandle != NULL) {
            CloseHandle(pHandle);
            pHandle = NULL;
        }
    }
};

// Static member initialization
HANDLE Mem::pHandle = NULL;

int main() {
    Mem mem;

    // Example: find process by name and open it
    std::string processName = "example.exe";
    int procID = mem.getProcIDFromName(processName);

    if (mem.OpenGameProcess(procID)) {
        std::cout << "Process opened successfully.\n";

        // Example: read a string from a memory location
        std::string readVal = mem.readString("module+offset");
        std::cout << "Read value: " << readVal << std::endl;

        // Example: write an integer to memory
        mem.writeMemory("module+offset", "int", "123");

        // Close the process handle when done
        mem.closeProcess();
    } else {
        std::cout << "Failed to open process.\n";
    }
    return 0;
}
